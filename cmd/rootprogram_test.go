package cmd

// Tests of the Windows root program (ROADMAP.md R7-T3, rootprogram.go): the
// cabinet parsing (including the MSZIP sliding window over the real
// authrootstl.cab), the PKCS#7 verification under the pinned signer, the CTL
// parsing, the cache load/harvest/veto state machine and the refresh policy.
// The trust machinery is exercised on generated material pinned into the
// verification exactly the way the binary pins the Microsoft signer; the two
// committed real cabinets ride as end-to-end fixtures of the format as
// Microsoft actually ships it. No network: the refresh tests inject an
// httptest server or a failing fetch.

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- fixtures ----

// realAuthRootCAB is the authrootstl.cab downloaded from
// ctldl.windowsupdate.com on 2026-11-12, committed as the format fixture.
func realAuthRootCAB(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "authrootstl.cab"))
	if err != nil {
		t.Fatalf("could not read the real authrootstl.cab fixture: %s", err)
	}
	return raw
}

func realDisallowedCAB(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "disallowedcertstl.cab"))
	if err != nil {
		t.Fatalf("could not read the real disallowedcertstl.cab fixture: %s", err)
	}
	return raw
}

// realAuthRootSTL extracts the signed CTL from the real cabinet.
func realAuthRootSTL(t *testing.T) []byte {
	t.Helper()
	members, err := parseCabinet(realAuthRootCAB(t))
	if err != nil {
		t.Fatalf("the real authrootstl.cab does not parse: %s", err)
	}
	if len(members) != 1 {
		t.Fatalf("the real authrootstl.cab carries %d members, want 1", len(members))
	}
	return members[0].data
}

// realCTLTime is the era the real fixtures and the pinned signer live in.
var realCTLTime = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

// synthNow is the clock the generated-material tests ride: the generated
// signer is valid around time.Now() by construction, so the fixed fixture
// era must not gate it — the suite would die the day the wall clock moved
// past the generated validity window. Truncated to seconds because a CTL
// thisUpdate rides UTCTime (second precision) and the round-trip assertions
// compare the decoded verdict against this clock.
var synthNow = time.Now().Truncate(time.Second)

// ---- generated material helpers ----

// testCTLSigner generates a self-signed RSA signer certificate, the shape of
// the pinned Microsoft CTL signer at small scale.
func testCTLSigner(t *testing.T, commonName string) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate the signer key: %s", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour), // the refresh tests ride clocks up to synthNow+20d
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create the signer certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("could not parse the signer certificate: %s", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, key, pemBytes
}

// ---- minimal DER assembly for the synthetic signed CTLs ----

func mustASN1(t *testing.T, v any) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("could not marshal %v: %s", v, err)
	}
	return der
}

// asn1Wrap returns the TLV of the given universal tag around the children.
func asn1Wrap(tag int, children ...[]byte) []byte {
	var body bytes.Buffer
	for _, c := range children {
		body.Write(c)
	}
	out, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: tag, IsCompound: true, Bytes: body.Bytes()})
	if err != nil {
		panic(err)
	}
	return out
}

func asn1Seq(children ...[]byte) []byte        { return asn1Wrap(16, children...) }
func asn1Set(children ...[]byte) []byte        { return asn1Wrap(17, children...) }
func asn1NULL() []byte                         { out, _ := asn1.Marshal(asn1.RawValue{Tag: 5}); return out }
func asn1OID(oid asn1.ObjectIdentifier) []byte { out, _ := asn1.Marshal(oid); return out }

// asn1ExplicitTag0 wraps children in a context-specific constructed [0]
// element (the CMS content wrappers ride it implicitly in the MS shape).
func asn1ExplicitTag0(children []byte) []byte {
	out, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: children})
	if err != nil {
		panic(err)
	}
	return out
}

// buildCTLDER assembles the MS-CRTD CertificateTrustList as observed on the
// real files: subjectUsage AlgorithmIdentifier, listIdentifier INTEGER,
// thisUpdate UTCTime, subjectAlgorithm (sha1), entries SEQUENCE OF { hash }.
func buildCTLDER(t *testing.T, usage asn1.ObjectIdentifier, thisUpdate time.Time, hashes []ctlHash) []byte {
	t.Helper()
	entries := make([][]byte, 0, len(hashes))
	for _, h := range hashes {
		entries = append(entries, mustASN1(t, struct{ SubjectIdentifier []byte }{h[:]}))
	}
	return asn1Seq(
		asn1Seq(asn1OID(usage), asn1NULL()),
		mustASN1(t, big.NewInt(1)),
		mustASN1(t, thisUpdate.UTC()),
		asn1Seq(asn1OID(oidSHA1Digest), asn1NULL()),
		asn1Seq(entries...),
	)
}

// buildSignedSTL wraps a CTL into the MS-shaped PKCS#7 SignedData: digest
// SHA-256, signedAttrs (contentType + messageDigest) with the RSA signature
// over the SET re-tagged attributes — or the legacy no-attributes shape, or
// an ECDSA signer, per the flags.
func buildSignedSTL(t *testing.T, signerCert *x509.Certificate, signerKey crypto.Signer, ctlDER []byte, withAttrs, ecdsaMode bool) []byte {
	t.Helper()

	// the messageDigest rides the CTL content octets exactly the way the real
	// cabinets carry it (ctlContentHashInput strips the outermost TLV header)
	digestHash := sha256.Sum256(ctlContentHashInput(ctlDER))
	digest := digestHash[:]

	signerInfoChildren := [][]byte{
		mustASN1(t, 1),
		asn1Seq(signerCert.RawIssuer, mustASN1(t, signerCert.SerialNumber)),
		asn1Seq(asn1OID(oidSHA256Digest), asn1NULL()),
	}
	sigAlgDER := asn1Seq(asn1OID(oidRSAEncryption), asn1NULL())
	var signature []byte
	if withAttrs {
		// the attributes ride the [0] element directly — an inner SEQUENCE
		// wrapper would be a shape the real files do not carry (and the
		// decoder rightly refuses); the messageDigest value is a proper
		// OCTET STRING inside its SET, as the real files encode it
		attrsContent := append(
			asn1Seq(asn1OID(oidAttrContentType), asn1Set(asn1OID(oidMSCertificateTrustList))),
			asn1Seq(asn1OID(oidAttrMessageDigest), asn1Set(mustASN1(t, digest)))...,
		)
		// the signed form is the SET; the SignerInfo carries the same
		// content under the [0] IMPLICIT tag
		setDER := asn1Set(attrsContent)
		signerInfoChildren = append(signerInfoChildren, append([]byte{0xA0}, setDER[1:]...))
		if ecdsaMode {
			priv, ok := signerKey.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("ecdsaMode wants an ECDSA key, got %T", signerKey)
			}
			sig, err := ecdsa.SignASN1(rand.Reader, priv, digestHashOf(t, setDER))
			if err != nil {
				t.Fatalf("could not sign the attributes: %s", err)
			}
			signature = sig
			sigAlgDER = asn1Seq(asn1OID(oidECDSAPublicKey))
		} else {
			priv, ok := signerKey.(*rsa.PrivateKey)
			if !ok {
				t.Fatalf("the RSA path wants an RSA key, got %T", signerKey)
			}
			sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digestHashOf(t, setDER))
			if err != nil {
				t.Fatalf("could not sign the attributes: %s", err)
			}
			signature = sig
		}
	} else {
		if ecdsaMode {
			priv := signerKey.(*ecdsa.PrivateKey)
			sig, err := ecdsa.SignASN1(rand.Reader, priv, digestHashOf(t, ctlDER))
			if err != nil {
				t.Fatalf("could not sign the content: %s", err)
			}
			signature = sig
			sigAlgDER = asn1Seq(asn1OID(oidECDSAPublicKey))
		} else {
			priv := signerKey.(*rsa.PrivateKey)
			sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digestHashOf(t, ctlDER))
			if err != nil {
				t.Fatalf("could not sign the content: %s", err)
			}
			signature = sig
		}
	}
	signerInfoChildren = append(signerInfoChildren, sigAlgDER, mustASN1(t, signature))

	encap := asn1Seq(asn1OID(oidMSCertificateTrustList), asn1ExplicitTag0(ctlDER))
	certificates := asn1ExplicitTag0(signerCert.Raw)
	signerInfos := asn1Set(asn1Seq(signerInfoChildren...))
	signedData := asn1Seq(
		mustASN1(t, 1),
		asn1Set(asn1Seq(asn1OID(oidSHA256Digest), asn1NULL())),
		encap,
		certificates,
		signerInfos,
	)
	return asn1Seq(asn1OID(oidPKCS7SignedData), asn1ExplicitTag0(signedData))
}

func digestHashOf(t *testing.T, data []byte) []byte {
	t.Helper()
	h := sha256.Sum256(data)
	return h[:]
}

// ---- cabinet builder for the synthetic fixtures ----

// buildTestCAB assembles a cabinet around one member, in the root-program
// CFFILE variant (two extra bytes) or the standard one, compressed NONE or
// MSZIP. The MSZIP chunks ride compress/flate (raw deflate) exactly the way
// the implementation inflates them.
func buildTestCAB(t *testing.T, codec byte, memberName string, member []byte, rootProgramLayout bool) []byte {
	t.Helper()
	const chunkSize = 32768

	blocks := make([][]byte, 0, len(member)/chunkSize+1)
	for start := 0; start < len(member) || start == 0; start += chunkSize {
		end := start + chunkSize
		if end > len(member) {
			end = len(member)
		}
		chunk := member[start:end]
		if codec == 0x01 {
			var buf bytes.Buffer
			fw, err := flate.NewWriter(&buf, flate.BestSpeed)
			if err != nil {
				t.Fatalf("could not create the deflate writer: %s", err)
			}
			if _, err := fw.Write(chunk); err != nil {
				t.Fatalf("could not deflate the chunk: %s", err)
			}
			fw.Close()
			blocks = append(blocks, append([]byte("CK"), buf.Bytes()...))
		} else {
			blocks = append(blocks, append([]byte{}, chunk...))
		}
	}

	nameOffDelta := 14
	if rootProgramLayout {
		nameOffDelta = 16
	}
	// CFFOLDER sits right behind the 36-byte header, the CFFILE entry follows
	// it directly, and the data blocks follow the CFFILE entry (name plus its
	// NUL terminator behind the date/time/attribs fields)
	folderOff := 36 + 8
	dataOff := folderOff + nameOffDelta + len(memberName) + 1

	var buf bytes.Buffer
	write := func(order binary.ByteOrder, v any) {
		if err := binary.Write(&buf, order, v); err != nil {
			t.Fatalf("could not write the cabinet: %s", err)
		}
	}
	totalSize := dataOff
	for _, b := range blocks {
		totalSize += 8 + len(b)
	}
	buf.WriteString("MSCF")
	write(binary.LittleEndian, uint32(0))         // reserved1
	write(binary.LittleEndian, uint32(totalSize)) // cbCabinet
	write(binary.LittleEndian, uint32(0))         // reserved2
	write(binary.LittleEndian, uint32(folderOff))
	write(binary.LittleEndian, uint32(0)) // reserved3
	buf.WriteByte(3)                      // versionMinor
	buf.WriteByte(1)                      // versionMajor
	write(binary.LittleEndian, uint16(1)) // cFolders
	write(binary.LittleEndian, uint16(1)) // cFiles
	write(binary.LittleEndian, uint16(0)) // flags
	write(binary.LittleEndian, uint16(0)) // setID
	write(binary.LittleEndian, uint16(0)) // iCabinet
	// CFFOLDER
	write(binary.LittleEndian, uint32(dataOff))
	write(binary.LittleEndian, uint16(len(blocks)))
	write(binary.LittleEndian, uint16(codec))
	// CFFILE
	write(binary.LittleEndian, uint32(len(member)))
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0) // iFolder
	if rootProgramLayout {
		buf.WriteByte(0)
		buf.WriteByte(0) // the two extra bytes of the root-program variant
	}
	write(binary.LittleEndian, uint16(0x5D57)) // date 2026-10-23
	write(binary.LittleEndian, uint16(0x82CD)) // time 16:22:26
	write(binary.LittleEndian, uint16(0x20))   // attribs: archive
	buf.WriteString(memberName)
	buf.WriteByte(0)
	// CFDATA blocks
	for i, b := range blocks {
		uncomp := chunkSize
		if i == len(blocks)-1 {
			uncomp = len(member) - (len(blocks)-1)*chunkSize
			if uncomp > chunkSize {
				uncomp = chunkSize
			}
		}
		write(binary.LittleEndian, uint32(0)) // checksum (not verified: the signature is the integrity anchor)
		write(binary.LittleEndian, uint16(len(b)))
		write(binary.LittleEndian, uint16(uncomp))
		buf.Write(b)
	}
	return buf.Bytes()
}

// ---- newTestRootProgram ----

func newTestRootProgram(t *testing.T, dir string, signerPEM []byte, now time.Time) *rootProgram {
	t.Helper()
	return &rootProgram{
		ssh3Dir:             dir,
		enabled:             true,
		signerPEM:           signerPEM,
		disallowedSignerPEM: signerPEM, // the synthetic lists share one generated signer
		blessed:             make(map[[sha256.Size]byte]struct{}),
		fetch: func(ctx context.Context, url string) ([]byte, error) {
			return nil, errors.New("unexpected fetch in this test")
		},
		now: func() time.Time { return now },
	}
}

// ---- CAB parsing ----

// The real cabinet rides the exact shape Microsoft ships: MSZIP chunks bound
// to the CFDATA blocks, the shifted CFFILE layout, one authroot.stl member.
func TestParseCabinetRealAuthRootSTL(t *testing.T) {
	members, err := parseCabinet(realAuthRootCAB(t))
	if err != nil {
		t.Fatalf("the real authrootstl.cab does not parse: %s", err)
	}
	if len(members) != 1 {
		t.Fatalf("the real authrootstl.cab carries %d members, want 1", len(members))
	}
	if members[0].name != "authroot.stl" {
		t.Errorf("member name %q, want authroot.stl", members[0].name)
	}
	if len(members[0].data) != 204675 {
		t.Errorf("authroot.stl is %d bytes, want 204675", len(members[0].data))
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(members[0].data))
	if sum != "2f402c0556aaa1dc3afa2750a88bfd1670a72619ad4a34de2d340db677742f40" {
		t.Errorf("authroot.stl sha256 %s does not match the committed fixture", sum)
	}
}

func TestParseCabinetRealDisallowedSTL(t *testing.T) {
	members, err := parseCabinet(realDisallowedCAB(t))
	if err != nil {
		t.Fatalf("the real disallowedcertstl.cab does not parse: %s", err)
	}
	if len(members) != 1 || members[0].name != "disallowedcert.stl" {
		t.Fatalf("members = %v, want one disallowedcert.stl", members)
	}
	if len(members[0].data) != 6704 {
		t.Errorf("disallowedcert.stl is %d bytes, want 6704", len(members[0].data))
	}
}

// The synthetic NONE and MSZIP cabinets round-trip in both CFFILE layouts,
// including the multi-block MSZIP case (the sliding window carries across
// the chunks).
func TestParseCabinetSyntheticRoundTrip(t *testing.T) {
	member := make([]byte, 70000)
	for i := range member {
		member[i] = byte(i * 31)
	}
	for _, codec := range []byte{0x00, 0x01} {
		for _, layout := range []bool{true, false} {
			cab := buildTestCAB(t, codec, "member.bin", member, layout)
			got, err := parseCabinet(cab)
			if err != nil {
				t.Fatalf("codec 0x%x layout %v: the cabinet does not parse: %s", codec, layout, err)
			}
			if len(got) != 1 || got[0].name != "member.bin" {
				t.Fatalf("codec 0x%x layout %v: members = %v", codec, layout, got)
			}
			if !bytes.Equal(got[0].data, member) {
				t.Fatalf("codec 0x%x layout %v: the member does not round-trip", codec, layout)
			}
		}
	}
}

func TestParseCabinetRejectsGarbage(t *testing.T) {
	if _, err := parseCabinet([]byte("this is not a cabinet at all")); err == nil {
		t.Fatal("a non-MSCF body must not parse")
	}
	cab := buildTestCAB(t, 0x00, "x", []byte("hello"), true)
	if _, err := parseCabinet(cab[:len(cab)/2]); err == nil {
		t.Fatal("a truncated cabinet must not parse")
	}
}

// LZX folders are refused honestly (the root program never ships them).
func TestParseCabinetRejectsLZX(t *testing.T) {
	cab := buildTestCAB(t, 0x00, "x", []byte("hello"), true)
	binary.LittleEndian.PutUint16(cab[36+6:36+8], 0x0003) // folder codec LZX
	if _, err := parseCabinet(cab); err == nil || !strings.Contains(err.Error(), "LZX") {
		t.Fatalf("an LZX folder must be refused naming LZX, got %v", err)
	}
}

// A broken MSZIP chunk signature is refused (a corrupted cabinet must not
// yield a payload that would then fail the signature check confusingly).
func TestParseCabinetRejectsBrokenMSZIP(t *testing.T) {
	cab := buildTestCAB(t, 0x01, "x", []byte(strings.Repeat("payload ", 1000)), true)
	// the first CFDATA block rides where the folder header points; smash its CK
	dataOff := int(binary.LittleEndian.Uint32(cab[36:40]))
	if !bytes.Equal(cab[dataOff+8:dataOff+10], []byte("CK")) {
		t.Fatalf("the test cabinet does not start with a CK chunk")
	}
	cab[dataOff+8] = 'X'
	if _, err := parseCabinet(cab); err == nil {
		t.Fatal("a broken MSZIP signature must not parse")
	}
}

// ---- PKCS#7 / CTL verification ----

// The real trust list verifies under the pinned Microsoft signer and parses
// to the observed verdict.
func TestVerifySignedCTLRealAuthRoot(t *testing.T) {
	verdict, err := verifySignedCTL(realAuthRootSTL(t), msCTLSignerPEM, realCTLTime, oidRootListSignerUsage, true)
	if err != nil {
		t.Fatalf("the real authrootstl.cab does not verify under the pinned signer: %s", err)
	}
	if !verdict.usage.Equal(oidRootListSignerUsage) {
		t.Errorf("usage %v, want %v", verdict.usage, oidRootListSignerUsage)
	}
	if got := verdict.thisUpdate.UTC(); !got.Equal(time.Date(2026, 10, 23, 23, 18, 35, 0, time.UTC)) {
		t.Errorf("thisUpdate %s, want the observed 2026-10-23 23:18:35Z", got)
	}
	if len(verdict.hashes) < 100 {
		t.Errorf("%d CTL entries, want at least 100 roots in the real list", len(verdict.hashes))
	}
	// the pinned signer of the fixture era: no expiry warning should have
	// failed the verdict, and the signerNotAfter rides the verdict
	if verdict.signerNotAfter.IsZero() {
		t.Error("the verdict carries no signerNotAfter")
	}
}

// The embedded ISRG roots ride the real verdict — the reason the truncated
// store case works at all (probed against the committed fixture).
func TestRealCTLListsEmbeddedISRGRoots(t *testing.T) {
	verdict, err := verifySignedCTL(realAuthRootSTL(t), msCTLSignerPEM, realCTLTime, oidRootListSignerUsage, true)
	if err != nil {
		t.Fatalf("the real authrootstl.cab does not verify: %s", err)
	}
	for _, tc := range []struct {
		name string
		pem  []byte
	}{
		{"ISRG Root X1", isrgRootX1PEM},
		{"ISRG Root X2", isrgRootX2PEM},
	} {
		block, _ := pem.Decode(tc.pem)
		if block == nil {
			t.Fatalf("%s: the embedded PEM does not decode", tc.name)
		}
		h := sha1.Sum(block.Bytes)
		if _, ok := verdict.hashes[ctlHash(h)]; !ok {
			t.Errorf("%s (sha1 %x) is not listed in the real CTL", tc.name, h)
		}
	}
}

// The real disallowed list verifies under the same signer and parses with
// the disallowed usage.
func TestVerifySignedCTLRealDisallowed(t *testing.T) {
	members, err := parseCabinet(realDisallowedCAB(t))
	if err != nil {
		t.Fatalf("the real disallowedcertstl.cab does not parse: %s", err)
	}
	verdict, err := verifySignedCTL(members[0].data, msCTLDisallowedSignerPEM, realCTLTime, oidDisallowedUsage, false)
	if err != nil {
		t.Fatalf("the real disallowedcertstl.cab does not verify: %s", err)
	}
	if !verdict.usage.Equal(oidDisallowedUsage) {
		t.Errorf("usage %v, want %v", verdict.usage, oidDisallowedUsage)
	}
	// the real disallowed entries ride md5 and sha384 widths (extraHashes);
	// the synthetic lists in the state tests use SHA-1 entries, both ride the
	// same gate
	if len(verdict.hashes)+len(verdict.extraHashes) < 1 {
		t.Error("the real disallowed list carries no entries")
	}
	if len(verdict.extraHashes) < 1 {
		t.Errorf("the real disallowed list carries %d extra-width entries, want at least 1", len(verdict.extraHashes))
	}
}

// A swapped list (the disallowed verdict offered as the trust list) is
// refused on the usage check.
func TestVerifySignedCTLRefusesSwappedUsage(t *testing.T) {
	members, err := parseCabinet(realDisallowedCAB(t))
	if err != nil {
		t.Fatalf("the real disallowedcertstl.cab does not parse: %s", err)
	}
	if _, err := verifySignedCTL(members[0].data, msCTLDisallowedSignerPEM, realCTLTime, oidRootListSignerUsage, false); err == nil {
		t.Fatal("the disallowed list must not pass as the trust list")
	}
}

// Tampering with the CTL content trips the messageDigest check before the
// signature is even attempted.
func TestVerifySignedCTLTamperedContent(t *testing.T) {
	stl := append([]byte{}, realAuthRootSTL(t)...)
	stl[1000] ^= 0xFF
	if _, err := verifySignedCTL(stl, msCTLSignerPEM, realCTLTime, oidRootListSignerUsage, true); err == nil {
		t.Fatal("a tampered CTL must not verify")
	}
}

// An unknown signer is refused — the circular-trust breaker: the same
// synthetic CTL verifies under its own signer's pin and fails under the
// Microsoft pin.
func TestVerifySignedCTLRefusesUnknownSigner(t *testing.T) {
	signerCert, signerKey, signerPEM := testCTLSigner(t, "Other CTL Publisher")
	ctl := buildCTLDER(t, oidRootListSignerUsage, synthNow.Add(-time.Hour), []ctlHash{{1, 2, 3}})
	stl := buildSignedSTL(t, signerCert, signerKey, ctl, true, false)
	if _, err := verifySignedCTL(stl, signerPEM, synthNow, oidRootListSignerUsage, true); err != nil {
		t.Fatalf("the synthetic CTL must verify under its own pin: %s", err)
	}
	if _, err := verifySignedCTL(stl, msCTLSignerPEM, synthNow, oidRootListSignerUsage, true); err == nil {
		t.Fatal("a CTL signed by a stranger must not verify under the Microsoft pin")
	}
}

// The pinned signer outside its validity window fails the verdict: an aged
// pin demands a client update instead of riding forever.
func TestVerifySignedCTLSignerExpired(t *testing.T) {
	_, err := verifySignedCTL(realAuthRootSTL(t), msCTLSignerPEM, time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC), oidRootListSignerUsage, true)
	if err == nil || !strings.Contains(err.Error(), "outdated") {
		t.Fatalf("an expired pinned signer must refuse naming the outdated build, got %v", err)
	}
}

// The synthetic round-trip: the same code path verifies a generated CTL
// (signed-attributes RSA shape), and the legacy no-attributes and ECDSA
// shapes ride the same gate.
func TestVerifySignedCTLSyntheticShapes(t *testing.T) {
	signerCert, signerKey, signerPEM := testCTLSigner(t, "Test CTL Publisher")
	hashes := []ctlHash{{1}, {2}, {3}}
	ctl := buildCTLDER(t, oidRootListSignerUsage, synthNow.Add(-time.Hour), hashes)

	for _, tc := range []struct {
		name      string
		withAttrs bool
		ecdsa     bool
	}{
		{"rsa with signedAttrs", true, false},
		{"rsa legacy no attrs", false, false},
	} {
		stl := buildSignedSTL(t, signerCert, signerKey, ctl, tc.withAttrs, tc.ecdsa)
		verdict, err := verifySignedCTL(stl, signerPEM, synthNow, oidRootListSignerUsage, true)
		if err != nil {
			t.Fatalf("%s: the synthetic CTL does not verify: %s", tc.name, err)
		}
		if len(verdict.hashes) != 3 {
			t.Errorf("%s: %d hashes, want 3", tc.name, len(verdict.hashes))
		}
		if !verdict.thisUpdate.Equal(synthNow.Add(-time.Hour)) {
			t.Errorf("%s: thisUpdate %s did not round-trip", tc.name, verdict.thisUpdate)
		}
	}

	// the ECDSA shape rides the same verification
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the ECDSA key: %s", err)
	}
	ecTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(43),
		Subject:      pkix.Name{CommonName: "Test ECDSA CTL Publisher"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	ecDER, err := x509.CreateCertificate(rand.Reader, ecTmpl, ecTmpl, &ecKey.PublicKey, ecKey)
	if err != nil {
		t.Fatalf("could not create the ECDSA signer certificate: %s", err)
	}
	ecCert, err := x509.ParseCertificate(ecDER)
	if err != nil {
		t.Fatalf("could not parse the ECDSA signer certificate: %s", err)
	}
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ecDER})
	stl := buildSignedSTL(t, ecCert, ecKey, ctl, true, true)
	if _, err := verifySignedCTL(stl, ecPEM, synthNow, oidRootListSignerUsage, true); err != nil {
		t.Fatalf("the ECDSA-signed synthetic CTL does not verify: %s", err)
	}
}

// ---- the state machine: load, harvest, veto, refresh ----

// The cache load gates the collected anchors on the verdict, the harvest
// blesses CTL-listed self-signed roots into the pool and the file, and a
// verdict that stops listing a collected root drops it.
func TestRootProgramLoadHarvestAndDrop(t *testing.T) {
	dir := t.TempDir()
	rootPEM, root, intermediate, leaf := certChain(t, "rp.example.org")
	signerCert, signerKey, signerPEM := testCTLSigner(t, "Test CTL Publisher")
	now := synthNow

	writeVerdict := func(hashes []ctlHash) {
		ctl := buildCTLDER(t, oidRootListSignerUsage, now.Add(-time.Hour), hashes)
		stl := buildSignedSTL(t, signerCert, signerKey, ctl, true, false)
		cab := buildTestCAB(t, 0x01, "authroot.stl", stl, true)
		if err := os.WriteFile(filepath.Join(dir, authRootSTLCabFileName), cab, 0600); err != nil {
			t.Fatalf("could not write the CTL cache: %s", err)
		}
	}

	// first verdict blesses the root
	writeVerdict([]ctlHash{sha1OfCert(root)})
	rp := newTestRootProgram(t, dir, signerPEM, now)
	pool := x509.NewCertPool()
	rp.load(dir, pool)
	if rp.ctl == nil {
		t.Fatal("the cached verdict did not load")
	}
	if chainVerifies(pool, intermediate, leaf, "rp.example.org") {
		t.Fatal("the root must not anchor before the harvest blesses it")
	}
	if n := rp.harvest([]*x509.Certificate{root}, pool); n != 1 {
		t.Fatalf("the harvest blessed %d roots, want 1", n)
	}
	if !chainVerifies(pool, intermediate, leaf, "rp.example.org") {
		t.Fatal("the blessed root must anchor the chain")
	}
	if _, err := os.Stat(filepath.Join(dir, authRootsFileName)); err != nil {
		t.Fatalf("the harvest did not write %s: %s", authRootsFileName, err)
	}
	if n := rp.harvest([]*x509.Certificate{root}, pool); n != 0 {
		t.Fatalf("the second harvest re-blessed %d roots, want 0", n)
	}

	// the next start rides the cache without any new harvest
	pool2 := x509.NewCertPool()
	rp2 := newTestRootProgram(t, dir, signerPEM, now)
	rp2.load(dir, pool2)
	if !chainVerifies(pool2, intermediate, leaf, "rp.example.org") {
		t.Fatal("the cached anchor must ride the next start")
	}

	// the verdict stops listing the root: the anchor is dropped
	writeVerdict(nil)
	pool3 := x509.NewCertPool()
	rp3 := newTestRootProgram(t, dir, signerPEM, now)
	rp3.load(dir, pool3)
	if chainVerifies(pool3, intermediate, leaf, "rp.example.org") {
		t.Fatal("a root the verdict no longer lists must be dropped")
	}

	// a CTL whose hash never listed the root never blesses it
	if n := rp3.harvest([]*x509.Certificate{root}, pool3); n != 0 {
		t.Fatalf("an unlisted root was blessed %d times, want 0", n)
	}
	_ = rootPEM
}

// Harvest requires a young, signature-valid verdict and a self-signed
// candidate; disabled state harvests nothing.
func TestRootProgramHarvestGates(t *testing.T) {
	_, root, _, _ := certChain(t, "gate.example.org")
	signerCert, signerKey, signerPEM := testCTLSigner(t, "Test CTL Publisher")

	// disabled feature
	dir := t.TempDir()
	disabled := newTestRootProgram(t, dir, signerPEM, synthNow)
	disabled.enabled = false
	if n := disabled.harvest([]*x509.Certificate{root}, x509.NewCertPool()); n != 0 {
		t.Fatalf("a disabled root program blessed %d roots", n)
	}

	// stale verdict
	dir2 := t.TempDir()
	ctl := buildCTLDER(t, oidRootListSignerUsage, synthNow.Add(-60*24*time.Hour), []ctlHash{sha1OfCert(root)})
	stl := buildSignedSTL(t, signerCert, signerKey, ctl, true, false)
	if err := os.WriteFile(filepath.Join(dir2, authRootSTLCabFileName), buildTestCAB(t, 0x01, "authroot.stl", stl, true), 0600); err != nil {
		t.Fatalf("could not write the cache: %s", err)
	}
	stale := newTestRootProgram(t, dir2, signerPEM, synthNow)
	stalePool := x509.NewCertPool()
	stale.load(dir2, stalePool)
	if stale.ctl == nil {
		t.Fatal("the stale verdict should still load (positive anchors ride a valid signature)")
	}
	if n := stale.harvest([]*x509.Certificate{root}, stalePool); n != 0 {
		t.Fatalf("a stale verdict minted %d anchors, want 0", n)
	}

	// a non-self-signed certificate is never an anchor candidate
	_, _, intermediate, _ := certChain(t, "nonself.example.org")
	fresh := newTestRootProgram(t, t.TempDir(), signerPEM, synthNow)
	ctl2 := buildCTLDER(t, oidRootListSignerUsage, synthNow.Add(-time.Hour), []ctlHash{sha1OfCert(intermediate)})
	stl2 := buildSignedSTL(t, signerCert, signerKey, ctl2, true, false)
	if err := os.WriteFile(filepath.Join(fresh.ssh3Dir, authRootSTLCabFileName), buildTestCAB(t, 0x01, "authroot.stl", stl2, true), 0600); err != nil {
		t.Fatalf("could not write the cache: %s", err)
	}
	freshPool := x509.NewCertPool()
	fresh.load(fresh.ssh3Dir, freshPool)
	if n := fresh.harvest([]*x509.Certificate{intermediate}, freshPool); n != 0 {
		t.Fatalf("a non-self-signed certificate was blessed (%d)", n)
	}
}

// The disallowed verdict vetoes a chain carrying a listed certificate; the
// negative (removed-root) verdict vetoes on a fresh CTL and pauses on a
// stale one.
func TestRootProgramVetoes(t *testing.T) {
	rootPEM, root, intermediate, leaf := certChain(t, "veto.example.org")
	_, rootB, intermediateB, leafB := certChain(t, "veto-b.example.org")
	signerCert, signerKey, signerPEM := testCTLSigner(t, "Test CTL Publisher")
	pool := x509.NewCertPool()
	pool.AddCert(root)
	pool.AddCert(rootB)

	// disallowed: hash of the leaf is on the list
	dir := t.TempDir()
	disCtl := buildCTLDER(t, oidDisallowedUsage, synthNow.Add(-24*time.Hour), []ctlHash{sha1OfCert(leaf)})
	disSTL := buildSignedSTL(t, signerCert, signerKey, disCtl, true, false)
	if err := os.WriteFile(filepath.Join(dir, disallowedCertSTLCabFileName), buildTestCAB(t, 0x01, "disallowedcert.stl", disSTL, true), 0600); err != nil {
		t.Fatalf("could not write the disallowed cache: %s", err)
	}
	// the trust list still carries rootA (fresh) and has DROPPED rootB: the
	// history listing rootB turns its absence into a removal verdict
	ctl := buildCTLDER(t, oidRootListSignerUsage, synthNow.Add(-time.Hour), []ctlHash{sha1OfCert(root)})
	stl := buildSignedSTL(t, signerCert, signerKey, ctl, true, false)
	if err := os.WriteFile(filepath.Join(dir, authRootSTLCabFileName), buildTestCAB(t, 0x01, "authroot.stl", stl, true), 0600); err != nil {
		t.Fatalf("could not write the trust list cache: %s", err)
	}
	// the history lists rootB: the current CTL dropping it is a removal
	history := strings.ToUpper(hexOfHash(sha1OfCert(rootB))) + "\n"
	if err := os.WriteFile(filepath.Join(dir, authRootHistoryFileName), []byte(history+"\n"), 0600); err != nil {
		t.Fatalf("could not write the history: %s", err)
	}
	rp := newTestRootProgram(t, dir, signerPEM, synthNow)
	rp.load(dir, pool)

	if reason, veto := rp.vetoesChain([]*x509.Certificate{leaf, intermediate}, pool); !veto {
		t.Fatalf("a disallowed leaf must veto (reason %q, verdict %v)", reason, rp.disallowed != nil)
	} else if !strings.Contains(reason, "disallowed") {
		t.Errorf("the veto reason %q does not name the disallowed list", reason)
	}

	// rootB was removed from the program (in the history, absent now): the
	// chain leafB->intermediateB->rootB is refused
	if reason, veto := rp.vetoesChain([]*x509.Certificate{leafB, intermediateB}, pool); !veto {
		t.Fatalf("a chain anchored at a removed root must veto, got %q", reason)
	} else if !strings.Contains(reason, "no longer trusts") {
		t.Errorf("the veto reason %q does not name the removal", reason)
	}

	// chain B (neither certificate on any negative list) rides clean with no
	// pool to re-verify against: without the pool the removal check steps
	// aside, and nothing else vets against it
	if reason, veto := rp.vetoesChain([]*x509.Certificate{leafB, intermediateB}, nil); veto {
		t.Fatalf("the clean chain vetoes with no pool to re-verify against: %q", reason)
	}

	// a self-signed leaf on the disallowed list is caught too
	if _, veto := rp.vetoesChain([]*x509.Certificate{root}, pool); veto {
		t.Fatal("rootA is not on the disallowed list and must not veto")
	}
	_ = rootPEM
}

// With a stale verdict the negative filtering pauses: absence from an old
// CTL is no removal evidence.
func TestRootProgramNegativePausesOnStaleVerdict(t *testing.T) {
	_, root, intermediate, leaf := certChain(t, "stale.example.org")
	signerCert, signerKey, signerPEM := testCTLSigner(t, "Test CTL Publisher")
	dir := t.TempDir()
	pool := x509.NewCertPool()
	pool.AddCert(root)

	ctl := buildCTLDER(t, oidRootListSignerUsage, synthNow.Add(-30*24*time.Hour), []ctlHash{sha1OfCert(root)})
	stl := buildSignedSTL(t, signerCert, signerKey, ctl, true, false)
	if err := os.WriteFile(filepath.Join(dir, authRootSTLCabFileName), buildTestCAB(t, 0x01, "authroot.stl", stl, true), 0600); err != nil {
		t.Fatalf("could not write the cache: %s", err)
	}
	history := hexOfHash(sha1OfCert(root)) + "\n"
	if err := os.WriteFile(filepath.Join(dir, authRootHistoryFileName), []byte(history), 0600); err != nil {
		t.Fatalf("could not write the history: %s", err)
	}
	rp := newTestRootProgram(t, dir, signerPEM, synthNow)
	rp.load(dir, pool)
	if len(rp.negative) != 0 {
		t.Fatalf("a stale verdict must pause the negative filtering, got %d removals", len(rp.negative))
	}
	if _, veto := rp.vetoesChain([]*x509.Certificate{leaf, intermediate}, pool); veto {
		t.Fatal("a chain to a root of a stale-but-valid CTL must not veto")
	}
}

func hexOfHash(h ctlHash) string {
	return fmt.Sprintf("%x", h[:])
}

// The refresh policy: a fresh cache means zero requests; a stale cache
// fetches both lists through the candidate URLs, verifies and rewrites; a
// bad signature rides the old verdict.
func TestRootProgramRefreshPolicy(t *testing.T) {
	signerCert, signerKey, signerPEM := testCTLSigner(t, "Test CTL Publisher")
	_, root, _, _ := certChain(t, "refresh.example.org")

	var requests atomic.Int32
	var seenURLs atomic.Value
	seenURLs.Store([]string{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urls := seenURLs.Load().([]string)
		seenURLs.Store(append(urls, r.URL.Path))
		now := synthNow
		switch {
		case strings.HasSuffix(r.URL.Path, authRootSTLCabFileName):
			ctl := buildCTLDER(t, oidRootListSignerUsage, now.Add(-time.Hour), []ctlHash{sha1OfCert(root), {9, 9, 9}})
			stl := buildSignedSTL(t, signerCert, signerKey, ctl, true, false)
			w.Write(buildTestCAB(t, 0x01, "authroot.stl", stl, true))
		case strings.HasSuffix(r.URL.Path, disallowedCertSTLCabFileName):
			ctl := buildCTLDER(t, oidDisallowedUsage, now.Add(-2*time.Hour), []ctlHash{{7, 7}})
			stl := buildSignedSTL(t, signerCert, signerKey, ctl, true, false)
			w.Write(buildTestCAB(t, 0x01, "disallowedcert.stl", stl, true))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	staleTime := synthNow
	freshNow := staleTime.Add(20 * 24 * time.Hour) // the served CTL is fresh for this clock

	// fresh cache: zero requests
	dir := t.TempDir()
	ctl := buildCTLDER(t, oidRootListSignerUsage, freshNow.Add(-time.Hour), []ctlHash{sha1OfCert(root)})
	stl := buildSignedSTL(t, signerCert, signerKey, ctl, true, false)
	if err := os.WriteFile(filepath.Join(dir, authRootSTLCabFileName), buildTestCAB(t, 0x01, "authroot.stl", stl, true), 0600); err != nil {
		t.Fatalf("could not write the cache: %s", err)
	}
	rp := newTestRootProgram(t, dir, signerPEM, freshNow)
	rp.load(dir, x509.NewCertPool())
	rp.fetch = func(ctx context.Context, url string) ([]byte, error) {
		requests.Add(1)
		return nil, errors.New("no fetch expected on a fresh cache")
	}
	rp.refresh()
	if requests.Load() != 0 {
		t.Fatalf("a fresh cache fetched %d times, want 0", requests.Load())
	}

	// stale cache: both lists refresh through the httptest server
	dir2 := t.TempDir()
	oldCtl := buildCTLDER(t, oidRootListSignerUsage, staleTime.Add(-time.Hour), []ctlHash{sha1OfCert(root)})
	oldSTL := buildSignedSTL(t, signerCert, signerKey, oldCtl, true, false)
	if err := os.WriteFile(filepath.Join(dir2, authRootSTLCabFileName), buildTestCAB(t, 0x01, "authroot.stl", oldSTL, true), 0600); err != nil {
		t.Fatalf("could not write the stale cache: %s", err)
	}
	rp2 := newTestRootProgram(t, dir2, signerPEM, freshNow)
	rp2.load(dir2, x509.NewCertPool())
	rp2.fetch = func(ctx context.Context, url string) ([]byte, error) {
		requests.Add(1)
		// the test double maps every candidate URL (the built-in https host
		// and its http fallback alike) onto the local server, file name kept
		name := url[strings.LastIndex(url, "/")+1:]
		if name != authRootSTLCabFileName && name != disallowedCertSTLCabFileName {
			return nil, fmt.Errorf("unexpected fetch URL %s", url)
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/"+name, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	rp2.refresh()
	if got := requests.Load(); got != 2 {
		t.Fatalf("a stale cache fetched %d times, want 2 (both lists); seen %v", got, seenURLs.Load())
	}
	if rp2.ctl == nil || !rp2.ctl.thisUpdate.Equal(synthNow.Add(-time.Hour)) {
		t.Fatalf("the refreshed verdict did not land (thisUpdate %v)", rp2.ctl)
	}
	if rp2.disallowed == nil || len(rp2.disallowed.hashes) != 1 {
		t.Fatal("the refreshed disallowed verdict did not land")
	}
	if _, err := os.Stat(filepath.Join(dir2, authRootHistoryFileName)); err != nil {
		t.Fatal("the refresh did not persist the verdict history")
	}

	// a refreshed file failing the signature rides the cached verdict
	dir3 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir3, authRootSTLCabFileName), buildTestCAB(t, 0x01, "authroot.stl", oldSTL, true), 0600); err != nil {
		t.Fatalf("could not write the stale cache: %s", err)
	}
	rp3 := newTestRootProgram(t, dir3, signerPEM, freshNow)
	rp3.load(dir3, x509.NewCertPool())
	if rp3.ctl == nil {
		t.Fatal("the stale cache did not load for the bad-signature case")
	}
	rp3.fetch = func(ctx context.Context, url string) ([]byte, error) {
		requests.Add(1)
		// tamper the CTL content itself: a flip inside the PKCS#7 frame (the
		// version INTEGER, the digest-algorithms SET) would be a byte the
		// signature does not cover and the tampered list would verify
		tamperedCtl := append([]byte{}, oldCtl...)
		tamperedCtl[len(tamperedCtl)/2] ^= 0xFF
		tamperedSTL := buildSignedSTL(t, signerCert, signerKey, tamperedCtl, true, false)
		return buildTestCAB(t, 0x01, "authroot.stl", tamperedSTL, true), nil
	}
	before := rp3.ctl
	rp3.refresh()
	if rp3.ctl != before {
		t.Fatal("a signature-failing refresh must ride the cached verdict")
	}
	if requests.Load() != 3 {
		t.Fatalf("the bad-signature refresh made %d total requests, want 3", requests.Load())
	}
}

// The env gates: SSH3_NO_ROOT_PROGRAM=1 disables everything; the URL
// override replaces the candidate host entirely.
func TestRootProgramEnvGates(t *testing.T) {
	signerCert, signerKey, signerPEM := testCTLSigner(t, "Test CTL Publisher")
	_, root, _, _ := certChain(t, "env.example.org")
	now := synthNow

	// disabled: nothing loads and nothing fetches even with a stale cache
	t.Setenv(rootProgramDisableEnvVar, "1")
	dir := t.TempDir()
	ctl := buildCTLDER(t, oidRootListSignerUsage, now.Add(-60*24*time.Hour), []ctlHash{sha1OfCert(root)})
	stl := buildSignedSTL(t, signerCert, signerKey, ctl, true, false)
	if err := os.WriteFile(filepath.Join(dir, authRootSTLCabFileName), buildTestCAB(t, 0x01, "authroot.stl", stl, true), 0600); err != nil {
		t.Fatalf("could not write the cache: %s", err)
	}
	rp := newTestRootProgram(t, dir, signerPEM, now)
	rp.enabled = false
	pool := x509.NewCertPool()
	rp.load(dir, pool)
	if rp.ctl != nil {
		t.Fatal("the disabled root program must not load the verdict")
	}
	rp.fetch = func(ctx context.Context, url string) ([]byte, error) {
		return nil, errors.New("a disabled root program must not fetch")
	}
	rp.refresh()
	if rp.ctl != nil {
		t.Fatal("the disabled root program must not refresh")
	}
	t.Setenv(rootProgramDisableEnvVar, "")

	// the URL override replaces the candidate base (no windowsupdate host)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(buildTestCAB(t, 0x01, "authroot.stl", stl, true))
	}))
	defer srv.Close()
	t.Setenv(rootProgramBaseURLEnvVar, srv.URL)
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, authRootSTLCabFileName), buildTestCAB(t, 0x01, "authroot.stl", stl, true), 0600); err != nil {
		t.Fatalf("could not write the stale cache: %s", err)
	}
	rp2 := newTestRootProgram(t, dir2, signerPEM, now)
	rp2.fetch = func(ctx context.Context, url string) ([]byte, error) {
		if !strings.HasPrefix(url, srv.URL+"/") {
			return nil, fmt.Errorf("the override was ignored: fetched %s", url)
		}
		return rp2.fetchOverride(url)
	}
	rp2.refresh()
	if rp2.ctl == nil {
		t.Fatal("the overridden refresh did not land a verdict")
	}
	t.Setenv(rootProgramBaseURLEnvVar, "")
}

// fetchOverride is a tiny helper for the URL-override test: plain GET.
func (rp *rootProgram) fetchOverride(url string) ([]byte, error) {
	return rootProgramHTTPFetch(context.Background(), url)
}

// The production wiring: loadClientCAPool rides the root program cache as
// the fourth source, gated by SSH3_NO_ROOT_PROGRAM.
func TestLoadClientCAPoolWithRootProgramCache(t *testing.T) {
	rootPEM, root, intermediate, leaf := certChain(t, "wiring.example.org")
	signerCert, signerKey, signerPEM := testCTLSigner(t, "Test CTL Publisher")

	// swap the default instance pin to the test signer, restore on exit
	origSigner := rootProgramDefault.signerPEM
	origNow := rootProgramDefault.now
	rootProgramDefault.signerPEM = signerPEM
	rootProgramDefault.now = func() time.Time { return synthNow }
	defer func() {
		rootProgramDefault.signerPEM = origSigner
		rootProgramDefault.now = origNow
	}()

	dir := t.TempDir()
	ctl := buildCTLDER(t, oidRootListSignerUsage, synthNow.Add(-time.Hour), []ctlHash{sha1OfCert(root)})
	stl := buildSignedSTL(t, signerCert, signerKey, ctl, true, false)
	if err := os.WriteFile(filepath.Join(dir, authRootSTLCabFileName), buildTestCAB(t, 0x01, "authroot.stl", stl, true), 0600); err != nil {
		t.Fatalf("could not write the CTL cache: %s", err)
	}
	if err := os.WriteFile(filepath.Join(dir, authRootsFileName), rootPEM, 0600); err != nil {
		t.Fatalf("could not write the collected anchors: %s", err)
	}

	pool := loadClientCAPool(dir)
	if !chainVerifies(pool, intermediate, leaf, "wiring.example.org") {
		t.Fatal("the collected anchor must ride the production pool")
	}

	t.Setenv(rootProgramDisableEnvVar, "1")
	pool2 := loadClientCAPool(dir)
	if chainVerifies(pool2, intermediate, leaf, "wiring.example.org") {
		t.Fatal("SSH3_NO_ROOT_PROGRAM=1 must remove the fourth source")
	}
	t.Setenv(rootProgramDisableEnvVar, "")
}

// The candidate URLs of one list: the env override is used as-is, the
// built-in base falls back from https to the plain http variant of the same
// path (the pinned signature is the trust carrier — see rootprogram.go).
func TestCandidateCTLURLs(t *testing.T) {
	base := rootProgramDefaultBaseURL
	got := candidateCTLURLs(base, authRootSTLCabFileName)
	want := []string{
		base + "/" + authRootSTLCabFileName,
		"http://" + strings.TrimPrefix(base, "https://") + "/" + authRootSTLCabFileName,
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("candidate URLs = %v, want %v", got, want)
	}
	t.Setenv(rootProgramBaseURLEnvVar, "http://example.invalid/ctl")
	got = candidateCTLURLs(base, disallowedCertSTLCabFileName)
	if len(got) != 1 || got[0] != "http://example.invalid/ctl/"+disallowedCertSTLCabFileName {
		t.Fatalf("override candidate URLs = %v", got)
	}
}
