package cmd

// The Windows root program of ROADMAP.md R7-T3 (CERT-VERIFICATION-CANON.md
// 2.6 complement): a Windows Server SKU with a truncated store holds neither
// the ISRG roots nor fresh anchors, and the auto-update of SChannel's root
// verdicts does not carry over to a Go client. This module rides the same
// verdicts the Windows root program does — the Certificate Trust List (CTL)
// Microsoft publishes at ctldl.windowsupdate.com as authrootstl.cab, with the
// disallowed-certificate list (disallowedcertstl.cab) beside it.
//
// The honest shape of the delivery: a CTL carries certificate HASHES and a
// signature, never the certificates themselves. The client therefore does not
// "download roots" — it downloads a verifiable Microsoft verdict about which
// root is acceptable, and applies that verdict to the certificates it can
// already observe:
//
//   - a self-signed root surfaced by a server chain or by the AIA chase whose
//     SHA-1 rides a signature-valid CTL is cached into ~/.ssh3/authroots.pem
//     and becomes an anchor,
//   - anchors already present (system store, embedded ISRG, collected roots)
//     are re-checked against every CTL refresh: a root the current CTL dropped
//     from a hash set it previously blessed is removed from the anchor pool
//     (the negative filtering), and a certificate on the disallowed list
//     vetoes the connection outright.
//
// Trust semantics against the canon ("fetched trust never anchors itself"):
// a CTL-blessed root does not anchor because it was fetched — it anchors
// because the whole bundle it belongs to is signed by the Microsoft CTL
// signer whose certificate is pinned in this binary. The pin breaks the
// circularity: a substituted CAB cannot pass, whatever channel delivered it
// (plain http is acceptable for exactly that reason; https is attempted
// first and falls back). This is a verified SET anchor, not a per-certificate
// fetched anchor, and is deliberately distinct from the AIA chase of canon
// 2.6, where fetched material stays intermediate-only.
//
// The signer pin is a release constant like the embedded ISRG roots: the
// CTL-signing certificate of Microsoft ("Microsoft Certificate Trust List
// Publisher") rotates roughly annually, so a client whose pin aged out must
// be updated — until then the feature degrades to the T1 sources and says so
// in a warning.
//
// Refresh policy: the CTL DER carries thisUpdate (no nextUpdate — verified on
// the real files), and Microsoft regenerates the lists on a weekly-ish
// cadence. The client refreshes in the background when the cache ages past
// ctlRefreshAfter; a fresh cache means zero network requests, an unavailable
// network means the client rides the cache. The download never rides the dial
// path: it lands in a goroutine started at client startup, the refreshed
// verdicts reach the current process's harvest/veto gates and the on-disk
// caches, and the anchor pool itself is rebuilt on the next start (removals
// are applied then — a dial never waits on the root program).

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

//go:embed msctl-signer.pem
var msCTLSignerPEM []byte

// The pinned CTL signer, byte-exact from the real authrootstl.cab of
// 2026-11-12 (verified to chain to "Microsoft Certificate List CA 2024" at
// pinning time):
//
//	CN=Microsoft Certificate Trust List Publisher
//	serial 330000001AE4F97D734074744B00000000001A
//	valid 2026-09-24 .. 2027-09-27
//	SHA-256(der) 5D:78:0A:6A:57:FF:ED:EA:BA:84:DE:C8:CC:FA:49:A8:6C:EF:7D:BF:5A:4E:FD:82:6B:0F:5E:20:E1:D4:CE:B4

//go:embed msctl-disallowed-signer.pem
var msCTLDisallowedSignerPEM []byte

// The pinned disallowed-list signer, byte-exact from the real
// disallowedcertstl.cab of 2026-11-12 — the previous generation of the same
// publisher, which Microsoft still uses for that list after the trust list
// already moved to the 2026 certificate:
//
//	CN=Microsoft Certificate Trust List Publisher
//	serial 33000000110B1218F077D9ADF9000000000011
//	valid 2025-11-13 .. 2026-11-11 (already lapsed, see below)
//	SHA-256(der) 9F:82:5C:43:10:C0:05:AB:8A:D2:D1:6E:2A:1E:42:9E:D9:B9:FB:51:DF:A1:DC:FC:90:49:A6:28:10:01:23:65
//
// The asymmetry in expiry handling follows from what each list can do: the
// trust list CREATES anchors, so its signer's validity window is enforced
// strictly and a lapsed pin demands a client update; the disallowed list can
// only NARROW trust (a forged denial cannot mint trust), so its verdict
// applies for as long as the signature verifies under the pinned key — a
// stale denial stays a denial. When Microsoft re-signs the list with a newer
// publisher certificate, an aged pin stops matching and the deny-list
// degrades to a warning until the client is updated.

const (
	// rootProgramDisableEnvVar turns the whole feature off (SSH3_NO_ROOT_PROGRAM=1):
	// no cache, no refresh, no harvest, no vetoes — the client rides the
	// T1/T2 sources alone.
	rootProgramDisableEnvVar = "SSH3_NO_ROOT_PROGRAM"

	// rootProgramBaseURLEnvVar overrides the base URL the two CTL cabinets
	// are fetched from (SSH3_ROOTPROGRAM_URL; the e2e tests point it at a
	// local server). The URL names the base directory: the client appends
	// authrootstl.cab / disallowedcertstl.cab.
	rootProgramBaseURLEnvVar = "SSH3_ROOTPROGRAM_URL"

	// rootProgramDefaultBaseURL is where the Windows root program publishes
	// its CTL cabinets. https rides first, the plain http variant is the
	// fallback: the pinned-signature check is what carries the trust, so a
	// cleartext fetch cannot substitute content (and a store so truncated it
	// cannot verify the CDN's own certificate still refreshes).
	rootProgramDefaultBaseURL = "https://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en"

	// rootProgramFetchBudget bounds one background refresh (both files).
	rootProgramFetchBudget = 30 * time.Second

	// maxRootProgramFetchBytes caps a CTL cabinet body (the real
	// authrootstl.cab is ~80 KiB; the cap bounds a hostile server).
	maxRootProgramFetchBytes = 512 * 1024

	// ctlRefreshAfter ages a cache into refresh territory: the real CTLs are
	// regenerated on a weekly-ish cadence, so two weeks past thisUpdate is
	// refresh territory while a fresh cache keeps the client at zero requests.
	ctlRefreshAfter = 14 * 24 * time.Hour

	// ctlNegativeMaxAge bounds how long absence-from-the-CTL counts as a
	// removal verdict: negative filtering acts only on a verdict young enough
	// to reflect the current program (an offline machine's stale CTL pauses
	// the removals, it does not freeze them in).
	ctlNegativeMaxAge = 14 * 24 * time.Hour

	// ctlBlessMaxAge bounds blessing NEW roots: an observed root may join the
	// anchors only while the CTL vouching for it is young enough (a years-old
	// verdict must not mint new anchors).
	ctlBlessMaxAge = 28 * 24 * time.Hour
)

// OIDs of the MS-CRTD subjectUsage field separating the two list kinds
// (observed on the real files).
var (
	oidRootListSignerUsage = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 9}
	oidDisallowedUsage     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 30}
	// the subjectAlgorithm marker the disallowed cabinet carries instead of
	// sha1 (szOID_DISALLOWED_HASH)
	oidDisallowedHashAlgorithm = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 11, 15}
)

// State file names riding the ssh3 directory next to known_hosts and the
// other R7 state.
const (
	authRootSTLCabFileName       = "authrootstl.cab"
	disallowedCertSTLCabFileName = "disallowedcertstl.cab"
	authRootsFileName            = "authroots.pem"
	authRootHistoryFileName      = "authroots.history"
)

// sha1Size is the CTL entry hash width (subjectAlgorithm = sha1 on the real
// files).
const sha1Size = 20

type ctlHash [sha1Size]byte

// ---- CAB (MSFCAB) parsing ----

// cabMember is one extracted member of the cabinet.
type cabMember struct {
	name string
	data []byte
}

// cabDirEntry is the directory record of one member before its bytes are
// carved out of the decompressed folder.
type cabDirEntry struct {
	name        string
	folder      int
	folderStart uint32
	size        uint32
}

// parseCabinet extracts the members of a Microsoft cabinet archive (MSFCAB).
// Only the shape the Windows root program ships is supported: no reserved
// header fields, no cabinet spanning, folders compressed with NONE (0x0000)
// or MSZIP (0x0001). LZX folders are refused honestly — implementing an LZX
// decoder for a format the root program does not use would be surface without
// payoff.
//
// CFFILE deviation, observed on the real root-program cabinets: they carry
// two extra zero bytes between iFolder and the date fields, so the date does
// not sit at the standard MSFCAB offset. The parser accepts both layouts,
// telling them apart by which offset holds a plausible DOS date.
func parseCabinet(data []byte) ([]cabMember, error) {
	if len(data) < 36 || !bytes.Equal(data[:4], []byte("MSCF")) {
		return nil, errors.New("not a Microsoft cabinet (MSCF signature missing)")
	}
	if flags := binary.LittleEndian.Uint16(data[30:]); flags&0x0004 != 0 {
		return nil, errors.New("cabinet reserved header fields are not supported")
	}
	nFolders := int(binary.LittleEndian.Uint16(data[26:]))
	nFiles := int(binary.LittleEndian.Uint16(data[28:]))

	type cabFolder struct {
		firstDataOff uint32
		nBlocks      int
		codec        byte
	}
	folders := make([]cabFolder, 0, nFolders)
	off := 36
	for i := 0; i < nFolders; i++ {
		if off+8 > len(data) {
			return nil, errors.New("cabinet truncated in the folder area")
		}
		folders = append(folders, cabFolder{
			firstDataOff: binary.LittleEndian.Uint32(data[off:]),
			nBlocks:      int(binary.LittleEndian.Uint16(data[off+4:])),
			codec:        data[off+6],
		})
		off += 8
	}

	entries := make([]cabDirEntry, 0, nFiles)
	for i := 0; i < nFiles; i++ {
		if off+16 > len(data) {
			return nil, errors.New("cabinet truncated in the file area")
		}
		size := binary.LittleEndian.Uint32(data[off:])
		folderStart := uint32(data[off+4]) | uint32(data[off+5])<<8 | uint32(data[off+6])<<16
		ifolder := int(data[off+7])
		var nameOff int
		switch {
		case plausibleDOSDate(binary.LittleEndian.Uint16(data[off+8:])):
			// standard MSFCAB CFFILE: date right after iFolder
			nameOff = off + 14
		case plausibleDOSDate(binary.LittleEndian.Uint16(data[off+10:])):
			// root-program variant: two zero bytes between iFolder and date
			nameOff = off + 16
		default:
			return nil, errors.New("cabinet file entry carries no plausible date field")
		}
		nameEnd := bytes.IndexByte(data[nameOff:], 0)
		if nameEnd < 0 {
			return nil, errors.New("cabinet file entry name is not terminated")
		}
		entries = append(entries, cabDirEntry{
			name:        string(data[nameOff : nameOff+nameEnd]),
			folder:      ifolder,
			folderStart: folderStart,
			size:        size,
		})
		off = nameOff + nameEnd + 1
	}

	// decompress the folders
	folderData := make([][]byte, len(folders))
	for fi, f := range folders {
		switch f.codec {
		case 0x00, 0x01:
		default:
			return nil, fmt.Errorf("cabinet folder codec 0x%x is not supported (only NONE and MSZIP; LZX refused)", f.codec)
		}
		if int(f.firstDataOff) > len(data) {
			return nil, errors.New("cabinet data area out of bounds")
		}
		out := make([]byte, 0, 256*1024)
		p := int(f.firstDataOff)
		var hist []byte
		for b := 0; b < f.nBlocks; b++ {
			if p+8 > len(data) {
				return nil, errors.New("cabinet truncated in the data blocks")
			}
			cbData := int(binary.LittleEndian.Uint16(data[p+4:]))
			cbUncomp := int(binary.LittleEndian.Uint16(data[p+6:]))
			if p+8+cbData > len(data) {
				return nil, errors.New("cabinet data block overruns the file")
			}
			payload := data[p+8 : p+8+cbData]
			p += 8 + cbData
			if f.codec == 0x00 {
				out = append(out, payload...)
				continue
			}
			// MSZIP: the block payload is one CK chunk — a raw deflate stream
			// sharing the folder-wide 32 KiB sliding window (the real
			// root-program cabinets pack exactly one chunk per block; a
			// multi-chunk block is refused as a format the code does not
			// pretend to cover).
			if len(payload) < 2 || !bytes.Equal(payload[:2], []byte("CK")) {
				return nil, fmt.Errorf("MSZIP chunk signature missing in data block %d", b)
			}
			chunkOut, err := mszipInflate(hist, payload[2:])
			if err != nil {
				return nil, fmt.Errorf("MSZIP chunk in data block %d: %s", b, err)
			}
			if len(chunkOut) != cbUncomp {
				return nil, fmt.Errorf("data block %d unpacked %d bytes, header says %d (multi-chunk blocks are not supported)", b, len(chunkOut), cbUncomp)
			}
			out = append(out, chunkOut...)
			hist = windowHistory(out)
		}
		folderData[fi] = out
	}

	// carve the members out of their folders
	members := make([]cabMember, 0, len(entries))
	for _, e := range entries {
		if e.folder < 0 || e.folder >= len(folderData) {
			return nil, fmt.Errorf("cabinet member %q references folder %d that does not exist (spanned cabinets unsupported)", e.name, e.folder)
		}
		blob := folderData[e.folder]
		start, end := int(e.folderStart), int(e.folderStart)+int(e.size)
		if end > len(blob) {
			return nil, fmt.Errorf("cabinet member %q overruns its folder", e.name)
		}
		members = append(members, cabMember{name: e.name, data: blob[start:end]})
	}
	return members, nil
}

// windowHistory keeps the last 32 KiB of decompressed output: the sliding
// window the next MSZIP chunk of the folder references.
func windowHistory(out []byte) []byte {
	if len(out) > 32768 {
		return out[len(out)-32768:]
	}
	return out
}

// mszipInflate inflates one MSZIP chunk. The chunks of a folder form separate
// raw deflate streams that share the 32 KiB history window, and
// compress/flate cannot seed a window — so the history is replayed into the
// decoder as a synthetic stored block and the replayed prefix is stripped
// from the output. The chunk bytes follow the CK signature; the deflate
// stream carries its own final block and ends inside the chunk.
func mszipInflate(hist []byte, chunk []byte) ([]byte, error) {
	stored := make([]byte, 5+len(hist))
	n := len(hist)
	stored[0] = 0x00 // BFINAL=0, BTYPE=00 (stored)
	stored[1] = byte(n)
	stored[2] = byte(n >> 8)
	stored[3] = byte(^n)
	stored[4] = byte(^n >> 8)
	copy(stored[5:], hist)

	zr := flate.NewReader(bytes.NewReader(append(stored, chunk...)))
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	if len(out) < n {
		return nil, errors.New("deflate output shorter than the replayed history")
	}
	return out[n:], nil
}

// plausibleDOSDate reports whether a MS-DOS packed date word encodes a month
// and day that exist (the discriminator between the standard CFFILE layout
// and the root-program variant with the two extra bytes).
func plausibleDOSDate(v uint16) bool {
	day := v & 0x1F
	month := (v >> 5) & 0x0F
	return day >= 1 && month >= 1 && month <= 12
}

// ---- PKCS#7 SignedData verification under the pinned CTL signer ----

// The stdlib carries no PKCS#7 parser, so the pieces the CTL verification
// needs are decoded here: ContentInfo(signedData) -> SignedData -> signerInfo
// -> (signedAttrs) -> signature. The MS-CRTD control uses digestAlgorithm
// SHA-256 with signedAttributes (contentType + messageDigest + SpcSpOpusInfo
// on the real files) and an RSA PKCS#1 v1.5 signature over the DER of the
// signed attributes re-tagged as SET; the no-attributes legacy path (the
// signature riding the content directly) is supported as well.

var (
	oidPKCS7SignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidMSCertificateTrustList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 1}
	oidAttrContentType        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidRSAEncryption          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA1Digest             = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256Digest           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384Digest           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512Digest           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidECDSAPublicKey         = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

type ctlAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	// the [0] element is captured raw (implicit capture, not explicit): its
	// Bytes hold the inner element, the SignedData or the CTL respectively
	Content asn1.RawValue `asn1:"tag:0,optional"`
}

type pkcs7EncapContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,optional"`
}

type pkcs7IssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type pkcs7SignerInfo struct {
	Version         int
	SID             pkcs7IssuerAndSerial
	DigestAlgorithm ctlAlgorithmIdentifier
	SignedAttrs     asn1.RawValue `asn1:"tag:0,optional"`
	SignatureAlg    ctlAlgorithmIdentifier
	Signature       []byte
	UnsignedAttrs   asn1.RawValue `asn1:"tag:1,optional"`
}

type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms []ctlAlgorithmIdentifier `asn1:"set"`
	ContentInfo      pkcs7EncapContentInfo
	Certificates     asn1.RawValue     `asn1:"tag:0,optional"`
	CRLs             []asn1.RawValue   `asn1:"tag:1,optional"`
	SignerInfos      []pkcs7SignerInfo `asn1:"set"`
}

// ctlVerdict is a parsed, signature-verified Certificate Trust List: the
// thisUpdate stamp the refresh policy rides, the usage OID that separates the
// trust list from the disallowed list, and the subject hashes. The trust
// list stamps SHA-1 over the whole certificate; the disallowed list rides
// other widths (MD5 and SHA-384 observed on the real files) — those land in
// extraHashes keyed by the raw hash bytes.
type ctlVerdict struct {
	thisUpdate     time.Time
	usage          asn1.ObjectIdentifier
	hashes         map[ctlHash]struct{}
	extraHashes    map[string]struct{}
	signerNotAfter time.Time
}

// hashByOID maps the digest algorithm OIDs of the CTL signatures onto
// crypto.Hash.
func hashByOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA1Digest):
		return crypto.SHA1, nil
	case oid.Equal(oidSHA256Digest):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384Digest):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512Digest):
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("unsupported digest algorithm %v", oid)
}

// verifySignerSignature checks data/sig under the pinned signer key. The RSA
// path is PKCS#1 v1.5 (what Microsoft signs CTLs with, rsaEncryption +
// separate digest algorithm); ECDSA is carried for the same standard shape.
func verifySignerSignature(signer *x509.Certificate, sigAlg asn1.ObjectIdentifier, digestAlg asn1.ObjectIdentifier, data, sig []byte) error {
	hash, err := hashByOID(digestAlg)
	if err != nil {
		return err
	}
	switch {
	case sigAlg.Equal(oidRSAEncryption):
		pub, ok := signer.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("the signer key is %T, not RSA", signer.PublicKey)
		}
		h := hash.New()
		h.Write(data)
		return rsa.VerifyPKCS1v15(pub, hash, h.Sum(nil), sig)
	case sigAlg.Equal(oidECDSAPublicKey):
		pub, ok := signer.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("the signer key is %T, not ECDSA", signer.PublicKey)
		}
		h := hash.New()
		h.Write(data)
		if ecdsa.VerifyASN1(pub, h.Sum(nil), sig) {
			return nil
		}
		return errors.New("the ECDSA signature does not verify")
	}
	return fmt.Errorf("unsupported signature algorithm %v", sigAlg)
}

// pinnedCTLSigner parses the given signer certificate PEM. The production
// PEM is the release constant embedded in the binary (msCTLSignerPEM); the
// field is a parameter so the tests can pin their own signer — the pin is
// what the whole trust path hangs on, and the tests ride exactly the same
// verification code with their own pin.
func pinnedCTLSigner(signerPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(signerPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("the pinned CTL signer PEM does not decode")
	}
	return x509.ParseCertificate(block.Bytes)
}

// findSignedAttribute returns the first value of the named attribute inside a
// signedAttrs SET (captured raw with its [0] IMPLICIT tag). The value rides
// whole (FullBytes = the TLV): the contentType attribute carries an OID
// element directly in its SET, the messageDigest an OCTET STRING — the
// caller picks what it needs.
func findSignedAttribute(signedAttrs asn1.RawValue, want asn1.ObjectIdentifier) (asn1.RawValue, error) {
	body := signedAttrs.Bytes
	for len(body) > 0 {
		var attr struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue `asn1:"set"`
		}
		rest, err := asn1.Unmarshal(body, &attr)
		if err != nil {
			return asn1.RawValue{}, fmt.Errorf("signed attributes do not decode: %s", err)
		}
		if attr.Type.Equal(want) {
			var value asn1.RawValue
			if _, err := asn1.Unmarshal(attr.Values.Bytes, &value); err != nil {
				return asn1.RawValue{}, fmt.Errorf("the attribute value does not decode: %s", err)
			}
			return value, nil
		}
		body = rest
	}
	return asn1.RawValue{}, fmt.Errorf("signed attribute %v is missing", want)
}

// ctlContentHashInput returns the bytes a CTL messageDigest rides. Observed
// and reproduced on the real Windows cabinets: the digest covers the
// encapsulated CTL's content octets — the value of the outermost TLV with
// the header itself excluded — and the CMS OCTET STRING form lands on the
// same rule (the value of the OCTET STRING). A body that does not decode as
// a single TLV is hashed as-is (the verification then simply fails on the
// compare if the sender meant something else).
func ctlContentHashInput(content []byte) []byte {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(content, &raw)
	if err != nil || len(rest) != 0 || len(raw.Bytes) >= len(content) {
		return content
	}
	return raw.Bytes
}

// verifySignedCTL runs the full trust path of one .stl payload: PKCS#7 parse,
// signer match against the PINNED certificate (the certificates the message
// itself carries are never trusted), signer validity window, messageDigest
// over the encapsulated CTL and the signature over the signed attributes —
// then the CTL parse. expectUsage pins which list kind the file must be
// (rootListSigner vs disallowed), so a swapped file cannot pass. The
// strictExpiry flag enforces the pinned signer's validity window: on for the
// trust list (which creates anchors), off for the disallowed list (which can
// only narrow trust — see the pin comment at the top of the file).
func verifySignedCTL(stl []byte, signerPEM []byte, now time.Time, expectUsage asn1.ObjectIdentifier, strictExpiry bool) (*ctlVerdict, error) {
	signer, err := pinnedCTLSigner(signerPEM)
	if err != nil {
		return nil, err
	}
	if strictExpiry && (now.Before(signer.NotBefore) || now.After(signer.NotAfter)) {
		return nil, fmt.Errorf("the pinned Microsoft CTL signer %q is valid %s..%s, not at %s — the client build is outdated and must be updated",
			signer.Subject.CommonName, signer.NotBefore.Format(time.DateOnly), signer.NotAfter.Format(time.DateOnly), now.Format(time.DateOnly))
	}

	var contentInfo pkcs7ContentInfo
	rest, err := asn1.Unmarshal(stl, &contentInfo)
	if err != nil {
		return nil, fmt.Errorf("not a PKCS#7 ContentInfo: %s", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing bytes after the PKCS#7 ContentInfo")
	}
	if !contentInfo.ContentType.Equal(oidPKCS7SignedData) {
		return nil, fmt.Errorf("the PKCS#7 content type is %v, not signedData", contentInfo.ContentType)
	}

	var sd pkcs7SignedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("the SignedData does not decode: %s", err)
	}
	if !sd.ContentInfo.ContentType.Equal(oidMSCertificateTrustList) {
		return nil, fmt.Errorf("the encapsulated content type is %v, not the certificate trust list", sd.ContentInfo.ContentType)
	}
	if len(sd.SignerInfos) == 0 {
		return nil, errors.New("the SignedData carries no signerInfo")
	}

	// the signerInfo must name the pinned signer — issuer DER and serial
	// equal, exactly the identification CryptMsg does with an hCryptProv
	// pinned to one certificate
	rawContent := sd.ContentInfo.Content.Bytes
	content := ctlContentHashInput(rawContent)
	var signerInfo *pkcs7SignerInfo
	for i := range sd.SignerInfos {
		si := &sd.SignerInfos[i]
		if si.SID.SerialNumber.Cmp(signer.SerialNumber) == 0 && bytes.Equal(si.SID.IssuerName.FullBytes, signer.RawIssuer) {
			signerInfo = si
			break
		}
	}
	if signerInfo == nil {
		return nil, errors.New("the CTL is signed by an unknown signer (the pinned Microsoft CTL signer did not sign it)")
	}

	digestFunc, err := hashByOID(signerInfo.DigestAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	digestHash := digestFunc.New()
	digestHash.Write(content)
	digest := digestHash.Sum(nil)

	sigData := rawContent
	if len(signerInfo.SignedAttrs.FullBytes) > 0 {
		// the messageDigest attribute vouches for the content, the
		// contentType attribute names it (CMS 11.2-11.3), and the signature
		// rides the DER of the attributes with the [0] IMPLICIT tag replaced
		// by the SET tag — the exact bytes CryptMsgControl verifies
		ct, err := findSignedAttribute(signerInfo.SignedAttrs, oidAttrContentType)
		if err != nil {
			return nil, err
		}
		var ctOID asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(ct.FullBytes, &ctOID); err != nil || !ctOID.Equal(sd.ContentInfo.ContentType) {
			return nil, errors.New("the signed contentType attribute does not match the encapsulated content type")
		}
		md, err := findSignedAttribute(signerInfo.SignedAttrs, oidAttrMessageDigest)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(md.Bytes, digest) {
			return nil, errors.New("the signed messageDigest does not match the CTL content (the payload was altered)")
		}
		sigData = make([]byte, len(signerInfo.SignedAttrs.FullBytes))
		copy(sigData, signerInfo.SignedAttrs.FullBytes)
		sigData[0] = 0x31 // [0] IMPLICIT SET OF Attribute -> SET OF Attribute
	}
	if err := verifySignerSignature(signer, signerInfo.SignatureAlg.Algorithm, signerInfo.DigestAlgorithm.Algorithm, sigData, signerInfo.Signature); err != nil {
		return nil, fmt.Errorf("the CTL signature does not verify under the pinned signer: %s", err)
	}

	verdict, err := parseCTL(rawContent)
	if err != nil {
		return nil, err
	}
	if !verdict.usage.Equal(expectUsage) {
		return nil, fmt.Errorf("the CTL subjectUsage is %v, want %v", verdict.usage, expectUsage)
	}
	verdict.signerNotAfter = signer.NotAfter
	if d := time.Until(signer.NotAfter); d > 0 && d < 60*24*time.Hour {
		log.Warn().Msgf("root program: the pinned Microsoft CTL signer expires in %d days (%s) — update the client",
			int(d.Hours()/24), signer.NotAfter.Format(time.DateOnly))
	}
	return verdict, nil
}

// parseCTL walks the MS-CRTD CertificateTrustList:
//
//	SEQUENCE { subjectUsage AlgorithmIdentifier, listIdentifier ANY,
//	           thisUpdate UTCTime, subjectAlgorithm AlgorithmIdentifier,
//	           trustListEntries SEQUENCE OF { hash OCTET STRING, attrs SET optional },
//	           extendedInformation [0] optional }
//
// The layout is the one observed on the real files (the DER carries no
// version INTEGER and no nextUpdate — the refresh policy rides thisUpdate).
func parseCTL(ctlDER []byte) (*ctlVerdict, error) {
	var ctl asn1.RawValue
	rest, err := asn1.Unmarshal(ctlDER, &ctl)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("the CTL is not a single DER sequence")
	}
	if ctl.Class != 0 || ctl.Tag != 16 {
		return nil, errors.New("the CTL is not a sequence")
	}

	verdict := &ctlVerdict{hashes: make(map[ctlHash]struct{}), extraHashes: make(map[string]struct{})}
	body := ctl.Bytes

	var usage ctlAlgorithmIdentifier
	if body, err = asn1.Unmarshal(body, &usage); err != nil {
		return nil, fmt.Errorf("the CTL subjectUsage does not decode: %s", err)
	}
	verdict.usage = usage.Algorithm

	var listIdentifier asn1.RawValue
	if body, err = asn1.Unmarshal(body, &listIdentifier); err != nil {
		return nil, fmt.Errorf("the CTL listIdentifier does not decode: %s", err)
	}

	// between the list identifier and thisUpdate the real lists carry an
	// extra INTEGER (a FILETIME stamp; observed on the disallowed cabinet,
	// the trust list omits it) — skip whatever INTEGERs ride there, the time
	// element is what the refresh policy needs
	var thisUpdate time.Time
	for {
		var peek asn1.RawValue
		if body, err = asn1.Unmarshal(body, &peek); err != nil {
			return nil, fmt.Errorf("the CTL thisUpdate does not decode: %s", err)
		}
		if peek.Tag == 23 || peek.Tag == 24 {
			if _, err := asn1.Unmarshal(peek.FullBytes, &thisUpdate); err != nil {
				return nil, fmt.Errorf("the CTL thisUpdate does not decode: %s", err)
			}
			break
		}
	}
	verdict.thisUpdate = thisUpdate

	var subjectAlgorithm ctlAlgorithmIdentifier
	if body, err = asn1.Unmarshal(body, &subjectAlgorithm); err != nil {
		return nil, fmt.Errorf("the CTL subjectAlgorithm does not decode: %s", err)
	}
	// the trust list stamps its entries sha1; the disallowed list carries the
	// szOID_DISALLOWED_HASH marker instead (both observed on the real files,
	// the entries themselves are 20-byte hashes either way)
	if !subjectAlgorithm.Algorithm.Equal(oidSHA1Digest) && !subjectAlgorithm.Algorithm.Equal(oidDisallowedHashAlgorithm) {
		return nil, fmt.Errorf("the CTL subject hash algorithm %v is neither sha1 nor the disallowed-hash marker", subjectAlgorithm.Algorithm)
	}

	var entries asn1.RawValue
	if body, err = asn1.Unmarshal(body, &entries); err != nil || entries.Class != 0 || entries.Tag != 16 {
		return nil, fmt.Errorf("the CTL trust list entries do not decode: %v", err)
	}
	entryBody := entries.Bytes
	for len(entryBody) > 0 {
		var entry asn1.RawValue
		entryBody, err = asn1.Unmarshal(entryBody, &entry)
		if err != nil {
			return nil, fmt.Errorf("a CTL entry does not decode: %s", err)
		}
		var hashValue asn1.RawValue
		if _, err := asn1.Unmarshal(entry.Bytes, &hashValue); err != nil || hashValue.Tag != 4 {
			return nil, errors.New("a CTL entry carries no subject hash octet string")
		}
		switch len(hashValue.Bytes) {
		case sha1Size:
			var h ctlHash
			copy(h[:], hashValue.Bytes)
			verdict.hashes[h] = struct{}{}
		case md5.Size, sha512.Size384:
			verdict.extraHashes[string(hashValue.Bytes)] = struct{}{}
		default:
			return nil, fmt.Errorf("a CTL entry hash is %d bytes, want 20 (sha1), 16 (md5) or 48 (sha384)", len(hashValue.Bytes))
		}
	}
	return verdict, nil
}

// ---- the process-wide root program state ----

// rootProgram holds the CTL verdicts the client currently rides plus the
// collected anchors. One instance rides per process (rootProgramDefault,
// initialized once from loadClientCAPool); the tests build isolated ones.
type rootProgram struct {
	mu                  sync.Mutex
	ssh3Dir             string
	enabled             bool
	signerPEM           []byte // the trust-list pin (anchors)
	disallowedSignerPEM []byte // the disallowed-list pin (denials only)
	ctl                 *ctlVerdict
	disallowed          *ctlVerdict
	negative            map[ctlHash]struct{}
	blessed             map[[sha256.Size]byte]struct{}
	fetch               func(ctx context.Context, url string) ([]byte, error)
	now                 func() time.Time
	refreshOnce         sync.Once
}

// rootProgramDefault is the client's instance; its pins ride the binary.
var rootProgramDefault = &rootProgram{
	signerPEM:           msCTLSignerPEM,
	disallowedSignerPEM: msCTLDisallowedSignerPEM,
	fetch:               rootProgramHTTPFetch,
	now:                 time.Now,
}

// ctlFromCAB unpacks the signed CTL out of a fetched or cached cabinet: the
// root-program cabinets carry exactly one member named authroot.stl or
// disallowedcert.stl.
func ctlFromCAB(cab []byte, memberName string) ([]byte, error) {
	members, err := parseCabinet(cab)
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		if m.name == memberName {
			return m.data, nil
		}
	}
	return nil, fmt.Errorf("the cabinet carries no %s member", memberName)
}

// sha1OfCert computes the CTL entry hash of a certificate.
func sha1OfCert(cert *x509.Certificate) ctlHash {
	return ctlHash(sha1.Sum(cert.Raw))
}

// rootProgramHTTPFetch GETs one URL with a per-fetch timeout and a body cap.
func rootProgramHTTPFetch(ctx context.Context, url string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the CTL server answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRootProgramFetchBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxRootProgramFetchBytes {
		return nil, fmt.Errorf("the CTL answer exceeds %d bytes", maxRootProgramFetchBytes)
	}
	return body, nil
}

// candidateCTLURLs lists the URLs one list rides: the env override is used
// as-is (the tests point it at their local server), the built-in base falls
// back from https to the plain http variant of the same path (the pinned
// signature is the trust carrier — see the file comment).
func candidateCTLURLs(base, name string) []string {
	if override := os.Getenv(rootProgramBaseURLEnvVar); override != "" {
		return []string{override + "/" + name}
	}
	urls := []string{base + "/" + name}
	if strings.HasPrefix(base, "https://") {
		urls = append(urls, "http://"+strings.TrimPrefix(base, "https://")+"/"+name)
	}
	return urls
}

// fetchCTLFile downloads one cabinet through the candidate URLs.
func (rp *rootProgram) fetchCTLFile(ctx context.Context, base, name string) ([]byte, error) {
	var lastErr error
	for _, url := range candidateCTLURLs(base, name) {
		data, err := rp.fetch(ctx, url)
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// load initializes the process-wide state from the cache files and merges the
// collected anchors into pool. It never fails: every missing or invalid
// source degrades to a warning and the remaining trust rides on.
func (rp *rootProgram) load(ssh3Dir string, pool *x509.CertPool) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.ssh3Dir = ssh3Dir
	rp.enabled = os.Getenv(rootProgramDisableEnvVar) != "1"
	rp.ctl, rp.disallowed, rp.negative = nil, nil, nil
	rp.blessed = make(map[[sha256.Size]byte]struct{})
	if !rp.enabled {
		log.Debug().Msg("root program: disabled by SSH3_NO_ROOT_PROGRAM, riding the T1/T2 trust sources alone")
		return
	}

	history := rp.loadHistory()
	ctl := rp.loadCachedCTL(authRootSTLCabFileName, "authroot.stl", oidRootListSignerUsage, rp.signerPEM, true)
	if ctl != nil {
		rp.ctl = ctl
		rp.blessed = rp.loadAuthRoots(pool, ctl)
		if age := rp.now().Sub(ctl.thisUpdate); age <= ctlNegativeMaxAge {
			negative := make(map[ctlHash]struct{})
			for h := range history {
				if _, ok := ctl.hashes[h]; !ok {
					negative[h] = struct{}{}
				}
			}
			rp.negative = negative
		}
		for h := range ctl.hashes {
			history[h] = struct{}{}
		}
		rp.storeHistory(history)
		log.Info().Msgf("root program: riding the cached Windows CTL verdict (%d trusted roots, thisUpdate %s)",
			len(ctl.hashes), ctl.thisUpdate.UTC().Format(time.RFC3339))
		if d := time.Until(ctl.signerNotAfter); d < 60*24*time.Hour {
			log.Warn().Msgf("root program: the pinned Microsoft CTL signer expires %s — update the client",
				ctl.signerNotAfter.Format(time.DateOnly))
		}
	} else if rp.cacheExists(authRootSTLCabFileName) {
		log.Warn().Msg("root program: the cached authrootstl.cab does not verify under the pinned signer — its verdict is ignored")
	}
	if dis := rp.loadCachedCTL(disallowedCertSTLCabFileName, "disallowedcert.stl", oidDisallowedUsage, rp.disallowedSignerPEM, false); dis != nil {
		rp.disallowed = dis
		log.Info().Msgf("root program: riding the cached Windows disallowed-certificate verdict (%d entries)", len(dis.hashes))
	} else if rp.cacheExists(disallowedCertSTLCabFileName) {
		log.Warn().Msg("root program: the cached disallowedcertstl.cab does not verify under the pinned signer — its verdict is ignored")
	}
}

// cacheExists reports whether a cache file is present (used to tell "no
// cache" from "cache rejected" in the logs).
func (rp *rootProgram) cacheExists(name string) bool {
	_, err := os.Stat(path.Join(rp.ssh3Dir, name))
	return err == nil
}

// loadCachedCTL reads one cached cabinet, unpacks its member and verifies it
// under the given pin; any failure degrades to nil (no verdict).
func (rp *rootProgram) loadCachedCTL(name string, memberName string, expectUsage asn1.ObjectIdentifier, signerPEM []byte, strictExpiry bool) *ctlVerdict {
	raw, err := os.ReadFile(path.Join(rp.ssh3Dir, name))
	if err != nil {
		return nil
	}
	stl, err := ctlFromCAB(raw, memberName)
	if err != nil {
		log.Debug().Msgf("root program: %s rejected: %s", name, err)
		return nil
	}
	verdict, err := verifySignedCTL(stl, signerPEM, rp.now(), expectUsage, strictExpiry)
	if err != nil {
		log.Debug().Msgf("root program: %s rejected: %s", name, err)
		return nil
	}
	return verdict
}

// loadHistory reads the SHA-1 verdict history: every hash a signature-valid
// CTL ever blessed here. It is the evidence the negative filtering needs —
// absence from the current CTL only means "Microsoft removed it" when a
// previous CTL listed it (a private CA never in the program is untouched).
func (rp *rootProgram) loadHistory() map[ctlHash]struct{} {
	history := make(map[ctlHash]struct{})
	raw, err := os.ReadFile(path.Join(rp.ssh3Dir, authRootHistoryFileName))
	if err != nil {
		return history
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if len(line) != 2*sha1Size {
			continue
		}
		decoded, err := hex.DecodeString(line)
		if err != nil {
			continue
		}
		var h ctlHash
		copy(h[:], decoded)
		history[h] = struct{}{}
	}
	return history
}

// storeHistory persists the verdict history (sorted hex lines).
func (rp *rootProgram) storeHistory(history map[ctlHash]struct{}) {
	lines := make([]string, 0, len(history))
	for h := range history {
		lines = append(lines, hex.EncodeToString(h[:]))
	}
	sort.Strings(lines)
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	if err := os.WriteFile(path.Join(rp.ssh3Dir, authRootHistoryFileName), []byte(content), 0600); err != nil {
		log.Debug().Msgf("root program: could not store the verdict history: %s", err)
	}
}

// loadAuthRoots adds the collected anchors to the pool — but only the ones
// the valid CTL still vouches for: the collected trust rides the verdict, and
// a root Microsoft dropped is rewritten out of the cache (it may ride back in
// through the system store if the store itself carries it; the pool here is
// the root program's own addition).
func (rp *rootProgram) loadAuthRoots(pool *x509.CertPool, ctl *ctlVerdict) map[[sha256.Size]byte]struct{} {
	blessed := make(map[[sha256.Size]byte]struct{})
	raw, err := os.ReadFile(path.Join(rp.ssh3Dir, authRootsFileName))
	if err != nil {
		return blessed
	}
	keep := new(bytes.Buffer)
	dropped := 0
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Warn().Msgf("root program: skipping a %s entry that does not parse: %s", authRootsFileName, err)
			continue
		}
		if _, ok := ctl.hashes[sha1OfCert(cert)]; !ok {
			dropped++
			log.Info().Msgf("root program: dropping %q from %s — the current Windows verdict no longer lists it",
				cert.Subject.String(), authRootsFileName)
			continue
		}
		if pool != nil {
			pool.AddCert(cert)
		}
		fp := sha256.Sum256(cert.Raw)
		blessed[fp] = struct{}{}
		keep.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}
	if dropped > 0 {
		if err := os.WriteFile(path.Join(rp.ssh3Dir, authRootsFileName), keep.Bytes(), 0600); err != nil {
			log.Debug().Msgf("root program: could not rewrite %s: %s", authRootsFileName, err)
		}
	}
	return blessed
}

// refreshAsync starts the background refresh (once per process). The dial
// path never calls this: a connection never waits on the root program.
func (rp *rootProgram) refreshAsync() {
	rp.refreshOnce.Do(func() {
		go rp.refresh()
	})
}

// refresh re-downloads the CTL cabinets when the cached verdict aged out of
// ctlRefreshAfter, verifies them against the pinned signer, rewrites the
// caches and swaps the in-process verdicts (the harvest and veto gates ride
// the new verdicts immediately; the anchor pool rebuild happens on the next
// start). A fresh cache returns before any network activity — zero requests
// between refreshes; a failed refresh warns and the cache rides on.
func (rp *rootProgram) refresh() {
	rp.mu.Lock()
	if !rp.enabled {
		rp.mu.Unlock()
		return
	}
	ssh3Dir, ctl := rp.ssh3Dir, rp.ctl
	now := rp.now()
	rp.mu.Unlock()
	if ctl != nil && now.Sub(ctl.thisUpdate) <= ctlRefreshAfter {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), rootProgramFetchBudget)
	defer cancel()
	base := rootProgramDefaultBaseURL
	cab, err := rp.fetchCTLFile(ctx, base, authRootSTLCabFileName)
	if err != nil {
		log.Warn().Msgf("root program: could not refresh the Windows trust list, riding the cached verdict (%s)", err)
		return
	}
	stl, err := ctlFromCAB(cab, "authroot.stl")
	if err != nil {
		log.Warn().Msgf("root program: the refreshed authrootstl.cab does not unpack (%s), riding the cached verdict", err)
		return
	}
	verdict, err := verifySignedCTL(stl, rp.signerPEM, rp.now(), oidRootListSignerUsage, true)
	if err != nil {
		log.Warn().Msgf("root program: the refreshed authrootstl.cab fails the pinned-signer verification (%s), riding the cached verdict", err)
		return
	}
	var disallowed *ctlVerdict
	if disCab, err := rp.fetchCTLFile(ctx, base, disallowedCertSTLCabFileName); err == nil {
		if disSTL, err := ctlFromCAB(disCab, "disallowedcert.stl"); err == nil {
			if dis, err := verifySignedCTL(disSTL, rp.disallowedSignerPEM, rp.now(), oidDisallowedUsage, false); err == nil {
				disallowed = dis
				if err := os.WriteFile(path.Join(ssh3Dir, disallowedCertSTLCabFileName), disCab, 0600); err != nil {
					log.Debug().Msgf("root program: could not store %s: %s", disallowedCertSTLCabFileName, err)
				}
			}
		}
	}
	if err := os.WriteFile(path.Join(ssh3Dir, authRootSTLCabFileName), cab, 0600); err != nil {
		log.Debug().Msgf("root program: could not store %s: %s", authRootSTLCabFileName, err)
	}

	rp.mu.Lock()
	rp.ctl = verdict
	if disallowed != nil {
		rp.disallowed = disallowed
	}
	history := rp.loadHistory()
	for h := range verdict.hashes {
		history[h] = struct{}{}
	}
	rp.storeHistory(history)
	if rp.now().Sub(verdict.thisUpdate) <= ctlNegativeMaxAge {
		negative := make(map[ctlHash]struct{})
		for h := range history {
			if _, ok := verdict.hashes[h]; !ok {
				negative[h] = struct{}{}
			}
		}
		rp.negative = negative
	}
	rp.loadAuthRoots(nil, verdict) // rewrite the collected cache against the new verdict
	rp.mu.Unlock()
	log.Info().Msgf("root program: refreshed the Windows CTL verdict (%d trusted roots, thisUpdate %s)",
		len(verdict.hashes), verdict.thisUpdate.UTC().Format(time.RFC3339))
}

// harvest offers certificates surfaced by a dial (the server-presented chain,
// the AIA chase results) to the root program: a self-signed certificate whose
// SHA-1 the current, signature-valid CTL vouches for is appended to
// authroots.pem and becomes an anchor of pool. It returns how many
// certificates were blessed; the caller retries the handshake when the
// blessing grew the anchor pool. A certificate is never blessed because it
// was fetched — only because the pinned-signer CTL lists its hash (see the
// file comment on the verified-SET semantics).
func (rp *rootProgram) harvest(certs []*x509.Certificate, pool *x509.CertPool) int {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if !rp.enabled || rp.ctl == nil || pool == nil {
		return 0
	}
	ctl := rp.ctl
	if age := rp.now().Sub(ctl.thisUpdate); age > ctlBlessMaxAge || age < -time.Hour {
		return 0 // a stale (or clock-skewed future) verdict mints no new anchors
	}
	added := 0
	for _, cert := range certs {
		if cert.CheckSignatureFrom(cert) != nil {
			continue // only self-signed roots are anchor candidates
		}
		if _, ok := ctl.hashes[sha1OfCert(cert)]; !ok {
			continue
		}
		fp := sha256.Sum256(cert.Raw)
		if _, known := rp.blessed[fp]; known {
			continue
		}
		file, err := os.OpenFile(path.Join(rp.ssh3Dir, authRootsFileName), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Debug().Msgf("root program: could not append to %s: %s", authRootsFileName, err)
			return added
		}
		_, err = file.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		file.Close()
		if err != nil {
			log.Debug().Msgf("root program: could not append to %s: %s", authRootsFileName, err)
			return added
		}
		rp.blessed[fp] = struct{}{}
		pool.AddCert(cert)
		added++
		log.Info().Msgf("root program: the Windows CTL verdict blesses %q — cached as an anchor in %s",
			cert.Subject.String(), authRootsFileName)
	}
	return added
}

// vetoesChain applies the negative verdicts of the root program to a
// presented chain: a certificate on the disallowed list vetoes outright (a
// signature-valid disallowed CTL applies however old — a stale denial is a
// denial), and on a fresh CTL a chain that anchors at a root Microsoft
// removed from the program is refused as well. The removal check re-derives
// the verified chain against the anchor pool: when the re-verification
// disagrees with the handshake (an exotic EKU constraint, say) the check
// steps aside — the TLS verdict stays authoritative for trust, the root
// program only narrows it.
func (rp *rootProgram) vetoesChain(presented []*x509.Certificate, pool *x509.CertPool) (string, bool) {
	if len(presented) == 0 {
		return "", false
	}
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if !rp.enabled {
		return "", false
	}
	if disallowed := rp.disallowed; disallowed != nil {
		for _, cert := range presented {
			if _, hit := disallowed.hashes[sha1OfCert(cert)]; hit {
				return "certificate is on the disallowed list of the Microsoft root program", true
			}
			// the disallowed list rides md5 and sha384 beside sha1
			m5 := md5.Sum(cert.Raw)
			if _, hit := disallowed.extraHashes[string(m5[:])]; hit {
				return "certificate is on the disallowed list of the Microsoft root program", true
			}
			s384 := sha512.Sum384(cert.Raw)
			if _, hit := disallowed.extraHashes[string(s384[:])]; hit {
				return "certificate is on the disallowed list of the Microsoft root program", true
			}
		}
	}
	if negative := rp.negative; len(negative) > 0 && pool != nil {
		// re-derive the chain the handshake anchored to: the presented
		// intermediates plus the anchor pool reproduce the crypto/tls verify
		intermediates := x509.NewCertPool()
		for _, cert := range presented[1:] {
			intermediates.AddCert(cert)
		}
		if chains, err := presented[0].Verify(x509.VerifyOptions{
			Roots:         pool,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err == nil && len(chains) > 0 {
			chain := chains[0]
			if _, hit := negative[sha1OfCert(chain[len(chain)-1])]; hit {
				return "the chain anchors at a root the Microsoft root program no longer trusts", true
			}
		}
	}
	return "", false
}
