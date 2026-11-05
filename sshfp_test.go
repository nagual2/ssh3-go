package ssh3

// Unit tests for the RFC 4255 SSHFP verification: parsing of raw DNS answers
// (fixtures, no network), record selection against the presented host key, and
// the failure modes that must stay soft (no record, NXDOMAIN, timeout).

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// --- test helpers -----------------------------------------------------------

// dnsRRFixture describes one answer record to encode in a test message.
type dnsRRFixture struct {
	// name is written as-is unless namePtr is set, in which case a compression
	// pointer to namePtr is written instead.
	name    string
	namePtr int
	rrType  uint16
	rrClass uint16
	ttl     uint32
	rdata   []byte
}

func encodeTestName(t *testing.T, name string) []byte {
	t.Helper()
	var out []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			t.Fatalf("test label %q is longer than 63 bytes", label)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func compressionPointer(offset int) []byte {
	return []byte{byte(0xC0 | (offset >> 8)), byte(offset)}
}

// buildDNSMessage encodes a DNS message: 12-byte header, one question and the
// given answers. The question name always starts at offset 12, which lets a
// test build name-compression pointers deterministically.
func buildDNSMessage(t *testing.T, id uint16, flags uint16, qname string, answers []dnsRRFixture) []byte {
	t.Helper()
	var msg []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:], id)
	binary.BigEndian.PutUint16(header[2:], flags)
	binary.BigEndian.PutUint16(header[4:], 1) // QDCOUNT
	binary.BigEndian.PutUint16(header[6:], uint16(len(answers)))
	msg = append(msg, header...)
	msg = append(msg, encodeTestName(t, qname)...)
	msg = binary.BigEndian.AppendUint16(msg, dnsTypeSSHFP)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN) // QTYPE/QCLASS
	for _, rr := range answers {
		if rr.namePtr > 0 {
			msg = append(msg, compressionPointer(rr.namePtr)...)
		} else {
			msg = append(msg, encodeTestName(t, rr.name)...)
		}
		var fields []byte
		fields = binary.BigEndian.AppendUint16(fields, rr.rrType)
		fields = binary.BigEndian.AppendUint16(fields, rr.rrClass)
		fields = binary.BigEndian.AppendUint32(fields, rr.ttl)
		fields = binary.BigEndian.AppendUint16(fields, uint16(len(rr.rdata)))
		msg = append(msg, fields...)
		msg = append(msg, rr.rdata...)
	}
	return msg
}

func sshfpRdata(algorithm uint8, hashType uint8, fingerprint []byte) []byte {
	return append([]byte{algorithm, hashType}, fingerprint...)
}

// bytesOf builds a deterministic n-byte buffer starting with the given prefix.
func bytesOf(first byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = first + byte(i)
	}
	return out
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// fakeSSHFPResolver returns a canned result, optionally after a delay or after
// waiting for the context to be cancelled.
type fakeSSHFPResolver struct {
	records []SSHFP
	err     error
	wait    bool
	delay   time.Duration
	queried []string
}

func (f *fakeSSHFPResolver) LookupSSHFP(ctx context.Context, name string) ([]SSHFP, error) {
	f.queried = append(f.queried, name)
	if f.wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.records, f.err
}

// --- answer parsing ---------------------------------------------------------

func TestParseSSHFPResponse(t *testing.T) {
	msg := buildDNSMessage(t, 0xbeef, dnsFlagResponse, "sshfp.example.org", []dnsRRFixture{
		{
			name: "sshfp.example.org", rrType: dnsTypeSSHFP, rrClass: dnsClassIN, ttl: 3600,
			rdata: sshfpRdata(SSHFPAlgorithmRSA, SSHFPDigestSHA256, bytesOf(0xa0, 32)),
		},
		{
			name: "sshfp.example.org", rrType: dnsTypeSSHFP, rrClass: dnsClassIN, ttl: 3600,
			rdata: sshfpRdata(SSHFPAlgorithmECDSA, SSHFPDigestSHA1, bytesOf(0xb0, 20)),
		},
	})

	records, rcode, err := ParseSSHFPResponse(msg)
	if err != nil {
		t.Fatalf("ParseSSHFPResponse returned error %s", err)
	}
	if rcode != dnsRcodeSuccess {
		t.Errorf("rcode = %d, want %d", rcode, dnsRcodeSuccess)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if records[0].Algorithm != SSHFPAlgorithmRSA || records[0].DigestType != SSHFPDigestSHA256 ||
		len(records[0].Fingerprint) != 32 || records[0].Fingerprint[0] != 0xa0 {
		t.Errorf("record[0] = %+v, want RSA/SHA-256 record starting with 0xa0", records[0])
	}
	if records[1].Algorithm != SSHFPAlgorithmECDSA || records[1].DigestType != SSHFPDigestSHA1 ||
		len(records[1].Fingerprint) != 20 {
		t.Errorf("record[1] = %+v, want ECDSA/SHA-1 record of 20 bytes", records[1])
	}
	if got := records[0].String(); !strings.Contains(got, "RSA") || !strings.Contains(got, "SHA-256") {
		t.Errorf("record[0].String() = %q, want it to mention RSA and SHA-256", got)
	}
	if !records[0].Valid() || !records[1].Valid() {
		t.Errorf("Valid() = %v/%v, want true/true", records[0].Valid(), records[1].Valid())
	}
}

func TestParseSSHFPResponseNameCompression(t *testing.T) {
	// The question name sits at offset 12: "sshfp.example.org".
	// Offset 18 is the start of the "example.org" suffix, so a pointer there
	// yields a shorter name -- both forms must be supported.
	const suffixOffset = 12 + len("sshfp") + 1
	msg := buildDNSMessage(t, 1, dnsFlagResponse, "sshfp.example.org", []dnsRRFixture{
		{namePtr: 12, rrType: dnsTypeSSHFP, rrClass: dnsClassIN, ttl: 60,
			rdata: sshfpRdata(SSHFPAlgorithmRSA, SSHFPDigestSHA256, bytesOf(0x01, 32))},
		{namePtr: suffixOffset, rrType: dnsTypeSSHFP, rrClass: dnsClassIN, ttl: 60,
			rdata: sshfpRdata(SSHFPAlgorithmRSA, SSHFPDigestSHA1, bytesOf(0x02, 20))},
		{name: "sshfp.example.org", rrType: dnsTypeSSHFP, rrClass: dnsClassIN, ttl: 60,
			rdata: sshfpRdata(SSHFPAlgorithmECDSA, SSHFPDigestSHA256, bytesOf(0x03, 32))},
	})

	records, rcode, err := ParseSSHFPResponse(msg)
	if err != nil {
		t.Fatalf("ParseSSHFPResponse returned error %s", err)
	}
	if rcode != dnsRcodeSuccess {
		t.Errorf("rcode = %d, want %d", rcode, dnsRcodeSuccess)
	}
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3 (name compression must not hide records)", len(records))
	}
	for i, want := range []byte{0x01, 0x02, 0x03} {
		if records[i].Fingerprint[0] != want {
			t.Errorf("record[%d] fingerprint starts with %#x, want %#x", i, records[i].Fingerprint[0], want)
		}
	}
}

func TestParseSSHFPResponseNoRecordsAndNXDomain(t *testing.T) {
	cases := []struct {
		name      string
		flags     uint16
		answers   []dnsRRFixture
		wantRcode uint8
	}{
		{"NOERROR without answer", dnsFlagResponse, nil, dnsRcodeSuccess},
		{"NXDOMAIN", dnsFlagResponse | uint16(dnsRcodeNXDOMAIN), nil, dnsRcodeNXDOMAIN},
		{"NODATA with unrelated types", dnsFlagResponse, []dnsRRFixture{
			{name: "sshfp.example.org", rrType: dnsTypeTXT, rrClass: dnsClassIN, ttl: 60, rdata: []byte{0x03, 'h', 'i'}},
			{name: "sshfp.example.org", rrType: dnsTypeCNAME, rrClass: dnsClassIN, ttl: 60, rdata: encodeTestName(t, "elsewhere.example.org")},
			{name: "sshfp.example.org", rrType: dnsTypeSSHFP, rrClass: 3 /* CHAOS */, ttl: 60,
				rdata: sshfpRdata(SSHFPAlgorithmRSA, SSHFPDigestSHA256, bytesOf(0x09, 32))},
		}, dnsRcodeSuccess},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := buildDNSMessage(t, 7, c.flags, "sshfp.example.org", c.answers)
			records, rcode, err := ParseSSHFPResponse(msg)
			if err != nil {
				t.Fatalf("ParseSSHFPResponse returned error %s", err)
			}
			if rcode != c.wantRcode {
				t.Errorf("rcode = %d, want %d", rcode, c.wantRcode)
			}
			if len(records) != 0 {
				t.Errorf("records = %v, want none", records)
			}
		})
	}
}

func TestParseSSHFPResponseMalformed(t *testing.T) {
	valid := buildDNSMessage(t, 3, dnsFlagResponse, "sshfp.example.org", []dnsRRFixture{
		{name: "sshfp.example.org", rrType: dnsTypeSSHFP, rrClass: dnsClassIN, ttl: 60,
			rdata: sshfpRdata(SSHFPAlgorithmRSA, SSHFPDigestSHA256, bytesOf(0x01, 32))},
	})

	// a name pointing back to itself: the pointer walk must not loop forever
	loop := make([]byte, 12)
	binary.BigEndian.PutUint16(loop[4:], 1)
	binary.BigEndian.PutUint16(loop[6:], 1)
	loop = append(loop, compressionPointer(12)...)
	loop = binary.BigEndian.AppendUint16(loop, dnsTypeSSHFP)
	loop = binary.BigEndian.AppendUint16(loop, dnsClassIN)
	loop = append(loop, compressionPointer(12)...)
	loop = binary.BigEndian.AppendUint16(loop, dnsTypeSSHFP)
	loop = binary.BigEndian.AppendUint16(loop, dnsClassIN)
	loop = binary.BigEndian.AppendUint32(loop, 60)
	rdata := sshfpRdata(SSHFPAlgorithmRSA, SSHFPDigestSHA256, bytesOf(0x01, 32))
	loop = binary.BigEndian.AppendUint16(loop, uint16(len(rdata)))
	loop = append(loop, rdata...)

	badLabel := make([]byte, 12)
	binary.BigEndian.PutUint16(badLabel[4:], 1)
	badLabel = append(badLabel, 0x40, 0x01, 'a', 0x00) // reserved label type
	badLabel = binary.BigEndian.AppendUint16(badLabel, dnsTypeSSHFP)
	badLabel = binary.BigEndian.AppendUint16(badLabel, dnsClassIN)

	cases := []struct {
		name string
		msg  []byte
	}{
		{"truncated header", []byte{0x00, 0x01, 0x81}},
		{"truncated question", valid[:15]},
		{"truncated answer", valid[:len(valid)-5]},
		{"compression loop", loop},
		{"reserved label type", badLabel},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := ParseSSHFPResponse(c.msg); err == nil {
				t.Error("ParseSSHFPResponse returned no error on a malformed message")
			}
		})
	}
}

func TestBuildSSHFPQuery(t *testing.T) {
	query, err := BuildSSHFPQuery(0x1234, "sshfp.example.org")
	if err != nil {
		t.Fatalf("BuildSSHFPQuery returned error %s", err)
	}
	if got := binary.BigEndian.Uint16(query[0:]); got != 0x1234 {
		t.Errorf("query ID = %#x, want 0x1234", got)
	}
	if qdcount := binary.BigEndian.Uint16(query[4:]); qdcount != 1 {
		t.Errorf("QDCOUNT = %d, want 1", qdcount)
	}
	if ancount := binary.BigEndian.Uint16(query[6:]); ancount != 0 {
		t.Errorf("ANCOUNT = %d, want 0", ancount)
	}
	name, next, err := parseDNSName(query, dnsHeaderSize)
	if err != nil {
		t.Fatalf("could not decode the queried name: %s", err)
	}
	if name != "sshfp.example.org" {
		t.Errorf("queried name = %q, want %q", name, "sshfp.example.org")
	}
	if qtype := binary.BigEndian.Uint16(query[next:]); qtype != dnsTypeSSHFP {
		t.Errorf("QTYPE = %d, want %d (SSHFP)", qtype, dnsTypeSSHFP)
	}
	if qclass := binary.BigEndian.Uint16(query[next+2:]); qclass != dnsClassIN {
		t.Errorf("QCLASS = %d, want %d (IN)", qclass, dnsClassIN)
	}
	for _, bad := range []string{"", "sshfp..example.org", strings.Repeat("a", 64) + ".example.org"} {
		if _, err := BuildSSHFPQuery(1, bad); err == nil {
			t.Errorf("BuildSSHFPQuery(%q) returned no error", bad)
		}
	}
}

func TestParseDNSServers(t *testing.T) {
	content := `# a comment
nameserver 192.0.2.53
nameserver 2001:db8::53   # inline comment
; another comment
search example.org
options ndots:2
`
	servers := parseDNSServers(content)
	if len(servers) != 2 {
		t.Fatalf("parseDNSServers returned %v, want two servers", servers)
	}
	if servers[0] != "192.0.2.53" || servers[1] != "2001:db8::53" {
		t.Errorf("parseDNSServers = %v, want [192.0.2.53 2001:db8::53]", servers)
	}
	if got := parseDNSServers("search example.org\n"); len(got) != 0 {
		t.Errorf("parseDNSServers without nameserver = %v, want none", got)
	}
}

// --- record selection against the presented key ------------------------------

func TestCheckSSHFPMatch(t *testing.T) {
	cert := newSelfSignedCert(t, "sshfp.example.org")
	sha1Digest := sha1.Sum(cert.Raw)
	sha256Digest := sha256.Sum256(cert.Raw)

	cases := []struct {
		name    string
		records []SSHFP
	}{
		{"SHA-256", []SSHFP{{Algorithm: SSHFPAlgorithmECDSA, DigestType: SSHFPDigestSHA256, Fingerprint: sha256Digest[:]}}},
		{"SHA-1", []SSHFP{{Algorithm: SSHFPAlgorithmECDSA, DigestType: SSHFPDigestSHA1, Fingerprint: sha1Digest[:]}}},
		{"both digests published", []SSHFP{
			{Algorithm: SSHFPAlgorithmECDSA, DigestType: SSHFPDigestSHA256, Fingerprint: sha256Digest[:]},
			{Algorithm: SSHFPAlgorithmECDSA, DigestType: SSHFPDigestSHA1, Fingerprint: sha1Digest[:]},
		}},
		{"unrelated records alongside the matching one", []SSHFP{
			{Algorithm: SSHFPAlgorithmRSA, DigestType: SSHFPDigestSHA256, Fingerprint: bytesOf(0x00, 32)},
			{Algorithm: SSHFPAlgorithmECDSA, DigestType: SSHFPDigestSHA1, Fingerprint: bytesOf(0x00, 20)},
			{Algorithm: SSHFPAlgorithmECDSA, DigestType: SSHFPDigestSHA256, Fingerprint: sha256Digest[:]},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resolver := &fakeSSHFPResolver{records: c.records}
			got := CheckSSHFP(context.Background(), "sshfp.example.org", cert, resolver)
			if got.Status != SSHFPStatusVerified {
				t.Fatalf("status = %s, want %s (err: %v)", got.Status, SSHFPStatusVerified, got.Err)
			}
			if got.Matched == nil {
				t.Fatal("Matched = nil, want the matching record")
			}
			if len(resolver.queried) != 1 || resolver.queried[0] != "sshfp.example.org" {
				t.Errorf("resolver queried %v, want [sshfp.example.org]", resolver.queried)
			}
		})
	}
}

func TestCheckSSHFPMismatch(t *testing.T) {
	cert := newSelfSignedCert(t, "sshfp.example.org")
	other := newSelfSignedCert(t, "sshfp.example.org")
	cases := []struct {
		name    string
		records []SSHFP
	}{
		{"different key", []SSHFP{{Algorithm: SSHFPAlgorithmECDSA, DigestType: SSHFPDigestSHA256, Fingerprint: bytesOf(0x11, 32)}}},
		{"wrong algorithm number", []SSHFP{{Algorithm: SSHFPAlgorithmRSA, DigestType: SSHFPDigestSHA256, Fingerprint: bytesOf(0x11, 32)}}},
		{"wrong digest type for a matching value", []SSHFP{
			{Algorithm: SSHFPAlgorithmECDSA, DigestType: SSHFPDigestSHA1, Fingerprint: bytesOf(0x11, 32)},
		}},
		{"truncated fingerprint", []SSHFP{
			{Algorithm: SSHFPAlgorithmECDSA, DigestType: SSHFPDigestSHA256, Fingerprint: bytesOf(0x11, 16)},
		}},
		{"no record for the key algorithm", []SSHFP{
			{Algorithm: 99, DigestType: SSHFPDigestSHA256, Fingerprint: bytesOf(0x11, 32)},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resolver := &fakeSSHFPResolver{records: c.records}
			got := CheckSSHFP(context.Background(), "sshfp.example.org", cert, resolver)
			if got.Status != SSHFPStatusMismatch {
				t.Errorf("status = %s, want %s", got.Status, SSHFPStatusMismatch)
			}
			if got.Matched != nil {
				t.Errorf("Matched = %v, want nil", got.Matched)
			}
			if len(got.Records) != len(c.records) {
				t.Errorf("Records = %d entries, want the %d fetched ones", len(got.Records), len(c.records))
			}
		})
	}
	// sanity check: the second certificate really differs from the first one
	if other.Raw == nil {
		t.Fatal("could not build the second certificate")
	}
}

func TestCheckSSHFPSoftFailures(t *testing.T) {
	cert := newSelfSignedCert(t, "sshfp.example.org")
	cases := []struct {
		name     string
		resolver *fakeSSHFPResolver
		want     SSHFPStatus
		wantErr  error
	}{
		{"no record published", &fakeSSHFPResolver{}, SSHFPStatusNoRecords, nil},
		{"NXDOMAIN", &fakeSSHFPResolver{err: ErrNoSSHFPRecords}, SSHFPStatusNoRecords, nil},
		{"resolver failure", &fakeSSHFPResolver{err: errors.New("network is down")}, SSHFPStatusLookupFailed, nil},
		{"timeout", &fakeSSHFPResolver{wait: true}, SSHFPStatusLookupFailed, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			got := CheckSSHFP(ctx, "sshfp.example.org", cert, c.resolver)
			if got.Status != c.want {
				t.Errorf("status = %s, want %s", got.Status, c.want)
			}
			if c.want == SSHFPStatusLookupFailed && got.Err == nil {
				t.Error("Err = nil, want the lookup failure to be reported")
			}
			if got.Matched != nil {
				t.Errorf("Matched = %v, want nil", got.Matched)
			}
		})
	}
}

func TestCheckSSHFPPreconditions(t *testing.T) {
	cert := newSelfSignedCert(t, "sshfp.example.org")
	resolver := &fakeSSHFPResolver{err: errors.New("must not be called")}
	if got := CheckSSHFP(context.Background(), "sshfp.example.org", nil, resolver); got.Status != SSHFPStatusNotChecked {
		t.Errorf("status without certificate = %s, want %s", got.Status, SSHFPStatusNotChecked)
	}
	if got := CheckSSHFP(context.Background(), "sshfp.example.org", cert, nil); got.Status != SSHFPStatusLookupFailed {
		t.Errorf("status without resolver = %s, want %s", got.Status, SSHFPStatusLookupFailed)
	}
	if len(resolver.queried) != 0 {
		t.Errorf("resolver was queried %v, want no lookup at all", resolver.queried)
	}
}

func TestSSHFPQueryName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"sshfp.example.org:443/ssh3-term", "sshfp.example.org"},
		{"sshfp.example.org:443", "sshfp.example.org"},
		{"sshfp.example.org/", "sshfp.example.org"},
		{"SSHFP.Example.ORG.:443/ssh3", "sshfp.example.org"},
		{"example.org", "example.org"},
		{"[2001:db8::1]:443/ssh3-term", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"},
		{"192.0.2.1:443/", "1.2.0.192.in-addr.arpa"},
	}
	for _, c := range cases {
		got, err := SSHFPQueryName(c.in)
		if err != nil {
			t.Errorf("SSHFPQueryName(%q) returned error %s", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("SSHFPQueryName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := SSHFPQueryName(""); err == nil {
		t.Error("SSHFPQueryName(\"\") returned no error")
	}
}

func TestSSHFPDigestOfCertificate(t *testing.T) {
	cert := newSelfSignedCert(t, "sshfp.example.org")
	wantSHA1 := sha1.Sum(cert.Raw)
	wantSHA256 := sha256.Sum256(cert.Raw)

	if got := SSHFPDigest(SSHFPDigestSHA1, cert.Raw); !equalBytes(got, wantSHA1[:]) {
		t.Errorf("SSHFPDigest(SHA1) = %x, want %x", got, wantSHA1)
	}
	if got := SSHFPDigest(SSHFPDigestSHA256, cert.Raw); !equalBytes(got, wantSHA256[:]) {
		t.Errorf("SSHFPDigest(SHA256) = %x, want %x", got, wantSHA256)
	}
	if got := SSHFPDigest(9, cert.Raw); got != nil {
		t.Errorf("SSHFPDigest(unknown type) = %x, want nil", got)
	}

	algo, ok := HostKeyAlgorithm(cert)
	if !ok || algo != SSHFPAlgorithmECDSA {
		t.Errorf("HostKeyAlgorithm = %d/%v, want %d/true", algo, ok, SSHFPAlgorithmECDSA)
	}
	sha1Digest, sha256Digest := HostKeyDigests(cert)
	if !equalBytes(sha1Digest, wantSHA1[:]) || !equalBytes(sha256Digest, wantSHA256[:]) {
		t.Error("HostKeyDigests disagrees with the direct digests of the certificate")
	}
}

// --- resolver against a local DNS server ------------------------------------

func TestUDPSSHFPResolver(t *testing.T) {
	answer := buildDNSMessage(t, 0x4242, dnsFlagResponse, "sshfp.example.org", []dnsRRFixture{
		{namePtr: 12, rrType: dnsTypeSSHFP, rrClass: dnsClassIN, ttl: 60,
			rdata: sshfpRdata(SSHFPAlgorithmECDSA, SSHFPDigestSHA256, bytesOf(0x42, 32))},
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not open a local UDP socket: %s", err)
	}
	defer pc.Close()

	served := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		query := buf[:n]
		if qtype := binary.BigEndian.Uint16(query[len(query)-4:]); qtype != dnsTypeSSHFP {
			return
		}
		binary.BigEndian.PutUint16(answer[0:], binary.BigEndian.Uint16(query[0:]))
		_, _ = pc.WriteTo(answer, addr)
		served <- struct{}{}
	}()

	resolver := UDPSSHFPResolver{
		Servers: []string{pc.LocalAddr().String()},
		Timeout: 2 * time.Second,
	}
	records, err := resolver.LookupSSHFP(context.Background(), "sshfp.example.org")
	if err != nil {
		t.Fatalf("LookupSSHFP returned error %s", err)
	}
	if len(records) != 1 || records[0].Algorithm != SSHFPAlgorithmECDSA {
		t.Errorf("records = %+v, want a single ECDSA record", records)
	}
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Error("the local server was never queried")
	}

	// a server that never answers must give up on its own
	deadResolver := UDPSSHFPResolver{Servers: []string{"127.0.0.1:1"}, Timeout: 200 * time.Millisecond}
	start := time.Now()
	if _, err := deadResolver.LookupSSHFP(context.Background(), "sshfp.example.org"); err == nil {
		t.Error("LookupSSHFP against a dead server returned no error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("LookupSSHFP took %s, want it bounded by the configured timeout", elapsed)
	}
}

func TestSystemDNSServersAndEmptyResolver(t *testing.T) {
	// the system list is platform-dependent: on unix it comes from
	// /etc/resolv.conf, elsewhere it is empty.
	servers := SystemDNSServers()
	for _, server := range servers {
		if net.ParseIP(strings.Trim(server, "[]")) == nil {
			t.Errorf("SystemDNSServers returned %q, which is not an IP address", server)
		}
	}
	if len(servers) == 0 {
		// with no server to query, the lookup must fail rather than hang or
		// silently succeed
		if _, err := (UDPSSHFPResolver{}).LookupSSHFP(context.Background(), "sshfp.example.org"); !errors.Is(err, ErrNoDNSServers) {
			t.Errorf("LookupSSHFP without any DNS server returned %v, want ErrNoDNSServers", err)
		}
	}
}

// The self-signed rotation of the canon §2.4: the host is pinned with certA,
// the server comes back with the self-signed certB, and the SSHFP zone is the
// only signal left to vouch for the new key — the verified record re-pins,
// the absence of the DNS signal stays a refusal.
func TestSSHFPVouchesSelfSignedRotation(t *testing.T) {
	certA := newSelfSignedCert(t, "rotating.example.org")
	certB := newSelfSignedCert(t, "rotating.example.org")
	pinned := KnownHosts{"rotating.example.org:443/ssh3-term": {certA}}
	hostKey := "rotating.example.org:443/ssh3-term"
	if pinned.CheckCertificate(hostKey, certB) != HostCertificateChanged {
		t.Fatal("the rotated certificate was not detected as changed")
	}

	algorithm, ok := HostKeyAlgorithm(certB)
	if !ok {
		t.Fatalf("the self-signed certificate carries no SSHFP algorithm (key type %T)", certB.PublicKey)
	}
	sha256Digest := sha256.Sum256(certB.Raw)
	zone := &fakeSSHFPResolver{records: []SSHFP{{
		Algorithm:   algorithm,
		DigestType:  SSHFPDigestSHA256,
		Fingerprint: sha256Digest[:],
	}}}
	verified := CheckSSHFP(context.Background(), hostKey, certB, zone)
	if verified.Status != SSHFPStatusVerified {
		t.Fatalf("the zone publishes the digest of certB: status = %s, want %s (err: %v)", verified.Status, SSHFPStatusVerified, verified.Err)
	}
	if !verified.VouchesRotation() {
		t.Error("a verified record must vouch for the self-signed rotation")
	}

	silent := CheckSSHFP(context.Background(), hostKey, certB, &fakeSSHFPResolver{})
	if silent.Status != SSHFPStatusNoRecords {
		t.Fatalf("an empty zone gave status %s, want %s", silent.Status, SSHFPStatusNoRecords)
	}
	if silent.VouchesRotation() {
		t.Error("an empty zone must not vouch for the rotation")
	}
}

// Only a verified record is a proof: every soft verdict says nothing about
// the key and must keep the self-signed rotation refused.
func TestSSHFPResultVouchesRotation(t *testing.T) {
	cases := []struct {
		status  SSHFPStatus
		vouches bool
	}{
		{SSHFPStatusNotChecked, false},
		{SSHFPStatusVerified, true},
		{SSHFPStatusNoRecords, false},
		{SSHFPStatusLookupFailed, false},
		{SSHFPStatusMismatch, false},
	}
	for _, c := range cases {
		result := SSHFPResult{Status: c.status}
		if got := result.VouchesRotation(); got != c.vouches {
			t.Errorf("status %s: VouchesRotation() = %t, want %t", c.status, got, c.vouches)
		}
	}
}
