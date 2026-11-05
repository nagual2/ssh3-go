package ssh3

// SSHFP (RFC 4255) verification of the host identity.
//
// ssh3 pins X.509 certificates in its known_hosts file (see known_hosts.go)
// instead of raw SSH public keys, so the "host key" verified here is the DER
// certificate itself: the digests computed by SSHFPDigest are taken over
// cert.Raw, exactly the bytes compared by KnownHosts.CheckCertificate.
//
// The DNS exchange is implemented on top of the standard library only: the
// wire format is built and parsed here, so no third-party resolver is needed.
// Parsing (ParseSSHFPResponse) is deliberately kept apart from the network call
// (SSHFPResolver) so that it can be exercised on raw fixtures.

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// SSHFP algorithm numbers (RFC 4255 section 5, extended by RFC 7479 for
// Ed25519). They designate the signature algorithm of the host key the
// fingerprint belongs to.
const (
	SSHFPAlgorithmReserved uint8 = 0
	SSHFPAlgorithmRSA      uint8 = 1
	SSHFPAlgorithmDSA      uint8 = 2
	SSHFPAlgorithmECDSA    uint8 = 3
	SSHFPAlgorithmEd25519  uint8 = 4
)

// SSHFP digest numbers (RFC 4255 section 5).
const (
	SSHFPDigestReserved uint8 = 0
	SSHFPDigestSHA1     uint8 = 1
	SSHFPDigestSHA256   uint8 = 2
)

// DNS constants needed to carry a type 44 (SSHFP) question and its answer.
const (
	dnsTypeA     uint16 = 1
	dnsTypeCNAME uint16 = 5
	dnsTypeTXT   uint16 = 16
	dnsTypeSSHFP uint16 = 44

	dnsClassIN uint16 = 1

	dnsHeaderSize = 12

	// dnsFlagResponse is the QR bit of the header flags.
	dnsFlagResponse uint16 = 1 << 15
	// dnsFlagRecursionDesired asks the resolver to recurse on our behalf.
	dnsFlagRecursionDesired uint16 = 1 << 8

	dnsRcodeSuccess        uint8 = 0
	dnsRcodeFormatError    uint8 = 1
	dnsRcodeServerFailure  uint8 = 2
	dnsRcodeNXDOMAIN       uint8 = 3
	dnsRcodeNotImplemented uint8 = 4
	dnsRcodeRefused        uint8 = 5

	// dnsMaxNamePointers bounds the number of compression pointers followed
	// while decoding a name, so that a hostile answer cannot make us loop.
	dnsMaxNamePointers = 16
	// dnsMaxNameLength is the maximum length of a domain name in wire format.
	dnsMaxNameLength = 255
)

// DefaultSSHFPTimeout bounds the DNS exchange. SSHFP is meant to be a cheap
// extra signal, never a new source of connection latency.
const DefaultSSHFPTimeout = 2 * time.Second

// resolvConfPath is the standard location of the resolver list on unix systems.
// Windows has no equivalent file; on such platforms the caller is expected to
// provide the servers explicitly through UDPSSHFPResolver.Servers.
const resolvConfPath = "/etc/resolv.conf"

// Errors reported by the SSHFP machinery.
var (
	// ErrNoSSHFPRecords means the host publishes no SSHFP record at all
	// (NXDOMAIN or NODATA). This is a soft signal, not an error.
	ErrNoSSHFPRecords = errors.New("no SSHFP record published for this host")
	// ErrNoDNSServers means no DNS server could be determined for the lookup.
	ErrNoDNSServers = errors.New("no DNS server available for the SSHFP lookup")
	// ErrDNSMalformed means the DNS message could not be decoded.
	ErrDNSMalformed = errors.New("malformed DNS message")
	// ErrDNSResponseMismatch means the answer does not belong to our query.
	ErrDNSResponseMismatch = errors.New("DNS response does not match the query")
	// ErrDNSTruncated means the answer was cut by the UDP datagram size; a TCP
	// retry would be required to read it.
	ErrDNSTruncated = errors.New("truncated DNS response")
	// ErrSSHFPName means no SSHFP query name could be derived from a host key.
	ErrSSHFPName = errors.New("could not derive an SSHFP query name")
)

// SSHFP is one SSHFP resource record: the algorithm of the host key, the digest
// algorithm used to fingerprint it, and the fingerprint itself.
type SSHFP struct {
	Algorithm   uint8
	DigestType  uint8
	Fingerprint []byte
}

// Valid reports whether the record is self-consistent: the digest type must be
// known and the fingerprint must have the digest length it implies.
func (r SSHFP) Valid() bool {
	switch r.DigestType {
	case SSHFPDigestSHA1:
		return len(r.Fingerprint) == sha1.Size
	case SSHFPDigestSHA256:
		return len(r.Fingerprint) == sha256.Size
	default:
		return false
	}
}

// AlgorithmName returns the RFC name of the host key algorithm.
func (r SSHFP) AlgorithmName() string {
	switch r.Algorithm {
	case SSHFPAlgorithmRSA:
		return "RSA"
	case SSHFPAlgorithmDSA:
		return "DSA"
	case SSHFPAlgorithmECDSA:
		return "ECDSA"
	case SSHFPAlgorithmEd25519:
		return "ED25519"
	default:
		return fmt.Sprintf("ALG%d", r.Algorithm)
	}
}

// DigestName returns the RFC name of the digest algorithm.
func (r SSHFP) DigestName() string {
	switch r.DigestType {
	case SSHFPDigestSHA1:
		return "SHA-1"
	case SSHFPDigestSHA256:
		return "SHA-256"
	default:
		return fmt.Sprintf("DIGEST%d", r.DigestType)
	}
}

func (r SSHFP) String() string {
	return fmt.Sprintf("%d %d %s (%s %s)", r.Algorithm, r.DigestType, hex.EncodeToString(r.Fingerprint),
		r.AlgorithmName(), r.DigestName())
}

// Matches reports whether the record certifies the given host key: the
// algorithm must be the one of the key, the digest type must be one we can
// compute, and the bytes must be equal.
func (r SSHFP) Matches(algorithm uint8, hostKey []byte) bool {
	if r.Algorithm != algorithm || !r.Valid() {
		return false
	}
	digest := SSHFPDigest(r.DigestType, hostKey)
	if digest == nil {
		return false
	}
	return len(digest) == len(r.Fingerprint) && subtleEqual(digest, r.Fingerprint)
}

// SSHFPDigest computes the fingerprint of a host key with the requested digest
// algorithm, or nil when the digest type is unknown.
func SSHFPDigest(digestType uint8, hostKey []byte) []byte {
	switch digestType {
	case SSHFPDigestSHA1:
		sum := sha1.Sum(hostKey)
		return sum[:]
	case SSHFPDigestSHA256:
		sum := sha256.Sum256(hostKey)
		return sum[:]
	default:
		return nil
	}
}

// subtleEqual compares two byte slices in constant time.
func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// HostKeyAlgorithm maps the public key carried by a host certificate to the
// SSHFP algorithm number it must be published with. It reports false when the
// key algorithm has no SSHFP number, in which case no SSHFP record can ever
// match this host key.
func HostKeyAlgorithm(cert *x509.Certificate) (uint8, bool) {
	if cert == nil {
		return SSHFPAlgorithmReserved, false
	}
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return SSHFPAlgorithmRSA, true
	case *ecdsa.PublicKey:
		return SSHFPAlgorithmECDSA, true
	case ed25519.PublicKey:
		return SSHFPAlgorithmEd25519, true
	default:
		return SSHFPAlgorithmReserved, false
	}
}

// HostKeyDigests returns the SHA-1 and SHA-256 fingerprints of a host
// certificate, i.e. the two values an SSHFP owner may publish.
func HostKeyDigests(cert *x509.Certificate) (sha1Digest, sha256Digest []byte) {
	if cert == nil {
		return nil, nil
	}
	s1 := sha1.Sum(cert.Raw)
	s2 := sha256.Sum256(cert.Raw)
	return s1[:], s2[:]
}

// SSHFPQueryName derives the DNS name under which the SSHFP records of a host
// key are published. It accepts the canonical ssh3 host key ("host:port/path")
// as well as a bare hostname, and maps IP literals to the corresponding
// in-addr.arpa / ip6.arpa name (RFC 4255 section 3).
func SSHFPQueryName(hostKey string) (string, error) {
	name := strings.TrimSpace(hostKey)
	if name == "" {
		return "", fmt.Errorf("%w: empty host key", ErrSSHFPName)
	}
	// drop the URL path and any query/fragment
	if i := strings.IndexAny(name, "/?#"); i >= 0 {
		name = name[:i]
	}
	switch {
	case strings.HasPrefix(name, "["):
		end := strings.Index(name, "]")
		if end < 0 {
			return "", fmt.Errorf("%w: unbalanced brackets in %q", ErrSSHFPName, hostKey)
		}
		name = name[1:end]
	default:
		if host, _, err := net.SplitHostPort(name); err == nil {
			name = host
		}
	}
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return "", fmt.Errorf("%w: no host in %q", ErrSSHFPName, hostKey)
	}
	if ip := net.ParseIP(name); ip != nil {
		return reverseIPName(ip), nil
	}
	return strings.ToLower(name), nil
}

// reverseIPName builds the reverse-mapping name used to store SSHFP records of
// an IP address (RFC 4255 section 3).
func reverseIPName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0])
	}
	v6 := ip.To16()
	var sb strings.Builder
	for i := len(v6) - 1; i >= 0; i-- {
		sb.WriteString(hexDigit(v6[i] & 0x0f))
		sb.WriteByte('.')
		sb.WriteString(hexDigit(v6[i] >> 4))
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa")
	return sb.String()
}

func hexDigit(nibble byte) string {
	return strconv.FormatUint(uint64(nibble), 16)
}

// --- DNS message building ---------------------------------------------------

// BuildSSHFPQuery encodes a standard recursive DNS query for the SSHFP records
// (type 44, class IN) of name.
func BuildSSHFPQuery(id uint16, name string) ([]byte, error) {
	encoded, err := encodeDNSName(name)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, dnsHeaderSize, dnsHeaderSize+len(encoded)+4)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], dnsFlagRecursionDesired)
	binary.BigEndian.PutUint16(msg[4:], 1) // QDCOUNT
	msg = append(msg, encoded...)
	msg = binary.BigEndian.AppendUint16(msg, dnsTypeSSHFP)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	return msg, nil
}

// encodeDNSName converts a dotted name into the length-prefixed label sequence
// terminated by a zero octet.
func encodeDNSName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil, fmt.Errorf("%w: empty name", ErrSSHFPName)
	}
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return nil, fmt.Errorf("%w: empty label in %q", ErrDNSMalformed, name)
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("%w: label longer than 63 octets in %q", ErrDNSMalformed, name)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	if len(out) > dnsMaxNameLength {
		return nil, fmt.Errorf("%w: name longer than %d octets", ErrDNSMalformed, dnsMaxNameLength)
	}
	return out, nil
}

// --- DNS message parsing ----------------------------------------------------

// parseDNSName decodes a (possibly compressed) name starting at off. It returns
// the dotted name and the offset just after the encoded name in the enclosing
// record, so that the caller can go on with the type/class/ttl fields.
func parseDNSName(msg []byte, off int) (string, int, error) {
	var labels []string
	next := -1
	jumps := 0
	for {
		if off < 0 || off >= len(msg) {
			return "", 0, fmt.Errorf("%w: name runs past the message", ErrDNSMalformed)
		}
		length := int(msg[off])
		switch length & 0xC0 {
		case 0x00:
			if length == 0 {
				if next < 0 {
					next = off + 1
				}
				return strings.Join(labels, "."), next, nil
			}
			off++
			if off+length > len(msg) {
				return "", 0, fmt.Errorf("%w: label runs past the message", ErrDNSMalformed)
			}
			labels = append(labels, string(msg[off:off+length]))
			off += length
		case 0xC0:
			if off+1 >= len(msg) {
				return "", 0, fmt.Errorf("%w: truncated compression pointer", ErrDNSMalformed)
			}
			if next < 0 {
				next = off + 2
			}
			jumps++
			if jumps > dnsMaxNamePointers {
				return "", 0, fmt.Errorf("%w: too many compression pointers", ErrDNSMalformed)
			}
			off = int(msg[off]&0x3F)<<8 | int(msg[off+1])
		default:
			return "", 0, fmt.Errorf("%w: reserved label type %#x", ErrDNSMalformed, msg[off])
		}
	}
}

// ParseSSHFPResponse decodes a DNS answer and returns the SSHFP records it
// carries (type 44, class IN), along with the rcode of the message.
//
// An empty record list with rcode NXDOMAIN or NOERROR means the host simply
// publishes no SSHFP record; the caller must treat that as a soft signal rather
// than a verification failure.
func ParseSSHFPResponse(msg []byte) ([]SSHFP, uint8, error) {
	if len(msg) < dnsHeaderSize {
		return nil, 0, fmt.Errorf("%w: message shorter than a header", ErrDNSMalformed)
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	rcode := uint8(flags & 0x0F)
	questions := int(binary.BigEndian.Uint16(msg[4:]))
	answers := int(binary.BigEndian.Uint16(msg[6:]))

	off := dnsHeaderSize
	for i := 0; i < questions; i++ {
		if _, next, err := parseDNSName(msg, off); err != nil {
			return nil, rcode, err
		} else {
			off = next + 4 // QTYPE + QCLASS
		}
	}
	if off > len(msg) {
		return nil, rcode, fmt.Errorf("%w: question section runs past the message", ErrDNSMalformed)
	}

	var records []SSHFP
	for i := 0; i < answers; i++ {
		if _, next, err := parseDNSName(msg, off); err != nil {
			return nil, rcode, err
		} else {
			off = next
		}
		if off+10 > len(msg) {
			return nil, rcode, fmt.Errorf("%w: answer header runs past the message", ErrDNSMalformed)
		}
		rrType := binary.BigEndian.Uint16(msg[off:])
		rrClass := binary.BigEndian.Uint16(msg[off+2:])
		rdLength := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdLength > len(msg) {
			return nil, rcode, fmt.Errorf("%w: record data runs past the message", ErrDNSMalformed)
		}
		rdata := msg[off : off+rdLength]
		if rrType == dnsTypeSSHFP && rrClass == dnsClassIN && rdLength >= 2 {
			records = append(records, SSHFP{
				Algorithm:   rdata[0],
				DigestType:  rdata[1],
				Fingerprint: cloneBytes(rdata[2:]),
			})
		}
		off += rdLength
	}
	return records, rcode, nil
}

func cloneBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

// --- resolvers --------------------------------------------------------------

// SSHFPResolver fetches the SSHFP records published for a DNS name. The
// interface keeps the DNS wire format testable without a network.
type SSHFPResolver interface {
	LookupSSHFP(ctx context.Context, name string) ([]SSHFP, error)
}

// UDPSSHFPResolver queries DNS servers directly over UDP. An empty Servers list
// makes it read the system resolver configuration.
type UDPSSHFPResolver struct {
	// Servers holds "host:port" (or bare addresses, defaulting to port 53)
	// entries tried in order. When empty, SystemDNSServers is used.
	Servers []string
	// Timeout bounds the whole exchange. Zero means DefaultSSHFPTimeout.
	Timeout time.Duration
}

// SystemDNSServers returns the resolvers declared in the system configuration,
// or nil when they cannot be determined (typically on Windows, which keeps that
// configuration in the registry rather than in a file).
func SystemDNSServers() []string {
	content, err := os.ReadFile(resolvConfPath)
	if err != nil {
		return nil
	}
	return parseDNSServers(string(content))
}

// parseDNSServers extracts the nameserver entries of a resolv.conf content.
func parseDNSServers(content string) []string {
	var servers []string
	for _, line := range strings.Split(content, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if addr := strings.TrimSpace(fields[1]); addr != "" {
			servers = append(servers, addr)
		}
	}
	return servers
}

// LookupSSHFP performs the DNS exchange and returns the records found. It
// returns ErrNoSSHFPRecords when the name exists but publishes no SSHFP record,
// and a transport error when no answer could be obtained at all.
func (r UDPSSHFPResolver) LookupSSHFP(ctx context.Context, name string) ([]SSHFP, error) {
	servers := r.Servers
	if len(servers) == 0 {
		servers = SystemDNSServers()
	}
	if len(servers) == 0 {
		return nil, ErrNoDNSServers
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultSSHFPTimeout
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, fmt.Errorf("could not pick a DNS query ID: %w", err)
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	query, err := BuildSSHFPQuery(id, name)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, server := range servers {
		records, err := querySSHFPOnce(ctx, server, query, id, name, deadline)
		if err == nil {
			return records, nil
		}
		lastErr = err
		if errors.Is(err, ErrNoSSHFPRecords) {
			// an authoritative "no record" answer is a final verdict
			return nil, err
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			break
		}
	}
	return nil, lastErr
}

// querySSHFPOnce runs a single query/response exchange against one server.
func querySSHFPOnce(ctx context.Context, server string, query []byte, id uint16, name string, deadline time.Time) ([]SSHFP, error) {
	conn, err := net.Dial("udp", normalizeServerAddr(server))
	if err != nil {
		return nil, fmt.Errorf("could not reach the DNS server %s: %w", server, err)
	}
	defer conn.Close()
	// the effective deadline already accounts for both the resolver timeout
	// and the context deadline, so a single call covers both.
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("could not send the DNS query to %s: %w", server, err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("no answer from %s: %w", server, err)
	}
	response := buf[:n]
	if len(response) < 2 || binary.BigEndian.Uint16(response) != id {
		return nil, ErrDNSResponseMismatch
	}
	if len(response) >= 4 && binary.BigEndian.Uint16(response[2:])&(1<<9) != 0 {
		return nil, ErrDNSTruncated
	}
	records, rcode, err := ParseSSHFPResponse(response)
	if err != nil {
		return nil, err
	}
	switch {
	case rcode == dnsRcodeSuccess:
	case rcode == dnsRcodeNXDOMAIN:
		return nil, ErrNoSSHFPRecords
	default:
		return nil, fmt.Errorf("the DNS server %s answered with rcode %d for %s", server, rcode, name)
	}
	if len(records) == 0 {
		return nil, ErrNoSSHFPRecords
	}
	return records, nil
}

// normalizeServerAddr adds the default DNS port when the address has none.
func normalizeServerAddr(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, "53")
}

// --- verification -----------------------------------------------------------

// SSHFPStatus is the outcome of an SSHFP verification attempt.
type SSHFPStatus int

const (
	// SSHFPStatusNotChecked means no verification was attempted at all
	// (verification disabled, or no host certificate to check).
	SSHFPStatusNotChecked SSHFPStatus = iota
	// SSHFPStatusVerified means a published record matches the presented key.
	SSHFPStatusVerified
	// SSHFPStatusNoRecords means the host publishes no SSHFP record: a soft
	// signal that says nothing about the key.
	SSHFPStatusNoRecords
	// SSHFPStatusLookupFailed means the records could not be obtained (no
	// network, timeout, broken resolver). It must be distinguished from a
	// mismatch: an unreachable resolver must never reject a host.
	SSHFPStatusLookupFailed
	// SSHFPStatusMismatch means records were published and none matches the
	// presented key: the strongest possible MITM signal.
	SSHFPStatusMismatch
)

func (s SSHFPStatus) String() string {
	switch s {
	case SSHFPStatusNotChecked:
		return "not-checked"
	case SSHFPStatusVerified:
		return "verified"
	case SSHFPStatusNoRecords:
		return "no-records"
	case SSHFPStatusLookupFailed:
		return "lookup-failed"
	case SSHFPStatusMismatch:
		return "mismatch"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// SSHFPResult carries the verdict of an SSHFP verification together with the
// evidence behind it.
type SSHFPResult struct {
	// QueryName is the DNS name the records were requested for.
	QueryName string
	// Status is the verdict.
	Status SSHFPStatus
	// Records holds the records that were published, empty when none were
	// obtained.
	Records []SSHFP
	// Matched points to the record that certified the host key, nil otherwise.
	Matched *SSHFP
	// Err holds the reason of a lookup failure, nil otherwise.
	Err error
}

// VouchesRotation tells whether the verdict is strong enough to re-pin a
// rotated self-signed certificate (CERT-VERIFICATION-CANON.md 2.4). Under
// the selfsigned.ssh3 anchor the hostname is not proven against the target,
// so a published record matching the new key is the only proof left that the
// rotation is legitimate. The soft verdicts (not checked, no records,
// lookup failed) say nothing about the key and never vouch: a self-signed
// rotation without the DNS signal stays a refusal.
func (r SSHFPResult) VouchesRotation() bool {
	return r.Status == SSHFPStatusVerified
}

// CheckSSHFP fetches the SSHFP records of a host key and looks for one matching
// the presented certificate.
//
// It never returns SSHFPStatusMismatch for a missing answer: a timeout, an
// unreachable resolver, a truncated datagram or a host without any record all
// yield SSHFPStatusNoRecords or SSHFPStatusLookupFailed, so that an absent DNS
// signal can never be read as a MITM.
func CheckSSHFP(ctx context.Context, hostKey string, cert *x509.Certificate, resolver SSHFPResolver) SSHFPResult {
	if cert == nil {
		return SSHFPResult{Status: SSHFPStatusNotChecked}
	}
	if resolver == nil {
		return SSHFPResult{Status: SSHFPStatusLookupFailed, Err: ErrNoDNSServers}
	}
	name, err := SSHFPQueryName(hostKey)
	if err != nil {
		return SSHFPResult{Status: SSHFPStatusLookupFailed, Err: err}
	}
	records, err := resolver.LookupSSHFP(ctx, name)
	result := SSHFPResult{QueryName: name, Records: records}
	if err != nil {
		if errors.Is(err, ErrNoSSHFPRecords) {
			result.Status = SSHFPStatusNoRecords
		} else {
			result.Status = SSHFPStatusLookupFailed
			result.Err = err
		}
		return result
	}
	if len(records) == 0 {
		result.Status = SSHFPStatusNoRecords
		return result
	}
	algorithm, ok := HostKeyAlgorithm(cert)
	for i := range records {
		if !ok || !records[i].Matches(algorithm, cert.Raw) {
			continue
		}
		matched := records[i]
		result.Status = SSHFPStatusVerified
		result.Matched = &matched
		return result
	}
	result.Status = SSHFPStatusMismatch
	return result
}
