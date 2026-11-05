package ssh3

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/francoismichel/ssh3/util"
)

type KnownHosts map[string][]*x509.Certificate

func (kh KnownHosts) Knows(hostname string) bool {
	if len(kh) == 0 {
		return false
	}
	_, ok := kh[hostname]
	return ok
}

// HostCertificateStatus expresses how a certificate presented by a server
// relates to the certificates pinned in known_hosts for that host.
type HostCertificateStatus int

const (
	// HostCertificateUnknown means no certificate is pinned for this host yet.
	HostCertificateUnknown HostCertificateStatus = iota
	// HostCertificateMatches means the presented certificate is exactly the
	// pinned one (same DER bytes).
	HostCertificateMatches
	// HostCertificateChanged means certificates are pinned for this host but
	// none matches the presented one: the server key changed, which can be a
	// machine-in-the-middle attack.
	HostCertificateChanged
)

// HasCertificate reports whether cert is exactly one of the certificates
// pinned for hostname (comparison on the raw DER bytes, i.e. on the SHA-256
// fingerprint, since the fingerprint is a hash of those bytes).
func (kh KnownHosts) HasCertificate(hostname string, cert *x509.Certificate) bool {
	return kh.CheckCertificate(hostname, cert) == HostCertificateMatches
}

// CheckCertificate classifies a presented certificate against the
// certificates pinned for hostname.
func (kh KnownHosts) CheckCertificate(hostname string, cert *x509.Certificate) HostCertificateStatus {
	if cert == nil {
		return HostCertificateUnknown
	}
	certs, ok := kh[hostname]
	if !ok || len(certs) == 0 {
		return HostCertificateUnknown
	}
	for _, pinned := range certs {
		if pinned != nil && bytes.Equal(pinned.Raw, cert.Raw) {
			return HostCertificateMatches
		}
	}
	return HostCertificateChanged
}

// Fingerprints returns the SHA-256 fingerprints of the certificates pinned
// for hostname, in the "SHA256:<base64>" form used in error messages.
func (kh KnownHosts) Fingerprints(hostname string) []string {
	certs, ok := kh[hostname]
	if !ok {
		return nil
	}
	fingerprints := make([]string, 0, len(certs))
	for _, cert := range certs {
		if cert != nil {
			fingerprints = append(fingerprints, "SHA256:"+util.Sha256Fingerprint(cert.Raw))
		}
	}
	return fingerprints
}

type InvalidKnownHost struct {
	line string
}

func (e InvalidKnownHost) Error() string {
	return fmt.Sprintf("invalid known host line: %s", e.line)
}

func ParseKnownHosts(filename string) (knownHosts KnownHosts, invalidLines []int, err error) {
	knownHosts = make(map[string][]*x509.Certificate)
	file, err := os.Open(filename)
	if os.IsNotExist(err) {
		// the known hosts file simply does not exist yet, so there is no known host
		return knownHosts, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	for i := 0; scanner.Scan(); i++ {
		knownHost := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(knownHost)
		if len(fields) != 3 || fields[1] != "x509-certificate" {
			invalidLines = append(invalidLines, i)
			continue
		}
		certBytes, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil {
			invalidLines = append(invalidLines, i)
			continue
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			invalidLines = append(invalidLines, i)
			continue
		}
		certs := knownHosts[fields[0]]
		certs = append(certs, cert)
		knownHosts[fields[0]] = certs
	}
	return knownHosts, invalidLines, nil
}

func AppendKnownHost(filename string, host string, cert *x509.Certificate) error {
	encodedCert := base64.StdEncoding.EncodeToString(cert.Raw)
	knownHosts, err := os.OpenFile(filename, os.O_CREATE|syscall.O_APPEND|syscall.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer knownHosts.Close()
	_, err = knownHosts.WriteString(fmt.Sprintf("%s x509-certificate %s\n", host, encodedCert))
	if err != nil {
		return err
	}

	return nil
}

// ReplaceKnownHost rewrites the certificates pinned for host: the old
// certificate lines of the host drop, the presented certificate rides
// alone. The rotation path of CERT-VERIFICATION-CANON.md 2.4: the chain
// verified against a system CA and the SAN covered the hostname, so the
// rotated certificate is the legitimate successor of the pinned one.
// The missing file rides the plain append; the rewrite is atomic-ish
// (the temp file + rename, 0600 preserved).
func ReplaceKnownHost(filename string, host string, cert *x509.Certificate) error {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return AppendKnownHost(filename, host, cert)
	}
	if err != nil {
		return err
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	encodedCert := base64.StdEncoding.EncodeToString(cert.Raw)
	newLine := fmt.Sprintf("%s x509-certificate %s", host, encodedCert)

	var kept strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == host && fields[1] == "x509-certificate" {
			continue // the rotated certificate replaces the old pins
		}
		if strings.TrimSpace(line) != "" {
			kept.WriteString(line)
			kept.WriteString("\n")
		}
	}
	kept.WriteString(newLine)
	kept.WriteString("\n")

	tmp := filename + ".tmp"
	if err := os.WriteFile(tmp, []byte(kept.String()), 0600); err != nil {
		return err
	}

	return os.Rename(tmp, filename)
}
