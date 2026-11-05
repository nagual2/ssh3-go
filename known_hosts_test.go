package ssh3

// Unit tests for the known_hosts fingerprint matching used by
// StrictHostKeyChecking: a known host presenting a certificate that differs
// from the pinned one must be detected (possible MITM), while the exact
// pinned certificate keeps matching.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/francoismichel/ssh3/util"
)

// newSelfSignedCert generates a distinct self-signed certificate for tests.
func newSelfSignedCert(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate private key: %s", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("could not create certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("could not parse generated certificate: %s", err)
	}
	return cert
}

func TestCheckCertificate(t *testing.T) {
	certA := newSelfSignedCert(t, "servera.ssh3")
	certB := newSelfSignedCert(t, "serverb.ssh3")
	kh := KnownHosts{
		"example.org:443/ssh3-term": {certA},
		"emptehost:443/":            {},
	}

	cases := []struct {
		host string
		cert *x509.Certificate
		want HostCertificateStatus
	}{
		{"example.org:443/ssh3-term", certA, HostCertificateMatches},
		{"example.org:443/ssh3-term", certB, HostCertificateChanged},
		{"unknown.example.org:443/", certA, HostCertificateUnknown},
		{"emptehost:443/", certA, HostCertificateUnknown},
		{"example.org:443/ssh3-term", nil, HostCertificateUnknown},
	}
	for _, c := range cases {
		if got := kh.CheckCertificate(c.host, c.cert); got != c.want {
			t.Errorf("CheckCertificate(%q, _) = %d, want %d", c.host, got, c.want)
		}
	}
	if !kh.HasCertificate("example.org:443/ssh3-term", certA) {
		t.Error("HasCertificate(certA) = false, want true")
	}
	if kh.HasCertificate("example.org:443/ssh3-term", certB) {
		t.Error("HasCertificate(certB) = false-want mismatch: got true, want false")
	}
}

func TestKnownHostsFingerprints(t *testing.T) {
	certA := newSelfSignedCert(t, "servera.ssh3")
	certB := newSelfSignedCert(t, "serverb.ssh3")
	kh := KnownHosts{"example.org:443/": {certA, certB}}

	fingerprints := kh.Fingerprints("example.org:443/")
	if len(fingerprints) != 2 {
		t.Fatalf("Fingerprints returned %d entries, want 2", len(fingerprints))
	}
	wantA := "SHA256:" + util.Sha256Fingerprint(certA.Raw)
	wantB := "SHA256:" + util.Sha256Fingerprint(certB.Raw)
	if fingerprints[0] != wantA || fingerprints[1] != wantB {
		t.Errorf("Fingerprints = [%s, %s], want [%s, %s]", fingerprints[0], fingerprints[1], wantA, wantB)
	}
	if got := kh.Fingerprints("unknown.example.org:443/"); got != nil {
		t.Errorf("Fingerprints(unknown host) = %v, want nil", got)
	}
}

func TestParseAppendKnownHostsRoundTrip(t *testing.T) {
	certA := newSelfSignedCert(t, "servera.ssh3")
	certB := newSelfSignedCert(t, "serverb.ssh3")

	dir := t.TempDir()
	filename := filepath.Join(dir, "known_hosts")

	if err := AppendKnownHost(filename, "example.org:443/ssh3-term", certA); err != nil {
		t.Fatalf("could not append known host: %s", err)
	}
	if err := AppendKnownHost(filename, "other.example.org:443/", certB); err != nil {
		t.Fatalf("could not append known host: %s", err)
	}

	knownHosts, invalidLines, err := ParseKnownHosts(filename)
	if err != nil {
		t.Fatalf("could not parse known hosts: %s", err)
	}
	if len(invalidLines) != 0 {
		t.Errorf("invalidLines = %v, want none", invalidLines)
	}
	if knownHosts.CheckCertificate("example.org:443/ssh3-term", certA) != HostCertificateMatches {
		t.Error("the freshly pinned certA should match after a parse round-trip")
	}
	if knownHosts.CheckCertificate("other.example.org:443/", certB) != HostCertificateMatches {
		t.Error("the freshly pinned certB should match after a parse round-trip")
	}
	// a change of certificate must be detected after reloading from disk
	if knownHosts.CheckCertificate("example.org:443/ssh3-term", certB) != HostCertificateChanged {
		t.Error("certB must be detected as a changed certificate for the host pinned with certA")
	}
}

func TestParseKnownHostsInvalidLines(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "known_hosts")
	content := "not enough fields\n" +
		"host wrong-algo abc\n" +
		"host x509-certificate not-base64!!\n"
	if err := os.WriteFile(filename, []byte(content), 0600); err != nil {
		t.Fatalf("could not write known hosts file: %s", err)
	}

	knownHosts, invalidLines, err := ParseKnownHosts(filename)
	if err != nil {
		t.Fatalf("could not parse known hosts: %s", err)
	}
	if len(knownHosts) != 0 {
		t.Errorf("knownHosts = %v, want empty", knownHosts)
	}
	if len(invalidLines) != 3 {
		t.Errorf("invalidLines = %v, want the three invalid lines [0 1 2]", invalidLines)
	}
}

// TestReplaceKnownHost rides the rotation path of CERT-VERIFICATION-CANON.md
// 2.4: the replaced host keeps only the new certificate, the other hosts and
// the malformed lines survive, the missing file rides the plain append.
func TestReplaceKnownHost(t *testing.T) {
	certA := newSelfSignedCert(t, "rotatea.ssh3")
	certB := newSelfSignedCert(t, "rotateb.ssh3")
	certOther := newSelfSignedCert(t, "rotateother.ssh3")

	dir := t.TempDir()
	filename := filepath.Join(dir, "known_hosts")

	if err := AppendKnownHost(filename, "example.org:443/ssh3-term", certA); err != nil {
		t.Fatalf("could not append known host: %s", err)
	}
	if err := AppendKnownHost(filename, "other.example.org:443/", certOther); err != nil {
		t.Fatalf("could not append known host: %s", err)
	}

	certBOldPins := func() bool {
		knownHosts, _, err := ParseKnownHosts(filename)
		if err != nil {
			t.Fatalf("could not parse known hosts: %s", err)
		}
		return knownHosts.CheckCertificate("example.org:443/ssh3-term", certA) == HostCertificateMatches
	}
	if !certBOldPins() {
		t.Fatal("certA should match before the rotation re-pin")
	}

	if err := ReplaceKnownHost(filename, "example.org:443/ssh3-term", certB); err != nil {
		t.Fatalf("could not replace known host: %s", err)
	}

	knownHosts, invalidLines, err := ParseKnownHosts(filename)
	if err != nil {
		t.Fatalf("could not parse known hosts after the replace: %s", err)
	}
	if len(invalidLines) != 0 {
		t.Errorf("invalidLines = %v, want none", invalidLines)
	}
	if knownHosts.CheckCertificate("example.org:443/ssh3-term", certB) != HostCertificateMatches {
		t.Error("the rotated certificate should match after the replace")
	}
	if knownHosts.CheckCertificate("example.org:443/ssh3-term", certA) != HostCertificateChanged {
		t.Error("the old certificate should be gone from the store (a changed cert against the new pin)")
	}
	if knownHosts.CheckCertificate("other.example.org:443/", certOther) != HostCertificateMatches {
		t.Error("the other host pin should survive the rewrite")
	}

	// the missing store rides the plain append
	missing := filepath.Join(dir, "absent-known_hosts")
	if err := ReplaceKnownHost(missing, "example.org:443/ssh3-term", certB); err != nil {
		t.Fatalf("could not replace on the missing store: %s", err)
	}
	knownHosts, _, err = ParseKnownHosts(missing)
	if err != nil {
		t.Fatalf("could not parse the appended store: %s", err)
	}
	if knownHosts.CheckCertificate("example.org:443/ssh3-term", certB) != HostCertificateMatches {
		t.Error("the appended store should match the new certificate")
	}
}
