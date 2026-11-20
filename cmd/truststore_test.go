package cmd

// The trust store policy tests (R14-6, the ssh3-c wave-14 canon
// ee30795/35ad2e6): the parse (own|system, the unknown text refuses),
// the own pool (the embedded set + the user bundles, the platform store
// stays out), the system union (the platform store rides over the own
// set — never worse than the system store alone, an unavailable store
// rides the own set), the trust-bundle overlay of the state dir and the
// embed gate of the 109-root CCADB set. The system store inputs ride
// injected, so the set composition is deterministic on every platform.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/francoismichel/ssh3/internal/trustbundle"
)

// makeRootCert mints a self-signed CA certificate.
func makeRootCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the key: %s", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create the certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("could not parse the certificate: %s", err)
	}
	return cert
}

// rootAnchors reports whether the pool carries the root as an anchor.
func rootAnchors(pool *x509.CertPool, root *x509.Certificate) bool {
	if pool == nil {
		return false
	}
	_, err := root.Verify(x509.VerifyOptions{Roots: pool})
	return err == nil
}

func writeBundleFile(t *testing.T, ssh3Dir, name string, cert *x509.Certificate) {
	t.Helper()
	if err := os.MkdirAll(ssh3Dir, 0700); err != nil {
		t.Fatalf("could not create %s: %s", ssh3Dir, err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(filepath.Join(ssh3Dir, name), body, 0600); err != nil {
		t.Fatalf("could not write %s: %s", name, err)
	}
}

func TestParseTrustPolicy(t *testing.T) {
	ok := map[string]TrustPolicy{
		"own": TrustPolicyOwn, "OWN": TrustPolicyOwn, "Own": TrustPolicyOwn, "oWn": TrustPolicyOwn,
		"system": TrustPolicySystem, "SYSTEM": TrustPolicySystem, "System": TrustPolicySystem, "sYsTeM": TrustPolicySystem,
	}
	for text, want := range ok {
		got, err := ParseTrustPolicy(text)
		if err != nil {
			t.Errorf("ParseTrustPolicy(%q) refused: %s", text, err)
			continue
		}
		if got != want {
			t.Errorf("ParseTrustPolicy(%q) = %s, want %s", text, got, want)
		}
	}
	for _, text := range []string{"bogus", "", " own", "own ", "own|system"} {
		if _, err := ParseTrustPolicy(text); err == nil {
			t.Errorf("ParseTrustPolicy(%q) rode past the refusal", text)
		}
	}
	if TrustPolicyOwn.String() != "own" || TrustPolicySystem.String() != "system" {
		t.Errorf("the policy names ride wrong: %q %q", TrustPolicyOwn, TrustPolicySystem)
	}
	if defaultTrustPolicy != TrustPolicyOwn {
		t.Errorf("the default policy rides %s, want own (the phase-1 owner decision, the C canon ee30795)", defaultTrustPolicy)
	}
}

func TestTrustStoreFlagValue(t *testing.T) {
	var flag trustStoreFlag
	if err := flag.Set("system"); err != nil || flag.policy != TrustPolicySystem || !flag.set {
		t.Errorf("the flag did not take the system value: %v %v", flag, err)
	}
	if err := flag.Set("bogus"); err == nil {
		t.Error("the flag took the bogus value")
	}
	var unset trustStoreFlag
	if got := unset.String(); got != "own" {
		t.Errorf("the unset flag renders %q, want the default own", got)
	}
}

func TestOwnPolicyKeepsSystemStoreOut(t *testing.T) {
	ownRoot := makeRootCert(t, "Own Fixture Root")
	systemRoot := makeRootCert(t, "System Fixture Root")
	systemPool := x509.NewCertPool()
	systemPool.AddCert(systemRoot)

	ssh3Dir := t.TempDir()
	writeBundleFile(t, ssh3Dir, caBundleFileName, ownRoot)

	pool := buildPolicyPool(TrustPolicyOwn, systemPool, nil, ssh3Dir)
	if !rootAnchors(pool, ownRoot) {
		t.Error("the own pool lost the ca-bundle anchor")
	}
	if rootAnchors(pool, systemRoot) {
		t.Error("the own pool leaked the platform store in (the browser model keeps it out)")
	}
}

func TestSystemPolicyRidesTheUnion(t *testing.T) {
	ownRoot := makeRootCert(t, "Own Fixture Root")
	systemRoot := makeRootCert(t, "System Fixture Root")
	systemPool := x509.NewCertPool()
	systemPool.AddCert(systemRoot)

	ssh3Dir := t.TempDir()
	writeBundleFile(t, ssh3Dir, caBundleFileName, ownRoot)

	pool := buildPolicyPool(TrustPolicySystem, systemPool, nil, ssh3Dir)
	if !rootAnchors(pool, ownRoot) {
		t.Error("the system union lost the own set (the union is never worse than the own set)")
	}
	if !rootAnchors(pool, systemRoot) {
		t.Error("the system union lost the platform store")
	}
}

func TestSystemUnionSurvivesUnavailableStore(t *testing.T) {
	ownRoot := makeRootCert(t, "Own Fixture Root")

	ssh3Dir := t.TempDir()
	writeBundleFile(t, ssh3Dir, caBundleFileName, ownRoot)

	pool := buildPolicyPool(TrustPolicySystem, nil, errors.New("the store is sealed"), ssh3Dir)
	if !rootAnchors(pool, ownRoot) {
		t.Error("the unavailable store killed the own set (the union rides the own set with a warning)")
	}
}

func TestTrustBundleOverlayRidesThePool(t *testing.T) {
	overlayRoot := makeRootCert(t, "Trust Overlay Root")
	ssh3Dir := t.TempDir()
	writeBundleFile(t, ssh3Dir, "trust-bundle.pem", overlayRoot)

	pool := buildPolicyPool(TrustPolicyOwn, nil, nil, ssh3Dir)
	if !rootAnchors(pool, overlayRoot) {
		t.Error("the trust-bundle overlay did not anchor (the phase-1c landing feeds the own policy)")
	}

	// the absent overlay is the plain shape (the fresh home)
	other := t.TempDir()
	pool = buildPolicyPool(TrustPolicyOwn, nil, nil, other)
	if rootAnchors(pool, overlayRoot) {
		t.Error("the absent overlay anchored another dir")
	}
}

func TestCABundleEnvOverrideRidesThePool(t *testing.T) {
	envRoot := makeRootCert(t, "Env Override Root")
	envPath := filepath.Join(t.TempDir(), "override.pem")
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: envRoot.Raw})
	if err := os.WriteFile(envPath, body, 0600); err != nil {
		t.Fatalf("could not write the override bundle: %s", err)
	}
	t.Setenv(caBundleEnvVar, envPath)

	pool := buildPolicyPool(TrustPolicyOwn, nil, nil, t.TempDir())
	if !rootAnchors(pool, envRoot) {
		t.Error("the SSH3_CA_BUNDLE override did not anchor")
	}
}

func TestEmbeddedTrustSetRidesTheCanon(t *testing.T) {
	// the embed gate (the C canon 35ad2e6): the browser-size set, the
	// ISRG pair stays a mandatory member, the report snapshot sha pins
	// the source
	certs, err := parsePEMCerts(trustRootsPEM)
	if err != nil {
		t.Fatalf("the embedded trust set does not parse: %s", err)
	}
	if len(certs) != 109 {
		t.Errorf("the embedded set carries %d roots, want the 109 of the CCADB snapshot", len(certs))
	}

	var meta trustbundle.Meta
	if err := json.Unmarshal(trustRootsMeta, &meta); err != nil {
		t.Fatalf("the trust set meta does not parse: %s", err)
	}
	if meta.Roots != len(certs) {
		t.Errorf("the meta roots (%d) disagree with the embed (%d)", meta.Roots, len(certs))
	}
	if meta.SourceURL != trustbundle.SourceURL {
		t.Errorf("the meta source rides %q, want the CCADB report url", meta.SourceURL)
	}

	// the mandatory members: the ISRG pair the wave-13 tests pin
	fingerprints := map[string]bool{}
	for _, cert := range certs {
		sum := sha256.Sum256(cert.Raw)
		fingerprints[hex.EncodeToString(sum[:])] = true
	}
	for _, fp := range []string{isrgRootX1SHA256, isrgRootX2SHA256} {
		if !fingerprints[fp] {
			t.Errorf("the mandatory member %s left the set", fp)
		}
	}

	// the report snapshot gate: the committed csv carries the sha the
	// meta names, and the generator over it reproduces the embed
	csvBody, err := os.ReadFile(path.Join("..", "scripts", "trust-roots", meta.ReportSnapshot))
	if err != nil {
		t.Fatalf("the report snapshot is missing: %s", err)
	}
	sum := sha256.Sum256(csvBody)
	if hex.EncodeToString(sum[:]) != meta.ReportSHA256 {
		t.Errorf("the report snapshot sha drifted from the meta")
	}
	regenerated, summary, err := trustbundle.Generate(bytes.NewReader(csvBody))
	if err != nil {
		t.Fatalf("the generator refused the committed snapshot: %s", err)
	}
	if !bytes.Equal(regenerated, trustRootsPEM) {
		t.Errorf("the generator output drifted from the embedded set (%d roots over %d report rows)", summary.Roots, summary.ReportRows)
	}
}

func parsePEMCerts(bundle []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
