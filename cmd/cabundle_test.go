package cmd

// Tests of the CA-bundle bootstrap (ROADMAP.md R7-T1): the client trust pool
// rides the system store merged with the embedded ISRG roots and an optional
// user bundle file. The merge machinery is exercised on injected inputs (the
// test roots are generated here, no network); the embedded public roots keep
// one smoke-pin (they parse, two certificates ride, the subjects are the
// announced ones).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"
)

// certChain generates a self-signed root CA, an intermediate and a leaf
// covering dnsName: the CA-issue shape of CERT-VERIFICATION-CANON.md 2.3,
// with the root playing the part of a public anchor riding the bundle.
func certChain(t *testing.T, dnsName string) (rootPEM []byte, root, intermediate, leaf *x509.Certificate) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the root key: %s", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root " + dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("could not create the root: %s", err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("could not parse the root: %s", err)
	}

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the intermediate key: %s", err)
	}
	intermediateTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test intermediate " + dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTmpl, root, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("could not create the intermediate: %s", err)
	}
	intermediate, err = x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatalf("could not parse the intermediate: %s", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the leaf key: %s", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{dnsName},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intermediate, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatalf("could not create the leaf: %s", err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("could not parse the leaf: %s", err)
	}

	rootPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	return rootPEM, root, intermediate, leaf
}

// chainVerifies reports whether the leaf builds a chain to an anchor of the
// pool through the given intermediate (the server presents leaf and
// intermediate, the pool holds the root).
func chainVerifies(pool *x509.CertPool, intermediate, leaf *x509.Certificate, dnsName string) bool {
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		DNSName:       dnsName,
	})
	return err == nil
}

// The core case of the truncated-store problem: an empty system store plus a
// bundle anchor verifies a CA-issued chain, and the empty store alone does
// not (the bundle is what fixes the verification).
func TestBuildClientCAPoolBundleAnchorVerifiesChain(t *testing.T) {
	rootPEM, _, intermediate, leaf := certChain(t, "server.example.org")

	empty := x509.NewCertPool()
	if chainVerifies(empty, intermediate, leaf, "server.example.org") {
		t.Fatal("an empty system store must not verify the chain by itself")
	}

	pool := buildClientCAPool(empty, nil, rootPEM)
	if pool == nil {
		t.Fatal("buildClientCAPool returned no pool")
	}
	if !chainVerifies(pool, intermediate, leaf, "server.example.org") {
		t.Fatal("the bundle anchor must verify the chain over an empty system store")
	}
}

// The pool is a union: anchors from the system store and from the bundles
// both verify chains (the default behaviour stays a superset of the old
// system-only pool).
func TestBuildClientCAPoolMergesSystemAndBundle(t *testing.T) {
	rootAPEM, rootA, intermediateA, leafA := certChain(t, "a.example.org")
	rootBPEM, _, intermediateB, leafB := certChain(t, "b.example.org")

	system := x509.NewCertPool()
	system.AddCert(rootA)

	pool := buildClientCAPool(system, nil, rootAPEM, rootBPEM)
	if pool == nil {
		t.Fatal("buildClientCAPool returned no pool")
	}
	if !chainVerifies(pool, intermediateA, leafA, "a.example.org") {
		t.Fatal("the system store anchor must survive the merge")
	}
	if !chainVerifies(pool, intermediateB, leafB, "b.example.org") {
		t.Fatal("the bundle anchor must ride next to the system anchor")
	}
}

// A system store that cannot be read must not kill the client: the bundles
// still carry the trust (the production call rides the embedded roots there).
func TestBuildClientCAPoolSystemStoreErrorFallsBackToBundle(t *testing.T) {
	rootPEM, _, intermediate, leaf := certChain(t, "server.example.org")

	pool := buildClientCAPool(nil, errors.New("the store is sealed"), rootPEM)
	if pool == nil {
		t.Fatal("buildClientCAPool returned no pool on a system store error")
	}
	if !chainVerifies(pool, intermediate, leaf, "server.example.org") {
		t.Fatal("the bundle anchor must verify the chain despite the system store error")
	}

	// with no bundle at all the pool still builds (empty worst case, never a panic)
	if empty := buildClientCAPool(nil, errors.New("the store is sealed")); empty == nil {
		t.Fatal("buildClientCAPool returned no pool without bundles")
	}
}

// A broken bundle degrades to a warning: the unusable blocks are skipped and
// the usable ones still land.
func TestBuildClientCAPoolToleratesBrokenBundle(t *testing.T) {
	rootPEM, _, intermediate, leaf := certChain(t, "server.example.org")

	garbage := []byte("this is not a pem file at all")
	brokenCert := []byte("-----BEGIN CERTIFICATE-----\ngarbagebytes\n-----END CERTIFICATE-----\n")

	pool := buildClientCAPool(x509.NewCertPool(), nil, garbage, brokenCert, rootPEM)
	if pool == nil {
		t.Fatal("buildClientCAPool returned no pool on broken bundles")
	}
	if !chainVerifies(pool, intermediate, leaf, "server.example.org") {
		t.Fatal("the valid anchor must land despite the broken bundles")
	}
}

// A PEM block that is not a certificate (a private key riding the bundle, a
// CRL, ...) is skipped, not fatal.
func TestBuildClientCAPoolSkipsNonCertificateBlocks(t *testing.T) {
	rootPEM, _, intermediate, leaf := certChain(t, "server.example.org")

	privateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not really a key")})
	bundle := append(append([]byte{}, privateKey...), rootPEM...)

	pool := buildClientCAPool(x509.NewCertPool(), nil, bundle)
	if pool == nil {
		t.Fatal("buildClientCAPool returned no pool")
	}
	if !chainVerifies(pool, intermediate, leaf, "server.example.org") {
		t.Fatal("the certificate must land despite the non-certificate blocks")
	}
}

// The embedded public roots are a compile-time constant: one smoke-pin proves
// they parse and are the announced roots.
func TestEmbeddedRootPEMsSmokePin(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pem        []byte
		commonName string
	}{
		{"ISRG Root X1", isrgRootX1PEM, "ISRG Root X1"},
		{"ISRG Root X2", isrgRootX2PEM, "ISRG Root X2"},
	} {
		pool := x509.NewCertPool()
		if added := appendPEMToPool(pool, tc.pem, tc.name); added < 1 {
			t.Errorf("%s: the embedded PEM yielded %d certificates, want at least 1", tc.name, added)
		}
		block, _ := pem.Decode(tc.pem)
		if block == nil {
			t.Errorf("%s: the embedded PEM does not decode", tc.name)
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Errorf("%s: the embedded certificate does not parse: %s", tc.name, err)
			continue
		}
		if got := cert.Subject.CommonName; got != tc.commonName {
			t.Errorf("%s: the embedded certificate subject is %q, want %q", tc.name, got, tc.commonName)
		}
	}
}

// The user bundle path: SSH3_CA_BUNDLE overrides the default ca-bundle.pem
// next to the other client state.
func TestCABundleFilePath(t *testing.T) {
	t.Setenv("SSH3_CA_BUNDLE", "/custom/bundle.pem")
	if got := caBundleFilePath("/home/u/.ssh3"); got != "/custom/bundle.pem" {
		t.Errorf("SSH3_CA_BUNDLE override ignored: got %q, want /custom/bundle.pem", got)
	}

	t.Setenv("SSH3_CA_BUNDLE", "")
	if got := caBundleFilePath("/home/u/.ssh3"); got != path.Join("/home/u/.ssh3", "ca-bundle.pem") {
		t.Errorf("default bundle path wrong: got %q, want %q", got, path.Join("/home/u/.ssh3", "ca-bundle.pem"))
	}
}

// The production wiring: a bundle file written where loadClientCAPool looks
// for it adds its anchor to the pool.
func TestLoadClientCAPoolReadsBundleFile(t *testing.T) {
	dir := t.TempDir()
	rootPEM, _, intermediate, leaf := certChain(t, "file.example.org")
	if err := os.WriteFile(filepath.Join(dir, "ca-bundle.pem"), rootPEM, 0600); err != nil {
		t.Fatalf("could not write the bundle file: %s", err)
	}

	pool := loadClientCAPool(dir)
	if pool == nil {
		t.Fatal("loadClientCAPool returned no pool")
	}
	if !chainVerifies(pool, intermediate, leaf, "file.example.org") {
		t.Fatal("the bundle file anchor must ride the production pool")
	}
}

// A missing or garbage bundle file must not fail the pool: the embedded
// roots and the system store keep riding.
func TestLoadClientCAPoolToleratesMissingAndGarbageBundleFile(t *testing.T) {
	dir := t.TempDir()

	if pool := loadClientCAPool(dir); pool == nil {
		t.Fatal("loadClientCAPool returned no pool with no bundle file")
	}

	if err := os.WriteFile(filepath.Join(dir, "ca-bundle.pem"), []byte("garbage, no pem"), 0600); err != nil {
		t.Fatalf("could not write the garbage bundle file: %s", err)
	}
	if pool := loadClientCAPool(dir); pool == nil {
		t.Fatal("loadClientCAPool returned no pool with a garbage bundle file")
	}

	// the override path rides the same tolerance
	override := filepath.Join(t.TempDir(), "custom.pem")
	if err := os.WriteFile(override, []byte("still garbage"), 0600); err != nil {
		t.Fatalf("could not write the override bundle file: %s", err)
	}
	t.Setenv("SSH3_CA_BUNDLE", override)
	if pool := loadClientCAPool(dir); pool == nil {
		t.Fatal("loadClientCAPool returned no pool with a garbage override file")
	}
}
