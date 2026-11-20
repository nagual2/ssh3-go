package trustupdate

// The trust update tests (R14-6, the ssh3-c canon s3_trust_update_run,
// commit 31d8625): the fetched bundle body validates (every PEM block a
// certificate, the count floor), the landing is atomic (tmp+rename,
// 0600) into the state dir as trust-bundle.pem and the manifest next to
// it names the source and the sha256; any failure keeps the previous
// copy (the offline scheduler run is the plain shape). The fetch hook
// carries the fixture — zero network in the units.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeCertPEM mints a self-signed certificate and returns its PEM body.
func makeCertPEM(t *testing.T, cn string) string {
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
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func bundleFixture(t *testing.T, count int) string {
	t.Helper()
	var b strings.Builder
	for i := 0; i < count; i++ {
		b.WriteString(makeCertPEM(t, fmt.Sprintf("Fixture Root %d", i)))
	}
	return b.String()
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read %s: %s", path, err)
	}
	return string(body)
}

func TestRunLandsBundleAndManifest(t *testing.T) {
	dir := t.TempDir()
	body := bundleFixture(t, 2)

	landed, err := Run(Options{
		URL:      "https://trust.example/bundle.pem",
		Dir:      dir,
		MinCerts: 2,
		Fetch:    func(string) ([]byte, error) { return []byte(body), nil },
	})
	if err != nil {
		t.Fatalf("the run refused the clean body: %s", err)
	}
	if landed != BundlePath(dir) {
		t.Errorf("the run landed at %s, want %s", landed, BundlePath(dir))
	}

	bundle := readFile(t, landed)
	if !strings.HasPrefix(bundle, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("the bundle does not ride the PEM form: %.40s", bundle)
	}

	// the manifest names the source and the sha256 of the body
	manifest := readFile(t, landed+".man")
	lines := strings.Split(manifest, "\n")
	if len(lines) != 3 || lines[2] != "" {
		t.Errorf("the manifest does not ride the two lines: %q", manifest)
	}
	if lines[0] != "https://trust.example/bundle.pem" {
		t.Errorf("the manifest does not name the source: %q", lines[0])
	}
	sum := sha256.Sum256([]byte(body))
	if lines[1] != hex.EncodeToString(sum[:]) {
		t.Errorf("the manifest sha256 does not match the body: %q", lines[1])
	}
}

func TestRunKeepsPreviousCopyOnAnyFailure(t *testing.T) {
	dir := t.TempDir()
	good := bundleFixture(t, 2)
	fetchBody := good
	fetch := func(string) ([]byte, error) { return []byte(fetchBody), nil }

	if _, err := Run(Options{URL: "https://trust.example/first.pem", Dir: dir, MinCerts: 2, Fetch: fetch}); err != nil {
		t.Fatalf("the first run refused the clean body: %s", err)
	}
	bundlePath := BundlePath(dir)
	landed := readFile(t, bundlePath)
	manifest := readFile(t, bundlePath+".man")

	// the truncated PEM block never lands: the store copy stays
	fetchBody = "-----BEGIN CERTIFICATE-----\nnot-a-cert\n"
	if _, err := Run(Options{URL: "https://trust.example/bad.pem", Dir: dir, MinCerts: 2, Fetch: fetch}); err == nil {
		t.Fatal("the broken body rode past the validation walk")
	}
	if got := readFile(t, bundlePath); got != landed {
		t.Error("the broken body replaced the landed copy")
	}
	if got := readFile(t, bundlePath+".man"); got != manifest {
		t.Error("the broken body replaced the manifest")
	}

	// the fetch failure keeps the copy too (the offline scheduler run)
	fetchBody = good
	failing := func(string) ([]byte, error) { return nil, fmt.Errorf("the network is down") }
	if _, err := Run(Options{URL: "https://trust.example/offline.pem", Dir: dir, MinCerts: 2, Fetch: failing}); err == nil {
		t.Fatal("the failed fetch rode past")
	}
	if got := readFile(t, bundlePath); got != landed {
		t.Error("the failed fetch replaced the landed copy")
	}
}

func TestRunRefusesBelowCertFloor(t *testing.T) {
	dir := t.TempDir()
	single := makeCertPEM(t, "Lonely Root")
	fetch := func(string) ([]byte, error) { return []byte(single), nil }

	if _, err := Run(Options{URL: "https://trust.example/one.pem", Dir: dir, Fetch: fetch}); err == nil {
		t.Error("the single-cert body rode past the product floor of 30")
	}
	if _, err := Run(Options{URL: "https://trust.example/one.pem", Dir: dir, MinCerts: 1, Fetch: fetch}); err != nil {
		t.Errorf("the floor hook did not lower the floor: %s", err)
	}
}

func TestRunRefusesBodyOverTheCap(t *testing.T) {
	dir := t.TempDir()
	huge := strings.Repeat("x", BodyMax+1)
	fetch := func(string) ([]byte, error) { return []byte(huge), nil }
	if _, err := Run(Options{URL: "https://trust.example/huge.pem", Dir: dir, Fetch: fetch}); err == nil {
		t.Error("the oversized body rode past the cap")
	}
}

func TestRunCreatesFreshStateDir(t *testing.T) {
	// the fresh home rides the scheduler before any state exists: the
	// two levels go one by one (the canon of the aia cache)
	dir := filepath.Join(t.TempDir(), "home", ".ssh3")
	body := bundleFixture(t, 2)

	landed, err := Run(Options{
		URL:      "https://trust.example/bundle.pem",
		Dir:      dir,
		MinCerts: 2,
		Fetch:    func(string) ([]byte, error) { return []byte(body), nil },
	})
	if err != nil {
		t.Fatalf("the run refused the fresh home: %s", err)
	}
	if _, err := os.Stat(landed); err != nil {
		t.Errorf("the bundle did not land in the created dir: %s", err)
	}
}

func TestRunRefusesPlainHTTPOverTheTransport(t *testing.T) {
	dir := t.TempDir()
	// the neutral https infra: the default transport refuses the plain
	// scheme; the hook (the tests) carries its own trust
	if _, err := Run(Options{URL: "http://trust.example/bundle.pem", Dir: dir}); err == nil {
		t.Error("the plain-http source rode the https transport")
	}
}

func TestBundlePathRidesTheStateDir(t *testing.T) {
	if got, want := BundlePath("/home/u/.ssh3"), filepath.Join("/home/u/.ssh3", "trust-bundle.pem"); got != want {
		t.Errorf("BundlePath rides %q, want %q", got, want)
	}
}
