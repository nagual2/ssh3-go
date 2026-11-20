package main

// The ssh3-cert dispatch tests (R14-6, the ssh3-c canon f359fc9 +
// 31d8625): the subcommands ride the ticketkey parser (the nginx form,
// the reuse of internal/ticketkey) and the trust update runner (the
// fetch fixture, zero network); the exit shapes are 0 fresh / 255
// stale / 255 for every refusal.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/francoismichel/ssh3/internal/ticketkey"
	"github.com/francoismichel/ssh3/internal/trustupdate"
)

func fixtureBundle(t *testing.T, count int) string {
	t.Helper()
	var b strings.Builder
	for i := 0; i < count; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("could not generate the key: %s", err)
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: "ssh3-cert Fixture Root"},
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
		b.WriteString(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	}
	return b.String()
}

func TestTicketKeySubcommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session-ticket.key")
	if code := run([]string{"ticket-key", path}); code != 0 {
		t.Fatalf("ticket-key refused with %d", code)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the key file did not land: %s", err)
	}
	if _, err := ticketkey.Parse(body); err != nil {
		t.Errorf("the generated key file does not ride the nginx form: %s", err)
	}
	if len(body) != ticketkey.NginxKeyLen {
		t.Errorf("the key file carries %d bytes, want the %d nginx form", len(body), ticketkey.NginxKeyLen)
	}

	// the argument shapes refuse
	if code := run([]string{"ticket-key"}); code != 255 {
		t.Errorf("the fileless ticket-key exited %d, want 255", code)
	}
	if code := run([]string{"ticket-key", "a", "b"}); code != 255 {
		t.Errorf("the two-file ticket-key exited %d, want 255", code)
	}
}

func TestTrustUpdateSubcommand(t *testing.T) {
	dir := t.TempDir()
	body := fixtureBundle(t, 2)
	opts := trustupdate.Options{
		Dir:      dir,
		MinCerts: 2,
		Fetch:    func(string) ([]byte, error) { return []byte(body), nil },
	}

	// the args ride the flags only (the dispatch strips the command word)
	if code := runTrustUpdateCmd([]string{"--trust-update-url", "https://trust.example/bundle.pem"}, opts); code != 0 {
		t.Fatalf("trust-update refused the clean body with %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "trust-bundle.pem")); err != nil {
		t.Errorf("the bundle did not land: %s", err)
	}

	// the stale body rides exit 255 and keeps the previous copy
	bad := opts
	bad.Fetch = func(string) ([]byte, error) { return []byte("-----BEGIN CERTIFICATE-----\nnot-a-cert\n"), nil }
	if code := runTrustUpdateCmd([]string{"--trust-update-url", "https://trust.example/bad.pem"}, bad); code != 255 {
		t.Errorf("the stale body exited %d, want 255", code)
	}

	// the urlless form rides the default source (the hook takes it)
	defaulted := opts
	var hooked string
	defaulted.Fetch = func(url string) ([]byte, error) { hooked = url; return []byte(body), nil }
	if code := runTrustUpdateCmd(nil, defaulted); code != 0 {
		t.Errorf("the urlless trust-update refused with %d", code)
	}
	if hooked != trustupdate.DefaultURL {
		t.Errorf("the default source rides %q, want %q", hooked, trustupdate.DefaultURL)
	}
}

func TestTrustUpdateArgumentRefusals(t *testing.T) {
	if code := runTrustUpdateCmd([]string{"--bogus"}, trustupdate.Options{Dir: t.TempDir()}); code != 255 {
		t.Errorf("the unknown flag exited %d, want 255", code)
	}
	if code := runTrustUpdateCmd([]string{"--trust-update-url"}, trustupdate.Options{Dir: t.TempDir()}); code != 255 {
		t.Errorf("the valueless url flag exited %d, want 255", code)
	}
}

func TestDispatchRefusals(t *testing.T) {
	if code := run([]string{}); code != 255 {
		t.Errorf("the empty dispatch exited %d, want 255", code)
	}
	if code := run([]string{"--help"}); code != 0 {
		t.Errorf("--help exited %d, want 0", code)
	}
	if code := run([]string{"-h"}); code != 0 {
		t.Errorf("-h exited %d, want 0", code)
	}
	if code := run([]string{"nope"}); code != 255 {
		t.Errorf("the unknown command exited %d, want 255", code)
	}
}
