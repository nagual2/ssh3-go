// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package server_auth

// The client certificate pieces of the server (the phase 3 of the
// mTLS wave, the ssh3-c canon e3477ef + the run-as fix 2706fcf): the
// policy parse (none|optional|require), the TLS arming, the identity
// mapping of the leaf (the SAN URI spki: form, the SAN email, the CN
// fallback — the single pass of the C mapper, the SAN order decides)
// and the chain verification against the CA anchors (the record-only
// shape: the ssh3 layer refuses, the handshake never dies from the
// verdict).

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// genTestCA mints a throwaway CA root for the leg
func genTestCA(t *testing.T, name string) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the ca key: %s", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("could not create the ca certificate: %s", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("could not parse the ca certificate: %s", err)
	}

	return cert, priv
}

// genTestLeaf mints a leaf under the ca with the given identity fields
// (the empty strings leave the field out, the ssh3-c e2e shape)
func genTestLeaf(t *testing.T, caCert *x509.Certificate, caKey ed25519.PrivateKey, uri, email, cn string) *x509.Certificate {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the leaf key: %s", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	if uri != "" {
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatalf("could not parse the san uri %s: %s", uri, err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	if email != "" {
		tmpl.EmailAddresses = []string{email}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	if err != nil {
		t.Fatalf("could not create the leaf certificate: %s", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("could not parse the leaf certificate: %s", err)
	}

	_ = priv
	return cert
}

func TestParseClientCertPolicy(t *testing.T) {
	cases := []struct {
		value   string
		require bool
		wantErr bool
	}{
		{"none", false, false},
		{"optional", false, false},
		{"require", true, false},
		{"", false, true},
		{"mandatory", false, true},
		{"REQUIRED", false, true},
	}

	for _, c := range cases {
		require, err := ParseClientCertPolicy(c.value)
		if c.wantErr {
			if err == nil {
				t.Errorf("policy %q must refuse", c.value)
			}
			continue
		}
		if err != nil {
			t.Errorf("policy %q refused: %s", c.value, err)
			continue
		}
		if require != c.require {
			t.Errorf("policy %q: require = %v, want %v", c.value, require, c.require)
		}
	}
}

func TestLoadClientCertCA(t *testing.T) {
	caCert, _ := genTestCA(t, "client-cert-ca-e2e")
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatalf("could not write the ca file: %s", err)
	}

	pool, err := LoadClientCertCA(caPath)
	if err != nil {
		t.Fatalf("the ca load failed: %s", err)
	}
	if pool == nil {
		t.Fatal("the ca load returned no pool")
	}

	if _, err := LoadClientCertCA(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("the missing ca file must refuse")
	}

	broken := filepath.Join(t.TempDir(), "broken.pem")
	if err := os.WriteFile(broken, []byte("not a certificate"), 0600); err != nil {
		t.Fatalf("could not write the broken ca file: %s", err)
	}
	if _, err := LoadClientCertCA(broken); err == nil {
		t.Error("the broken ca file must refuse")
	}
}

func TestArmClientCertTLS(t *testing.T) {
	caCert, _ := genTestCA(t, "client-cert-arm-e2e")
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// the none policy arms nothing: the current behavior (no
	// CertificateRequest at all)
	plain := &tls.Config{}
	ArmClientCertTLS(plain, nil)
	if plain.ClientAuth != tls.NoClientCert || plain.ClientCAs != nil {
		t.Error("the unarmed config must stay NoClientCert without ClientCAs")
	}

	// the optional policy requests the certificate, the absence keeps
	// the handshake (the fall to the other backends)
	optional := &tls.Config{}
	ArmClientCertTLS(optional, &ClientCertConfig{CAs: pool, Require: false})
	if optional.ClientAuth != tls.RequestClientCert {
		t.Errorf("the optional policy arms RequestClientCert, got %v", optional.ClientAuth)
	}
	if optional.ClientCAs != pool {
		t.Error("the optional policy carries the ca names of the request")
	}

	// the require policy dies the handshake without a presented
	// certificate (the FAIL_IF_NO_PEER_CERT shape of the C canon)
	require := &tls.Config{}
	ArmClientCertTLS(require, &ClientCertConfig{CAs: pool, Require: true})
	if require.ClientAuth != tls.RequireAnyClientCert {
		t.Errorf("the require policy arms RequireAnyClientCert, got %v", require.ClientAuth)
	}
	if require.ClientCAs != pool {
		t.Error("the require policy carries the ca names of the request")
	}
}

func TestCertIdentity(t *testing.T) {
	caCert, caKey := genTestCA(t, "client-cert-id-e2e")

	cases := []struct {
		name  string
		uri   string
		email string
		cn    string
		want  string
		ok    bool
	}{
		// the ssh3-c e2e mapping legs: spki, email, cn
		{"spki wins", "spki:alice", "", "ignored-cn", "alice", true},
		{"email rides", "", "bob@example.com", "ignored-cn", "bob@example.com", true},
		{"cn last resort", "", "", "carol", "carol", true},
		// the san order decides (the single pass of the C mapper): the
		// go marshaler always puts the emails ahead of the uris in the
		// der, so a both-fields cert rides the email here — the raw
		// order legs live in TestCertIdentitySanOrder
		{"email and spki: the email rides the der order", "", "bob@example.com", "cn", "bob@example.com", true},
		// the non-spki uri is not an identity
		{"plain uri ignored", "https://example.org", "", "dan", "dan", true},
		// nothing usable: no identity, the verdict refuses
		{"no identity", "https://example.org", "", "", "", false},
	}

	for _, c := range cases {
		cert := genTestLeaf(t, caCert, caKey, c.uri, c.email, c.cn)
		got, ok := CertIdentity(cert)
		if ok != c.ok {
			t.Errorf("%s: ok = %v, want %v", c.name, ok, c.ok)
			continue
		}
		if got != c.want {
			t.Errorf("%s: identity = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestCertIdentitySanOrder rides hand-built raw san extensions: the
// go marshaler fixes the email-ahead-of-uri der order, so the san
// order legs of the C single pass (the first spki: uri or the first
// email wins) ride their own der here
func TestCertIdentitySanOrder(t *testing.T) {
	caCert, caKey := genTestCA(t, "client-cert-san-order-e2e")

	sanValue := func(names ...asn1.RawValue) []byte {
		der, err := asn1.Marshal(names)
		if err != nil {
			t.Fatalf("could not marshal the san: %s", err)
		}
		return der
	}

	sanExt := func(value []byte) []pkix.Extension {
		return []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: value}}
	}

	genRawLeaf := func(exts []pkix.Extension) *x509.Certificate {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("could not generate the leaf key: %s", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:    big.NewInt(time.Now().UnixNano()),
			Subject:         pkix.Name{CommonName: "raw-cn"},
			NotBefore:       time.Now().Add(-time.Hour),
			NotAfter:        time.Now().Add(24 * time.Hour),
			KeyUsage:        x509.KeyUsageDigitalSignature,
			ExtraExtensions: exts,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
		if err != nil {
			t.Fatalf("could not create the leaf: %s", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("could not parse the leaf: %s", err)
		}
		_ = priv
		return cert
	}

	uri := func(v string) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(v)}
	}
	email := func(v string) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte(v)}
	}

	// the spki uri ahead of the email in the san order: the spki wins
	uriFirst := genRawLeaf(sanExt(sanValue(uri("spki:alice"), email("bob@example.com"))))
	if got, ok := CertIdentity(uriFirst); !ok || got != "alice" {
		t.Errorf("the spki-first san: identity = %q, %v, want alice", got, ok)
	}

	// the email ahead of the spki uri: the email wins (the first match
	// of the C single pass stops the search)
	emailFirst := genRawLeaf(sanExt(sanValue(email("bob@example.com"), uri("spki:alice"))))
	if got, ok := CertIdentity(emailFirst); !ok || got != "bob@example.com" {
		t.Errorf("the email-first san: identity = %q, %v, want bob@example.com", got, ok)
	}

	// the case-sensitive prefix of the C canon: SPKI: is not spki:
	upper := genRawLeaf(sanExt(sanValue(uri("SPKI:alice"))))
	if got, ok := CertIdentity(upper); !ok || got != "raw-cn" {
		t.Errorf("the uppercase scheme falls to the cn: identity = %q, %v, want raw-cn", got, ok)
	}

	// the bare spki: (nothing behind the colon) is no identity
	bare := genRawLeaf(sanExt(sanValue(uri("spki:"))))
	if got, ok := CertIdentity(bare); !ok || got != "raw-cn" {
		t.Errorf("the bare spki: falls to the cn: identity = %q, %v, want raw-cn", got, ok)
	}
}

func TestVerifyClientCertChain(t *testing.T) {
	caCert, caKey := genTestCA(t, "client-cert-chain-e2e")
	foreignCert, foreignKey := genTestCA(t, "client-cert-foreign-e2e")

	leaf := genTestLeaf(t, caCert, caKey, "spki:alice", "", "")
	foreignLeaf := genTestLeaf(t, foreignCert, foreignKey, "spki:alice", "", "")
	foreignSelf, _ := genTestCA(t, "self-signed-leaf")

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// the ca-signed leaf rides clean
	if err := VerifyClientCertChain([]*x509.Certificate{leaf}, pool); err != nil {
		t.Errorf("the ca-signed leaf must verify: %s", err)
	}

	// the foreign-issued leaf refuses (the unknown issuer)
	if err := VerifyClientCertChain([]*x509.Certificate{foreignLeaf}, pool); err == nil {
		t.Error("the foreign-issued leaf must refuse")
	}

	// the self-signed leaf refuses (the e2e leg 3 shape of the C canon)
	if err := VerifyClientCertChain([]*x509.Certificate{foreignSelf}, pool); err == nil {
		t.Error("the self-signed leaf must refuse")
	}

	// no anchors: nothing verifies
	if err := VerifyClientCertChain([]*x509.Certificate{leaf}, x509.NewCertPool()); err == nil {
		t.Error("the leaf must refuse without the anchors")
	}
}
