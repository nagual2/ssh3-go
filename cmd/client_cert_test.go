// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

// The client certificate pair of the mTLS wave (the phase 3, the
// ssh3-c canon e3477ef): --cert and --key ride together (one alone
// refuses at the wiring, the C "--cert and --key ride together"
// shape), a broken or missing pair refuses before any dial, and a
// mismatched key refuses eagerly (the SSL_CTX_check_private_key canon
// — the refusal happens at the wiring, not mid-handshake).

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestPair mints a throwaway leaf pair into dir, returns the paths
func writeTestPair(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the key: %s", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("could not create the certificate: %s", err)
	}

	certPath = filepath.Join(dir, name+".pem")
	keyPath = filepath.Join(dir, name+".key")

	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatalf("could not write the certificate: %s", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("could not marshal the key: %s", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatalf("could not write the key: %s", err)
	}

	return certPath, keyPath
}

func TestLoadClientCertPair(t *testing.T) {
	dir := t.TempDir()

	// the current behavior: no flags, no certificate
	cert, err := loadClientCertPair("", "")
	if cert != nil || err != nil {
		t.Fatalf("the empty flags must ride nil, got (%v, %v)", cert, err)
	}

	// the pair rides together: one alone refuses
	certPath, keyPath := writeTestPair(t, dir, "alice")
	if _, err := loadClientCertPair(certPath, ""); err == nil {
		t.Error("--cert alone must refuse")
	}
	if _, err := loadClientCertPair("", keyPath); err == nil {
		t.Error("--key alone must refuse")
	}

	// the valid pair loads, the leaf rides parsed
	loaded, err := loadClientCertPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("the valid pair refused: %s", err)
	}
	if loaded == nil || loaded.Leaf == nil {
		t.Fatal("the valid pair must carry the parsed leaf")
	}

	// the missing file refuses at the wiring
	if _, err := loadClientCertPair(filepath.Join(dir, "missing.pem"), keyPath); err == nil {
		t.Error("the missing certificate must refuse")
	}

	// the mismatched key refuses eagerly (the check_private_key canon)
	_, otherKey := writeTestPair(t, dir, "bob")
	if _, err := loadClientCertPair(certPath, otherKey); err == nil {
		t.Error("the mismatched key must refuse")
	}
}
