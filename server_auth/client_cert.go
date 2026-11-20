// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package server_auth

// The server side of the client certificates (the mTLS wave, the
// phase 3 of the ssh3-c canon e3477ef + the run-as gate fix 2706fcf):
// the --client-cert-ca file arms the policy, the auth chain runs the
// cert verdict first — the presented chain verifies against the
// anchors (the record-only shape of the C canon: a failed verification
// refuses at the ssh3 layer, the handshake itself never dies from the
// verdict), the identity maps from the leaf (the SAN URI spki: form,
// the SAN email, the CN fallback) and the mapped name rides the same
// GetUser gate the URL username does.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"os"
	"strings"
)

// the subject alt name extension (RFC 5280 4.2.1.2)
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// ClientCertConfig carries the armed client certificate policy of the
// server: the CAs anchor the presented chains (the names ride the
// CertificateRequest of the handshake), Require dies the handshake
// when the client presents none (the FAIL_IF_NO_PEER_CERT shape of the
// OpenSSL canon)
type ClientCertConfig struct {
	CAs     *x509.CertPool
	Require bool
}

// ParseClientCertPolicy parses the --client-cert value: none (the
// default, the current behavior — no CertificateRequest at all),
// optional (the presented chain verifies, the absence falls to the
// other backends) or require (the handshake dies without one; the
// wiring wants the ca file)
func ParseClientCertPolicy(value string) (require bool, err error) {
	switch value {
	case "none":
		return false, nil
	case "optional":
		return false, nil
	case "require":
		return true, nil
	default:
		return false, fmt.Errorf("--client-cert wants none|optional|require, got %q", value)
	}
}

// LoadClientCertCA reads the trusted issuers of the client chains (the
// PEM file of the ca anchors) into the verification pool
func LoadClientCertCA(path string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read the client certificate ca file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("the client certificate ca file %s carries no certificate", path)
	}
	return pool, nil
}

// ArmClientCertTLS applies the armed policy to the server TLS config.
// The verify mode mirrors the C canon (SSL_VERIFY_PEER with the
// optional FAIL_IF_NO_PEER_CERT): the certificate is requested in both
// armed modes, require kills the handshake when the client presents
// none. The chain verification itself stays record-only — the
// crypto/tls modes ride the verification in the ssh3 verdict layer
// (VerifyClientCertChain), so a presented but untrusted chain keeps
// the handshake and refuses at the auth chain instead
func ArmClientCertTLS(tlsConfig *tls.Config, cfg *ClientCertConfig) {
	if cfg == nil {
		return
	}
	tlsConfig.ClientCAs = cfg.CAs
	if cfg.Require {
		tlsConfig.ClientAuth = tls.RequireAnyClientCert
	} else {
		tlsConfig.ClientAuth = tls.RequestClientCert
	}
}

// CertIdentity maps the identity of the presented leaf (the
// s3_ssh3_auth_cert_user canon of e3477ef): the single pass over the
// raw san extension keeps the san order — the first uri of the spki:
// form or the first email wins — and the common name falls behind
// both. ok is false when the certificate carries no usable identity
func CertIdentity(cert *x509.Certificate) (string, bool) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		return certIdentityFromSAN(ext.Value, cert)
	}
	// no san extension: the common name is the last resort
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, true
	}
	return "", false
}

// certIdentityFromSAN walks the general names of the raw san value in
// the certificate order (the C mapper rides the single pass: the first
// spki: uri or the first email stops the search), the common name of
// the subject is the fallback
func certIdentityFromSAN(raw []byte, cert *x509.Certificate) (string, bool) {
	var names []asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &names); err != nil {
		// unreachable for a certificate crypto/x509 already parsed (a
		// malformed san fails the whole certificate), kept honest
		return "", false
	}
	for i := range names {
		if names[i].Class != asn1.ClassContextSpecific {
			continue
		}
		switch names[i].Tag {
		case 6: // uniformResourceIdentifier: the spki:<user> form of the ssh3 uri canon
			uri := string(names[i].Bytes)
			if strings.HasPrefix(uri, "spki:") && len(uri) > len("spki:") {
				return uri[len("spki:"):], true
			}
		case 1: // rfc822Name: the email falls behind every spki the order puts first
			if email := string(names[i].Bytes); email != "" {
				return email, true
			}
		}
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, true
	}
	return "", false
}

// VerifyClientCertChain verifies the presented client chain against
// the ca anchors (the record-only verdict of the ssh3 layer): the leaf
// is certs[0], the rest ride the intermediates pool. The key usage is
// the client auth of the canon (a certificate without the eku
// extension rides any usage, the RFC 5280 shape)
func VerifyClientCertChain(certs []*x509.Certificate, roots *x509.CertPool) error {
	if len(certs) == 0 {
		return fmt.Errorf("no client certificate presented")
	}
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if len(certs) > 1 {
		intermediates := x509.NewCertPool()
		for _, c := range certs[1:] {
			intermediates.AddCert(c)
		}
		opts.Intermediates = intermediates
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("the client certificate chain does not verify: %w", err)
	}
	return nil
}
