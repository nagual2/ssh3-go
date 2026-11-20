// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

// The client certificate pair of the mTLS wave (the phase 3, the
// ssh3-c canon e3477ef): --cert and --key ride together, the pair
// loads into the tls.Config of every dial of the process (the
// destination, the jump hops and the reconnect re-dials ride the same
// config), and the server's CertificateRequest carries it.

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// loadClientCertPair loads the client certificate pair: both flags
// ride together (one alone refuses at the wiring, the C "--cert and
// --key ride together" shape), the pair loads eagerly and the key must
// match the certificate (the SSL_CTX_check_private_key canon — the
// refusal happens here, not mid-handshake). Both paths empty rides
// nil, nil — the no-certificate behavior of the client is unchanged
func loadClientCertPair(certPath, keyPath string) (*tls.Certificate, error) {
	if certPath == "" && keyPath == "" {
		return nil, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("--cert and --key ride together")
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("the client certificate load failed: %w", err)
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("the client certificate does not parse: %w", err)
	}

	privPub, ok := cert.PrivateKey.(interface{ Public() crypto.PublicKey })
	if !ok {
		return nil, fmt.Errorf("the client key type does not expose its public key")
	}
	pubEqual, ok := privPub.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return nil, fmt.Errorf("the client key public type does not support the match check")
	}
	if !pubEqual.Equal(cert.Leaf.PublicKey) {
		return nil, fmt.Errorf("the client certificate and the key do not match")
	}

	return &cert, nil
}
