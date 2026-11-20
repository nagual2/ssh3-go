package ticketkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// selfSignedCert builds an in-memory TLS certificate for the loopback server.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %s", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %s", err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
	return cert
}

// resumeDial rides one full handshake: a fresh TCP loopback pair, the server
// side armed with the given config, one app-data round trip on top (the
// round trip makes the client process the post-handshake flight — the
// NewSessionTicket lands in the client cache during it) and the client
// connection state riding back for the DidResume verdict.
func resumeDial(t *testing.T, serverCfg, clientCfg *tls.Config) tls.ConnectionState {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %s", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		conn := tls.Server(raw, serverCfg)
		if err := conn.Handshake(); err != nil {
			serverErr <- err
			return
		}
		// the echo of the probe line: the server read proves the client's
		// Finished landed, the server write flushes the ticket flight
		buf := make([]byte, 4)
		if _, err := conn.Read(buf); err != nil {
			serverErr <- err
			return
		}
		if _, err := conn.Write(buf); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %s", err)
	}
	conn := tls.Client(raw, clientCfg)
	if err := conn.Handshake(); err != nil {
		// the server verdict rides next to the client one: the alert of the
		// client alone hides the failing leg
		select {
		case serr := <-serverErr:
			t.Fatalf("client handshake: %s; server: %s", err, serr)
		case <-time.After(time.Second):
			t.Fatalf("client handshake: %s; server verdict timed out", err)
		}
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %s", err)
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("client read: %s", err)
	}
	state := conn.ConnectionState()
	conn.Close()
	if err := <-serverErr; err != nil {
		t.Fatalf("server side: %s", err)
	}
	return state
}

// newClientConfig rides the client shape of the proofs: the shared session
// cache is the disk-persisted SSL_SESSION of the C client (the fork's client
// cache outlives the dials the same way), InsecureSkipVerify stands for the
// pin verdicts the proofs do not ride.
func newClientConfig(cache tls.ClientSessionCache) *tls.Config {
	return &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		ClientSessionCache: cache,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h3"},
	}
}

// TestRestartPersistsTicket is the main proof of the wave: the tickets
// survive the restart. The server lifetime #1 arms from the key file, the
// client handshake stores the issued ticket; the "restart" is a fresh
// tls.Config armed from the same file — the second handshake resumes from
// the client cache (DidResume), which only happens when the restarted
// server decrypted the ticket of the dead lifetime.
func TestRestartPersistsTicket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	cert := selfSignedCert(t)

	// the daemon lifetime #1
	lifetime1 := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	m1 := NewManager(lifetime1, path)
	if err := m1.Arm(); err != nil {
		t.Fatalf("arm #1: %s", err)
	}

	cache := tls.NewLRUClientSessionCache(4)
	clientCfg := newClientConfig(cache)
	state1 := resumeDial(t, lifetime1, clientCfg)
	if state1.DidResume {
		t.Fatalf("the first handshake resumed: the proof needs a fresh session")
	}

	// the key file stays the one secret of both lifetimes
	body1, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the key file after lifetime #1: %s", err)
	}

	// the restart: a fresh config object (the old keys of the process are
	// gone), armed from the same file
	lifetime2 := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	m2 := NewManager(lifetime2, path)
	if err := m2.Arm(); err != nil {
		t.Fatalf("arm #2: %s", err)
	}

	body2, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the key file after the restart: %s", err)
	}
	if string(body1) != string(body2) {
		t.Fatalf("the restart regenerated the key file")
	}

	state2 := resumeDial(t, lifetime2, clientCfg)
	if !state2.DidResume {
		t.Fatalf("the restarted server went 1-RTT: the ticket of the dead lifetime did not decrypt")
	}
}

// TestRotationKeepsOldTicketsDecryptable rides the rotation contract on a
// live config: the session of the pre-rotation lifetime resumes after the
// watcher adopted the fresh key (the old key stays in the decrypt-only
// tail), and the fresh key seals the tickets of the next handshake.
func TestRotationKeepsOldTicketsDecryptable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	cert := selfSignedCert(t)

	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	m := NewManager(serverCfg, path)
	if err := m.Arm(); err != nil {
		t.Fatalf("arm: %s", err)
	}

	cache := tls.NewLRUClientSessionCache(4)
	clientCfg := newClientConfig(cache)
	state1 := resumeDial(t, serverCfg, clientCfg)
	if state1.DidResume {
		t.Fatalf("the first handshake resumed: the proof needs a fresh session")
	}

	// the operator rotates the file (fresh key, moved mtime), the poll
	// adopts it
	newBody := make([]byte, NginxKeyLen)
	if _, err := rand.Read(newBody); err != nil {
		t.Fatalf("generate the rotated body: %s", err)
	}
	if err := os.WriteFile(path, newBody, 0600); err != nil {
		t.Fatalf("write the rotated body: %s", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("move the mtime: %s", err)
	}
	m.Poll()
	if len(m.keys) != 2 || string(m.keys[0][:]) != string(newBody[48:80]) {
		t.Fatalf("the rotation did not arm the fresh key first")
	}

	// the in-flight ticket of the pre-rotation lifetime still resumes
	state2 := resumeDial(t, serverCfg, clientCfg)
	if !state2.DidResume {
		t.Fatalf("the rotated server dropped the pre-rotation ticket: the old key left the decrypt tail")
	}

	// a second client lifetime rides the fresh key: its session seals with
	// the new key and resumes after another rotation retires the first one
	if err := os.WriteFile(path, func() []byte {
		b := make([]byte, NginxKeyLen)
		if _, err := rand.Read(b); err != nil {
			t.Fatalf("generate the second body: %s", err)
		}
		return b
	}(), 0600); err != nil {
		t.Fatalf("write the second body: %s", err)
	}
	future = time.Now().Add(4 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("move the mtime again: %s", err)
	}
	m.Poll()
	state3 := resumeDial(t, serverCfg, clientCfg)
	if !state3.DidResume {
		t.Fatalf("the session sealed by the first rotation did not resume: the fresh key did not seal")
	}
}
