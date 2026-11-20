package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// The full-chain contract of the server (the C canon 14165c2, the v0.5.14
// ssl fix): the server presents the leaf AND the intermediates in the
// handshake — a client whose trust pool holds only the root anchor builds
// the path from the served intermediates, because a client without AIA
// cannot chase a missing intermediate on its own. The leaf-only side is
// unverifiable for such a client (the live LE deployment finding). The
// Go server rides tls.LoadX509KeyPair, which carries every PEM block of
// the certificate file as the chain behind the leaf — the test pins the
// handshake contract against the regression.

// mintTestChain mints root -> intermediate -> leaf and returns the full
// chain PEM (the leaf first, like a fullchain file), the leaf-only PEM,
// the leaf key PEM and the root certificate.
func mintTestChain(t *testing.T) (fullchainPEM, leafOnlyPEM, keyPEM []byte, root *x509.Certificate) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the root key: %s", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ssh3 fullchain test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("could not mint the root: %s", err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("could not parse the root: %s", err)
	}

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the intermediate key: %s", err)
	}
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ssh3 fullchain test intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("could not mint the intermediate: %s", err)
	}
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("could not parse the intermediate: %s", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the leaf key: %s", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "ssh3 fullchain test leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, inter, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("could not mint the leaf: %s", err)
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	fullchainPEM = append(leafPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})...)
	leafOnlyPEM = leafPEM
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("could not marshal the leaf key: %s", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return fullchainPEM, leafOnlyPEM, keyPEM, root
}

// dialTestTLS runs the client handshake against the loopback listener with
// a trust pool holding the root anchor alone — no intermediate anywhere in
// the client state, so only the served chain can complete the path. After
// the handshake the probe rides the wire, so the server goroutine finishes
// its own handshake before the client closes.
func dialTestTLS(t *testing.T, addr string, root *x509.Certificate) (*tls.ConnectionState, error) {
	t.Helper()

	pool := x509.NewCertPool()
	pool.AddCert(root)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("could not dial the listener: %s", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	client := tls.Client(conn, &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
	})
	if err := client.Handshake(); err != nil {
		return nil, err
	}
	if _, err := client.Write([]byte("ssh3-fullchain-probe")); err != nil {
		return nil, err
	}
	state := client.ConnectionState()
	return &state, nil
}

func TestFullChainHandshakeBuildsPathFromServedIntermediates(t *testing.T) {
	fullchainPEM, _, keyPEM, root := mintTestChain(t)

	pair, err := tls.X509KeyPair(fullchainPEM, keyPEM)
	if err != nil {
		t.Fatalf("the fullchain pair did not load: %s", err)
	}
	// the load carries the whole chain: the leaf first, the intermediate
	// behind it (the shape tls.LoadX509KeyPair hands the ssh3-server)
	if len(pair.Certificate) != 2 {
		t.Fatalf("the fullchain load kept %d certificates, want the leaf plus the intermediate", len(pair.Certificate))
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatalf("could not listen: %s", err)
	}
	defer listener.Close()

	served := make(chan int, 1)
	servedErr := make(chan error, 1)
	go func() {
		serverConn, err := listener.Accept()
		if err != nil {
			served <- 0
			servedErr <- err
			return
		}
		defer serverConn.Close()
		serverConn.SetDeadline(time.Now().Add(5 * time.Second))
		tlsConn := serverConn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			served <- 0
			servedErr <- err
			return
		}
		// the probe of the client rides after its handshake: the server side
		// completed too
		probe := make([]byte, len("ssh3-fullchain-probe"))
		if _, err := io.ReadFull(tlsConn, probe); err != nil {
			served <- 0
			servedErr <- err
			return
		}
		servedErr <- nil
		served <- 1
	}()

	state, err := dialTestTLS(t, listener.Addr().String(), root)
	if err != nil {
		t.Fatalf("the handshake failed with the full chain served: %s", err)
	}
	// the path built from the served intermediates: the client state holds
	// the leaf plus the intermediate the server presented
	if len(state.PeerCertificates) != 2 {
		t.Errorf("the client saw %d peer certificates, want the leaf plus the served intermediate", len(state.PeerCertificates))
	}
	if state.VerifiedChains == nil || len(state.VerifiedChains) == 0 {
		t.Error("the handshake verified no chain: the path did not build to the root anchor")
	}
	if n := <-served; n == 0 {
		t.Errorf("the server side of the handshake failed: %v", <-servedErr)
	}
}

func TestLeafOnlySideStaysUnverifiableWithoutAIA(t *testing.T) {
	_, leafOnlyPEM, keyPEM, root := mintTestChain(t)

	pair, err := tls.X509KeyPair(leafOnlyPEM, keyPEM)
	if err != nil {
		t.Fatalf("the leaf-only pair did not load: %s", err)
	}
	if len(pair.Certificate) != 1 {
		t.Fatalf("the leaf-only load kept %d certificates, want 1", len(pair.Certificate))
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatalf("could not listen: %s", err)
	}
	defer listener.Close()

	go func() {
		serverConn, err := listener.Accept()
		if err != nil {
			return
		}
		serverConn.SetDeadline(time.Now().Add(5 * time.Second))
		_ = serverConn.(*tls.Conn).Handshake()
		serverConn.Close()
	}()

	if _, err := dialTestTLS(t, listener.Addr().String(), root); err == nil {
		t.Error("the leaf-only handshake verified with a root-only client: the regression the C canon 14165c2 fixed would ride")
	}
}
