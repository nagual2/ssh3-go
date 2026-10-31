package ssh3

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/francoismichel/ssh3/util"
)

// greaseSelfSignedCert builds an in-memory TLS certificate for the loopback server.
func greaseSelfSignedCert(t *testing.T) tls.Certificate {
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
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create self-signed certificate: %s", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startGreaseTestServer runs the production accept loop (ServeQUICConn over
// NewRawServerConn) on a loopback UDP transport, so grease uni streams are
// classified by exactly the code path a real deployment uses.
func startGreaseTestServer(t *testing.T) (*net.UDPAddr, func()) {
	t.Helper()
	h3srv := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}),
	}
	h3srv.ConnContext = func(ctx context.Context, c *quic.Conn) context.Context {
		return context.WithValue(ctx, quicConnContextKey{}, c)
	}
	ssh3srv := NewServer(30000, 10, h3srv, func(authenticatedUsername string, conv *Conversation) error {
		return nil
	})
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %s", err)
	}
	trans := &quic.Transport{Conn: udp}
	ln, err := trans.Listen(&tls.Config{
		Certificates: []tls.Certificate{greaseSelfSignedCert(t)},
		NextProtos:   []string{"h3"},
	}, nil)
	if err != nil {
		udp.Close()
		t.Fatalf("QUIC listen: %s", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			qconn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			hconn, err := h3srv.NewRawServerConn(qconn)
			if err != nil {
				_ = qconn.CloseWithError(quic.ApplicationErrorCode(0), "internal error")
				continue
			}
			go func() {
				_ = ssh3srv.ServeQUICConn(ctx, qconn, hconn)
			}()
		}
	}()
	cleanup := func() {
		cancel()
		_ = ln.Close()
		_ = trans.Close()
		_ = udp.Close()
	}
	return udp.LocalAddr().(*net.UDPAddr), cleanup
}

// dialGreaseTestClient dials the server and drives the client-side HTTP/3
// accept loops on a RawClientConn, mirroring what the http3.Transport does
// internally while still letting the test open raw streams.
func dialGreaseTestClient(t *testing.T, addr *net.UDPAddr) (*quic.Conn, *http3.RawClientConn, func()) {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client UDP: %s", err)
	}
	ctrans := &quic.Transport{Conn: udp}
	ctx, cancel := context.WithCancel(context.Background())
	qconn, err := ctrans.Dial(ctx, addr, &tls.Config{NextProtos: []string{"h3"}, InsecureSkipVerify: true}, nil)
	if err != nil {
		cancel()
		udp.Close()
		t.Fatalf("QUIC dial: %s", err)
	}
	rconn := (&http3.Transport{}).NewRawClientConn(qconn)
	go func() {
		for {
			str, err := qconn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			go rconn.HandleUnidirectionalStream(str)
		}
	}()
	cleanup := func() {
		cancel()
		_ = qconn.CloseWithError(quic.ApplicationErrorCode(0), "test done")
		_ = ctrans.Close()
		_ = udp.Close()
	}
	return qconn, rconn, cleanup
}

// sendGreaseUniStream opens a reserved (grease) unidirectional stream of the
// given type and sends an arbitrary payload. RFC 9114 §6.2.3: reserved stream
// types are 0x1f * N + 0x21 (N=0 → 0x21, N=1 → 0x40); "these streams have no
// semantics".
func sendGreaseUniStream(t *testing.T, qconn *quic.Conn, streamType uint64) {
	t.Helper()
	str, err := qconn.OpenUniStreamSync(context.Background())
	if err != nil {
		t.Fatalf("open grease uni stream (type 0x%x): %s", streamType, err)
	}
	payload := append(util.AppendVarInt(nil, streamType), []byte("grease: this stream has no semantics (RFC 9114 6.2.3)")...)
	if _, err := str.Write(payload); err != nil {
		t.Fatalf("write grease uni stream (type 0x%x): %s", streamType, err)
	}
	if err := str.Close(); err != nil {
		t.Fatalf("close grease uni stream (type 0x%x): %s", streamType, err)
	}
}

// greaseRoundTrip issues a GET over the live HTTP/3 connection and checks the
// request path still answers 200 "ok".
func greaseRoundTrip(t *testing.T, rconn *http3.RawClientConn) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://localhost/", http.NoBody)
	if err != nil {
		t.Fatalf("build request: %s", err)
	}
	resp, err := rconn.RoundTrip(req)
	if err != nil {
		t.Fatalf("GET over the live connection failed (connection was torn down): %s", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET returned %d, want 200", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Fatalf("GET returned %q, want %q", body, "ok")
	}
}

// greasePhase runs one connection phase: grease uni stream over the live
// session (after the client's control stream is served), then the request
// path must keep answering, and the connection must not be torn down.
//
// The SSH3 protocol spends the connection's single HTTP/3 request stream on
// its CONNECT, so each connection carries exactly one plain GET here; a new
// connection to the same server proves the server as a whole keeps serving.
func greasePhase(t *testing.T, addr *net.UDPAddr, streamType uint64) {
	t.Helper()
	qconn, rconn, stopClient := dialGreaseTestClient(t, addr)
	defer stopClient()
	sendGreaseUniStream(t, qconn, streamType)
	time.Sleep(500 * time.Millisecond) // let a misbehaving peer's CONNECTION_CLOSE arrive
	greaseRoundTrip(t, rconn)
	if err := qconn.Context().Err(); err != nil {
		t.Fatalf("QUIC connection torn down after grease uni stream 0x%x: %s", streamType, err)
	}
}

// R12 / RFC 9114 §6.2 + §6.2.3 regression lock: a peer's reserved (grease)
// unidirectional stream MUST NOT be treated as a connection error of any kind
// — the recipient aborts reading the stream (SHOULD: H3_STREAM_CREATION_ERROR)
// and the connection, its control streams and request streams keep being
// served afterwards. This pins the quic-go http3 behavior the fork relies on:
// upstream changed the unknown-uni handling between versions, and the live
// interop case (rust client v0.2.4 opening grease against ssh3-c 0.5.4) showed
// a server tearing the connection down here is a real-world failure mode.
func TestReservedUniStreamDoesNotTearDownConnection(t *testing.T) {
	addr, stopServer := startGreaseTestServer(t)
	defer stopServer()

	// reserved stream type N=0 (0x21) over a live session
	greasePhase(t, addr, 0x21)

	// reserved stream type N=1 (0x40) on a fresh connection to the same server
	greasePhase(t, addr, 0x1f*1+0x21)
}
