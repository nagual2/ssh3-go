package cmd

// Tests of the AIA chasing (ROADMAP.md R7-T2, CERT-VERIFICATION-CANON.md 2.6):
// the missing intermediate certificates of a presented chain are fetched
// through the caIssuers URLs, cached on disk and gated — fetched material
// completes a chain to an anchor of the pool or is dropped, it never anchors
// itself. The chains are generated here; the caIssuers traffic rides a local
// httptest server with a request counter (no external network). The fetch
// policy of the pass 5 review (the C s3_ssh3_aia_url_admissible canon) rides
// its own unit tests on the pure function; the loopback test servers pass
// through the corporate-PKI valve the policy provides.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// aiaFixture generates the anchor root, levels intermediates and a leaf
// covering dnsName. With urls, every certificate below the root carries the
// caIssuers URL of its issuer (/aia/<n>: 0 is the root, n>0 the
// intermediates counted from the root); the fixture server answers the issuer
// certificates (DER, or PEM when pemBody) and counts the requests. rogueRoot,
// when set, is served at the leaf's caIssuers URL instead of the real
// intermediate (the machine-in-the-middle substitution of the plain-http
// answer the chase fetches).
type aiaFixture struct {
	root          *x509.Certificate
	anchors       *x509.CertPool
	leaf          *x509.Certificate
	intermediates []*x509.Certificate // intermediates[0] rides next to the root
	server        *httptest.Server
	requests      *atomic.Int64
	closed        bool
	delay         time.Duration // every served request stalls this long
	oversize      bool          // the server answers a body over the size cap
	pemBody       bool          // the server answers PEM instead of DER
}

func newAIAFixture(t *testing.T, dnsName string, levels int, urls, pemBody bool, rogueRoot *x509.Certificate) *aiaFixture {
	t.Helper()

	// the test caIssuers server rides the loopback — the corporate-PKI valve
	// admits it, exactly the shape the SSH3_AIA_ALLOW_PRIVATE env exists for
	// (the pure-function policy tests below ride without the valve)
	t.Setenv("SSH3_AIA_ALLOW_PRIVATE", "1")

	fx := &aiaFixture{pemBody: pemBody}
	var requests atomic.Int64
	fx.requests = &requests
	payloads := make(map[string][]byte)
	fx.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if fx.delay > 0 {
			time.Sleep(fx.delay)
		}
		if fx.oversize {
			w.Write(make([]byte, maxAIAFetchBytes+1))
			return
		}
		payload, ok := payloads[path.Base(r.URL.Path)]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if fx.pemBody {
			w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: payload}))
			return
		}
		w.Write(payload)
	}))
	t.Cleanup(fx.shutdown)

	issuerURL := func(level int) []string {
		if !urls {
			return nil
		}
		return []string{fx.server.URL + fmt.Sprintf("/aia/%d", level)}
	}

	// the root (URL level 0 of the scheme)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the root key: %s", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "aia test root"},
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
	fx.root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("could not parse the root: %s", err)
	}
	payloads["0"] = fx.root.Raw

	// the intermediates: intermediates[i] is signed by the root (i == 0) or by
	// intermediates[i-1], and announces its issuer's URL (URL level i)
	inters := make([]*x509.Certificate, levels)
	parent, parentKey := fx.root, rootKey
	for i := 0; i < levels; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("could not generate the intermediate %d key: %s", i, err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 2)),
			Subject:               pkix.Name{CommonName: fmt.Sprintf("aia test intermediate %d", i)},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IssuingCertificateURL: issuerURL(i),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatalf("could not create the intermediate %d: %s", i, err)
		}
		inters[i], err = x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("could not parse the intermediate %d: %s", i, err)
		}
		payloads[fmt.Sprintf("%d", i+1)] = der
		parent, parentKey = inters[i], key
	}
	fx.intermediates = inters

	// the leaf, signed by the deepest intermediate (or by the root directly)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the leaf key: %s", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(levels + 2)),
		Subject:               pkix.Name{CommonName: dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{dnsName},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IssuingCertificateURL: issuerURL(levels),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, parent, &leafKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("could not create the leaf: %s", err)
	}
	fx.leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("could not parse the leaf: %s", err)
	}

	fx.anchors = x509.NewCertPool()
	fx.anchors.AddCert(fx.root)

	if rogueRoot != nil {
		// the machine-in-the-middle substitution: the leaf's caIssuers URL
		// serves the attacker's certificate
		payloads[fmt.Sprintf("%d", levels)] = rogueRoot.Raw
	}
	return fx
}

// shutdown closes the fixture server (the offline tests); the cleanup keeps
// it idempotent.
func (fx *aiaFixture) shutdown() {
	if !fx.closed {
		fx.closed = true
		fx.server.Close()
	}
}

// aiaAttackerChain generates what a machine-in-the-middle would present: a
// self-signed CA under a fresh key and a leaf for dnsName signed by it (the
// chain reaches no anchor of the client pool).
func aiaAttackerChain(t *testing.T, dnsName string) (root, leaf *x509.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the attacker root key: %s", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(900),
		Subject:               pkix.Name{CommonName: "attacker root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("could not create the attacker root: %s", err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("could not parse the attacker root: %s", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the attacker leaf key: %s", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(901),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{dnsName},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("could not create the attacker leaf: %s", err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("could not parse the attacker leaf: %s", err)
	}
	return root, leaf
}

// The key case of the truncated-store problem: the server presents the leaf
// alone, the pool holds the root — the chase fetches the missing intermediate
// and the completed chain verifies (hostname included).
func TestAIAChaseFetchesMissingIntermediate(t *testing.T) {
	fx := newAIAFixture(t, "chase.example.org", 1, true, false, nil)
	if err := aiaVerifyPresentedChain([]*x509.Certificate{fx.leaf}, nil, fx.anchors, "chase.example.org"); err == nil {
		t.Fatal("the leaf must not verify while the intermediate is missing")
	}

	fetched := aiaCompleteChain(context.Background(), []*x509.Certificate{fx.leaf}, fx.anchors, t.TempDir(), "chase.example.org")
	if len(fetched) != 1 {
		t.Fatalf("the chase fetched %d certificates, want 1", len(fetched))
	}
	if !fetched[0].Equal(fx.intermediates[0]) {
		t.Fatal("the chase fetched the wrong certificate")
	}
	if got := fx.requests.Load(); got != 1 {
		t.Fatalf("the chase made %d HTTP requests, want 1", got)
	}
	if err := aiaVerifyPresentedChain([]*x509.Certificate{fx.leaf}, fetched, fx.anchors, "chase.example.org"); err != nil {
		t.Fatalf("the completed chain must verify: %s", err)
	}
}

// caIssuers answers ride both encodings: DER (RFC 5280 4.2.2.1) and the PEM
// form the servers in the wild serve.
func TestAIAChaseAcceptsPEMResponses(t *testing.T) {
	fx := newAIAFixture(t, "pem.example.org", 1, true, true, nil)
	fetched := aiaCompleteChain(context.Background(), []*x509.Certificate{fx.leaf}, fx.anchors, t.TempDir(), "pem.example.org")
	if len(fetched) != 1 || !fetched[0].Equal(fx.intermediates[0]) {
		t.Fatalf("the PEM answer must complete the chase: fetched %d certificates", len(fetched))
	}
}

// a two-level gap is chased to the anchor: the leaf's issuer first, then the
// issuer's issuer, and the gate verifies the whole assembled chain.
func TestAIAChaseMultiLevel(t *testing.T) {
	fx := newAIAFixture(t, "multi.example.org", 2, true, false, nil)
	fetched := aiaCompleteChain(context.Background(), []*x509.Certificate{fx.leaf}, fx.anchors, t.TempDir(), "multi.example.org")
	if len(fetched) != 2 {
		t.Fatalf("the chase fetched %d certificates, want 2", len(fetched))
	}
	if !fetched[0].Equal(fx.intermediates[1]) || !fetched[1].Equal(fx.intermediates[0]) {
		t.Fatal("the chase must fetch the chain bottom-up")
	}
	if got := fx.requests.Load(); got != 2 {
		t.Fatalf("the chase made %d HTTP requests, want 2", got)
	}
	if err := aiaVerifyPresentedChain([]*x509.Certificate{fx.leaf}, fetched, fx.anchors, "multi.example.org"); err != nil {
		t.Fatalf("the completed chain must verify: %s", err)
	}
}

// an intermediate the server did present is not fetched again: the chase
// completes only what is missing.
func TestAIAChaseUsesPresentedIntermediate(t *testing.T) {
	fx := newAIAFixture(t, "presented.example.org", 2, true, false, nil)
	presented := []*x509.Certificate{fx.leaf, fx.intermediates[1]}
	fetched := aiaCompleteChain(context.Background(), presented, fx.anchors, t.TempDir(), "presented.example.org")
	if len(fetched) != 1 || !fetched[0].Equal(fx.intermediates[0]) {
		t.Fatalf("the chase must fetch only the missing issuer: fetched %d", len(fetched))
	}
	if got := fx.requests.Load(); got != 1 {
		t.Fatalf("the chase made %d HTTP requests, want 1", got)
	}
	if err := aiaVerifyPresentedChain(presented, fetched, fx.anchors, "presented.example.org"); err != nil {
		t.Fatalf("the completed chain must verify: %s", err)
	}
}

// nothing is chased when the presented chain already verifies (the handshake
// failure was something else), and a self-signed leaf owns nothing to chase —
// the TOFU flows keep it.
func TestAIACompleteChainSkipsAlreadyVerifyingAndSelfSignedLeaves(t *testing.T) {
	fx := newAIAFixture(t, "skip.example.org", 1, true, false, nil)

	presented := []*x509.Certificate{fx.leaf, fx.intermediates[0]}
	if fetched := aiaCompleteChain(context.Background(), presented, fx.anchors, t.TempDir(), "skip.example.org"); len(fetched) != 0 {
		t.Fatalf("a verifying chain must not be chased: fetched %d", len(fetched))
	}
	if got := fx.requests.Load(); got != 0 {
		t.Fatalf("a verifying chain must not touch the network: %d requests", got)
	}

	selfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the self-signed key: %s", err)
	}
	selfTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "skip.example.org"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"skip.example.org"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		IssuingCertificateURL: []string{fx.server.URL + "/aia/0"},
	}
	selfDER, err := x509.CreateCertificate(rand.Reader, selfTmpl, selfTmpl, &selfKey.PublicKey, selfKey)
	if err != nil {
		t.Fatalf("could not create the self-signed leaf: %s", err)
	}
	selfLeaf, err := x509.ParseCertificate(selfDER)
	if err != nil {
		t.Fatalf("could not parse the self-signed leaf: %s", err)
	}
	if fetched := aiaCompleteChain(context.Background(), []*x509.Certificate{selfLeaf}, fx.anchors, t.TempDir(), "skip.example.org"); len(fetched) != 0 {
		t.Fatalf("a self-signed leaf must not be chased: fetched %d", len(fetched))
	}
	if got := fx.requests.Load(); got != 0 {
		t.Fatalf("a self-signed leaf must not touch the network: %d requests", got)
	}
}

// a machine-in-the-middle serves its own CA at the root's caIssuers URL: it
// is not the issuer of the leaf, the chase drops it and the connection stays
// refused.
func TestAIAChaseRogueIssuerRefused(t *testing.T) {
	attackerRoot, _ := aiaAttackerChain(t, "rogue.example.org")
	fx := newAIAFixture(t, "rogue.example.org", 1, true, false, attackerRoot)
	fetched := aiaCompleteChain(context.Background(), []*x509.Certificate{fx.leaf}, fx.anchors, t.TempDir(), "rogue.example.org")
	if len(fetched) != 0 {
		t.Fatalf("the rogue issuer must not ride the chase: fetched %d", len(fetched))
	}
	if err := aiaVerifyPresentedChain([]*x509.Certificate{fx.leaf}, nil, fx.anchors, "rogue.example.org"); err == nil {
		t.Fatal("the connection must stay refused")
	}
}

// the fetched trust never anchors itself: with an empty anchor pool the chase
// fetches the intermediates, but the gate drops every one of them — nothing
// rides into trust.
func TestAIACompleteChainNeverTrustsUnanchoredFetch(t *testing.T) {
	fx := newAIAFixture(t, "unanchored.example.org", 1, true, false, nil)
	empty := x509.NewCertPool()
	fetched := aiaCompleteChain(context.Background(), []*x509.Certificate{fx.leaf}, empty, t.TempDir(), "unanchored.example.org")
	if len(fetched) != 0 {
		t.Fatalf("an unanchored fetch must be dropped: fetched %d", len(fetched))
	}
	if got := fx.requests.Load(); got < 2 {
		t.Fatalf("the chase must have attempted the fetches (two passes): %d requests", got)
	}
}

// the network goes away after a warm chase: the stale cache carries the next
// connection, and it does not touch the network (canon R7-T2, the offline
// case).
func TestAIAChaseOfflineWarmCache(t *testing.T) {
	fx := newAIAFixture(t, "warm.example.org", 1, true, false, nil)
	ssh3Dir := t.TempDir()

	fetched := aiaCompleteChain(context.Background(), []*x509.Certificate{fx.leaf}, fx.anchors, ssh3Dir, "warm.example.org")
	if len(fetched) != 1 {
		t.Fatalf("the first chase must fetch the intermediate: fetched %d", len(fetched))
	}
	if got := fx.requests.Load(); got != 1 {
		t.Fatalf("the first chase made %d HTTP requests, want 1", got)
	}

	fx.shutdown()
	fetched = aiaCompleteChain(context.Background(), []*x509.Certificate{fx.leaf}, fx.anchors, ssh3Dir, "warm.example.org")
	if len(fetched) != 1 || !fetched[0].Equal(fx.intermediates[0]) {
		t.Fatalf("the offline chase must ride the stale cache: fetched %d", len(fetched))
	}
	if got := fx.requests.Load(); got != 1 {
		t.Fatalf("the offline chase must not touch the network: %d requests", got)
	}
}

// offline with a cold cache: the chase fails honestly and the connection
// stays refused, exactly like before the chasing existed.
func TestAIAChaseOfflineColdCacheRefuses(t *testing.T) {
	fx := newAIAFixture(t, "cold.example.org", 1, true, false, nil)
	fx.shutdown()
	fetched := aiaCompleteChain(context.Background(), []*x509.Certificate{fx.leaf}, fx.anchors, t.TempDir(), "cold.example.org")
	if len(fetched) != 0 {
		t.Fatalf("the cold offline chase must refuse: fetched %d", len(fetched))
	}
	if got := fx.requests.Load(); got != 0 {
		t.Fatalf("the closed server must not have answered: %d requests", got)
	}
}

// the brief's counter case: the second dial rides the warm cache — the
// counting server sees no second fetch.
func TestAIAChaseCacheReuseSkipsRefetch(t *testing.T) {
	fx := newAIAFixture(t, "reuse.example.org", 1, true, false, nil)
	ssh3Dir := t.TempDir()
	for i := 0; i < 2; i++ {
		fetched := aiaCompleteChain(context.Background(), []*x509.Certificate{fx.leaf}, fx.anchors, ssh3Dir, "reuse.example.org")
		if len(fetched) != 1 {
			t.Fatalf("the dial %d must complete the chain: fetched %d", i+1, len(fetched))
		}
	}
	if got := fx.requests.Load(); got != 1 {
		t.Fatalf("the second dial refetched: %d requests, want 1", got)
	}
}

// a stale or poisoned cache entry (a valid certificate that is not the
// issuer) must not wedge the client: the chase falls to the network and
// refreshes the entry.
func TestAIAChaseRefreshesStaleCacheEntry(t *testing.T) {
	fx := newAIAFixture(t, "stale.example.org", 1, true, false, nil)
	ssh3Dir := t.TempDir()
	if err := os.MkdirAll(aiaCacheDir(ssh3Dir), 0700); err != nil {
		t.Fatalf("could not create the cache directory: %s", err)
	}
	stalePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fx.leaf.Raw})
	if err := os.WriteFile(aiaCacheFilePath(aiaCacheDir(ssh3Dir), fx.server.URL+"/aia/0"), stalePEM, 0600); err != nil {
		t.Fatalf("could not write the stale cache entry: %s", err)
	}

	fetched := aiaCompleteChain(context.Background(), []*x509.Certificate{fx.leaf}, fx.anchors, ssh3Dir, "stale.example.org")
	if len(fetched) != 1 || !fetched[0].Equal(fx.intermediates[0]) {
		t.Fatalf("the chase must refresh past the stale entry: fetched %d", len(fetched))
	}
	if got := fx.requests.Load(); got < 1 {
		t.Fatalf("the stale entry must force the network refresh: %d requests", got)
	}
}

// the depth cap stops the recursion: a chain deeper than the cap refuses
// instead of chasing forever.
func TestAIAChaseDepthCap(t *testing.T) {
	fx := newAIAFixture(t, "deep.example.org", 10, true, false, nil)
	fetched := aiaCompleteChain(context.Background(), []*x509.Certificate{fx.leaf}, fx.anchors, t.TempDir(), "deep.example.org")
	if len(fetched) != 0 {
		t.Fatalf("a chain deeper than the cap must refuse: fetched %d", len(fetched))
	}
	if got := fx.requests.Load(); got < maxAIAChainDepth {
		t.Fatalf("the chase must ride the depth cap: %d fetches, cap %d", got, maxAIAChainDepth)
	}
}

// a stalled caIssuers server must not hold the chase: the fetch timeout cuts
// it off and the chase fails honestly.
func TestAIAChaseFetchTimeout(t *testing.T) {
	fx := newAIAFixture(t, "timeout.example.org", 1, true, false, nil)
	oldTimeout := aiaFetchTimeout
	aiaFetchTimeout = 100 * time.Millisecond
	t.Cleanup(func() { aiaFetchTimeout = oldTimeout })
	fx.delay = time.Second

	fetched := aiaCompleteChain(context.Background(), []*x509.Certificate{fx.leaf}, fx.anchors, t.TempDir(), "timeout.example.org")
	if len(fetched) != 0 {
		t.Fatalf("a stalled caIssuers server must not complete the chase: fetched %d", len(fetched))
	}
}

// the per-chase budget stops the whole recursion, not only one fetch.
func TestAIAChaseBudgetCap(t *testing.T) {
	fx := newAIAFixture(t, "budget.example.org", 3, true, false, nil)
	oldBudget := aiaChaseBudget
	aiaChaseBudget = 100 * time.Millisecond
	t.Cleanup(func() { aiaChaseBudget = oldBudget })
	fx.delay = 80 * time.Millisecond

	fetched := aiaCompleteChain(context.Background(), []*x509.Certificate{fx.leaf}, fx.anchors, t.TempDir(), "budget.example.org")
	if len(fetched) != 0 {
		t.Fatalf("the budget must stop the chase: fetched %d", len(fetched))
	}
}

// an oversized answer is refused before any parsing.
func TestAIAChaseOversizedResponseRefused(t *testing.T) {
	fx := newAIAFixture(t, "oversize.example.org", 1, true, false, nil)
	fx.oversize = true
	fetched := aiaCompleteChain(context.Background(), []*x509.Certificate{fx.leaf}, fx.anchors, t.TempDir(), "oversize.example.org")
	if len(fetched) != 0 {
		t.Fatalf("an oversized answer must not complete the chase: fetched %d", len(fetched))
	}
	if got := fx.requests.Load(); got < 1 {
		t.Fatalf("the oversized answer must have been attempted: %d requests", got)
	}
}

// the cache round-trips a certificate under its URL key.
func TestAIACacheRoundTrip(t *testing.T) {
	fx := newAIAFixture(t, "cache.example.org", 1, false, false, nil)
	chaser := newAIAChaser(fx.anchors, t.TempDir())
	url := "https://ca.example.org/issuer"

	if _, ok := chaser.aiaCacheLoad(url); ok {
		t.Fatal("the cold cache must miss")
	}
	chaser.aiaCacheStore(url, fx.intermediates[0])
	cert, ok := chaser.aiaCacheLoad(url)
	if !ok || !cert.Equal(fx.intermediates[0]) {
		t.Fatal("the cache must round-trip the certificate")
	}
}

// the cache paths: one directory next to the other client state, a
// deterministic and distinct file per URL.
func TestAIACachePaths(t *testing.T) {
	if got := aiaCacheDir("/home/u/.ssh3"); got != path.Join("/home/u/.ssh3", "aia-cache") {
		t.Fatalf("the cache directory rides next to the other client state: got %q", got)
	}
	first := aiaCacheFilePath("/c", "https://a.example.org/issuer")
	second := aiaCacheFilePath("/c", "http://b.example.org/other")
	if first == second {
		t.Fatal("distinct URLs must map onto distinct cache files")
	}
	if first != aiaCacheFilePath("/c", "https://a.example.org/issuer") {
		t.Fatal("the URL mapping must be deterministic")
	}
	if filepath.Ext(first) != ".pem" {
		t.Fatalf("the cache files ride the PEM extension: got %q", first)
	}
}

// the retry handshake configuration takes over the verification: the
// presented leaf-only chain verifies through the fetched intermediates, a
// machine-in-the-middle leaf does not.
func TestAIARetryTLSConfigVerifiesPresentedChain(t *testing.T) {
	fx := newAIAFixture(t, "retry.example.org", 1, true, false, nil)
	_, attackerLeaf := aiaAttackerChain(t, "retry.example.org")

	base := &tls.Config{ServerName: "retry.example.org"}
	retryConf := aiaRetryTLSConfig(base, []*x509.Certificate{fx.intermediates[0]}, fx.anchors)
	if !retryConf.InsecureSkipVerify {
		t.Fatal("the retry must take over the standard verification")
	}
	if retryConf.VerifyConnection == nil {
		t.Fatal("the retry must carry the custom verify callback")
	}
	if retryConf.ServerName != "retry.example.org" {
		t.Fatalf("the ServerName must ride the clone: got %q", retryConf.ServerName)
	}

	if err := retryConf.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{fx.leaf}}); err != nil {
		t.Fatalf("the presented chain must verify through the fetched intermediates: %s", err)
	}
	if err := retryConf.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{attackerLeaf}}); err == nil {
		t.Fatal("the machine-in-the-middle leaf must not verify")
	}
}

// ---- the fetch policy (the pass 5 review, the C s3_ssh3_aia_url_admissible
// canon): the caIssuers url rides the peer certificate — the
// attacker-flappable input — so the fetch refuses the shapes that turn the
// chase into a client-side probe ----

// the scheme allow-list: the http family only, the case folded (the IA5
// string of the certificate carries the case the CA chose); the empty url
// and the bare-host shape refuse.
func TestAIAURLAdmissibleSchemeRefusals(t *testing.T) {
	for _, url := range []string{
		"",
		"ftp://1.1.1.1/a",
		"file:///etc/passwd",
		"gopher://1.1.1.1/",
		"1.1.1.1/a",
		"http:/1.1.1.1/a",
	} {
		if err := aiaURLAdmissible(url); err == nil {
			t.Fatalf("%q must refuse by the scheme gate", url)
		}
	}
	for _, url := range []string{
		"https://1.1.1.1/a",
		"HTTP://1.1.1.1/a",
		"HTTPS://1.1.1.1/a",
	} {
		if err := aiaURLAdmissible(url); err != nil {
			t.Fatalf("%q must admit (the scheme folds the case): %s", url, err)
		}
	}
}

// the control bytes refuse on the whole string: the CRLF of the request-line
// injection, the tabs and the spaces of the header shaping, the DEL — no
// legitimate caIssuers url carries them.
func TestAIAURLAdmissibleControlBytesRefused(t *testing.T) {
	for _, url := range []string{
		"http://1.1.1.1/a\r\nInjected: 1\r\n\r\nGET /s HTTP/1.1\r\n",
		"http://1.1.1.1/a\nb",
		"http://1.1.1.1/a\tb",
		"http://1.1.1.1/a b",
		"http://exa\rmple.com/a",
		"http://1.1.1.1/a\x7f",
	} {
		err := aiaURLAdmissible(url)
		if err == nil {
			t.Fatalf("%q must refuse by the control-bytes gate", url)
		}
		var policy *aiaPolicyError
		if !errors.As(err, &policy) || policy.gate != "control bytes" {
			t.Fatalf("%q must refuse by the control-bytes gate, got %s", url, err)
		}
	}
}

// the private-target gate on the literals: the loopback, the this-net, the
// private, the carrier NAT, the link-local, the broadcast, the multicast and
// the reserved top refuse; the ports and the v6 brackets ride; the public
// literals admit with no resolver involved.
func TestAIAURLAdmissiblePrivateLiteralsRefused(t *testing.T) {
	for _, url := range []string{
		"http://127.0.0.1:48080/inter.pem",
		"http://127.200.1.1/x",
		"http://10.1.2.3/aia",
		"http://172.16.0.1/aia",
		"http://172.31.255.254/aia",
		"http://192.168.1.1/aia",
		"http://169.254.1.1/aia",
		"http://100.64.1.1/aia",
		"http://0.0.0.0/aia",
		"http://0.1.2.3/aia",
		"http://224.0.0.1/aia",
		"http://240.0.0.1/aia",
		"http://255.255.255.255/aia",
		"http://[::1]/x",
		"http://[::1]:8443/x",
		"http://[::]/x",
		"http://[fc00::]/aia",
		"http://[fd00::5]/aia",
		"http://[fe80::1]/aia",
		"http://[ff02::1]/aia",
		"http://[::ffff:127.0.0.1]/aia",
		"http://[::ffff:10.0.0.1]/aia",
		"http://::1/x",
		"http://[::1/x",
		"http://[::1]extra/x",
		"http:///aia",
	} {
		if err := aiaURLAdmissible(url); err == nil {
			t.Fatalf("%q must refuse by the private-target gate", url)
		}
	}
	for _, url := range []string{
		"http://1.1.1.1/aia",
		"http://1.1.1.1:8080/aia",
		"http://172.32.0.1/aia",
		"http://[2606:4700::1111]/aia",
		"http://[2001:db8::1]/aia",
	} {
		if err := aiaURLAdmissible(url); err != nil {
			t.Fatalf("%q must admit (a public literal): %s", url, err)
		}
	}
}

// the names walk the resolved answers: one private answer refuses, a public
// answer admits, the resolve failure refuses (the dial would fail the same).
// The lookup rides the injected hook — the Go shape of the C
// s3_ssh3_aia_resolve_hook, the network stays out.
func TestAIAURLAdmissibleResolvedPrivateRefused(t *testing.T) {
	old := aiaResolveIP
	t.Cleanup(func() { aiaResolveIP = old })
	aiaResolveIP = func(host string) ([]net.IP, error) {
		switch host {
		case "private.example":
			return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.5")}, nil
		case "public.example":
			return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("2606:4700::1111")}, nil
		default:
			return nil, errors.New("no such host")
		}
	}

	if err := aiaURLAdmissible("http://private.example/aia"); err == nil {
		t.Fatal("a name resolving into the private range must refuse")
	}
	if err := aiaURLAdmissible("http://public.example/aia"); err != nil {
		t.Fatalf("a name resolving into the public range must admit: %s", err)
	}
	if err := aiaURLAdmissible("http://dead.example/aia"); err == nil {
		t.Fatal("a resolve failure must refuse (the dial would fail the same)")
	}
}

// the SSH3_AIA_ALLOW_PRIVATE valve (the C S3_AIA_ALLOW_PRIVATE): the
// corporate PKI knob lifts the private gates on the literals and the
// resolved names — the scheme and the control bytes stay refused with it.
func TestAIAURLAdmissibleValveEnvAdmitsPrivateOnly(t *testing.T) {
	t.Setenv("SSH3_AIA_ALLOW_PRIVATE", "1")
	old := aiaResolveIP
	t.Cleanup(func() { aiaResolveIP = old })
	aiaResolveIP = func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.5")}, nil
	}

	for _, url := range []string{
		"http://127.0.0.1:48080/inter.pem",
		"http://10.1.2.3/aia",
		"http://[fd00::5]/aia",
		"http://private.example/aia",
	} {
		if err := aiaURLAdmissible(url); err != nil {
			t.Fatalf("%q must admit under the valve: %s", url, err)
		}
	}
	for _, url := range []string{
		"http://1.1.1.1/a\r\nb",
		"ftp://10.0.0.1/a",
	} {
		if err := aiaURLAdmissible(url); err == nil {
			t.Fatalf("%q must still refuse under the valve", url)
		}
	}
}

// the policy rides the real transport before the dial: the live loopback
// server never sees the request (the blind evidence of the C e2e leg 7).
func TestAIAHTTPFetchRefusesPrivateBeforeDial(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write([]byte("payload"))
	}))
	t.Cleanup(srv.Close)

	_, err := aiaHTTPFetch(context.Background(), srv.URL+"/aia")
	if err == nil {
		t.Fatal("the loopback literal must refuse before the dial")
	}
	var policy *aiaPolicyError
	if !errors.As(err, &policy) {
		t.Fatalf("the refusal must ride the policy error, got %s", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("the refused fetch must not dial: %d requests", got)
	}
}

// NOFOLLOW: the 3xx answer is not walked — the redirect response comes back
// and the non-200 check refuses it on the spot, the redirect target stays
// untouched.
func TestAIAHTTPFetchNofollowRedirect(t *testing.T) {
	t.Setenv("SSH3_AIA_ALLOW_PRIVATE", "1")
	var targetRequests atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/real", http.StatusFound)
	})
	mux.HandleFunc("/real", func(w http.ResponseWriter, r *http.Request) {
		targetRequests.Add(1)
		w.Write([]byte("payload"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if _, err := aiaHTTPFetch(context.Background(), srv.URL+"/real"); err != nil {
		t.Fatalf("the direct answer must fetch: %s", err)
	}
	afterDirect := targetRequests.Load()
	if _, err := aiaHTTPFetch(context.Background(), srv.URL+"/redirect"); err == nil {
		t.Fatal("the 3xx answer must refuse the fetch")
	}
	if got := targetRequests.Load(); got != afterDirect {
		t.Fatalf("the redirect must not be followed: the target went from %d to %d requests", afterDirect, got)
	}
}

// the entry cap: the directory bounds at maxAIACacheEntries, a fresh unique
// url evicts the oldest-by-mtime entries, a rewrite of an existing entry
// never evicts (the deliberate divergence from the C skip-on-full — see the
// evict comment).
func TestAIACacheEvictsOldestAtCap(t *testing.T) {
	fx := newAIAFixture(t, "cap.example.org", 1, false, false, nil)
	chaser := newAIAChaser(fx.anchors, t.TempDir())
	count := func() int {
		entries, err := os.ReadDir(chaser.cacheDir)
		if err != nil {
			t.Fatalf("could not read the cache directory: %s", err)
		}
		n := 0
		for _, entry := range entries {
			if path.Ext(entry.Name()) == ".pem" {
				n++
			}
		}
		return n
	}

	urls := make([]string, 0, maxAIACacheEntries)
	for i := 0; i < maxAIACacheEntries; i++ {
		url := fmt.Sprintf("https://ca.example.org/issuer/%d", i)
		urls = append(urls, url)
		chaser.aiaCacheStore(url, fx.intermediates[0])
	}
	// the deterministic mtimes: entry i rides one minute later than i-1, so
	// urls[0] is the oldest
	base := time.Now().Add(-2 * time.Hour)
	for i, url := range urls {
		stamp := base.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(aiaCacheFilePath(chaser.cacheDir, url), stamp, stamp); err != nil {
			t.Fatalf("could not stamp the cache entry %d: %s", i, err)
		}
	}
	if got := count(); got != maxAIACacheEntries {
		t.Fatalf("the cache must hold exactly the cap before the fresh entry: %d", got)
	}

	fresh := "https://ca.example.org/issuer/fresh"
	chaser.aiaCacheStore(fresh, fx.intermediates[0])

	if got := count(); got != maxAIACacheEntries {
		t.Fatalf("the cache must stay at the cap after the fresh entry: %d", got)
	}
	if _, ok := chaser.aiaCacheLoad(urls[0]); ok {
		t.Fatal("the oldest entry must be evicted")
	}
	if _, ok := chaser.aiaCacheLoad(urls[1]); !ok {
		t.Fatal("a newer entry must survive the eviction")
	}
	if _, ok := chaser.aiaCacheLoad(fresh); !ok {
		t.Fatal("the fresh entry must survive the cap")
	}

	chaser.aiaCacheStore(urls[maxAIACacheEntries-1], fx.intermediates[0])
	if got := count(); got != maxAIACacheEntries {
		t.Fatalf("a refresh must not grow the cache: %d", got)
	}
	if _, ok := chaser.aiaCacheLoad(fresh); !ok {
		t.Fatal("a refresh must not evict other entries")
	}
}

// the refusal is the fetch-failure of one issuer: the walk continues onto
// the next url and the chase verdict stays intact.
func TestAIAFetchIssuerContinuesPastRefusedURL(t *testing.T) {
	fx := newAIAFixture(t, "continue.example.org", 1, false, false, nil)
	chaser := newAIAChaser(fx.anchors, t.TempDir())
	urls := []string{"ftp://ca.example.org/issuer", fx.server.URL + "/aia/0"}
	issuer, ok := chaser.aiaFetchIssuer(context.Background(), fx.intermediates[0], urls, map[string]bool{}, false)
	if !ok || !issuer.Equal(fx.root) {
		t.Fatal("the walk must continue past the refused url onto the good one")
	}
	if got := fx.requests.Load(); got != 1 {
		t.Fatalf("the refused url must not dial: %d requests", got)
	}
}
