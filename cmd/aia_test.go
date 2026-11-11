package cmd

// Tests of the AIA chasing (ROADMAP.md R7-T2, CERT-VERIFICATION-CANON.md 2.6):
// the missing intermediate certificates of a presented chain are fetched
// through the caIssuers URLs, cached on disk and gated — fetched material
// completes a chain to an anchor of the pool or is dropped, it never anchors
// itself. The chains are generated here; the caIssuers traffic rides a local
// httptest server with a request counter (no external network).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
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
