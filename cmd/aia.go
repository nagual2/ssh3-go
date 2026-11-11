package cmd

// The AIA chasing of ROADMAP.md R7-T2 (CERT-VERIFICATION-CANON.md 2.6): the
// handshake of the client fails to verify a chain whose intermediate
// certificates are missing — the server presented the leaf alone and the
// trust pool holds only the anchors. The chase walks up from the presented
// certificates through their caIssuers URLs (RFC 5280 4.2.2.1), fetching the
// missing issuers, and the handshake is retried with the fetched ones riding
// as plain intermediates.
//
// The hard rule of the canon: fetched trust never anchors itself. The
// crypto/tls layer cannot inject intermediates without adding them to the
// RootCAs pool — and every pool entry is a potential anchor — so the retry
// handshake takes over the verification itself (InsecureSkipVerify plus a
// VerifyConnection callback): the presented leaf is verified against the
// anchor pool (the system store merged with the embedded ISRG roots, the
// user bundle and the pins) with the presented and the fetched certificates
// riding the Intermediates pool of x509.Verify. A fetched certificate that
// does not build a chain into the anchors is dropped — a machine-in-the-
// middle substitution of the caIssuers answer is neutralized by that gate,
// whatever protocol the answer rode (caIssuers is commonly plain http, the
// browser semantics allow both schemes). The same gate bounds the cache: an
// expired cached copy cannot complete the gate, so stale material never
// verifies.
//
// Privacy: an AIA fetch reveals the client's address to the CA operator's
// server named in the certificate, never to the ssh3 target.
//
// Bounds: the recursion is capped at maxAIAChainDepth issuers, one fetch is
// bounded by aiaFetchTimeout and the whole chase by aiaChaseBudget, and the
// response body by maxAIAFetchBytes. Every fetched certificate is cached
// under the ssh3 state directory (a warm cache keeps the later connections
// off the network — the second dial of the same server makes zero requests);
// an unavailable network rides the stale cache.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// maxAIAChainDepth caps the recursion: no sane chain carries more
	// intermediates than this, deeper chases refuse.
	maxAIAChainDepth = 8

	// maxAIAFetchBytes caps the caIssuers response body (a real intermediate
	// certificate is a few kilobytes; the cap bounds a hostile server).
	maxAIAFetchBytes = 256 * 1024
)

var (
	// aiaFetchTimeout bounds one caIssuers fetch.
	aiaFetchTimeout = 5 * time.Second

	// aiaChaseBudget bounds the whole chase of one chain (all fetches).
	aiaChaseBudget = 20 * time.Second
)

// aiaCacheDir is the on-disk chase cache, riding next to the other client
// state in the ssh3 directory (canon 2.6: the ~/.config path was folded into
// the ~/.ssh3 state the client already owns).
func aiaCacheDir(ssh3Dir string) string {
	return path.Join(ssh3Dir, "aia-cache")
}

// aiaCacheFilePath maps a caIssuers URL onto its cache file: the SHA-256 of
// the URL keeps the file names bounded and injective enough for the cache —
// two different URLs ride two different files, one URL always rides the same
// one.
func aiaCacheFilePath(cacheDir, caIssuersURL string) string {
	sum := sha256.Sum256([]byte(caIssuersURL))
	return path.Join(cacheDir, hex.EncodeToString(sum[:])+".pem")
}

// aiaParseResponse accepts both caIssuers answer encodings: DER (the RFC 5280
// form) and the PEM certificate block the servers in the wild serve.
func aiaParseResponse(body []byte) (*x509.Certificate, error) {
	if cert, err := x509.ParseCertificate(body); err == nil {
		return cert, nil
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("the answer carries neither a DER nor a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// aiaHTTPFetch GETs a caIssuers URL with the per-fetch timeout (both schemes
// ride, the fetched bytes carry no trust before the anchor gate — see the
// file comment).
func aiaHTTPFetch(ctx context.Context, caIssuersURL string) ([]byte, error) {
	client := &http.Client{Timeout: aiaFetchTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, caIssuersURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the caIssuers server answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAIAFetchBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxAIAFetchBytes {
		return nil, fmt.Errorf("the caIssuers answer exceeds %d bytes", maxAIAFetchBytes)
	}
	return body, nil
}

// aiaChaser chases the issuers of one presented chain: the anchors pool holds
// the trust the chase must land in, the cache dir keeps the stale-copy
// fallback, and the fetch rides a field so the tests can inject it.
type aiaChaser struct {
	anchors  *x509.CertPool
	cacheDir string
	fetch    func(ctx context.Context, caIssuersURL string) ([]byte, error)
}

func newAIAChaser(anchors *x509.CertPool, ssh3Dir string) *aiaChaser {
	return &aiaChaser{anchors: anchors, cacheDir: aiaCacheDir(ssh3Dir), fetch: aiaHTTPFetch}
}

// aiaCacheStore writes a fetched certificate into the cache; any problem
// degrades to a debug line, the cache must never break a working chase.
func (c *aiaChaser) aiaCacheStore(caIssuersURL string, cert *x509.Certificate) {
	if err := os.MkdirAll(c.cacheDir, 0700); err != nil {
		log.Debug().Msgf("aia: could not create the cache directory %s: %s", c.cacheDir, err)
		return
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(aiaCacheFilePath(c.cacheDir, caIssuersURL), pemBytes, 0600); err != nil {
		log.Debug().Msgf("aia: could not cache %s: %s", caIssuersURL, err)
	}
}

// aiaCacheLoad reads a cached certificate; any problem degrades to a miss.
func (c *aiaChaser) aiaCacheLoad(caIssuersURL string) (*x509.Certificate, bool) {
	raw, err := os.ReadFile(aiaCacheFilePath(c.cacheDir, caIssuersURL))
	if err != nil {
		return nil, false
	}
	cert, err := aiaParseResponse(raw)
	if err != nil {
		return nil, false
	}
	return cert, true
}

// aiaFetchIssuer fetches the issuer of child through its URLs, in the order
// the certificate announces them. With allowCache the cache rides first (a
// warm cache keeps the connection off the network entirely); a cache hit
// that does not issue the child (a stale or poisoned entry) falls through to
// the network and refreshes the entry. Every fetched certificate lands in
// the cache; the child signature check keeps a certificate that is not the
// issuer out of the chase.
func (c *aiaChaser) aiaFetchIssuer(ctx context.Context, child *x509.Certificate, urls []string, seen map[string]bool, allowCache bool) (*x509.Certificate, bool) {
	for _, caIssuersURL := range urls {
		if seen[caIssuersURL] {
			continue
		}
		seen[caIssuersURL] = true

		if allowCache {
			if cert, ok := c.aiaCacheLoad(caIssuersURL); ok && child.CheckSignatureFrom(cert) == nil {
				return cert, true
			}
		}

		raw, err := c.fetch(ctx, caIssuersURL)
		if err != nil {
			log.Debug().Msgf("aia: could not fetch %s: %s", caIssuersURL, err)
			continue
		}
		cert, err := aiaParseResponse(raw)
		if err != nil {
			log.Debug().Msgf("aia: %s answered an unusable certificate body: %s", caIssuersURL, err)
			continue
		}
		c.aiaCacheStore(caIssuersURL, cert)
		if child.CheckSignatureFrom(cert) != nil {
			log.Debug().Msgf("aia: %s answered a certificate that did not issue %q", caIssuersURL, child.Subject.CommonName)
			continue
		}
		return cert, true
	}
	return nil, false
}

// aiaIssuingURLs returns the usable caIssuers URLs of the certificate, in the
// order it announces them.
func aiaIssuingURLs(cert *x509.Certificate) []string {
	urls := make([]string, 0, len(cert.IssuingCertificateURL))
	for _, caIssuersURL := range cert.IssuingCertificateURL {
		if caIssuersURL != "" {
			urls = append(urls, caIssuersURL)
		}
	}
	return urls
}

// aiaChainsToAnchors reports whether cert already builds a chain into the
// anchor pool through the given fetched intermediates (the loop-control
// check: ExtKeyUsageAny keeps a CA certificate of a server-auth-only chain
// from a false negative — the authoritative gate is the leaf verify below).
func aiaChainsToAnchors(cert *x509.Certificate, anchors *x509.CertPool, fetched []*x509.Certificate) bool {
	if anchors == nil {
		return false
	}
	extras := x509.NewCertPool()
	for _, fetchedCert := range fetched {
		extras.AddCert(fetchedCert)
	}
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         anchors,
		Intermediates: extras,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

// aiaVerifyPresentedChain builds the chain the way crypto/tls would and
// verifies it against the anchor pool: the presented intermediates and the
// fetched ones ride the Intermediates pool — a fetched certificate is an
// intermediate of this verification, never an anchor of the pool (canon 2.6).
// The empty serverName skips the hostname check (the pre-retry gate rides it;
// the retry callback verifies against the real ServerName).
func aiaVerifyPresentedChain(presented []*x509.Certificate, fetched []*x509.Certificate, anchors *x509.CertPool, serverName string) error {
	if len(presented) == 0 {
		return errors.New("the server presented no certificate")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range presented[1:] {
		intermediates.AddCert(cert)
	}
	for _, cert := range fetched {
		intermediates.AddCert(cert)
	}
	_, err := presented[0].Verify(x509.VerifyOptions{
		Roots:         anchors,
		Intermediates: intermediates,
		DNSName:       serverName,
	})
	return err
}

// chaseOnce walks up from the top presented certificate, fetching the missing
// issuers, and gates the result: the leaf must build a chain to the anchors
// through the presented intermediates and the fetched ones. The gate failing
// drops the whole fetch — a chase is either a verified completion or nothing.
func (c *aiaChaser) chaseOnce(ctx context.Context, presented []*x509.Certificate, allowCache bool) ([]*x509.Certificate, bool) {
	fetched := make([]*x509.Certificate, 0, maxAIAChainDepth)
	seen := make(map[string]bool)
	top := presented[len(presented)-1]
	for depth := 0; depth < maxAIAChainDepth; depth++ {
		if aiaChainsToAnchors(top, c.anchors, fetched) {
			break
		}
		if top.CheckSignatureFrom(top) == nil {
			// the top is self-signed: nothing above it to fetch (an unknown
			// self-signed root is no anchor, the gate decides)
			break
		}
		urls := aiaIssuingURLs(top)
		if len(urls) == 0 {
			break
		}
		if ctx.Err() != nil {
			break
		}
		issuer, ok := c.aiaFetchIssuer(ctx, top, urls, seen, allowCache)
		if !ok {
			break
		}
		fetched = append(fetched, issuer)
		top = issuer
	}
	if len(fetched) == 0 {
		return nil, false
	}
	if err := aiaVerifyPresentedChain(presented, fetched, c.anchors, ""); err != nil {
		log.Debug().Msgf("aia: the fetched intermediates did not complete a chain to an anchor: %s", err)
		return nil, false
	}
	return fetched, true
}

// chase runs one cache-first pass (a warm cache keeps the whole pass off the
// network) and, when the cached material did not build a trusted chain, one
// network-forced pass — a stale or poisoned cache entry must not wedge the
// client, and the refreshed answers land in the cache behind it.
func (c *aiaChaser) chase(ctx context.Context, presented []*x509.Certificate) []*x509.Certificate {
	ctx, cancel := context.WithTimeout(ctx, aiaChaseBudget)
	defer cancel()
	if fetched, ok := c.chaseOnce(ctx, presented, true); ok {
		return fetched
	}
	if fetched, ok := c.chaseOnce(ctx, presented, false); ok {
		return fetched
	}
	return nil
}

// aiaCompleteChain chases the missing intermediate certificates of a chain
// the handshake could not verify: it returns the fetched intermediates when
// they complete the presented chain to an anchor of the pool, nil otherwise
// (the caller falls through to the historical refusal flows). A self-signed
// leaf owns nothing to chase — the TOFU flows keep it — and a chain that
// already verifies against the anchors (the failure was something else, e.g.
// the hostname) is left alone.
func aiaCompleteChain(ctx context.Context, presented []*x509.Certificate, anchors *x509.CertPool, ssh3Dir, serverName string) []*x509.Certificate {
	if len(presented) == 0 || anchors == nil {
		return nil
	}
	leaf := presented[0]
	if leaf.CheckSignatureFrom(leaf) == nil {
		return nil
	}
	if aiaVerifyPresentedChain(presented, nil, anchors, serverName) == nil {
		return nil
	}
	return newAIAChaser(anchors, ssh3Dir).chase(ctx, presented)
}

// aiaRetryTLSConfig clones the handshake configuration for the AIA-completed
// retry: the fetched intermediates cannot ride the RootCAs pool (every pool
// entry is a potential anchor, and fetched trust must never anchor itself,
// canon 2.6), so the retry takes InsecureSkipVerify and verifies the
// presented chain itself in the VerifyConnection callback — the fetched
// certificates riding as plain intermediates, the hostname check riding the
// same Verify call against the configuration's ServerName.
func aiaRetryTLSConfig(base *tls.Config, fetched []*x509.Certificate, anchors *x509.CertPool) *tls.Config {
	conf := base.Clone()
	conf.InsecureSkipVerify = true
	conf.VerifyConnection = func(cs tls.ConnectionState) error {
		return aiaVerifyPresentedChain(cs.PeerCertificates, fetched, anchors, conf.ServerName)
	}
	return conf
}
