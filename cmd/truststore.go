package cmd

// The trust store policy of the client (R14-6, the ssh3-c wave-14
// canon ee30795 + 35ad2e6 + 31d8625): one builder of the dial anchor
// pool over two policies.
//
//	own    - the browser model: the embedded root certificates (the
//	         ISRG pair plus the 109-root Mozilla CCADB set) plus the
//	         user bundle files (the SSH3_CA_BUNDLE / ~/.ssh3/ca-bundle.pem
//	         file and the ~/.ssh3/trust-bundle.pem overlay the trust
//	         update lands); the platform store stays out
//	system - the platform store rides over the own set (the union: the
//	         client is never worse than the system store alone, the
//	         browser semantics; an unavailable store rides the own set
//	         with a warning)
//
// The pins (known_hosts) are the separate trust channel: they ride the
// verdict machinery whatever the policy is (they land in the pool as
// anchors at the dial site, both policies).
//
// The default policy is own — the phase-1 decision of the owner
// (2026-11-12, the C canon): the switch of the default to system rides
// after the live acceptance of the platform bridges, whatever way the
// decision falls.

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	_ "embed"

	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3/internal/trustupdate"
)

// TrustPolicy is the anchor-set policy of the dial.
type TrustPolicy int

const (
	// TrustPolicyOwn carries the embedded roots plus the user bundles
	// (the default of the phase 1).
	TrustPolicyOwn TrustPolicy = iota
	// TrustPolicySystem adds the platform store over the own set.
	TrustPolicySystem
)

// defaultTrustPolicy is the phase-1 default (the owner's decision, the
// C canon ee30795): own.
const defaultTrustPolicy = TrustPolicyOwn

// ParseTrustPolicy parses the policy text ("own", "system",
// case-insensitive); the unknown text refuses.
func ParseTrustPolicy(text string) (TrustPolicy, error) {
	switch strings.ToLower(text) {
	case "own":
		return TrustPolicyOwn, nil
	case "system":
		return TrustPolicySystem, nil
	default:
		return defaultTrustPolicy, fmt.Errorf("unknown trust store policy %q: want own|system", text)
	}
}

// String renders the canonical name of the policy (the logs, the
// error texts).
func (p TrustPolicy) String() string {
	switch p {
	case TrustPolicySystem:
		return "system"
	default:
		return "own"
	}
}

// trustStoreFlag backs the --trust-store long flag: the value word
// parses at the flag time, so a bad value stops the run before any
// dial (the flag package refuses with the usage).
type trustStoreFlag struct {
	policy TrustPolicy
	set    bool
}

func (f *trustStoreFlag) String() string {
	if f == nil || !f.set {
		return defaultTrustPolicy.String()
	}
	return f.policy.String()
}

func (f *trustStoreFlag) Set(value string) error {
	policy, err := ParseTrustPolicy(value)
	if err != nil {
		return err
	}
	f.policy = policy
	f.set = true
	return nil
}

// The ISRG fingerprints the embedded set must carry (the wave-13 pins,
// the same values the C generator names as the mandatory members).
const (
	isrgRootX1SHA256 = "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6"
	isrgRootX2SHA256 = "69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470"
)

// The embedded trust set (R14-6 phase 1b, the ssh3-c canon 35ad2e6):
// the browser-size Mozilla CCADB set — the Websites trust bit of the
// report snapshot scripts/trust-roots/, the TLS-distrusted rows out,
// the DER SHA-256 of every row verified at the generation time. The
// generator rides scripts/gen-trust-bundle; the meta names the exact
// snapshot the set derives from.

//go:embed trust-roots.pem
var trustRootsPEM []byte

//go:embed trust-roots.meta
var trustRootsMeta []byte

// trustBundleFilePath resolves the bundle overlay path: the state dir
// the trust update lands into and the dial read — one name (the ssh3-c
// s3_trust_bundle_path_get contract).
func trustBundleFilePath(ssh3Dir string) string {
	return trustupdate.BundlePath(ssh3Dir)
}

// loadTrustBundleBundles gathers the file bundles of the state dir:
// the ca-bundle of the R7-T1 bootstrap and the trust-bundle overlay of
// the phase-1c update. The absent files are the plain shape (the fresh
// home), the unreadable ones lose only their trust.
func loadTrustBundleBundles(ssh3Dir string) [][]byte {
	var bundles [][]byte

	bundlePath := caBundleFilePath(ssh3Dir)
	filePEM, err := os.ReadFile(bundlePath)
	switch {
	case err == nil:
		bundles = append(bundles, filePEM)
	case os.IsNotExist(err):
		// the optional bundle file is absent: the embedded roots carry
		// the trust alone
	default:
		log.Warn().Msgf("ca-bundle: could not read %s: %s", bundlePath, err)
	}

	overlayPath := trustBundleFilePath(ssh3Dir)
	overlayPEM, err := os.ReadFile(overlayPath)
	switch {
	case err == nil:
		bundles = append(bundles, overlayPEM)
	case os.IsNotExist(err):
		// the overlay is absent until the first trust update lands
	default:
		log.Warn().Msgf("trust-bundle: could not read %s: %s", overlayPath, err)
	}
	return bundles
}

// buildPolicyPool assembles the dial anchor pool over the policy with
// the platform store inputs injected (the seam the units ride — the
// composition stays deterministic on every platform). The embedded set
// and the user bundles ride both policies; the platform store rides
// only the system policy, over the own set (the union is never worse
// than the system store alone).
func buildPolicyPool(policy TrustPolicy, systemPool *x509.CertPool, systemErr error, ssh3Dir string) *x509.CertPool {
	bundles := append([][]byte{isrgRootX1PEM, isrgRootX2PEM, trustRootsPEM}, loadTrustBundleBundles(ssh3Dir)...)

	if policy != TrustPolicySystem {
		// the own policy keeps the platform store out (the browser
		// model); the merge primitive starts from an empty base pool
		return buildClientCAPool(x509.NewCertPool(), nil, bundles...)
	}

	// the system union: the platform store rides under the own set —
	// an unavailable store warns and the own set carries the trust
	// alone, the dial never regresses on the policy choice
	return buildClientCAPool(systemPool, systemErr, bundles...)
}

// loadClientCAPool gathers the trust inputs of the client over the
// policy and merges them. It never fails: every missing source
// degrades to the remaining ones with a warning.
func loadClientCAPool(ssh3Dir string, policy TrustPolicy) *x509.CertPool {
	var systemPool *x509.CertPool
	var systemErr error
	if policy == TrustPolicySystem {
		systemPool, systemErr = x509.SystemCertPool()
	}
	pool := buildPolicyPool(policy, systemPool, systemErr, ssh3Dir)

	// R7-T3 (the Windows root program): the CTL-blessed roots collected
	// from observed chains ride as the fourth source whatever the
	// policy is — the cache is a fork-internal trust channel (a state
	// file of ~/.ssh3 like the ca-bundle), not the platform store, and
	// the CTL track predates the policy wave. The same load initializes
	// the process-wide state the refresh goroutine and the dial-path
	// gates use.
	rootProgramDefault.load(ssh3Dir, pool)
	return pool
}
