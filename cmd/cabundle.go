package cmd

// The CA-bundle bootstrap of ROADMAP.md R7-T1 (CERT-VERIFICATION-CANON.md,
// the "system CA store" path): the Go client builds its chain from the
// static content of the system stores, so a Windows Server SKU with a
// truncated store (no ISRG Root X1/X2) fails to verify Let's Encrypt chains
// and the client demanded -insecure. The trust pool merges these sources:
//
//   - the system certificate store (under the R14-6 policy only the
//     system policy carries it — truststore.go),
//   - the embedded ISRG roots, byte-exact as published on
//     https://letsencrypt.org/certs/ (publicly known roots: legitimate
//     anchors under the canon — the embedded trust does not anchor itself,
//     it anchors these well-known public roots),
//   - an optional user bundle file (~/.ssh3/ca-bundle.pem, SSH3_CA_BUNDLE
//     overrides the path) for private CAs,
//   - the Windows root program cache (~/.ssh3/authroots.pem, R7-T3): roots
//     collected from observed chains whose hash the signature-verified
//     Microsoft CTL vouches for (see rootprogram.go).
//
// Since R14-6 the composition rides the trust policy (truststore.go):
// the own policy keeps the platform store out, the system policy rides
// it over the own set — the union is never worse than the system store
// alone. A missing or broken user file and an unavailable system store
// degrade to warnings, never to a refusal to run: the remaining sources
// keep carrying the trust.

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"os"
	"path"

	"github.com/rs/zerolog/log"
)

// The ISRG roots ride the binary byte-exact (SHA-256 of their DER, verified
// against the fingerprints published for the roots):
//
//	ISRG Root X1  96:BC:EC:06:26:49:76:F3:74:60:77:9A:CF:28:C5:A7:CF:E8:A3:C0:AA:E1:1A:8F:FC:EE:05:C0:BD:DF:08:C6
//	ISRG Root X2  69:72:9B:8E:15:A8:6E:FC:17:7A:57:AF:B7:17:1D:FC:64:AD:D2:8C:2F:CA:8C:F1:50:7E:34:45:3C:CB:14:70

//go:embed isrgrootx1.pem
var isrgRootX1PEM []byte

//go:embed isrg-root-x2.pem
var isrgRootX2PEM []byte

// caBundleEnvVar names the user bundle file, overriding the default location.
const caBundleEnvVar = "SSH3_CA_BUNDLE"

// caBundleFileName is the user bundle riding next to the other client state
// (known_hosts) in the ssh3 directory.
const caBundleFileName = "ca-bundle.pem"

// caBundleFilePath resolves the user bundle path: SSH3_CA_BUNDLE wins, the
// default rides next to known_hosts.
func caBundleFilePath(ssh3Dir string) string {
	if override := os.Getenv(caBundleEnvVar); override != "" {
		return override
	}
	return path.Join(ssh3Dir, caBundleFileName)
}

// appendPEMToPool adds every certificate of the PEM bundle to the pool and
// returns how many certificates landed. Blocks that are not usable
// certificates are warned about and skipped, so a broken bundle degrades
// only the trust it adds, never the pool it rides into.
func appendPEMToPool(pool *x509.CertPool, bundle []byte, source string) int {
	added := 0
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			log.Warn().Msgf("ca-bundle: %s: skipping a PEM block of type %q: not a certificate", source, block.Type)
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Warn().Msgf("ca-bundle: %s: skipping a certificate that does not parse: %s", source, err)
			continue
		}
		pool.AddCert(cert)
		added++
	}
	if added == 0 && len(bytes.TrimSpace(bundle)) > 0 {
		log.Warn().Msgf("ca-bundle: %s carried no usable certificate", source)
	}
	return added
}

// buildClientCAPool assembles a trust pool from the system store and the
// given PEM bundles. The system pool is cloned so that the merge never
// mutates the caller's store; when the platform store is unavailable
// (systemErr set, or a nil pool) the bundles carry the trust alone — a
// degraded store must not kill the client. Bundle content problems are
// warnings: the pool only ever grows.
func buildClientCAPool(systemPool *x509.CertPool, systemErr error, bundles ...[]byte) *x509.CertPool {
	var pool *x509.CertPool
	switch {
	case systemErr != nil:
		log.Warn().Msgf("ca-bundle: the system certificate store is unavailable (%s), riding the bundles only", systemErr)
	case systemPool == nil:
		log.Warn().Msg("ca-bundle: the system certificate store provided no pool, riding the bundles only")
	default:
		pool = systemPool.Clone()
	}
	if pool == nil {
		pool = x509.NewCertPool()
	}
	for i, bundle := range bundles {
		appendPEMToPool(pool, bundle, fmt.Sprintf("bundle %d", i+1))
	}
	return pool
}

// loadClientCAPool moved to truststore.go with the R14-6 trust policy:
// the pool builder rides the own|system policy over the same merge
// primitive (buildClientCAPool), the embedded set grew the 109-root
// CCADB browser set and the user bundles grew the trust-bundle overlay.
