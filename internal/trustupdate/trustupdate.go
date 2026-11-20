// Package trustupdate rides the trust-bundle refresh of the client
// (R14-6, the ssh3-c wave-14 phase-1c canon, commit 31d8625): the
// scheduler calls the product shape `ssh3-cert trust-update` once a
// day. The run fetches the bundle body over the neutral https infra,
// validates it (every PEM block a certificate, the count floor — the
// Mozilla set carries ~110) and lands it atomically (tmp+rename, 0600)
// into the state dir as trust-bundle.pem, with the manifest next to it
// naming the source url and the sha256 of the body. Any failure keeps
// the previous copy — the offline scheduler run is the plain shape.
//
// The dial shares one name with the update: trustupdate.BundlePath is
// the file the client pool reads under the own policy (the ssh3-c
// s3_trust_bundle_path_get contract).
package trustupdate

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
)

// The update caps of the canon (the phase 1c): the fetch timeout of
// the bundle (the ~200 KiB body over a slow link), the body cap, the
// certificate count floor (the Mozilla set carries ~110).
const (
	// DefaultURL is the default source of the trust bundle update (the
	// Mozilla set of the curl distribution, the PEM form).
	DefaultURL = "https://curl.se/ca/cacert.pem"
	// FetchTimeout bounds the whole fetch exchange of the default
	// transport (the C canon rides a 30 s per-phase budget).
	FetchTimeout = 30 * time.Second
	// BodyMax caps the fetched body.
	BodyMax = 4 * 1024 * 1024
	// CertFloor is the certificate count floor of the validation walk.
	CertFloor = 30
	// bundleFileName rides next to the other client state in the ssh3
	// directory; the manifest appends .man.
	bundleFileName = "trust-bundle.pem"
)

// FetchFunc carries the bundle body of a source url. The product
// transport is the default https fetch; the tests inject their
// fixture (zero network).
type FetchFunc func(url string) ([]byte, error)

// Options carries one run: the source url, the landing dir (the empty
// value rides DefaultStateDir), the validation floor (0 rides
// CertFloor) and the fetch hook (nil rides the https transport).
type Options struct {
	URL      string
	Dir      string
	MinCerts int
	Fetch    FetchFunc
}

// DefaultStateDir resolves the client state directory (~/.ssh3, the
// shared base of the bundle paths — the ssh3-c s3_ssh3_aia_state_dir
// shape).
func DefaultStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not resolve the home directory: %w", err)
	}
	return filepath.Join(home, ".ssh3"), nil
}

// BundlePath returns the landing file of the bundle in the given state
// dir — the name the update and the dial share.
func BundlePath(stateDir string) string {
	return filepath.Join(stateDir, bundleFileName)
}

// Run executes one update: fetch, validate, land. It returns the path
// the fresh bundle landed at; any failure leaves the previous copy
// untouched and names the stage in the error.
func Run(opts Options) (string, error) {
	if opts.URL == "" {
		return "", fmt.Errorf("the update needs a source url")
	}

	dir := opts.Dir
	if dir == "" {
		resolved, err := DefaultStateDir()
		if err != nil {
			return "", err
		}
		dir = resolved
	}

	// the state dir may not exist yet (the fresh home rides the
	// scheduler before any pin write)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("could not create the state dir %s: %w", dir, err)
	}

	body, err := fetchBody(opts)
	if err != nil {
		return "", err
	}

	// the validation walk: every PEM block parses as a certificate, the
	// floor counts (the truncated tail stops the walk short of the
	// floor — the store copy stays)
	count := 0
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return "", fmt.Errorf("the bundle body carries a PEM block of type %q: not a certificate", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "", fmt.Errorf("the bundle body carries a certificate that does not parse: %w", err)
		}
		count++
	}
	floor := opts.MinCerts
	if floor <= 0 {
		floor = CertFloor
	}
	if count < floor {
		return "", fmt.Errorf("the trust bundle of %s carries %d certificates, the floor is %d - riding without the update",
			opts.URL, count, floor)
	}

	// the atomic landing: the tmp swap of the ticket cache shape, the
	// manifest names the source and the sha256
	path := BundlePath(dir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0600); err != nil {
		return "", fmt.Errorf("could not write the landing tmp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("could not land the bundle: %w", err)
	}

	sum := sha256.Sum256(body)
	manifest := path + ".man"
	manifestBody := opts.URL + "\n" + hex.EncodeToString(sum[:]) + "\n"
	if err := os.WriteFile(manifest, []byte(manifestBody), 0600); err != nil {
		// the broken manifest dies, the landed bundle stays
		_ = os.Remove(manifest)
		return "", fmt.Errorf("could not write the manifest: %w", err)
	}

	log.Info().Msgf("the trust bundle of %s landed (%d certificates, sha256 %s)", opts.URL, count, hex.EncodeToString(sum[:]))
	return path, nil
}

// fetchBody rides the fetch hook of the tests or the default https
// transport (the neutral https infra: the 30 s budget, the 4 MiB body
// cap, the 200 status).
func fetchBody(opts Options) ([]byte, error) {
	if opts.Fetch != nil {
		return opts.Fetch(opts.URL)
	}

	parsed, err := url.Parse(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("the source url does not parse: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("the source url %q rides the plain %q scheme, the neutral transport is https", opts.URL, parsed.Scheme)
	}

	client := &http.Client{Timeout: FetchTimeout}
	resp, err := client.Get(opts.URL)
	if err != nil {
		log.Warn().Msgf("the trust bundle fetch of %s failed", opts.URL)
		return nil, fmt.Errorf("the trust bundle fetch of %s failed: %w", opts.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the trust bundle fetch of %s rode the status %d, want 200", opts.URL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, BodyMax+1))
	if err != nil {
		return nil, fmt.Errorf("could not read the bundle body: %w", err)
	}
	if len(body) == 0 || len(body) > BodyMax {
		return nil, fmt.Errorf("the bundle body carries %d bytes, want 1..%d", len(body), BodyMax)
	}
	return body, nil
}
