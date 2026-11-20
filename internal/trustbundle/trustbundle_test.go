package trustbundle

// The generator logic tests (R14-6, the port of the ssh3-c canon
// scripts/gen-trust-bundle.py, commit 35ad2e6): the fixture rides
// hand-made roots in a mini report — the Websites trust bit keeps a
// row, the missing bit and the TLS distrust date drop it, the DER
// SHA-256 of every row verifies against the fingerprint column (a
// mismatched row refuses the whole generation), the fingerprints
// dedupe, the salesforce quote escape of the PEM field strips, the
// mandatory members guard the set. The real 109-root set is gated in
// the cmd package (the embed rides the committed report snapshot).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/csv"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path"
	"sort"
	"strings"
	"testing"
	"time"
)

// makeRootPEM mints a self-signed CA certificate with the given CN and
// returns the PEM body with the SHA-256 hex of its DER form.
func makeRootPEM(t *testing.T, cn string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the key: %s", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create the certificate: %s", err)
	}
	sum := sha256.Sum256(der)
	body := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return body, hex.EncodeToString(sum[:])
}

// isrgRows renders the two mandatory members of every happy-path
// fixture report (the guard is always on — the mini reports carry the
// real ISRG pair, the files the cmd embed rides).
func isrgRows(t *testing.T) [][]string {
	t.Helper()
	rows := make([][]string, 0, 2)
	for _, name := range []string{"isrgrootx1.pem", "isrg-root-x2.pem"} {
		body, err := os.ReadFile(path.Join("..", "..", "cmd", name))
		if err != nil {
			t.Fatalf("the ISRG fixture is missing: %s", err)
		}
		pemBody := strings.TrimSpace(string(body))
		rows = append(rows, row(name, mustSHA(t, pemBody), "Websites;Email", "", pemBody))
	}
	return rows
}

// reportCSV renders the mini report in the CCADB column layout the
// generator reads; the rows carry the pem/sha/trust-bits/distrust cells.
func reportCSV(t *testing.T, rows [][]string) string {
	t.Helper()
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	header := []string{"Owner", "Common Name or Certificate Name", "SHA-256 Fingerprint",
		"Trust Bits", "Distrust for TLS After Date", "PEM Info"}
	if err := writer.Write(header); err != nil {
		t.Fatalf("could not write the header: %s", err)
	}
	if err := writer.WriteAll(rows); err != nil {
		t.Fatalf("could not write the rows: %s", err)
	}
	writer.Flush()
	return buf.String()
}

func row(cn, sha, trustBits, distrust, pemBody string) []string {
	return []string{"TestOwner", cn, sha, trustBits, distrust, pemBody}
}

func TestGenerateKeepsWebsitesRowsOnly(t *testing.T) {
	keptPEM, keptSHA := makeRootPEM(t, "Kept Root")
	noBitPEM, _ := makeRootPEM(t, "No Websites Root")
	distrustedPEM, _ := makeRootPEM(t, "Distrusted Root")

	report := reportCSV(t, append(isrgRows(t), [][]string{
		row("Kept Root", keptSHA, "Websites;Email", "", keptPEM),
		row("No Websites Root", mustSHA(t, noBitPEM), "Email", "", noBitPEM),
		row("Distrusted Root", mustSHA(t, distrustedPEM), "Websites", "2027.01.01", distrustedPEM),
	}...))

	body, summary, err := Generate(strings.NewReader(report))
	if err != nil {
		t.Fatalf("Generate refused the clean report: %s", err)
	}
	// the two ISRG members ride the fixture report as the mandatory
	// members, the kept row adds the third
	if summary.Roots != 3 {
		t.Errorf("the set carries %d roots, want 3 (the rows without the Websites bit and the TLS-distrusted ones ride out)", summary.Roots)
	}
	if summary.DroppedNoWebsites != 1 || summary.DroppedDistrust != 1 || summary.ReportRows != 5 {
		t.Errorf("the drop counters ride wrong: %+v", summary)
	}
	certs, err := parseBundle(body)
	if err != nil {
		t.Fatalf("the generated bundle does not parse: %s", err)
	}
	if len(certs) != 3 {
		t.Errorf("the bundle carries %d certificates, want 3", len(certs))
	}
	for _, cert := range certs {
		if cert.Subject.CommonName == "No Websites Root" || cert.Subject.CommonName == "Distrusted Root" {
			t.Errorf("the dropped row %q made the set", cert.Subject.CommonName)
		}
	}
}

func TestGenerateVerifiesDERSHA256Gate(t *testing.T) {
	pemBody, _ := makeRootPEM(t, "Lying Root")

	report := reportCSV(t, [][]string{
		row("Lying Root", strings.Repeat("ab", 32), "Websites", "", pemBody),
	})

	_, _, err := Generate(strings.NewReader(report))
	if err == nil {
		t.Fatal("the mismatched fingerprint row rode past the gate")
	}
	if !strings.Contains(err.Error(), "Lying Root") {
		t.Errorf("the refusal does not name the row: %s", err)
	}
}

func TestGenerateDedupesFingerprints(t *testing.T) {
	pemBody, sha := makeRootPEM(t, "Twice Root")

	report := reportCSV(t, append(isrgRows(t), [][]string{
		row("Twice Root", sha, "Websites", "", pemBody),
		row("Twice Root", sha, "Websites", "", pemBody),
	}...))

	body, summary, err := Generate(strings.NewReader(report))
	if err != nil {
		t.Fatalf("Generate refused the duplicate row: %s", err)
	}
	if summary.Roots != 3 {
		t.Errorf("the repeated root rode twice: %d roots", summary.Roots)
	}
	certs, err := parseBundle(body)
	if err != nil {
		t.Fatalf("the generated bundle does not parse: %s", err)
	}
	twice := 0
	for _, cert := range certs {
		if cert.Subject.CommonName == "Twice Root" {
			twice++
		}
	}
	if twice != 1 {
		t.Errorf("the repeated root rode %d times, want once", twice)
	}
}

func TestGenerateStripsSalesforceQuotes(t *testing.T) {
	pemBody, sha := makeRootPEM(t, "Quoted Root")

	// the salesforce escape: the PEM field rides wrapped in leading and
	// trailing single quotes
	report := reportCSV(t, append(isrgRows(t), [][]string{
		row("Quoted Root", sha, "Websites", "", "'"+strings.TrimSpace(pemBody)+"'"),
	}...))

	body, _, err := Generate(strings.NewReader(report))
	if err != nil {
		t.Fatalf("Generate refused the quoted PEM field: %s", err)
	}
	certs, err := parseBundle(body)
	if err != nil {
		t.Fatalf("the generated bundle does not parse: %s", err)
	}
	found := false
	for _, cert := range certs {
		if cert.Subject.CommonName == "Quoted Root" {
			found = true
		}
	}
	if !found {
		t.Errorf("the quoted PEM row did not make the set")
	}
}

func TestGenerateRefusesRowWithoutPEM(t *testing.T) {
	_, sha := makeRootPEM(t, "Bare Root")

	report := reportCSV(t, [][]string{
		row("Bare Root", sha, "Websites", "", "not-a-pem-body"),
	})

	_, _, err := Generate(strings.NewReader(report))
	if err == nil {
		t.Fatal("the row without the PEM block rode past")
	}
}

func TestGenerateRefusesMissingMandatoryMembers(t *testing.T) {
	pemBody, sha := makeRootPEM(t, "Lonely Root")

	report := reportCSV(t, [][]string{
		row("Lonely Root", sha, "Websites", "", pemBody),
	})

	_, _, err := Generate(strings.NewReader(report))
	if err == nil {
		t.Fatal("the set without the mandatory members generated")
	}
	if !strings.Contains(err.Error(), "mandatory") {
		t.Errorf("the refusal does not name the mandatory guard: %s", err)
	}
}

func TestGenerateSortsByFingerprint(t *testing.T) {
	firstPEM, firstSHA := makeRootPEM(t, "Aaa Root")
	secondPEM, secondSHA := makeRootPEM(t, "Zzz Root")

	// the rows ride in the reverse order of their fingerprints
	report := reportCSV(t, append(isrgRows(t), [][]string{
		row("Zzz Root", secondSHA, "Websites", "", secondPEM),
		row("Aaa Root", firstSHA, "Websites", "", firstPEM),
	}...))

	body, _, err := Generate(strings.NewReader(report))
	if err != nil {
		t.Fatalf("Generate refused the report: %s", err)
	}
	certs, err := parseBundle(body)
	if err != nil {
		t.Fatalf("the generated bundle does not parse: %s", err)
	}
	// the bundle order is the fingerprint sort of the set
	sums := make([]string, 0, len(certs))
	for _, cert := range certs {
		sum := sha256.Sum256(cert.Raw)
		sums = append(sums, hex.EncodeToString(sum[:]))
	}
	sorted := append([]string(nil), sums...)
	sort.Strings(sorted)
	for i := range sums {
		if sums[i] != sorted[i] {
			t.Fatalf("the bundle does not ride the fingerprint sort at block %d", i)
		}
	}
}

// parseBundle parses every PEM block of the bundle body.
func parseBundle(body []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func mustSHA(t *testing.T, pemBody string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(pemBody))
	if block == nil {
		t.Fatal("the fixture PEM does not decode")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

func countBlocks(body []byte) int {
	rest := body
	count := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		count++
	}
	return count
}
