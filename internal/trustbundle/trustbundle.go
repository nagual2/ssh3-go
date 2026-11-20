// Package trustbundle generates the embedded trust-root set from the
// Mozilla CCADB report (R14-6, the port of the ssh3-c canon
// scripts/gen-trust-bundle.py, commit 35ad2e6 — the wave-14 phase 1b).
//
// The input is the IncludedCACertificateReportPEMCSV export of the
// CCADB, read from a local snapshot — the generation carries no
// network. For every row of the report:
//
//   - the Trust Bits carry "Websites" (the dial context of the client),
//   - the TLS distrust date is empty (a root leaving the TLS trust
//     never anchors, whatever the date is),
//   - the DER SHA-256 of the PEM row matches the fingerprint column of
//     the same row — the hard gate, a mismatched row refuses the whole
//     generation,
//   - the fingerprints dedupe (a repeated root rides once).
//
// The ISRG Root X1/X2 pins of the previous generation stay as the
// mandatory members (the pair the wave-13 trust tests pin). The output
// is the concatenated PEM bundle, sorted by fingerprint, one source of
// truth for the embed (cmd/trust-roots.pem).
package trustbundle

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"sort"
	"strings"
)

// SourceURL is the public export the report snapshot derives from.
const SourceURL = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV"

// mandatoryMembers pins the roots the set must never lose: the ISRG
// pair the earlier waves embedded (the DER SHA-256 fingerprints, the
// same values the go-fork rode since the CA-bundle bootstrap).
var mandatoryMembers = map[string]string{
	"96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6": "ISRG Root X1",
	"69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470": "ISRG Root X2",
}

// Meta is the generation record riding next to the bundle: the
// fingerprint of the exact report snapshot the set derives from, the
// filter counters and the source. The embed gate of the cmd package
// verifies the pair against the committed snapshot.
type Meta struct {
	SourceURL         string `json:"source_url"`
	ReportSnapshot    string `json:"report_snapshot"`
	ReportSHA256      string `json:"report_sha256"`
	Roots             int    `json:"roots"`
	ReportRows        int    `json:"report_rows"`
	DroppedNoWebsites int    `json:"dropped_no_websites"`
	DroppedDistrust   int    `json:"dropped_distrust"`
	PEMBytes          int    `json:"pem_bytes"`
}

// Generate walks the report and returns the concatenated PEM bundle of
// the picked roots with the generation summary. A row that fails the
// DER SHA-256 gate (or carries no PEM block) refuses the whole
// generation — the set never rides a half-verified report.
func Generate(report io.Reader) (bundle []byte, summary Meta, err error) {
	rows, err := csv.NewReader(report).ReadAll()
	if err != nil {
		return nil, summary, fmt.Errorf("the report does not parse as csv: %w", err)
	}
	if len(rows) < 2 {
		return nil, summary, fmt.Errorf("the report carries %d rows, want the header plus the roots", len(rows))
	}

	columns := map[string]int{}
	for i, name := range rows[0] {
		columns[strings.TrimSpace(name)] = i
	}
	for _, column := range []string{"Common Name or Certificate Name", "SHA-256 Fingerprint", "Trust Bits", "Distrust for TLS After Date", "PEM Info"} {
		if _, ok := columns[column]; !ok {
			return nil, summary, fmt.Errorf("the report misses the %q column", column)
		}
	}

	picked := map[string]string{}
	summary.ReportRows = len(rows) - 1
	for _, row := range rows[1:] {
		name := row[columns["Common Name or Certificate Name"]]
		trustBits := row[columns["Trust Bits"]]
		distrust := strings.TrimSpace(row[columns["Distrust for TLS After Date"]])

		if !strings.Contains(trustBits, "Websites") {
			summary.DroppedNoWebsites++
			continue
		}
		if distrust != "" {
			summary.DroppedDistrust++
			continue
		}

		// the salesforce escape: the PEM field rides wrapped in leading
		// and trailing single quotes
		pemBody := strings.TrimSpace(row[columns["PEM Info"]])
		pemBody = strings.Trim(pemBody, "'")
		if !strings.HasPrefix(pemBody, "-----BEGIN CERTIFICATE-----") {
			return nil, summary, fmt.Errorf("a row without the PEM block rides past: %s", name)
		}

		got, err := derSHA256(pemBody)
		if err != nil {
			return nil, summary, fmt.Errorf("%s: the PEM block does not parse: %w", name, err)
		}
		claimed := strings.ToLower(strings.TrimSpace(row[columns["SHA-256 Fingerprint"]]))
		claimed = strings.ReplaceAll(claimed, ":", "")
		if got != claimed {
			return nil, summary, fmt.Errorf("%s: the DER SHA-256 mismatch: got %s, the report claims %s", name, got, claimed)
		}

		// the fingerprints dedupe (a repeated root rides once)
		picked[got] = pemBody
	}

	missing := []string{}
	for fingerprint, member := range mandatoryMembers {
		if _, ok := picked[fingerprint]; !ok {
			missing = append(missing, member)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, summary, fmt.Errorf("the mandatory members left the set: %s", strings.Join(missing, ", "))
	}

	fingerprints := make([]string, 0, len(picked))
	for fingerprint := range picked {
		fingerprints = append(fingerprints, fingerprint)
	}
	sort.Strings(fingerprints)

	var out bytes.Buffer
	for _, fingerprint := range fingerprints {
		out.WriteString(strings.TrimRight(picked[fingerprint], "\n"))
		out.WriteString("\n")
	}
	summary.Roots = len(picked)
	summary.SourceURL = SourceURL
	summary.PEMBytes = out.Len()
	return out.Bytes(), summary, nil
}

// Summarize computes the meta record of a generated bundle: the bundle
// rides in, the report snapshot name and body hash complete the record.
func Summarize(bundle []byte, summary Meta, snapshotName string, snapshotBody []byte) Meta {
	sum := sha256.Sum256(snapshotBody)
	summary.ReportSnapshot = snapshotName
	summary.ReportSHA256 = hex.EncodeToString(sum[:])
	summary.PEMBytes = len(bundle)
	return summary
}

// derSHA256 returns the SHA-256 hex of the DER form of the PEM block
// (the gate the C generator runs through the openssl CLI).
func derSHA256(pemBody string) (string, error) {
	block, _ := pem.Decode([]byte(pemBody))
	if block == nil {
		return "", fmt.Errorf("no PEM block found")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", err
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
