// Command gen-trust-bundle regenerates the embedded trust-root set of
// the client from the Mozilla CCADB report snapshot (R14-6, the port
// of the ssh3-c canon scripts/gen-trust-bundle.py, commit 35ad2e6).
//
// The input is the local snapshot of the
// IncludedCACertificateReportPEMCSV export (the generation carries no
// network); the filter keeps the rows carrying the Websites trust bit,
// the TLS-distrusted rows ride out, the DER SHA-256 of every row
// verifies against the fingerprint column of the same row — a
// mismatched row refuses the whole generation. The ISRG Root X1/X2
// stay the mandatory members.
//
// Run from the repo root:
//
//	go run ./scripts/gen-trust-bundle scripts/trust-roots/ccadb-<date>.csv
//
// The output rides cmd/trust-roots.pem (the embed of the pool) and
// cmd/trust-roots.meta (the generation record the tests gate on).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/francoismichel/ssh3/internal/trustbundle"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintf(os.Stderr, "usage: gen-trust-bundle <ccadb-report.csv> [output-dir]\n")
		os.Exit(1)
	}

	reportPath := os.Args[1]
	outDir := "cmd"
	if len(os.Args) == 3 {
		outDir = os.Args[2]
	}

	report, err := os.ReadFile(reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: could not read the report %s: %s\n", reportPath, err)
		os.Exit(1)
	}

	bundle, summary, err := trustbundle.Generate(bytes.NewReader(report))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	meta := trustbundle.Summarize(bundle, summary, filepath.Base(reportPath), report)
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: the meta does not marshal: %s\n", err)
		os.Exit(1)
	}

	pemPath := filepath.Join(outDir, "trust-roots.pem")
	metaPath := filepath.Join(outDir, "trust-roots.meta")
	if err := os.WriteFile(pemPath, bundle, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not write %s: %s\n", pemPath, err)
		os.Exit(1)
	}
	if err := os.WriteFile(metaPath, append(metaJSON, '\n'), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not write %s: %s\n", metaPath, err)
		os.Exit(1)
	}

	fmt.Printf("verified %d roots, embedded %d PEM bytes (report %s, sha256 %s)\n",
		summary.Roots, summary.PEMBytes, meta.ReportSnapshot, meta.ReportSHA256)
	fmt.Printf("dropped: %d without the Websites bit, %d TLS-distrusted (of %d report rows)\n",
		summary.DroppedNoWebsites, summary.DroppedDistrust, summary.ReportRows)
	fmt.Printf("written %s and %s\n", pemPath, metaPath)
}
