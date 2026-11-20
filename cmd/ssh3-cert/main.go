// Command ssh3-cert is the PKI utility of the ssh3 set (R14-6, the
// ssh3-c canon f359fc9 — the split decision of the owner): the
// one-shot operations of the certificate life live here, NOT in the
// resident client or daemon. The processes consume the ready files
// this utility prepares (the anchor bundles, the session ticket key).
//
// The commands:
//
//	trust-update [--trust-update-url url]
//	            fetch the trust bundle, validate and land it atomically
//	            as ~/.ssh3/trust-bundle.pem (the manifest next to it
//	            names the source and the sha256; the previous copy
//	            stays on any failure) — the scheduler calls this once
//	            a day, exit 0 fresh / 255 stale
//	ticket-key file
//	            generate a session ticket key file (the nginx 80-byte
//	            form the server reads: 16 name + 32 hmac + 32 aes,
//	            0600) — the pre-seeded key survives the first daemon
//	            lifetime
//
// The scheduler units ride the packaging (the systemd user
// service+timer of the daily calendar); the enable stays the owner's
// step. The Windows twin is a schtasks one-liner (the README carries
// it) — the utility carries no install code, like the C canon.
package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3/internal/ticketkey"
	"github.com/francoismichel/ssh3/internal/trustupdate"
)

// exitStale rides the stale/refusal verdict of the C canon (the
// scheduler distinguishes the fresh run from the kept copy by it).
const exitStale = 255

func usage() {
	fmt.Fprintf(os.Stderr,
		"usage: %s <command> [args]\n"+
			"\n"+
			"the PKI utility of the ssh3 set (the certificate life outside\n"+
			"the resident processes):\n"+
			"\n"+
			"  trust-update [--trust-update-url url]\n"+
			"              fetch the trust bundle, validate and land it\n"+
			"              atomically as ~/.ssh3/trust-bundle.pem (the manifest\n"+
			"              next to it names the source and the sha256; the\n"+
			"              previous copy stays on any failure) - the scheduler\n"+
			"              calls this once a day, exit 0 fresh / 255 stale\n"+
			"  ticket-key file\n"+
			"              generate a session ticket key file (the nginx\n"+
			"              80-byte form the daemon reads: 16 name + 32 hmac\n"+
			"              + 32 aes, 0600) - the pre-seeded key survives the\n"+
			"              first daemon lifetime\n",
		os.Args[0])
}

// runTrustUpdateCmd parses the trust-update arguments and rides one
// update over the given options (the seam the tests inject their
// fixture through). The exit shapes: 0 lands a fresh bundle, 255
// keeps the stale one.
func runTrustUpdateCmd(args []string, opts trustupdate.Options) int {
	url := trustupdate.DefaultURL
	for i := 0; i < len(args); i++ {
		if args[i] == "--trust-update-url" && i+1 < len(args) {
			url = args[i+1]
			i++
			continue
		}
		fmt.Fprintf(os.Stderr, "ssh3-cert: trust-update takes only --trust-update-url url\n")
		return exitStale
	}
	opts.URL = url
	if _, err := trustupdate.Run(opts); err != nil {
		log.Error().Msgf("%s", err)
		return exitStale
	}
	return 0
}

// run dispatches one command; the exit codes are the process verdict.
func run(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		usage()
		if len(args) == 0 {
			return exitStale
		}
		return 0
	}

	switch args[0] {
	case "trust-update", "--trust-update":
		return runTrustUpdateCmd(args[1:], trustupdate.Options{})

	case "ticket-key", "--ticket-key":
		if len(args) != 2 {
			fmt.Fprintf(os.Stderr, "ssh3-cert: ticket-key wants the file argument\n")
			return exitStale
		}
		if _, err := ticketkey.Generate(args[1]); err != nil {
			log.Error().Msgf("ssh3-cert: %s", err)
			return exitStale
		}
		log.Info().Msgf("the session ticket key %s generated (the nginx 80-byte form)", args[1])
		return 0

	default:
		fmt.Fprintf(os.Stderr, "ssh3-cert: unknown command %q\n", args[0])
		usage()
		return exitStale
	}
}

func main() {
	// the stderr log rides the journal (the scheduler surface): the
	// human console form like the client's
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	os.Exit(run(os.Args[1:]))
}
