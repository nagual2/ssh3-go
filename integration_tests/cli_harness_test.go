// SPDX-License-Identifier: Apache-2.0 (fork changes: nagual2, 2026)

package integration_tests

import (
	"slices"
	"testing"
)

// The integration harness drives the fork's own binaries, so it has to follow
// the CLI canon of the CLI-parity wave (CTO_TASK §7c). The transfer mode
// moved to the -transfer long form; -f is the ssh(1) background flag now, and
// a harness still passing -f would background the client instead of moving the
// file: the transfer would silently never happen.
func TestTransferClientArgsUseTheTransferFlag(t *testing.T) {
	args := transferClientArgs("/tmp/id_rsa", "/tmp/local.bin", "user@127.0.0.1:4433/ssh3-tests:remote.bin")

	if !slices.Contains(args, "-transfer") {
		t.Fatalf("the transfer client args %v do not carry the -transfer flag", args)
	}
	if slices.Contains(args, "-f") {
		t.Fatalf("the transfer client args %v still use -f: it is the ssh(1) background flag now", args)
	}
}

// The identity flag of the ssh(1) canon is -i; the fork's own -privkey stays
// a working alias (CTO_TASK §7c row 2).
func TestClientArgsUseTheCanonicalIdentityFlag(t *testing.T) {
	if !slices.Contains(transferClientArgs("/tmp/id_rsa"), "-i") {
		t.Fatalf("the client args do not carry the canonical -i identity flag")
	}
}
