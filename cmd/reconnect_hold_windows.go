// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmd

// The interactive hold console of the reconnect on Windows (SPEC §17.4): the
// honest degradation of the ssh3-c PuTTY-canon hold — the window stays, the
// banner names the loss and the auto-retry re-dials after the interval, but
// the raw console keys are not scanned (the conpty raw capture of Ctrl+R is
// not served in this wave): the re-dial rides the auto-retry alone and the
// Ctrl+C exits through the interrupt signal with the 255 verdict.

import (
	"fmt"
	"os"
	"os/signal"
	"time"
)

// reconnectVerdict is the outcome of the hold: re-dial or exit.
type reconnectVerdict int

const (
	reconnectRetry reconnectVerdict = iota
	reconnectExit
)

// runReconnectHold runs the hold window and returns the verdict with the
// exit code of the exit verdict (255, the C S3_CLI_EXIT_ERROR).
func runReconnectHold(p ReconnectPolicy, line1 string) (reconnectVerdict, int) {
	fmt.Fprintf(os.Stderr, "%s\n", line1)
	fmt.Fprintf(os.Stderr,
		"      the auto-reconnect every %d s - Ctrl+C exit\n",
		int(p.Interval/time.Second))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)

	timer := time.NewTimer(p.Interval)
	defer timer.Stop()
	select {
	case <-timer.C:
		fmt.Fprint(os.Stderr, "      reconnecting...\n")
		return reconnectRetry, 0
	case <-sig:
		return reconnectExit, exitReconnectError
	}
}
