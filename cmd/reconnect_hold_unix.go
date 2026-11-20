// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cmd

// The interactive hold console of the reconnect (SPEC §17.4, the ssh3-c
// canon waves 12/16/17): the window stays, the banner names the loss, the
// auto-retry re-dials after the interval, Ctrl+R retries immediately, Ctrl+C
// exits 255. The hold owns the console in raw mode and polls the keys with
// select, so no background reader competes with the re-dialed session's
// stdin pump for the console bytes.

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// reconnectVerdict is the outcome of the hold: re-dial or exit.
type reconnectVerdict int

const (
	reconnectRetry reconnectVerdict = iota
	reconnectExit
)

// reconnectHoldPollSlice bounds one select wait so the dwell deadline is
// re-checked while the keys stay served.
const reconnectHoldPollSlice = 200 * time.Millisecond

// runReconnectHold runs the hold window and returns the verdict with the
// exit code of the exit verdict (255, the C S3_CLI_EXIT_ERROR).
func runReconnectHold(p ReconnectPolicy, line1 string) (reconnectVerdict, int) {
	fmt.Fprintf(os.Stderr, "%s\n", line1)
	fmt.Fprintf(os.Stderr,
		"      the auto-reconnect every %d s - Ctrl+R retry now, Ctrl+C exit\n",
		int(p.Interval/time.Second))

	fd := int(os.Stdin.Fd())
	oldState, rawErr := term.MakeRaw(fd)
	if rawErr != nil {
		// the console refuses the raw mode: the honest degradation — the
		// keys are not scanned, the auto-retry still rides
		time.Sleep(p.Interval)
		fmt.Fprint(os.Stderr, "      reconnecting...\n")
		return reconnectRetry, 0
	}
	defer term.Restore(fd, oldState)

	deadline := time.Now().Add(p.Interval)
	buf := make([]byte, 64)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			fmt.Fprint(os.Stderr, "      reconnecting...\n")
			return reconnectRetry, 0
		}

		poll := remain
		if poll > reconnectHoldPollSlice {
			poll = reconnectHoldPollSlice
		}
		if !reconnectHoldPollReadable(fd, poll) {
			continue
		}

		n, err := syscall.Read(fd, buf)
		if err != nil || n <= 0 {
			continue
		}
		for _, b := range buf[:n] {
			switch b {
			case 0x12: // Ctrl+R: the re-dial rides at once
				fmt.Fprint(os.Stderr, "      reconnecting...\n")
				return reconnectRetry, 0
			case 0x03: // Ctrl+C: the exit verdict
				return reconnectExit, exitReconnectError
			}
		}
	}
}

// reconnectHoldPollReadable reports whether the console descriptor carries
// readable bytes within the wait slice.
func reconnectHoldPollReadable(fd int, wait time.Duration) bool {
	var set unix.FdSet
	wordBits := int(unsafe.Sizeof(set.Bits[0])) * 8
	set.Bits[fd/wordBits] |= 1 << (uint(fd) % uint(wordBits))
	tv := unix.NsecToTimeval(wait.Nanoseconds())
	n, err := unix.Select(fd+1, &set, nil, nil, &tv)
	return err == nil && n > 0
}
