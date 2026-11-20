// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

// The deadline-capable console (the reconnect reclaim, SPEC §17.4): a tty fd
// is not pollable as-is, so the console rides a non-blocking dup — the poller
// serves the reads with the blocking semantics and the read deadlines work,
// so the dispatch of a dead session reclaims the console from its stale
// stdin pump deterministically. Non-terminals keep the plain stdin (the
// pipes already support the deadlines).

import (
	"os"

	"golang.org/x/sys/unix"
)

func makeDeadlineCapableStdin() {
	if fd, err := unix.Dup(int(os.Stdin.Fd())); err == nil {
		if err := unix.SetNonblock(fd, true); err == nil {
			if f := os.NewFile(uintptr(fd), "/dev/stdin-dup"); f != nil {
				os.Stdin = f
			}
		}
	}
}
