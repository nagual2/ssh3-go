// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmd

// The Windows console keeps the plain stdin: the conpty handles refuse the
// read deadlines whatever the wrapper, so there is nothing to gain — the
// stale stdin pump of a dead session exits on its next keypress (the hold
// window degrades to the auto-retry and the Ctrl+C signal verdict).

func makeDeadlineCapableStdin() {}
