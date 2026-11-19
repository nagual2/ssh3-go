// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"regexp"
	"sync"
	"testing"
)

// The session token (SPEC §17.1): 16 random bytes hex (32 chars), one draw
// per process, the SSH3_SESSION_TOKEN env pins it across processes (the e2e).

// resetTokenOnce drops the process-wide draw so a test rolls fresh.
func resetTokenOnce() { sessionTokenOnce = sync.Once{} }

func TestSessionTokenShape(t *testing.T) {
	t.Setenv("SSH3_SESSION_TOKEN", "")
	resetTokenOnce()
	token := SessionToken()
	if len(token) != 32 {
		t.Fatalf("the session token is %d chars, want the 32-hex canon (SPEC §17.1)", len(token))
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(token) {
		t.Fatalf("the session token %q is not 32 lowercase hex chars", token)
	}
}

func TestSessionTokenStablePerProcess(t *testing.T) {
	t.Setenv("SSH3_SESSION_TOKEN", "")
	resetTokenOnce()
	first := SessionToken()
	second := SessionToken()
	if first != second {
		t.Fatalf("the token drifted inside one process: %q vs %q", first, second)
	}
}

func TestSessionTokenEnvPin(t *testing.T) {
	resetTokenOnce()
	t.Setenv("SSH3_SESSION_TOKEN", "aabbccdd00112233445566778899aabb")
	if got := SessionToken(); got != "aabbccdd00112233445566778899aabb" {
		t.Fatalf("the env pin did not ride: %q", got)
	}
}
