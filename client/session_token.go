// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"sync"
)

// The client session token (SPEC §17.1): 16 random bytes, hex (32 chars),
// generated once per process. Every 1-RTT CONNECT of the process carries
// the same token — the re-dials of the same process (auto-retries, Ctrl+R)
// ride it too — and a new process rolls a new one. The server parks the
// live sessions of a dead connection under the token and re-attaches them
// on the next authenticated dial of the same user carrying the same token.
// The 0-RTT early flight never carries the token (the anti-replay canon:
// the token is only meaningful behind the auth verdict).
//
// SSH3_SESSION_TOKEN overrides the random draw: the e2e legs pin one token
// across two client processes.

const sessionTokenLen = 16

var (
	sessionTokenOnce  sync.Once
	sessionTokenValue string
)

// SessionToken returns the process-lifetime session token, empty when the
// random draw failed (the header is omitted — a tokenless dial rides an
// ordinary fresh session on the server).
func SessionToken() string {
	sessionTokenOnce.Do(func() {
		if pinned := os.Getenv("SSH3_SESSION_TOKEN"); pinned != "" {
			sessionTokenValue = pinned
			return
		}
		b := make([]byte, sessionTokenLen)
		if _, err := rand.Read(b); err != nil {
			// the tokenless dial rides an ordinary fresh session
			return
		}
		sessionTokenValue = hex.EncodeToString(b)
	})
	return sessionTokenValue
}
