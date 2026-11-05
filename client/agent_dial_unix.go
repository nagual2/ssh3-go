//go:build unix

// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"net"
	"os"
)

// AgentDial connects to the local SSH agent over its unix socket. The socket
// path must be set in SSH_AUTH_SOCK; an unset variable means no agent.
func AgentDial() (net.Conn, error) {
	sockPath := os.Getenv("SSH_AUTH_SOCK")
	if sockPath == "" {
		return nil, ErrNoAgentSocket
	}
	return net.Dial("unix", sockPath)
}
