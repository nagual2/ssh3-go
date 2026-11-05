//go:build unix

// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"net"
	"path/filepath"
	"testing"
)

func TestAgentDialUnixRequiresEnv(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	_, err := AgentDial()
	if !errors.Is(err, ErrNoAgentSocket) {
		t.Fatalf("unset SSH_AUTH_SOCK must yield ErrNoAgentSocket, got %v", err)
	}
}

func TestAgentDialUnixConnects(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	t.Setenv("SSH_AUTH_SOCK", sock)
	conn, err := AgentDial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
}

func TestAgentDialUnixAbsentSocket(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "absent.sock"))
	_, err := AgentDial()
	if err == nil || errors.Is(err, ErrNoAgentSocket) {
		t.Fatalf("dial to an absent socket must be a hard error, got %v", err)
	}
}
