//go:build !unix

// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"testing"
)

func TestAgentPipeName(t *testing.T) {
	testCases := map[string]struct {
		sockPath string
		want     string
	}{
		"explicit pipe env wins":     {sockPath: `\\.\pipe\custom-agent`, want: `\\.\pipe\custom-agent`},
		"unset env rides default":    {sockPath: "", want: defaultAgentPipe},
		"unix path rides default":    {sockPath: `/tmp/agent.sock`, want: defaultAgentPipe},
		"windows path rides default": {sockPath: `C:\pipe\agent`, want: defaultAgentPipe},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if got := agentPipeName(tc.sockPath); got != tc.want {
				t.Fatalf("agentPipeName(%q) = %q, want %q", tc.sockPath, got, tc.want)
			}
		})
	}
}

func TestAgentDialExplicitPipeFailure(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", `\\.\pipe\ssh3-agent-dial-test-absent`)
	_, err := AgentDial()
	if err == nil {
		t.Fatal("dial on an absent explicit pipe must fail")
	}
	if errors.Is(err, ErrNoAgentSocket) {
		t.Fatalf("explicit pipe failure must be a hard error, got ErrNoAgentSocket: %v", err)
	}
}

func TestAgentDialDefaultPipeSoftFailure(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	// An agent service on the host makes the dial succeed; any failure must
	// stay the soft "no agent" one so a run without an agent keeps working.
	if _, err := AgentDial(); err != nil && !errors.Is(err, ErrNoAgentSocket) {
		t.Fatalf("dial on the implicit default pipe must fail softly, got %v", err)
	}
}
