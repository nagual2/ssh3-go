//go:build !unix

// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Microsoft/go-winio"
)

// defaultAgentPipe is the named pipe the OpenSSH agent service listens on.
const defaultAgentPipe = `\\.\pipe\openssh-ssh-agent`

// agentPipeName resolves the agent endpoint from an SSH_AUTH_SOCK value: an
// explicit named-pipe path wins, anything else (an unset variable or a
// unix-style socket path inherited from an ssh config) falls back to the
// OpenSSH default pipe.
func agentPipeName(sockPath string) string {
	if strings.HasPrefix(sockPath, `\\.\`) {
		return sockPath
	}
	return defaultAgentPipe
}

// AgentDial connects to the local SSH agent over its named pipe. A failed
// dial of the implicit default pipe means no agent is running and comes back
// as ErrNoAgentSocket, so a run without an agent keeps working; an explicit
// SSH_AUTH_SOCK pipe that refuses the connection is a hard error.
func AgentDial() (net.Conn, error) {
	sockPath := os.Getenv("SSH_AUTH_SOCK")
	explicit := strings.HasPrefix(sockPath, `\\.\`)
	conn, err := winio.DialPipe(agentPipeName(sockPath), nil)
	if err != nil {
		if explicit {
			return nil, fmt.Errorf("dial agent pipe %s: %w", sockPath, err)
		}
		return nil, ErrNoAgentSocket
	}
	return conn, nil
}
