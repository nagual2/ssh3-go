// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package client

import "errors"

// ErrNoAgentSocket reports that no SSH agent endpoint is reachable by
// configuration: on unix, SSH_AUTH_SOCK is unset; on windows, SSH_AUTH_SOCK
// is unset and the default OpenSSH agent pipe is not listening. A caller may
// treat it as "no agent" and go on without agent-based authentication.
var ErrNoAgentSocket = errors.New("SSH_AUTH_SOCK is unset")
