// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

// The client reconnect (SPEC §17.4): the interactive pty console holds the
// window on a connection loss — the banner names the loss, the auto-retry
// re-dials the same peer in the same process (the session token of
// client/session_token.go rides every dial, so the server re-attaches the
// parked session), Ctrl+R retries immediately, Ctrl+C exits 255. The -n runs
// ride the silent flavor of the same mechanics: no banners, a retry budget of
// ten attempts at the reconnect interval covering the server parking window
// (SSH3_SESSION_PARK_SECONDS defaults to 300), one error line and exit 255 on
// the exhaustion; the first ride that lived resets the budget.
//
// The mechanics mirror the ssh3-c client (the hold waves 12/16/17, the silent
// -n of the automatic mode): the run-shape gates below mirror the C
// inactive_gate — the reconnect serves the plain session shell only, the
// shapes carrying listeners or a master (exec, sftp/transfer, subsystem,
// forwards, -N, control master, jump) keep the single-run contract.
//
// The enablement: -n arms the silent flavor directly; the interactive hold
// arms through the placeholder until the owner names the final key
// (-o Reconnect=hold or SSH3_CLI_RECONNECT=hold). The default stays off, so
// the pre-reconnect behavior of every shape is untouched.

import (
	"os"
	"strconv"
	"time"
)

// ReconnectMode selects the reconnect semantics of a run (SPEC §17.4).
type ReconnectMode int

const (
	ReconnectOff    ReconnectMode = iota // the single-run contract (the default)
	ReconnectHold                        // the interactive hold: banner, Ctrl+R, auto-retry
	ReconnectSilent                      // the -n flavor: no banners, the retry budget
)

const (
	// reconnectBudgetRetries is the silent-mode budget: ten retries cover the
	// server parking window at the default interval (10 x 30 s = 300 s).
	reconnectBudgetRetries = 10

	// defaultReconnectInterval is the auto-retry dwell of the hold and of the
	// silent reconnect (the C canon S3_CLI_RECONNECT_INTERVAL).
	defaultReconnectInterval = 30 * time.Second

	// reconnectIntervalEnv overrides the auto-retry dwell in whole seconds
	// (the Go spelling of the C S3_CLI_RECONNECT_INTERVAL). An invalid value
	// falls back to the default.
	reconnectIntervalEnv = "SSH3_CLI_RECONNECT_INTERVAL"

	// reconnectModeEnv arms the interactive hold through the placeholder
	// ("hold"); the final key comes with the owner's decision.
	reconnectModeEnv = "SSH3_CLI_RECONNECT"

	// exitReconnectError is the exit code of the reconnect refusals: the
	// budget exhaustion and the Ctrl+C of the hold (the C S3_CLI_EXIT_ERROR).
	exitReconnectError = 255

	// reconnectBudgetExhaustedLine is the single error line of the silent
	// budget exhaustion (the C canon ddef881/6dcc744).
	reconnectBudgetExhaustedLine = "ssh3: the reconnect budget exhausted (the server session parking window)"
)

// ReconnectPolicy carries the reconnect mechanics of a run (SPEC §17.4).
type ReconnectPolicy struct {
	Mode     ReconnectMode
	Budget   int           // the silent-mode attempt budget
	Interval time.Duration // the auto-retry dwell
}

// Exceeded reports whether the reconnect attempt of the silent mode exceeds
// the budget. The counter counts the attempts since the last ride, so the
// ten first retries ride and the eleventh refuses (the C dispatch shape).
func (p ReconnectPolicy) Exceeded(attempts int) bool {
	if p.Mode != ReconnectSilent {
		// the hold keeps retrying (the window watches the banner), the off
		// policy never dispatches a retry at all
		return false
	}
	return attempts > p.Budget
}

// parseReconnectKeyword parses the placeholder enable value: "hold" arms the
// interactive hold, "off" keeps the single-run (the explicit refusal beats
// the env), the empty value is unset and defers to the env. The parse is
// case-insensitive like the other -o keywords.
func parseReconnectKeyword(value string) (ReconnectMode, bool, error) {
	switch value {
	case "":
		return ReconnectOff, false, nil
	case "hold", "HOLD", "Hold":
		return ReconnectHold, true, nil
	case "off", "OFF", "Off":
		return ReconnectOff, true, nil
	default:
		return ReconnectOff, false, ErrBadReconnectKeyword
	}
}

// ErrBadReconnectKeyword refuses an unknown placeholder value.
var ErrBadReconnectKeyword = reconnectKeywordError("the Reconnect option wants \"hold\" or \"off\"")

type reconnectKeywordError string

func (e reconnectKeywordError) Error() string { return string(e) }

// newReconnectPolicy builds the policy of a run: -n wins with the silent
// mode (the C -n semantics), the explicit -o Reconnect value beats the env,
// the env "hold" arms the interactive hold, everything else stays off. The
// interval rides reconnectIntervalEnv in whole seconds.
func newReconnectPolicy(noStdin bool, keyword, modeEnv, intervalEnv string) ReconnectPolicy {
	interval := defaultReconnectInterval
	if secs, err := strconv.Atoi(intervalEnv); err == nil && secs > 0 {
		interval = time.Duration(secs) * time.Second
	}
	if noStdin {
		return ReconnectPolicy{Mode: ReconnectSilent, Budget: reconnectBudgetRetries, Interval: interval}
	}
	if mode, set, err := parseReconnectKeyword(keyword); err == nil && set {
		if mode == ReconnectHold {
			return ReconnectPolicy{Mode: ReconnectHold, Interval: interval}
		}
		return ReconnectPolicy{Mode: ReconnectOff, Interval: interval}
	}
	if modeEnv == "hold" {
		return ReconnectPolicy{Mode: ReconnectHold, Interval: interval}
	}
	return ReconnectPolicy{Mode: ReconnectOff, Interval: interval}
}

// reconnectShape carries the resolved run shape for the reconnect gates: the
// mirror of the ssh3-c client's gate inputs (the inactive gate and its
// pre-dial variant).
type reconnectShape struct {
	console        bool // the local console exists (the stdin is a terminal)
	ptyWanted      bool // the session requests a pty (the RequestTTY policy)
	noCommand      bool // the shell shape (no remote command)
	sftpOrTransfer bool // the file transfer modes own the session
	subsystem      bool // a remote subsystem owns the session channel
	hasForwards    bool // -L/-D/-R: the shapes carrying listeners
	noSession      bool // -N: the connection holder
	controlMaster  bool // the control master multiplexing
	jump           bool // the -J proxy jump chain
	noStdin        bool // -n: the silent flavor
}

// sessionShell tells whether the run is the plain session shell: the only
// shape the reconnect serves (the C gate comment: the shapes carrying the
// listeners or the master keep the single-run contract).
func (s reconnectShape) sessionShell() bool {
	return s.noCommand && !s.sftpOrTransfer && !s.subsystem && !s.hasForwards &&
		!s.noSession && !s.controlMaster && !s.jump
}

// holdAllowed mirrors the C s3_cli_inactive_gate: the plain pty console
// shell without the exec, the sftp, the forwards or the master, and never
// for -n (the silent flavor owns that run).
func (s reconnectShape) holdAllowed() bool {
	return s.console && s.ptyWanted && s.sessionShell() && !s.noStdin
}

// holdPredial mirrors the C s3_cli_inactive_gate_predial (the wave 16): the
// same interactive shape minus the pty — the pty arms with the session
// bring-up, so the dial failures land on the hold before any session existed.
func (s reconnectShape) holdPredial() bool {
	return s.console && s.sessionShell() && !s.noStdin
}

// silentAllowed mirrors the C -n arm: the silent flavor rides the same
// session shell, with or without a console (the scripted runs are headless).
func (s reconnectShape) silentAllowed() bool {
	return s.noStdin && s.sessionShell()
}

// unblockStaleStdinPump reclaims the console from the stdin pump of a dead
// session: the pump holds one blocking console read and would steal the
// bytes of the hold window or of the next ride's pump. A past read deadline
// aborts the pending read (the Go spelling of the C CancelIoEx on its reader
// thread); where the runtime cannot poll the console (the Windows console
// handles refuse deadlines) the pump exits on its next keypress instead —
// the honest degradation, the auto-retry does not read the console there.
func unblockStaleStdinPump() {
	var stdin any = os.Stdin
	deadliner, ok := stdin.(interface{ SetReadDeadline(time.Time) error })
	if !ok {
		return
	}
	if deadliner.SetReadDeadline(time.Now().Add(-time.Millisecond)) != nil {
		return
	}
	// give the stale pump the moment to observe the aborted read and exit,
	// then clear the deadline for the hold window and the next ride
	time.Sleep(100 * time.Millisecond)
	_ = deadliner.SetReadDeadline(time.Time{})
}
