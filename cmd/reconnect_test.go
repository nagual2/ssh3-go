// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

// The unit tests of the client reconnect (SPEC §17.4): the policy
// construction (-n, the placeholder enable, the interval env), the budget
// accounting and the run-shape gates mirroring the ssh3-c inactive gates.

import (
	"testing"
	"time"
)

func TestNewReconnectPolicyOffByDefault(t *testing.T) {
	p := newReconnectPolicy(false, "", "", "")
	if p.Mode != ReconnectOff {
		t.Fatalf("the default policy must stay off, got %d", p.Mode)
	}
	if p.Interval != defaultReconnectInterval {
		t.Fatalf("the default interval must ride %s, got %s", defaultReconnectInterval, p.Interval)
	}
}

func TestNewReconnectPolicySilentFromNoStdin(t *testing.T) {
	p := newReconnectPolicy(true, "hold", "hold", "")
	if p.Mode != ReconnectSilent {
		t.Fatalf("-n must win with the silent mode, got %d", p.Mode)
	}
	if p.Budget != reconnectBudgetRetries {
		t.Fatalf("the silent budget must ride %d, got %d", reconnectBudgetRetries, p.Budget)
	}
	if p.Interval != defaultReconnectInterval {
		t.Fatalf("the silent interval must ride the default, got %s", p.Interval)
	}
}

func TestNewReconnectPolicyHoldFromKeyword(t *testing.T) {
	p := newReconnectPolicy(false, "hold", "", "")
	if p.Mode != ReconnectHold {
		t.Fatalf("-o Reconnect=hold must arm the hold, got %d", p.Mode)
	}
}

func TestNewReconnectPolicyHoldFromEnv(t *testing.T) {
	p := newReconnectPolicy(false, "", "hold", "")
	if p.Mode != ReconnectHold {
		t.Fatalf("SSH3_CLI_RECONNECT=hold must arm the hold, got %d", p.Mode)
	}
}

func TestNewReconnectPolicyKeywordBeatsEnv(t *testing.T) {
	p := newReconnectPolicy(false, "off", "hold", "")
	if p.Mode != ReconnectOff {
		t.Fatalf("the explicit -o off must beat the env hold, got %d", p.Mode)
	}
}

func TestNewReconnectPolicyNoStdinBeatsKeyword(t *testing.T) {
	p := newReconnectPolicy(true, "hold", "", "")
	if p.Mode != ReconnectSilent {
		t.Fatalf("-n must beat the hold enable, got %d", p.Mode)
	}
}

func TestNewReconnectPolicyIntervalEnv(t *testing.T) {
	p := newReconnectPolicy(true, "", "", "2")
	if p.Interval != 2*time.Second {
		t.Fatalf("the interval env of 2 must ride 2s, got %s", p.Interval)
	}
	p = newReconnectPolicy(true, "", "", "0")
	if p.Interval != defaultReconnectInterval {
		t.Fatalf("the zero interval must fall back to the default, got %s", p.Interval)
	}
	p = newReconnectPolicy(true, "", "", "garbage")
	if p.Interval != defaultReconnectInterval {
		t.Fatalf("the invalid interval must fall back to the default, got %s", p.Interval)
	}
	p = newReconnectPolicy(true, "", "", "-5")
	if p.Interval != defaultReconnectInterval {
		t.Fatalf("the negative interval must fall back to the default, got %s", p.Interval)
	}
}

func TestParseReconnectKeyword(t *testing.T) {
	if mode, set, err := parseReconnectKeyword("hold"); err != nil || !set || mode != ReconnectHold {
		t.Fatalf("hold must parse to the armed hold, got mode=%d set=%t err=%v", mode, set, err)
	}
	if mode, set, err := parseReconnectKeyword("HOLD"); err != nil || !set || mode != ReconnectHold {
		t.Fatalf("the keyword parse is case-insensitive, got mode=%d set=%t err=%v", mode, set, err)
	}
	if mode, set, err := parseReconnectKeyword("off"); err != nil || !set || mode != ReconnectOff {
		t.Fatalf("off must parse to the explicit off, got mode=%d set=%t err=%v", mode, set, err)
	}
	if _, set, err := parseReconnectKeyword(""); err != nil || set {
		t.Fatalf("the empty value defers to the env, got set=%t err=%v", set, err)
	}
	if _, _, err := parseReconnectKeyword("sometimes"); err == nil {
		t.Fatalf("an unknown value must refuse")
	}
}

func TestReconnectPolicyExceeded(t *testing.T) {
	silent := ReconnectPolicy{Mode: ReconnectSilent, Budget: reconnectBudgetRetries}
	for attempts := 1; attempts <= reconnectBudgetRetries; attempts++ {
		if silent.Exceeded(attempts) {
			t.Fatalf("the attempt %d of %d must ride (the budget covers the parking window)", attempts, reconnectBudgetRetries)
		}
	}
	if !silent.Exceeded(reconnectBudgetRetries + 1) {
		t.Fatalf("the attempt past the budget must refuse")
	}
	hold := ReconnectPolicy{Mode: ReconnectHold}
	if hold.Exceeded(1000) {
		t.Fatalf("the hold carries no budget: the window keeps retrying")
	}
	off := ReconnectPolicy{Mode: ReconnectOff}
	if off.Exceeded(1000) {
		t.Fatalf("the off policy never dispatches a retry")
	}
}

// reconnectShapeCase builds one gate table row.
type reconnectShapeCase struct {
	name    string
	shape   reconnectShape
	hold    bool
	predial bool
	silent  bool
}

func TestReconnectShapeGates(t *testing.T) {
	cases := []reconnectShapeCase{
		{
			name:  "the plain pty shell holds",
			shape: reconnectShape{console: true, ptyWanted: true, noCommand: true},
			hold:  true, predial: true,
		},
		{
			name:    "the headless shell holds before the dial",
			shape:   reconnectShape{console: true, noCommand: true},
			predial: true,
		},
		{
			name:  "the pipe console holds nothing",
			shape: reconnectShape{noCommand: true},
		},
		{
			name:  "the exec keeps the single-run contract",
			shape: reconnectShape{console: true, ptyWanted: true},
		},
		{
			name:  "the sftp keeps the single-run contract",
			shape: reconnectShape{console: true, ptyWanted: true, noCommand: true, sftpOrTransfer: true},
		},
		{
			name:  "the transfer keeps the single-run contract",
			shape: reconnectShape{console: true, ptyWanted: true, noCommand: true, sftpOrTransfer: true},
		},
		{
			name:  "the subsystem keeps the single-run contract",
			shape: reconnectShape{console: true, ptyWanted: true, noCommand: true, subsystem: true},
		},
		{
			name:  "the forwards keep the single-run contract",
			shape: reconnectShape{console: true, ptyWanted: true, noCommand: true, hasForwards: true},
		},
		{
			name:  "-N keeps the single-run contract",
			shape: reconnectShape{console: true, ptyWanted: true, noCommand: true, noSession: true},
		},
		{
			name:  "the control master keeps the single-run contract",
			shape: reconnectShape{console: true, ptyWanted: true, noCommand: true, controlMaster: true},
		},
		{
			name:  "the jump chain keeps the single-run contract",
			shape: reconnectShape{console: true, ptyWanted: true, noCommand: true, jump: true},
		},
		{
			name:   "-n rides the silent flavor of the shell",
			shape:  reconnectShape{noCommand: true, noStdin: true},
			silent: true,
		},
		{
			name:   "-n never holds (the silent flavor owns the run)",
			shape:  reconnectShape{console: true, ptyWanted: true, noCommand: true, noStdin: true},
			silent: true,
		},
		{
			name:  "the silent flavor needs -n",
			shape: reconnectShape{console: true, ptyWanted: true, noCommand: true},
			hold:  true, predial: true,
		},
		{
			name:  "-n does not ride the exec shape",
			shape: reconnectShape{noStdin: true},
		},
		{
			name:  "-n does not ride the forwards",
			shape: reconnectShape{noCommand: true, noStdin: true, hasForwards: true},
		},
	}
	for _, tc := range cases {
		if got := tc.shape.holdAllowed(); got != tc.hold {
			t.Errorf("%s: holdAllowed = %t, want %t", tc.name, got, tc.hold)
		}
		if got := tc.shape.holdPredial(); got != tc.predial {
			t.Errorf("%s: holdPredial = %t, want %t", tc.name, got, tc.predial)
		}
		if got := tc.shape.silentAllowed(); got != tc.silent {
			t.Errorf("%s: silentAllowed = %t, want %t", tc.name, got, tc.silent)
		}
	}
}

func TestExitReconnectError(t *testing.T) {
	if exitReconnectError != 255 {
		t.Fatalf("the reconnect verdicts must exit 255 (the C canon S3_CLI_EXIT_ERROR), got %d", exitReconnectError)
	}
}
