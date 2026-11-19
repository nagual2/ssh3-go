// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

import (
	"sync/atomic"
	"testing"
	"time"

	ssh3 "github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/util"
)

// P4-03: the P3-01 fix — undo the pre-admission runningSessions insert when
// the channel budget refuses the session — was verified only by reading the
// accept loop. admitSessionChannel owns that pairing now; these tests pin it
// so a future refactor of the accept loop cannot silently restore the leak.
func TestAdmitSessionChannelRefusalPrunesRunningSessions(t *testing.T) {
	sessions := util.NewSyncMap[ssh3.Channel, *runningSession]()
	channels := newBudget(1)
	channels.tryAcquire() // exhaust the budget: the next admission must be refused

	var refusals atomic.Int32
	spawn := func(channel ssh3.Channel, run func()) bool {
		if !channels.tryAcquire() {
			refusals.Add(1)
			return false
		}
		go run()
		return true
	}
	stub := &stubSFTPChannel{}
	run := func() { t.Error("the session goroutine must not start on a budget refusal") }

	admitted := admitSessionChannel(&sessions, channels, stub, nil, spawn, run)

	if admitted {
		t.Fatal("admission succeeded despite the exhausted budget")
	}
	if refusals.Load() != 1 {
		t.Errorf("spawn was consulted %d times, want 1", refusals.Load())
	}
	if _, ok := sessions.Get(stub); ok {
		t.Error("runningSessions entry leaked: the refusal did not undo the pre-admission insert (P3-01 regression)")
	}
}

// the happy path: the entry must be visible to the spawn (the request
// handlers resolve the session through it) and stay registered
func TestAdmitSessionChannelAdmitsAndRegisters(t *testing.T) {
	sessions := util.NewSyncMap[ssh3.Channel, *runningSession]()
	channels := newBudget(1)

	var insertVisibleAtSpawn atomic.Bool
	runStarted := make(chan struct{})
	spawn := func(channel ssh3.Channel, run func()) bool {
		_, ok := sessions.Get(channel)
		insertVisibleAtSpawn.Store(ok)
		if !channels.tryAcquire() {
			return false
		}
		go run()
		return true
	}
	stub := &stubSFTPChannel{}

	admitted := admitSessionChannel(&sessions, channels, stub, nil, spawn, func() { close(runStarted) })

	if !admitted {
		t.Fatal("admission refused despite a free budget slot")
	}
	if !insertVisibleAtSpawn.Load() {
		t.Error("the runningSessions entry was not visible at spawn time")
	}
	select {
	case <-runStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("the session goroutine never started")
	}
	if _, ok := sessions.Get(stub); !ok {
		t.Error("the runningSessions entry vanished on a successful admission")
	}
}
