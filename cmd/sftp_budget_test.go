// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

import (
	"io"
	"sync/atomic"
	"testing"
	"time"

	ssh3 "github.com/francoismichel/ssh3"
	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util/unix_util"
)

// stubSFTPChannel only implements what the in-process serve path touches
// before its first read; every other method is a nil call on the embedded
// interface and must never be reached.
type stubSFTPChannel struct {
	ssh3.Channel
	readStarted chan struct{}
	releaseRead chan struct{}
	reads       atomic.Int32
	closes      atomic.Int32
}

func newStubSFTPChannel() *stubSFTPChannel {
	return &stubSFTPChannel{readStarted: make(chan struct{}, 1), releaseRead: make(chan struct{})}
}

func (s *stubSFTPChannel) NextData() (ssh3Messages.SSHDataType, []byte, error) {
	// the RWC read path of the ring wave pulls data frames through
	// NextData (channel_read.go): this is the serve path's first read
	s.reads.Add(1)
	select {
	case s.readStarted <- struct{}{}:
	default:
	}
	<-s.releaseRead
	return 0, nil, io.EOF
}

func (s *stubSFTPChannel) Close() {
	s.closes.Add(1)
}

// serveSFTPSubsystemAsync runs the entry point with a per-test budget and
// jail-mode scope, restoring the globals afterwards.
func serveSFTPSubsystemAsync(t *testing.T, user *unix_util.User, channel ssh3.Channel) <-chan struct{} {
	t.Helper()
	prevMode, prevBudgets := sftpJailMode, sftpChildrenBudgets
	t.Cleanup(func() { sftpJailMode, sftpChildrenBudgets = prevMode, prevBudgets })
	sftpJailMode = sftpJailLexical
	done := make(chan struct{})
	go func() {
		serveSFTPSubsystem(user, channel)
		close(done)
	}()
	return done
}

// P3-04: the per-user sftp cap must hold in the in-process (lexical or
// unprivileged) mode too — an exhausted budget must refuse the channel
// instead of silently serving it.
func TestSFTPSubsystemRefusesWhenUserBudgetExhaustedInProcess(t *testing.T) {
	const limit = 16
	const user = "carol"
	sftpChildrenBudgets = newUserBudgets(limit)
	budget := sftpChildrenBudgets.budgetFor(user)
	for i := 0; i < limit; i++ {
		budget.tryAcquire()
	}

	stub := newStubSFTPChannel()
	done := serveSFTPSubsystemAsync(t, &unix_util.User{Username: user, Dir: t.TempDir()}, stub)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(stub.releaseRead)
		t.Fatal("serveSFTPSubsystem did not return on an exhausted user budget")
	}
	if reads := stub.reads.Load(); reads != 0 {
		t.Errorf("the in-process sftp server started despite the exhausted user budget (%d reads)", reads)
	}
	if closes := stub.closes.Load(); closes != 1 {
		t.Errorf("the refused sftp channel was closed %d times, want 1", closes)
	}
}

// P3-04: while an in-process sftp session runs, it holds the user's budget
// slot and releases it on exit.
func TestSFTPSubsystemInProcessHoldsAndReleasesUserBudgetSlot(t *testing.T) {
	const limit = 16
	const user = "carol"
	sftpChildrenBudgets = newUserBudgets(limit)
	budget := sftpChildrenBudgets.budgetFor(user)
	for i := 0; i < limit-1; i++ {
		budget.tryAcquire()
	}

	stub := newStubSFTPChannel()
	done := serveSFTPSubsystemAsync(t, &unix_util.User{Username: user, Dir: t.TempDir()}, stub)
	select {
	case <-stub.readStarted:
	case <-time.After(2 * time.Second):
		close(stub.releaseRead)
		t.Fatal("the in-process sftp server did not start with a free budget slot")
	}
	if got := budget.current(); got != limit {
		t.Errorf("budget current = %d while serving, want %d (slot not held)", got, limit)
	}
	close(stub.releaseRead)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveSFTPSubsystem did not return after the channel ended")
	}
	if got := budget.current(); got != limit-1 {
		t.Errorf("budget current = %d after serving, want %d (slot not released)", got, limit-1)
	}
}
