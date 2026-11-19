// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package park

import (
	"sync"
	"time"
)

// Session is the opaque live state a parked record owns: the child the lot
// must be able to kill+reap on expiry, eviction or teardown. The concrete
// implementation (the server's runningSession) keeps draining its output
// into the record's ring while parked.
type Session interface {
	// ParkedKill kills and reaps the parked child and releases the fds.
	ParkedKill()
	// ParkedExited reports whether the child already terminated while
	// parked (its verdict rides the re-attach).
	ParkedExited() bool
}

// Record is one parked session: the identity it parked under, the moment it
// parked, the output ring and the exit verdict a child may have delivered
// while parked. The verdict stays readable after Take so the re-attach can
// replay it.
type Record struct {
	User     string // the authenticated user at park time; empty = the daemon identity
	Token    string // the x-ssh3-session-token of the dead connection
	ParkedAt time.Time

	mu         sync.Mutex
	ring       *Ring
	session    Session
	exited     bool
	exitStatus uint64
	exitSignal string
}

// Ring returns the parked output ring; the parked drain writes it, the
// re-attach replay consumes it.
func (r *Record) Ring() *Ring {
	return r.ring
}

// SetExit captures the verdict of a child that terminated while parked.
// An empty signal means a plain exit status.
func (r *Record) SetExit(status uint64, signal string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exited = true
	r.exitStatus = status
	r.exitSignal = signal
}

// Exited reports whether the child terminated while parked.
func (r *Record) Exited() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exited
}

// ExitStatus returns the recorded exit status (meaningful when the signal
// is empty).
func (r *Record) ExitStatus() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exitStatus
}

// ExitSignal returns the recorded wire signal name (without the SIG
// prefix), empty for a plain exit.
func (r *Record) ExitSignal() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exitSignal
}

// Lot is the bounded table of parked sessions: the expiry rides a lazy
// sweep (on Add and Find) backstopped by the server's ticker, the cap
// evicts the oldest record, max=0 disables the lot (the strict openssh
// compat: the teardown kills the child as before).
type Lot struct {
	mu       sync.Mutex
	max      int
	lifetime time.Duration
	table    []*Record // fixed cap with nil holes, the C canon shape
}

// NewLot builds a lot holding at most max records, each living at most
// lifetime past its park moment. max=0 disables the lot.
func NewLot(max int, lifetime time.Duration) *Lot {
	if max < 0 {
		max = 0
	}
	return &Lot{max: max, lifetime: lifetime, table: make([]*Record, max)}
}

// Enabled reports whether the lot accepts records.
func (l *Lot) Enabled() bool {
	return l != nil && l.max > 0
}

// Count reports the number of parked records.
func (l *Lot) Count() int {
	if !l.Enabled() {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.countLocked()
}

func (l *Lot) countLocked() int {
	n := 0
	for _, rec := range l.table {
		if rec != nil {
			n++
		}
	}
	return n
}

// Add parks a session: the record takes over the session, sweeps the
// expired records first (the lazy sweep) and evicts the oldest record when
// the table is full. Returns nil when the lot is disabled or the arguments
// are broken.
func (l *Lot) Add(user, token string, sess Session, now time.Time) *Record {
	if !l.Enabled() || token == "" || sess == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked(now)

	if l.countLocked() >= l.max {
		// The oldest record dies for the fresh entry.
		var victim *Record
		for _, rec := range l.table {
			if rec != nil && (victim == nil || rec.ParkedAt.Before(victim.ParkedAt)) {
				victim = rec
			}
		}
		if victim == nil {
			return nil
		}
		l.removeLocked(victim)
		victim.session.ParkedKill()
	}

	rec := &Record{
		User:     user,
		Token:    token,
		ParkedAt: now,
		ring:     NewRing(),
		session:  sess,
	}
	for i := range l.table {
		if l.table[i] == nil {
			l.table[i] = rec
			return rec
		}
	}
	return nil // unreachable with the eviction above
}

// Find looks a record up by user+token, sweeping the expired records first.
// The token must match exactly; the user is the second gate — a record that
// parked under an empty user (the daemon identity) binds on the token alone.
// Returns nil when nothing binds: the dial rides an ordinary fresh session.
func (l *Lot) Find(user, token string, now time.Time) *Record {
	if !l.Enabled() || token == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked(now)

	for _, rec := range l.table {
		if rec == nil || rec.Token != token {
			continue
		}
		if rec.User == "" || (user != "" && rec.User == user) {
			return rec
		}
	}
	return nil
}

// Take hands the ownership back to the attaching channel: the record leaves
// the lot and the session rides the result exactly once. The record object
// stays readable (the exit verdict, the ring) for the replay.
func (l *Lot) Take(rec *Record) (Session, bool) {
	if rec == nil || !l.Enabled() {
		return nil, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.removeLocked(rec) {
		return nil, false
	}
	rec.mu.Lock()
	sess := rec.session
	rec.mu.Unlock()
	return sess, sess != nil
}

// Sweep kills and removes every record older than the lifetime (the lazy
// expiry, the dos-guard shape).
func (l *Lot) Sweep(now time.Time) {
	if !l.Enabled() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
}

func (l *Lot) sweepLocked(now time.Time) {
	if l.lifetime <= 0 {
		return
	}
	for _, rec := range l.table {
		if rec == nil {
			continue
		}
		if now.Sub(rec.ParkedAt) >= l.lifetime {
			l.removeLocked(rec)
			rec.session.ParkedKill()
		}
	}
}

func (l *Lot) removeLocked(rec *Record) bool {
	for i := range l.table {
		if l.table[i] == rec {
			l.table[i] = nil
			return true
		}
	}
	return false
}

// Teardown kills every parked child (the daemon exit sweep).
func (l *Lot) Teardown() {
	if !l.Enabled() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, rec := range l.table {
		if rec != nil {
			rec.session.ParkedKill()
		}
	}
	l.table = make([]*Record, l.max)
}
