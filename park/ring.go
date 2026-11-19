// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

// Package park implements the server-side parking lot of interactive
// sessions (SPEC §17): when the QUIC connection dies mid-session, the live
// child (a pty shell or an exec command) does not have to die with it — the
// session detaches from its channel, its output drains into a bounded ring
// and the lot holds the record until the next authenticated dial of the
// same user with the same session token re-attaches it. Expired records are
// killed and reaped by a lazy sweep; the table is bounded with oldest
// eviction; max=0 disables the lot entirely (the strict openssh compat).
package park

// RingSize is the canon capacity of the parked output ring (SPEC §17.2).
const RingSize = 32 * 1024

// Ring is the bounded FIFO of the parked output: the newest bytes always
// win, the oldest leave silently once the capacity is exhausted
// (drop-oldest, SPEC §17.2). Not thread-safe by itself: the session owner
// serializes the parked writes and the re-attach replay.
type Ring struct {
	buf  [RingSize]byte
	head int // the read position
	len  int // the occupied span
}

// NewRing builds an empty ring.
func NewRing() *Ring {
	return &Ring{}
}

// Len reports the occupied byte count.
func (r *Ring) Len() int {
	return r.len
}

// Write appends p, dropping the oldest bytes when the ring overflows; every
// byte of p lands (the newest tail always survives). Returns the number of
// oldest bytes dropped.
func (r *Ring) Write(p []byte) int {
	dropped := 0
	if len(p) >= RingSize {
		// One oversized write: only the last RingSize bytes land.
		dropped = r.len + (len(p) - RingSize)
		copy(r.buf[:], p[len(p)-RingSize:])
		r.head = 0
		r.len = RingSize
		return dropped
	}
	if r.len+len(p) > RingSize {
		dropped = r.len + len(p) - RingSize
		r.head = (r.head + dropped) % RingSize
		r.len -= dropped
	}
	for _, b := range p {
		r.buf[(r.head+r.len)%RingSize] = b
		r.len++
	}
	return dropped
}

// Read consumes up to len(p) bytes in FIFO order and returns how many were
// copied into p.
func (r *Ring) Read(p []byte) int {
	n := len(p)
	if n > r.len {
		n = r.len
	}
	for i := 0; i < n; i++ {
		p[i] = r.buf[(r.head+i)%RingSize]
	}
	r.head = (r.head + n) % RingSize
	r.len -= n
	return n
}
