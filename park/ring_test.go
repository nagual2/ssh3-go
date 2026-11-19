// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package park

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// The parked output ring (SPEC §17.2): a bounded 32 KiB FIFO with
// drop-oldest semantics — the newest bytes always win, the oldest ones
// leave silently once the capacity is exhausted. The re-attach replay
// drains it in write order.

func TestRingSizeIsCanon(t *testing.T) {
	if RingSize != 32*1024 {
		t.Fatalf("RingSize = %d, want the canon %d (SPEC §17.2)", RingSize, 32*1024)
	}
}

func TestRingWriteReadOrder(t *testing.T) {
	r := NewRing()
	r.Write([]byte("hello "))
	r.Write([]byte("parked world"))

	out := make([]byte, r.Len())
	want := r.Len()
	if n := r.Read(out); n != want {
		t.Fatalf("Read returned %d bytes, want %d", n, want)
	}
	if got, want := string(out), "hello parked world"; got != want {
		t.Fatalf("ring replay broke the order: got %q, want %q", got, want)
	}
	if r.Len() != 0 {
		t.Fatalf("ring still holds %d bytes after a full read", r.Len())
	}
}

func TestRingReadConsumesInChunks(t *testing.T) {
	r := NewRing()
	r.Write([]byte("abcdefgh"))

	first := make([]byte, 3)
	if n := r.Read(first); n != 3 || string(first) != "abc" {
		t.Fatalf("first chunk = %q (n=%d), want \"abc\"", first, n)
	}
	second := make([]byte, 64)
	if n := r.Read(second); n != 5 || string(second[:n]) != "defgh" {
		t.Fatalf("second chunk = %q (n=%d), want \"defgh\"", second[:n], n)
	}
	if n := r.Read(second); n != 0 {
		t.Fatalf("empty ring returned %d bytes", n)
	}
}

func TestRingDropOldestOnFull(t *testing.T) {
	r := NewRing()

	// Fill the ring past its capacity: the tail (the newest bytes) must
	// survive, the head (the oldest bytes) is dropped.
	payload := make([]byte, RingSize+128)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	r.Write(payload)

	if r.Len() != RingSize {
		t.Fatalf("ring holds %d bytes after an overflow write, want the cap %d", r.Len(), RingSize)
	}
	out := make([]byte, RingSize)
	if n := r.Read(out); n != RingSize {
		t.Fatalf("Read returned %d bytes, want %d", n, RingSize)
	}
	if !bytes.Equal(out, payload[128:]) {
		t.Fatal("the ring kept the oldest bytes: drop-oldest broke (SPEC §17.2)")
	}
}

func TestRingLargeSingleWriteKeepsTail(t *testing.T) {
	r := NewRing()

	// One write larger than the whole ring: only the last RingSize bytes
	// land, exactly once, in order.
	payload := make([]byte, 3*RingSize)
	for i := 0; i < 3; i++ {
		for j := 0; j < RingSize; j++ {
			payload[i*RingSize+j] = byte(i)
		}
	}
	r.Write(payload)

	out := make([]byte, RingSize)
	if n := r.Read(out); n != RingSize {
		t.Fatalf("Read returned %d bytes, want %d", n, RingSize)
	}
	for _, b := range out {
		if b != 2 {
			t.Fatal("the ring tail is not the last third of the oversized write")
		}
	}
}

func TestRingMarkerSequenceSurvivesOverflow(t *testing.T) {
	// The smoke shape: a parked shell streams markers while nobody reads;
	// the last markers must replay in order after a re-attach.
	r := NewRing()
	var expected bytes.Buffer
	for i := 1; i <= 4096; i++ {
		line := make([]byte, 0, 32)
		line = binary.AppendUvarint(line, uint64(i))
		line = append(line, []byte("PARK-Marker\n")...)
		expected.Write(line)
		r.Write(line)
	}

	want := expected.Bytes()
	if r.Len() != RingSize {
		t.Fatalf("ring holds %d bytes, want %d", r.Len(), RingSize)
	}
	// The expected replay is the tail of the stream, cut on a write boundary.
	tail := want[len(want)-RingSize:]
	out := make([]byte, RingSize)
	r.Read(out)
	if !bytes.Equal(out, tail) {
		t.Fatal("the marker sequence lost its order under overflow")
	}
}

func TestRingExactFillThenMore(t *testing.T) {
	r := NewRing()
	full := make([]byte, RingSize)
	r.Write(full)
	if r.Len() != RingSize {
		t.Fatalf("exact fill holds %d bytes", r.Len())
	}
	r.Write([]byte("x"))
	if r.Len() != RingSize {
		t.Fatalf("post-overflow ring holds %d bytes, want the cap", r.Len())
	}
	out := make([]byte, RingSize)
	if n := r.Read(out); n != RingSize {
		t.Fatalf("Read returned %d bytes, want %d", n, RingSize)
	}
	// The oldest byte left (drop-oldest), the newest byte is the tail.
	if out[0] != 0 {
		t.Fatalf("the oldest surviving byte = %d, want 0", out[0])
	}
	if out[RingSize-1] != 'x' {
		t.Fatalf("the newest byte did not land at the tail (got %d)", out[RingSize-1])
	}
}
