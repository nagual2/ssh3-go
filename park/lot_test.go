// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package park

import (
	"sync"
	"testing"
	"time"
)

// The parking lot (SPEC §17.2/§17.3): the detached live sessions of dead
// connections, the token+user re-attach lookup with a fresh auth verdict,
// the lazy expiry sweep (kill+reap), the bounded table with oldest
// eviction, and the 0=off strict-openssh switch.

// fakeSession counts the kills so the tests can pin the kill+reap contract
// without any real child process.
type fakeSession struct {
	mu     sync.Mutex
	kills  int
	exited bool
}

func (f *fakeSession) ParkedKill() {
	f.mu.Lock()
	f.kills++
	f.mu.Unlock()
}

func (f *fakeSession) ParkedExited() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exited
}

func TestLotDisabledAtMaxZero(t *testing.T) {
	lot := NewLot(0, 300*time.Second)
	if lot.Enabled() {
		t.Fatal("a lot with max=0 must be disabled (SPEC §17.2: 0 = off)")
	}
	if rec := lot.Add("user", "aabb", &fakeSession{}, time.Now()); rec != nil {
		t.Fatal("Add must return nil when the lot is disabled")
	}
	if lot.Count() != 0 {
		t.Fatalf("the disabled lot holds %d records", lot.Count())
	}
}

func TestLotAddFindBindsSameUserSameToken(t *testing.T) {
	lot := NewLot(16, time.Minute)
	sess := &fakeSession{}
	now := time.Now()

	rec := lot.Add("alice", "aabbccdd00112233445566778899aabb", sess, now)
	if rec == nil {
		t.Fatal("Add failed on a healthy lot")
	}
	if lot.Count() != 1 {
		t.Fatalf("lot count = %d, want 1", lot.Count())
	}

	// The re-attach verdict (SPEC §17.3): a fresh auth of the same user
	// with the same token binds the parked record.
	found := lot.Find("alice", "aabbccdd00112233445566778899aabb", now.Add(time.Second))
	if found == nil {
		t.Fatal("the same user + same token must bind the parked record")
	}
	if found.Token != "aabbccdd00112233445566778899aabb" || found.User != "alice" {
		t.Fatalf("the record identity drifted: user=%q token=%q", found.User, found.Token)
	}
}

func TestLotFindRefusesForeignUser(t *testing.T) {
	lot := NewLot(16, time.Minute)
	lot.Add("alice", "tok1", &fakeSession{}, time.Now())

	if found := lot.Find("mallory", "tok1", time.Now()); found != nil {
		t.Fatal("a foreign user must not bind the parked session (SPEC §17.3: the user is the second gate)")
	}
}

func TestLotFindRefusesUnknownToken(t *testing.T) {
	lot := NewLot(16, time.Minute)
	lot.Add("alice", "tok1", &fakeSession{}, time.Now())

	// An unknown token means an ordinary fresh session, no binding.
	if found := lot.Find("alice", "tok-unknown", time.Now()); found != nil {
		t.Fatal("an unknown token must not bind any parked session")
	}
}

func TestLotFindRefusesEmptyToken(t *testing.T) {
	lot := NewLot(16, time.Minute)
	lot.Add("alice", "tok1", &fakeSession{}, time.Now())

	// The tokenless dial (an old client) rides a fresh session.
	if found := lot.Find("alice", "", time.Now()); found != nil {
		t.Fatal("an empty token must not bind any parked session")
	}
}

func TestLotFindMatchesEmptyRecordUser(t *testing.T) {
	lot := NewLot(16, time.Minute)
	lot.Add("", "tok1", &fakeSession{}, time.Now())

	// The daemon-identity session (no run-as user) binds on the token alone.
	if found := lot.Find("anybody", "tok1", time.Now()); found == nil {
		t.Fatal("an empty recorded user must bind on the token match alone")
	}
}

func TestLotFindSweepsExpired(t *testing.T) {
	lot := NewLot(16, 100*time.Millisecond)
	sess := &fakeSession{}
	now := time.Now()
	lot.Add("alice", "tok1", sess, now)

	// The lazy sweep rides the lookup (the dos-guard shape): an expired
	// record is killed+reaped on the touch and the lookup misses.
	if found := lot.Find("alice", "tok1", now.Add(200*time.Millisecond)); found != nil {
		t.Fatal("an expired record must not bind")
	}
	if got := sess.kills; got != 1 {
		t.Fatalf("the expired record was killed %d times, want 1", got)
	}
	if lot.Count() != 0 {
		t.Fatalf("the expired record stayed in the lot (count=%d)", lot.Count())
	}
}

func TestLotSweepKeepsFreshAndKillsExpired(t *testing.T) {
	lot := NewLot(16, time.Minute)
	fresh := &fakeSession{}
	stale := &fakeSession{}
	now := time.Now()

	lot.Add("u1", "tok1", fresh, now)
	lot.Add("u2", "tok2", stale, now.Add(-2*time.Minute))

	lot.Sweep(now)

	if got := stale.kills; got != 1 {
		t.Fatalf("the expired record was killed %d times, want 1", got)
	}
	if got := fresh.kills; got != 0 {
		t.Fatalf("a fresh record was killed %d times, want 0", got)
	}
	if lot.Count() != 1 {
		t.Fatalf("lot count = %d after the sweep, want 1", lot.Count())
	}
	if lot.Find("u1", "tok1", now) == nil {
		t.Fatal("the fresh record vanished from the lot")
	}
}

func TestLotEvictsOldestAtCap(t *testing.T) {
	lot := NewLot(2, time.Minute)
	first := &fakeSession{}
	second := &fakeSession{}
	third := &fakeSession{}
	now := time.Now()

	if lot.Add("u1", "t1", first, now) == nil {
		t.Fatal("first Add failed")
	}
	if lot.Add("u2", "t2", second, now.Add(time.Second)) == nil {
		t.Fatal("second Add failed")
	}
	if rec := lot.Add("u3", "t3", third, now.Add(2*time.Second)); rec == nil {
		t.Fatal("the Add at the cap failed: the oldest must be evicted, not refused")
	}
	if got := first.kills; got != 1 {
		t.Fatalf("the oldest record was killed %d times, want 1", got)
	}
	if lot.Count() != 2 {
		t.Fatalf("lot count = %d after the eviction, want 2", lot.Count())
	}
	if lot.Find("u2", "t2", now) == nil || lot.Find("u3", "t3", now) == nil {
		t.Fatal("the fresh records vanished from the lot after the eviction")
	}
	if lot.Find("u1", "t1", now) != nil {
		t.Fatal("the evicted record stayed findable")
	}
}

func TestLotTakeHandsSessionBackOnce(t *testing.T) {
	lot := NewLot(16, time.Minute)
	sess := &fakeSession{}
	now := time.Now()

	rec := lot.Add("alice", "tok1", sess, now)
	if rec == nil {
		t.Fatal("Add failed")
	}

	// Take hands the ownership back to the attaching channel and leaves
	// the lot; a second attach finds nothing.
	got, ok := lot.Take(rec)
	if !ok || got == nil {
		t.Fatal("Take must hand the parked session back once")
	}
	if lot.Count() != 0 {
		t.Fatalf("lot count = %d after the take, want 0", lot.Count())
	}
	if lot.Find("alice", "tok1", now) != nil {
		t.Fatal("the taken record stayed findable")
	}
	if _, ok := lot.Take(rec); ok {
		t.Fatal("a second Take must fail: the record is already bound")
	}
}

func TestLotTeardownKillsEverything(t *testing.T) {
	lot := NewLot(4, time.Minute)
	sessions := []*fakeSession{{}, {}, {}}
	now := time.Now()
	for i, s := range sessions {
		if lot.Add("u", string(rune('a'+i)), s, now) == nil {
			t.Fatalf("Add %d failed", i)
		}
	}

	lot.Teardown()

	for i, s := range sessions {
		if s.kills != 1 {
			t.Fatalf("record %d was killed %d times, want 1", i, s.kills)
		}
	}
	if lot.Count() != 0 {
		t.Fatalf("the teardown left %d records", lot.Count())
	}
}

func TestRecordExitVerdictRidesAttach(t *testing.T) {
	lot := NewLot(16, time.Minute)
	now := time.Now()
	rec := lot.Add("alice", "tok1", &fakeSession{}, now)

	if rec.Exited() {
		t.Fatal("a fresh record must not report an exit")
	}

	// The pump captures the verdict while parked: the command that finished
	// during the park delivers exactly once at the re-attach (SPEC §17.3).
	rec.SetExit(42, "")
	if !rec.Exited() {
		t.Fatal("the recorded exit verdict was lost")
	}
	if got := rec.ExitStatus(); got != 42 {
		t.Fatalf("ExitStatus = %d, want 42", got)
	}
	if rec.ExitSignal() != "" {
		t.Fatalf("ExitSignal = %q, want empty", rec.ExitSignal())
	}

	rec2 := lot.Add("bob", "tok2", &fakeSession{}, now)
	rec2.SetExit(0, "KILL")
	if rec2.ExitSignal() != "KILL" {
		t.Fatalf("ExitSignal = %q, want KILL", rec2.ExitSignal())
	}

	// The verdict stays readable after the take (the attach replays it).
	_, ok := lot.Take(rec2)
	if !ok {
		t.Fatal("Take failed")
	}
	if rec2.ExitSignal() != "KILL" {
		t.Fatal("the exit verdict did not survive the take")
	}
}

func TestLotAddSweepsLazily(t *testing.T) {
	lot := NewLot(1, 50*time.Millisecond)
	stale := &fakeSession{}
	now := time.Now()
	lot.Add("u1", "t1", stale, now.Add(-time.Second))

	// The next Add sweeps the expired record before taking a slot: the
	// fresh entry must not evict a record the expiry was about to kill.
	if rec := lot.Add("u2", "t2", &fakeSession{}, now); rec == nil {
		t.Fatal("the Add after the lazy sweep failed")
	}
	if got := stale.kills; got != 1 {
		t.Fatalf("the lazy sweep killed %d times, want 1", got)
	}
}
