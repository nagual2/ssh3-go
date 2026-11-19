// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"

	ssh3 "github.com/francoismichel/ssh3"
	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/park"
	"github.com/francoismichel/ssh3/util/unix_util"
)

// The session parking (SPEC §17): the eligibility gates of tryPark, the
// sink routing of the parked output (ring vs channel), the verdict capture
// of a child that terminates while parked, the re-attach binding, and the
// no-op shell/exec on an attached session.

// parkStubChannel captures the session-channel writes and requests; the
// embedded interface keeps the unused methods nil (same shape as
// stubSFTPChannel).
type parkStubChannel struct {
	ssh3.Channel

	mu       sync.Mutex
	writes   []string
	types    []ssh3Messages.SSHDataType
	requests []*ssh3Messages.ChannelRequestMessage
	writeErr error
	sendErr  error
}

func (s *parkStubChannel) WriteData(buf []byte, dataType ssh3Messages.SSHDataType) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	s.writes = append(s.writes, string(buf))
	s.types = append(s.types, dataType)
	return len(buf), nil
}

func (s *parkStubChannel) SendRequest(r *ssh3Messages.ChannelRequestMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendErr != nil {
		return s.sendErr
	}
	s.requests = append(s.requests, r)
	return nil
}

func (s *parkStubChannel) writtenText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.writes, "")
}

func (s *parkStubChannel) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// parkTestSession builds an OPEN session with a live (but never started)
// child, the shape the park eligibility expects.
func parkTestSession(token, user string) *runningSession {
	return &runningSession{
		channelState:   OPEN,
		runningCmd:     &runningCommand{},
		token:          token,
		user:           user,
		exitStatusSent: make(chan struct{}),
		runningCmdDone: make(chan struct{}),
	}
}

// withParkLot swaps the global lot for the test and restores it.
func withParkLot(t *testing.T, lot *park.Lot) {
	t.Helper()
	prev := globalParkLot
	t.Cleanup(func() { globalParkLot = prev })
	globalParkLot = lot
}

func TestTryParkEligibility(t *testing.T) {
	cases := []struct {
		name    string
		token   string
		lot     *park.Lot
		exited  bool
		state   channelType
		want    bool
		wantRec bool
	}{
		{"tokenless session never parks", "", park.NewLot(16, time.Minute), false, OPEN, false, false},
		{"nil lot never parks", "tok", nil, false, OPEN, false, false},
		{"disabled lot never parks", "tok", park.NewLot(0, time.Minute), false, OPEN, false, false},
		{"exited child never parks", "tok", park.NewLot(16, time.Minute), true, OPEN, false, false},
		{"larval session never parks", "tok", park.NewLot(16, time.Minute), false, LARVAL, false, false},
		{"live tokenized session parks", "tok", park.NewLot(16, time.Minute), false, OPEN, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withParkLot(t, tc.lot)
			sess := parkTestSession(tc.token, "alice")
			sess.channelState = tc.state
			if tc.exited {
				sess.childExited = true
			}

			if got := sess.tryPark(); got != tc.want {
				t.Fatalf("tryPark = %v, want %v", got, tc.want)
			}
			if tc.wantRec != (sess.rec != nil) {
				t.Fatalf("record presence = %v, want %v", sess.rec != nil, tc.wantRec)
			}
			if sess.parked != tc.want {
				t.Fatalf("parked flag = %v, want %v", sess.parked, tc.want)
			}
		})
	}
}

func TestTryParkIsIdempotent(t *testing.T) {
	withParkLot(t, park.NewLot(16, time.Minute))
	sess := parkTestSession("tok", "alice")

	if !sess.tryPark() {
		t.Fatal("the first park failed")
	}
	// The second death of the same connection must not create a second
	// record: the session is already parked.
	if !sess.tryPark() {
		t.Fatal("the idempotent park must still report true")
	}
	if got := globalParkLot.Count(); got != 1 {
		t.Fatalf("lot count = %d after a double park, want 1", got)
	}
}

func TestTryParkRecordsIdentity(t *testing.T) {
	lot := park.NewLot(16, time.Minute)
	withParkLot(t, lot)
	sess := parkTestSession("tok1", "alice")

	if !sess.tryPark() {
		t.Fatal("the park failed")
	}
	found := lot.Find("alice", "tok1", time.Now())
	if found == nil {
		t.Fatal("the parked session is not findable by user+token")
	}
	if sess.rec != found {
		t.Fatal("the session does not hold its own record")
	}
}

func TestWriteOutputRoutesParkedToRing(t *testing.T) {
	withParkLot(t, park.NewLot(16, time.Minute))
	sess := parkTestSession("tok", "alice")
	live := &parkStubChannel{}
	sess.setChannel(live)

	if !sess.tryPark() {
		t.Fatal("the park failed")
	}
	if err := sess.writeOutput([]byte("PARK-M-1\n"), ssh3Messages.SSH_EXTENDED_DATA_NONE); err != nil {
		t.Fatalf("parked write errored: %s", err)
	}
	if text := live.writtenText(); text != "" {
		t.Fatalf("the parked output leaked to the dead channel: %q", text)
	}
	if sess.rec.Ring().Len() != len("PARK-M-1\n") {
		t.Fatalf("the ring holds %d bytes, want %d", sess.rec.Ring().Len(), len("PARK-M-1\n"))
	}
}

func TestWriteOutputRoutesAttachedToChannel(t *testing.T) {
	withParkLot(t, park.NewLot(16, time.Minute))
	sess := parkTestSession("tok", "alice")
	live := &parkStubChannel{}
	sess.setChannel(live)

	if err := sess.writeOutput([]byte("live\n"), ssh3Messages.SSH_EXTENDED_DATA_NONE); err != nil {
		t.Fatalf("attached write errored: %s", err)
	}
	if text := live.writtenText(); text != "live\n" {
		t.Fatalf("the live output missed the channel: %q", text)
	}
}

func TestWriteOutputReportsDeadChannel(t *testing.T) {
	sess := parkTestSession("tok", "alice")
	dead := &parkStubChannel{writeErr: errors.New("stream gone")}
	sess.setChannel(dead)

	if err := sess.writeOutput([]byte("x"), ssh3Messages.SSH_EXTENDED_DATA_NONE); err == nil {
		t.Fatal("a dead channel write must surface the error (the pump parks on it)")
	}
}

func TestDeliverVerdictCapturedWhileParked(t *testing.T) {
	withParkLot(t, park.NewLot(16, time.Minute))
	sess := parkTestSession("tok", "alice")
	dead := &parkStubChannel{}
	sess.setChannel(dead)

	if !sess.tryPark() {
		t.Fatal("the park failed")
	}
	if err := sess.deliverVerdict(42, "", false); err != nil {
		t.Fatalf("the parked verdict errored: %s", err)
	}
	if !sess.childExited {
		t.Fatal("the verdict must mark the child exited")
	}
	if !sess.rec.Exited() || sess.rec.ExitStatus() != 42 {
		t.Fatalf("the verdict was not captured in the record (exited=%v status=%d)",
			sess.rec.Exited(), sess.rec.ExitStatus())
	}
	if dead.requestCount() != 0 {
		t.Fatal("the parked verdict leaked to the dead channel")
	}
}

func TestDeliverVerdictRidesLiveChannel(t *testing.T) {
	withParkLot(t, park.NewLot(16, time.Minute))
	sess := parkTestSession("tok", "alice")
	live := &parkStubChannel{}
	sess.setChannel(live)

	if err := sess.deliverVerdict(7, "", false); err != nil {
		t.Fatalf("the live verdict errored: %s", err)
	}
	if live.requestCount() != 1 {
		t.Fatalf("the live channel saw %d requests, want 1", live.requestCount())
	}
}

func TestDeliverVerdictSignalShape(t *testing.T) {
	withParkLot(t, park.NewLot(16, time.Minute))
	sess := parkTestSession("tok", "alice")
	live := &parkStubChannel{}
	sess.setChannel(live)

	if err := sess.deliverVerdict(0, "KILL", true); err != nil {
		t.Fatalf("the verdict errored: %s", err)
	}
	sess.mu.Lock()
	reqs := append([]*ssh3Messages.ChannelRequestMessage(nil), sess.ch.(*parkStubChannel).requests...)
	sess.mu.Unlock()
	if len(reqs) != 1 {
		t.Fatalf("saw %d requests, want 1", len(reqs))
	}
	sig, ok := reqs[0].ChannelRequest.(*ssh3Messages.ExitSignalRequest)
	if !ok || sig.SignalNameWithoutSig != "KILL" || !sig.CoreDumped {
		t.Fatalf("the exit-signal verdict lost its shape: %+v", reqs[0].ChannelRequest)
	}
}

func TestDeliverVerdictParksOnDeadChannel(t *testing.T) {
	withParkLot(t, park.NewLot(16, time.Minute))
	sess := parkTestSession("tok", "alice")
	dead := &parkStubChannel{sendErr: errors.New("stream gone")}
	sess.setChannel(dead)

	// The command finished exactly as the connection died: the verdict
	// send fails, the session parks, the record captures the verdict and
	// the re-attach delivers it (SPEC §17.3).
	if err := sess.deliverVerdict(3, "", false); err != nil {
		t.Fatalf("a verdict that parks must not surface the send error, got: %s", err)
	}
	if !sess.parked {
		t.Fatal("the failed verdict did not park the session")
	}
	if !sess.rec.Exited() || sess.rec.ExitStatus() != 3 {
		t.Fatal("the verdict was not captured after the park")
	}
}

func TestReattachBindsParkedSession(t *testing.T) {
	withParkLot(t, park.NewLot(16, time.Minute))
	lot := globalParkLot

	parked := parkTestSession("tok", "alice")
	dead := &parkStubChannel{}
	parked.setChannel(dead)
	if !parked.tryPark() {
		t.Fatal("the park failed")
	}
	// Output produced while parked lands in the ring.
	parked.writeOutput([]byte("PARK-M-1\n"), ssh3Messages.SSH_EXTENDED_DATA_NONE)
	parked.writeOutput([]byte("PARK-M-2\n"), ssh3Messages.SSH_EXTENDED_DATA_NONE)

	rec := lot.Find("alice", "tok", time.Now())
	if rec == nil {
		t.Fatal("the parked record vanished before the re-attach")
	}

	// The fresh dial: a LARVAL session of the new channel, the shape
	// admitSessionChannel creates.
	fresh := &runningSession{
		channelState:   LARVAL,
		exitStatusSent: make(chan struct{}),
		runningCmdDone: make(chan struct{}),
		attach:         rec,
	}
	attached := &parkStubChannel{}
	runningSessions.Insert(attached, fresh)
	t.Cleanup(func() { runningSessions.Delete(attached) })

	if err := reattachSession(attached, fresh, rec, 0, 0, 0, 0); err != nil {
		t.Fatalf("the re-attach failed: %s", err)
	}

	// The parked session rides the new channel; the fresh object is gone.
	bound, ok := runningSessions.Get(attached)
	if !ok || bound != parked {
		t.Fatal("the re-attach did not bind the parked session to the new channel")
	}
	if !parked.attached {
		t.Fatal("the bound session must carry the attached flag (the no-op gate)")
	}
	if parked.parked || parked.rec != nil {
		t.Fatal("the bound session still carries the park state")
	}
	if parked.ch != attached {
		t.Fatal("the pump sink was not re-targeted to the new channel")
	}
	// The ring replays in order before the live tail.
	if text := attached.writtenText(); text != "PARK-M-1\nPARK-M-2\n" {
		t.Fatalf("the ring replay broke: %q", text)
	}
	if got := lot.Count(); got != 0 {
		t.Fatalf("the lot still holds %d records after the take", got)
	}
}

func TestReattachAppliesGeometry(t *testing.T) {
	withParkLot(t, park.NewLot(16, time.Minute))

	parked := parkTestSession("tok", "alice")
	ptyFile, ttyFile, err := pty.Open()
	if err != nil {
		t.Skipf("pty unavailable in this environment: %s", err)
	}
	t.Cleanup(func() {
		ptyFile.Close()
		ttyFile.Close()
	})
	parked.pty = &openPty{pty: ptyFile, tty: ttyFile, term: "xterm", winSize: &pty.Winsize{Rows: 24, Cols: 80}}

	if !parked.tryPark() {
		t.Fatal("the park failed")
	}
	rec := globalParkLot.Find("alice", "tok", time.Now())
	if rec == nil {
		t.Fatal("the record vanished")
	}

	fresh := &runningSession{channelState: LARVAL, exitStatusSent: make(chan struct{}), runningCmdDone: make(chan struct{})}
	attached := &parkStubChannel{}
	runningSessions.Insert(attached, fresh)
	t.Cleanup(func() { runningSessions.Delete(attached) })

	if err := reattachSession(attached, fresh, rec, 120, 40, 0, 0); err != nil {
		t.Fatalf("the re-attach failed: %s", err)
	}
	if parked.pty.winSize == nil || parked.pty.winSize.Cols != 120 || parked.pty.winSize.Rows != 40 {
		t.Fatalf("the geometry of the new console was not applied: %+v", parked.pty.winSize)
	}
}

func TestNoOpShellAndExecOnAttachedSession(t *testing.T) {
	withParkLot(t, park.NewLot(16, time.Minute))

	parked := parkTestSession("tok", "alice")
	dead := &parkStubChannel{}
	parked.setChannel(dead)
	if !parked.tryPark() {
		t.Fatal("the park failed")
	}
	rec := globalParkLot.Find("alice", "tok", time.Now())

	fresh := &runningSession{channelState: LARVAL, exitStatusSent: make(chan struct{}), runningCmdDone: make(chan struct{}), attach: rec}
	attached := &parkStubChannel{}
	runningSessions.Insert(attached, fresh)
	t.Cleanup(func() { runningSessions.Delete(attached) })

	if err := reattachSession(attached, fresh, rec, 0, 0, 0, 0); err != nil {
		t.Fatalf("the re-attach failed: %s", err)
	}

	user := &unix_util.User{Username: "alice", Dir: t.TempDir(), Shell: "/bin/false"}
	spawned := parked.runningCmd

	// The shell request on the attached session is a no-op success: no
	// banner, no respawn (SPEC §17.3).
	if err := newShellReq(user, attached, true); err != nil {
		t.Fatalf("the shell no-op failed: %s", err)
	}
	if text := attached.writtenText(); strings.Contains(text, "ssh3-go session") {
		t.Fatal("the session banner polluted the attached session")
	}

	// The exec request likewise: the command already runs in the parked
	// child, a respawn would hang the client.
	if err := newCommandInShellReq(user, attached, true, "echo ATTACH-RIDE"); err != nil {
		t.Fatalf("the exec no-op failed: %s", err)
	}
	if spawned != parked.runningCmd {
		t.Fatal("the attached shell/exec respawned the child")
	}
}

func TestAttachRecordConsumedOncePerRedial(t *testing.T) {
	withParkLot(t, park.NewLot(16, time.Minute))

	parked := parkTestSession("tok", "alice")
	dead := &parkStubChannel{}
	parked.setChannel(dead)
	if !parked.tryPark() {
		t.Fatal("the park failed")
	}
	rec := globalParkLot.Find("alice", "tok", time.Now())

	// A racing second CONNECT with the same token finds the same record;
	// only the first attach binds, the second is refused.
	fresh := &runningSession{channelState: LARVAL, exitStatusSent: make(chan struct{}), runningCmdDone: make(chan struct{}), attach: rec}
	attached := &parkStubChannel{}
	runningSessions.Insert(attached, fresh)
	t.Cleanup(func() { runningSessions.Delete(attached) })
	if err := reattachSession(attached, fresh, rec, 0, 0, 0, 0); err != nil {
		t.Fatalf("the first re-attach failed: %s", err)
	}

	fresh2 := &runningSession{channelState: LARVAL, exitStatusSent: make(chan struct{}), runningCmdDone: make(chan struct{}), attach: rec}
	second := &parkStubChannel{}
	runningSessions.Insert(second, fresh2)
	t.Cleanup(func() { runningSessions.Delete(second) })
	if err := reattachSession(second, fresh2, rec, 0, 0, 0, 0); err == nil {
		t.Fatal("a second attach of the same record must be refused")
	}
}

func TestParkedKillTerminatesRecord(t *testing.T) {
	withParkLot(t, park.NewLot(16, 50*time.Millisecond))
	lot := globalParkLot

	parked := parkTestSession("tok", "alice")
	dead := &parkStubChannel{}
	parked.setChannel(dead)
	if !parked.tryPark() {
		t.Fatal("the park failed")
	}

	// The lazy expiry (the sweeper's sweep): the record leaves and the
	// kill rides the parked session.
	lot.Sweep(time.Now().Add(time.Minute))
	if got := lot.Count(); got != 0 {
		t.Fatalf("the expired record stayed (count=%d)", got)
	}
}
