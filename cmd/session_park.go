// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/creack/pty"
	"github.com/rs/zerolog/log"

	ssh3 "github.com/francoismichel/ssh3"
	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/park"
)

// The session parking of the server (SPEC §17.2/§17.3): when the QUIC
// connection dies mid-session, a live interactive child (a pty shell or an
// exec command) does not die with it — the session detaches from its
// channel, its output drains into the bounded ring of the lot record and
// the next authenticated dial of the same user carrying the same session
// token re-attaches it (the ring replays, the pump re-arms, the shell state
// — login, cwd, env — lives in the child, nothing respawns). The expiry is
// a lazy sweep (kill+reap); the lot is bounded with oldest eviction; 0
// seconds disables the parking (the strict openssh compat).

// globalParkLot holds the parking lot; nil (or max=0) means the parking is
// off and a dead connection tears its sessions down as before. Set once at
// the server start, before any conversation is served.
var globalParkLot *park.Lot

// parkSweepInterval is the ticker of the expiry backstop: the lot also
// sweeps lazily on every Add and Find, the ticker covers a lot nobody
// touches.
const parkSweepInterval = 500 * time.Millisecond

// newParkLotFromEnv builds the lot from the server environment (SPEC
// §17.2): SSH3_SESSION_PARK_SECONDS (default 300, 0 disables the lot),
// SSH3_PARKED_MAX (default 16). Invalid values fall back to the defaults.
func newParkLotFromEnv() *park.Lot {
	const (
		defaultParkSeconds = 300
		defaultParkedMax   = 16
	)
	parkSeconds := defaultParkSeconds
	if v := os.Getenv("SSH3_SESSION_PARK_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			parkSeconds = n
		} else {
			log.Warn().Msgf("invalid SSH3_SESSION_PARK_SECONDS %q, using the default", v)
		}
	}
	parkedMax := defaultParkedMax
	if v := os.Getenv("SSH3_PARKED_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			parkedMax = n
		} else {
			log.Warn().Msgf("invalid SSH3_PARKED_MAX %q, using the default", v)
		}
	}
	if parkSeconds == 0 {
		// 0 seconds disables the parking: the teardown kills the child as
		// before (the strict openssh compat)
		parkedMax = 0
	}
	if parkedMax > 0 {
		log.Info().Msgf("session parking enabled: park-seconds=%d parked-max=%d", parkSeconds, parkedMax)
	}
	return park.NewLot(parkedMax, time.Duration(parkSeconds)*time.Second)
}

// setChannel arms the live output sink of the session (the spawn path).
func (s *runningSession) setChannel(ch ssh3.Channel) {
	s.mu.Lock()
	s.ch = ch
	s.mu.Unlock()
}

// tryPark moves the live session into the lot (SPEC §17.2): the sink
// becomes the record's ring, the pump keeps draining, the child stays
// alive. Idempotent; returns whether the session is parked. Refuses a
// tokenless session, a dead child, a session without a running command
// (LARVAL) and a disabled lot — those ride the ordinary teardown.
func (s *runningSession) tryPark() bool {
	s.mu.Lock()
	if s.parked {
		s.mu.Unlock()
		return true
	}
	if globalParkLot == nil || !globalParkLot.Enabled() || s.token == "" ||
		s.childExited || s.channelState != OPEN || s.runningCmd == nil {
		s.mu.Unlock()
		return false
	}
	s.parked = true
	s.mu.Unlock()

	rec := globalParkLot.Add(s.user, s.token, s, time.Now())
	if rec == nil {
		// the lot rejected the entry (disabled or broken arguments): roll
		// the sink back and let the teardown proceed
		s.mu.Lock()
		s.parked = false
		s.mu.Unlock()
		return false
	}
	s.mu.Lock()
	s.rec = rec
	s.mu.Unlock()
	log.Info().Msgf("SSH3-SESSION-PARK user=%s token=%s ring=%d", s.user, s.token, rec.Ring().Len())
	return true
}

// writeOutput routes one output chunk to the current sink: the channel
// while attached, the record's ring while parked (the parked drain,
// SPEC §17.2 — the drop-oldest ring keeps the shell unblocked).
func (s *runningSession) writeOutput(data []byte, dataType ssh3Messages.SSHDataType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.parked {
		if s.rec != nil {
			s.rec.Ring().Write(data)
		}
		return nil
	}
	if s.ch == nil {
		return nil
	}
	_, err := s.ch.WriteData(data, dataType)
	return err
}

// deliverVerdict sends the terminal event of the child (the exit-status or
// the exit-signal request). While parked the verdict is captured in the
// record and rides the re-attach instead; a verdict that fails on a dying
// channel parks the session so the re-dial still receives it exactly once
// (SPEC §17.3).
func (s *runningSession) deliverVerdict(status uint64, signalName string, coreDumped bool) error {
	s.mu.Lock()
	parked, rec, ch := s.parked, s.rec, s.ch
	s.mu.Unlock()

	// parked: the verdict rides the record (the re-attach delivers it)
	if parked {
		s.setChildExited()
		if rec != nil {
			rec.SetExit(status, signalName)
		}
		return nil
	}
	if ch == nil {
		s.setChildExited()
		return nil
	}
	var req *ssh3Messages.ChannelRequestMessage
	if signalName != "" {
		req = &ssh3Messages.ChannelRequestMessage{
			WantReply: false,
			ChannelRequest: &ssh3Messages.ExitSignalRequest{
				SignalNameWithoutSig: signalName,
				CoreDumped:           coreDumped,
			},
		}
	} else {
		req = &ssh3Messages.ChannelRequestMessage{
			WantReply:      false,
			ChannelRequest: &ssh3Messages.ExitStatusRequest{ExitStatus: status},
		}
	}
	err := ch.SendRequest(req)
	if err == nil {
		s.setChildExited()
		return nil
	}
	// the sink died mid-verdict: park so the re-attach delivers the verdict
	// (the command of a parked exec rides exactly once). The eligibility
	// check runs before the child is marked exited — a dead child cannot
	// park.
	if s.tryPark() {
		s.setChildExited()
		s.mu.Lock()
		rec := s.rec
		s.mu.Unlock()
		if rec != nil {
			rec.SetExit(status, signalName)
		}
		return nil
	}
	s.setChildExited()
	return err
}

func (s *runningSession) setChildExited() {
	s.mu.Lock()
	s.childExited = true
	s.mu.Unlock()
}

// ParkedKill is the lot's expiry/eviction/teardown hook: kill+reap the
// child (the pump's Wait does the reap once the kill unblocks it) and
// release the pty fds.
func (s *runningSession) ParkedKill() {
	s.mu.Lock()
	cmd := s.runningCmd
	p := s.pty
	s.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if p != nil {
		_ = p.pty.Close()
		_ = p.tty.Close()
	}
}

// ParkedExited reports whether the child already terminated while parked.
func (s *runningSession) ParkedExited() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.childExited
}

// parkAfterDisconnect is the session-loop gate: a connection death hands
// the live child to the lot instead of the teardown (SPEC §17.2). The
// eligibility rides tryPark; a graceful EOF never reaches this gate — the
// client half-closing its input must not park a session whose connection
// is still alive.
func parkAfterDisconnect(channel ssh3.Channel) {
	session, ok := runningSessions.Get(channel)
	if !ok {
		return
	}
	session.tryPark()
}

// reattachSession binds a parked session to the fresh channel (SPEC
// §17.3): the ring replays before the fresh bytes, the sink re-targets the
// new channel, the geometry of the new console applies, the verdict of a
// child that terminated while parked rides to the fresh dial. The parked
// session object replaces the fresh LARVAL one in the runningSessions map —
// the request handlers resolve the session through that map.
func reattachSession(channel ssh3.Channel, fresh *runningSession, rec *park.Record,
	width, height, pixWidth, pixHeight uint64) error {
	if rec == nil || fresh == nil {
		return fmt.Errorf("no parked record to attach")
	}
	sess, ok := globalParkLot.Take(rec)
	if !ok {
		return fmt.Errorf("the parked session is already re-attached")
	}
	ps, ok := sess.(*runningSession)
	if !ok {
		return fmt.Errorf("the parked record holds a foreign session type %T", sess)
	}

	ps.mu.Lock()
	// the parked output replays before the fresh bytes; the whole replay
	// and the sink swap ride one critical section so the parked pump
	// cannot interleave a write past the replay head
	if ring := rec.Ring(); ring != nil && ring.Len() > 0 {
		buf := make([]byte, park.RingSize)
		for {
			n := ring.Read(buf)
			if n == 0 {
				break
			}
			if _, err := channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE); err != nil {
				ps.mu.Unlock()
				return fmt.Errorf("could not replay the parked output: %s", err)
			}
		}
	}
	ps.parked = false
	ps.rec = nil
	ps.attached = true
	ps.ch = channel
	ps.mu.Unlock()

	// the geometry of the new console (the term of the child keeps its
	// original value); the exec-form attach carries no geometry
	if ps.pty != nil && width != 0 && height != 0 {
		ps.pty.winSize = &pty.Winsize{
			Rows: uint16(height),
			Cols: uint16(width),
			X:    uint16(pixWidth),
			Y:    uint16(pixHeight),
		}
		setWinsize(ps.pty.pty, width, height, pixWidth, pixHeight)
	}

	// the parked session rides the new channel; the fresh LARVAL object is
	// discarded (its map entry is replaced)
	runningSessions.Insert(channel, ps)

	log.Info().Msgf("SSH3-SESSION-ATTACH user=%s token=%s attached=%t", ps.user, ps.token, ps.attached)

	// the verdict of a child that terminated while parked: the fresh dial
	// receives it and finishes (the command rode exactly once)
	if rec.Exited() {
		return ps.deliverVerdict(rec.ExitStatus(), rec.ExitSignal(), false)
	}
	return nil
}
