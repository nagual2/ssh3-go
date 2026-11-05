// Package client rides the session tickets of the 0-RTT stage (the
// resumption of the QUIC-TLS): the in-process cache keeps one session
// per server, the dial loads it through tls.Config.ClientSessionCache
// and the new-session callback refreshes the entry.
//
// The cache is deliberately process-lifetime: the Go standard library
// exports no serialization of tls.ClientSessionState, so the disk
// cache the ssh3-c client keeps (~/.ssh3/tickets, the cross-run
// resumption) cannot ride without vendoring crypto/tls internals. The
// resumption therefore lives inside one process: the proxy-jump chain
// (every hop dials its own conversation), the control master and the
// multi-forward setups gain the -1 RTT, the fresh ssh3 process dials
// cold like before.
//
// The cache line also carries the server-impl flag of the 425-retry
// contract: the flag derives from the Server header of the last
// established session ("c" — an ssh3-c server, which reroutes the
// ignored early flight; a fork server does not get the early CONNECT).
package client

import (
	"crypto/tls"
	"strings"
	"sync"
)

// retryFlagC marks a server that reroutes the ignored early flight
// (the ssh3-c implementation; the marker derives from its Server
// header).
const retryFlagC = "c"

// sessionEntry is one cached server: the ticket state and the
// retry-contract flag of the last session.
type sessionEntry struct {
	state *tls.ClientSessionState
	flag  string
}

// TicketCache is the in-process session cache. The ssh3 client
// dials its conversations through it: setupQUICConnection wires it
// into the tls.Config and the early-flight decision reads it back.
type TicketCache struct {
	mu      sync.Mutex
	entries map[string]*sessionEntry
	// dialKey is the server the ongoing dial targets (NoteDial rides
	// before quic.DialEarly; crypto/tls keys the cache callbacks with
	// its own internal shape, the cache routes through the noted dial
	// instead).
	dialKey   string
	lastFlag  string
	lastHitOK bool
}

var globalTickets = &TicketCache{entries: make(map[string]*sessionEntry)}

// GetTicketCache returns the process-wide cache (the single instance
// serves every dial; quic-go copies the states it takes).
func GetTicketCache() *TicketCache {
	return globalTickets
}

// NoteDial points the cache at the server the ongoing dial targets.
func (t *TicketCache) NoteDial(hostname string, port uint16) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dialKey = hostname + ":" + itoa(port)
	t.lastHitOK = false
}

// NoteServerFlag records the retry-contract flag derived from the
// Server header of the established session of the noted dial.
func (t *TicketCache) NoteServerFlag(serverHeader string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dialKey == "" {
		return
	}
	e, ok := t.entries[t.dialKey]
	if !ok {
		e = &sessionEntry{}
		t.entries[t.dialKey] = e
	}
	if strings.Contains(serverHeader, "ssh3-c") {
		e.flag = retryFlagC
	}
}

// RetryContract reports whether the noted dial's server held the
// 425-retry contract at its last session (and its ticket is cached).
func (t *TicketCache) RetryContract() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[t.dialKey]
	return ok && e.state != nil && e.flag == retryFlagC
}

// Get implements tls.ClientSessionCache; the key of crypto/tls is
// routed to the noted dial (the client dials one server at a time per
// setup).
func (t *TicketCache) Get(key string) (*tls.ClientSessionState, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[t.dialKey]
	if !ok || e.state == nil {
		t.lastHitOK = false
		return nil, false
	}
	t.lastHitOK = true
	t.lastFlag = e.flag
	return e.state, true
}

// Put implements tls.ClientSessionCache; the fresh ticket of the
// noted dial replaces its entry (the flag rides the entry, the fresh
// session does not reset it).
func (t *TicketCache) Put(key string, session *tls.ClientSessionState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if session == nil || t.dialKey == "" {
		return
	}
	e, ok := t.entries[t.dialKey]
	if !ok {
		e = &sessionEntry{}
		t.entries[t.dialKey] = e
	}
	e.state = session
}

// LastDialResumed reports whether the Get of the ongoing dial hit a
// cached ticket (the 0-RTT attempt is plausible; the actual use rides
// the conn state).
func (t *TicketCache) LastDialResumed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastHitOK
}

// itoa keeps the key format free of the fmt import cycle shape (the
// plain uint16 rendering).
func itoa(v uint16) string {
	if v == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
