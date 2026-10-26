package message

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	util "github.com/francoismichel/ssh3/util"
)

// Channel types for dynamic SOCKS forwarding (-D). The client opens one
// "dynamic-forward" control channel towards the server carrying a
// RequestDynamicForward as channel data; every connection the SOCKS listener
// accepts is then mirrored to the server as a client-initiated
// "dynamic-forward-tcp" channel carrying a DynamicForwardTarget as channel
// data, which the server dials and bridges.
const (
	ChannelTypeDynamicForward    = "dynamic-forward"
	ChannelTypeDynamicForwardTCP = "dynamic-forward-tcp"
)

// DynamicForwardVersion is the version of the dynamic forwarding payloads. It
// travels as the first varint of every payload so that a future revision of
// the codec can be rejected cleanly instead of being misinterpreted.
const DynamicForwardVersion = 1

// Kinds of dynamic forwarding payloads, carried as the second varint of every
// payload right after the version.
const (
	// DynamicForwardKindRequest is sent by the client on a "dynamic-forward"
	// control channel to announce its local SOCKS bind.
	DynamicForwardKindRequest = 1
	// DynamicForwardKindRequestReply is sent by the server in answer to a
	// DynamicForwardKindRequest payload.
	DynamicForwardKindRequestReply = 2
	// DynamicForwardKindTarget is sent by the client on a "dynamic-forward-tcp"
	// channel and carries the address the server must dial.
	DynamicForwardKindTarget = 3
	// DynamicForwardKindTargetReply is sent by the server in answer to a
	// DynamicForwardKindTarget payload; it reports whether the dial succeeded.
	DynamicForwardKindTargetReply = 4
)

// dynamicForwardHeaderLen is the size of the varint(version)|varint(kind)
// prefix: both values are small enough for a single-byte QUIC varint.
func dynamicForwardHeaderLen() int {
	return int(util.VarIntLen(uint64(DynamicForwardVersion)) + util.VarIntLen(DynamicForwardKindRequest))
}

// writeDynamicForwardHeader writes the versioned prefix shared by every
// dynamic forwarding payload.
func writeDynamicForwardHeader(buf []byte, kind uint64) (consumed int, err error) {
	if len(buf) < dynamicForwardHeaderLen() {
		return 0, errors.New("buffer too small to write dynamic forwarding header")
	}
	var tbuf [8]byte
	header := util.AppendVarInt(tbuf[:0], uint64(DynamicForwardVersion))
	consumed += copy(buf[consumed:], header)
	kindBuf := util.AppendVarInt(tbuf[:0], kind)
	consumed += copy(buf[consumed:], kindBuf)
	return consumed, nil
}

// readDynamicForwardHeader reads and validates the versioned prefix shared by
// every dynamic forwarding payload. An unsupported version or an unexpected
// kind is reported as an error instead of letting the caller decode garbage.
func readDynamicForwardHeader(buf util.Reader, expectedKind uint64) error {
	version, err := util.ReadVarInt(buf)
	if err != nil {
		return err
	}
	if version != uint64(DynamicForwardVersion) {
		return fmt.Errorf("unsupported dynamic forwarding protocol version: %d", version)
	}
	kind, err := util.ReadVarInt(buf)
	if err != nil {
		return err
	}
	if kind != expectedKind {
		return fmt.Errorf("unexpected dynamic forwarding message kind: %d instead of expected %d", kind, expectedKind)
	}
	return nil
}

// RequestDynamicForward is the payload a client sends as channel data on a
// "dynamic-forward" control channel to announce that it wants the server to
// serve dynamic forwarding. It deliberately travels as channel data (not as a
// new message-type id): ParseMessage panics on unknown message-type ids, so
// routing a new id through it would crash older peers instead of letting them
// reject the request gracefully.
//
// BindAddress and BindPort describe the SOCKS listener on the *client* side;
// the server never binds anything for a dynamic forward, it only echoes them
// back so the client can confirm the forwarding was accepted. BindAddress is
// an IP literal, "*" (wildcard) or empty (client default: loopback only).
type RequestDynamicForward struct {
	BindAddress string
	BindPort    uint16
}

// ParseRequestDynamicForward decodes a RequestDynamicForward payload.
func ParseRequestDynamicForward(buf util.Reader) (*RequestDynamicForward, error) {
	if err := readDynamicForwardHeader(buf, DynamicForwardKindRequest); err != nil {
		return nil, err
	}
	bindAddress, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, err
	}
	var bindPortBuf [2]byte
	if _, err := io.ReadFull(buf, bindPortBuf[:]); err != nil {
		return nil, err
	}
	return &RequestDynamicForward{
		BindAddress: bindAddress,
		BindPort:    binary.BigEndian.Uint16(bindPortBuf[:]),
	}, nil
}

// Length returns the encoded size of the payload, prefix included.
func (m *RequestDynamicForward) Length() int {
	return dynamicForwardHeaderLen() + util.SSHStringLen(m.BindAddress) + 2
}

// Write encodes the payload, prefix included, at the beginning of buf.
func (m *RequestDynamicForward) Write(buf []byte) (consumed int, err error) {
	if len(buf) < m.Length() {
		return 0, errors.New("buffer too small to write dynamic forwarding request")
	}
	consumed, err = writeDynamicForwardHeader(buf, DynamicForwardKindRequest)
	if err != nil {
		return 0, err
	}
	n, err := util.WriteSSHString(buf[consumed:], m.BindAddress)
	if err != nil {
		return 0, err
	}
	consumed += n
	var bindPortBuf [2]byte
	binary.BigEndian.PutUint16(bindPortBuf[:], m.BindPort)
	consumed += copy(buf[consumed:], bindPortBuf[:])
	return consumed, nil
}

// DynamicForwardReply is the payload the server sends back as channel data on
// the "dynamic-forward" control channel. An empty ErrorUTF8 means the request
// was accepted; otherwise it carries a human-readable reason. BoundPort echoes
// the client-side bind port the server was asked to serve.
type DynamicForwardReply struct {
	BoundPort uint16
	ErrorUTF8 string
}

// Success reports whether the server accepted the dynamic forwarding request.
func (m *DynamicForwardReply) Success() bool { return m.ErrorUTF8 == "" }

// ParseDynamicForwardReply decodes a DynamicForwardReply payload.
func ParseDynamicForwardReply(buf util.Reader) (*DynamicForwardReply, error) {
	if err := readDynamicForwardHeader(buf, DynamicForwardKindRequestReply); err != nil {
		return nil, err
	}
	var boundPortBuf [2]byte
	if _, err := io.ReadFull(buf, boundPortBuf[:]); err != nil {
		return nil, err
	}
	errorUTF8, err := util.ParseSSHString(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return &DynamicForwardReply{
		BoundPort: binary.BigEndian.Uint16(boundPortBuf[:]),
		ErrorUTF8: errorUTF8,
	}, err
}

// Length returns the encoded size of the payload, prefix included.
func (m *DynamicForwardReply) Length() int {
	return dynamicForwardHeaderLen() + 2 + util.SSHStringLen(m.ErrorUTF8)
}

// Write encodes the payload, prefix included, at the beginning of buf.
func (m *DynamicForwardReply) Write(buf []byte) (consumed int, err error) {
	if len(buf) < m.Length() {
		return 0, errors.New("buffer too small to write dynamic forwarding reply")
	}
	consumed, err = writeDynamicForwardHeader(buf, DynamicForwardKindRequestReply)
	if err != nil {
		return 0, err
	}
	var boundPortBuf [2]byte
	binary.BigEndian.PutUint16(boundPortBuf[:], m.BoundPort)
	consumed += copy(buf[consumed:], boundPortBuf[:])
	n, err := util.WriteSSHString(buf[consumed:], m.ErrorUTF8)
	if err != nil {
		return 0, err
	}
	consumed += n
	return consumed, nil
}

// DynamicForwardTarget is the payload a client sends as the first channel data
// on a "dynamic-forward-tcp" channel: the address the server must dial on
// behalf of the SOCKS client. Unlike the reverse forwarding (-R) targets,
// Address may be a hostname: the server resolves it, as a SOCKS client may
// only know a name.
type DynamicForwardTarget struct {
	Address string
	Port    uint16
}

// ParseDynamicForwardTarget decodes a DynamicForwardTarget payload. An empty
// address or a null port is rejected: there is nothing to dial.
func ParseDynamicForwardTarget(buf util.Reader) (*DynamicForwardTarget, error) {
	if err := readDynamicForwardHeader(buf, DynamicForwardKindTarget); err != nil {
		return nil, err
	}
	address, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, err
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(buf, portBuf[:]); err != nil {
		return nil, err
	}
	target := &DynamicForwardTarget{
		Address: address,
		Port:    binary.BigEndian.Uint16(portBuf[:]),
	}
	if target.Address == "" {
		return nil, errors.New("empty dynamic forwarding target address")
	}
	if target.Port == 0 {
		return nil, errors.New("null dynamic forwarding target port")
	}
	return target, nil
}

// Length returns the encoded size of the payload, prefix included.
func (m *DynamicForwardTarget) Length() int {
	return dynamicForwardHeaderLen() + util.SSHStringLen(m.Address) + 2
}

// Write encodes the payload, prefix included, at the beginning of buf.
func (m *DynamicForwardTarget) Write(buf []byte) (consumed int, err error) {
	if len(buf) < m.Length() {
		return 0, errors.New("buffer too small to write dynamic forwarding target")
	}
	consumed, err = writeDynamicForwardHeader(buf, DynamicForwardKindTarget)
	if err != nil {
		return 0, err
	}
	n, err := util.WriteSSHString(buf[consumed:], m.Address)
	if err != nil {
		return 0, err
	}
	consumed += n
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], m.Port)
	consumed += copy(buf[consumed:], portBuf[:])
	return consumed, nil
}

// DynamicForwardTargetReply is the payload the server sends as channel data on
// a "dynamic-forward-tcp" channel, right after the target. An empty ErrorUTF8
// means the connection to the target was established and the channel is now a
// live bridge; otherwise it carries the reason the dial failed (unreachable
// host, connection refused, ...) so the client can report it to the SOCKS
// client.
type DynamicForwardTargetReply struct {
	ErrorUTF8 string
}

// Success reports whether the server established the bridge to the target.
func (m *DynamicForwardTargetReply) Success() bool { return m.ErrorUTF8 == "" }

// ParseDynamicForwardTargetReply decodes a DynamicForwardTargetReply payload.
func ParseDynamicForwardTargetReply(buf util.Reader) (*DynamicForwardTargetReply, error) {
	if err := readDynamicForwardHeader(buf, DynamicForwardKindTargetReply); err != nil {
		return nil, err
	}
	errorUTF8, err := util.ParseSSHString(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return &DynamicForwardTargetReply{ErrorUTF8: errorUTF8}, err
}

// Length returns the encoded size of the payload, prefix included.
func (m *DynamicForwardTargetReply) Length() int {
	return dynamicForwardHeaderLen() + util.SSHStringLen(m.ErrorUTF8)
}

// Write encodes the payload, prefix included, at the beginning of buf.
func (m *DynamicForwardTargetReply) Write(buf []byte) (consumed int, err error) {
	if len(buf) < m.Length() {
		return 0, errors.New("buffer too small to write dynamic forwarding target reply")
	}
	consumed, err = writeDynamicForwardHeader(buf, DynamicForwardKindTargetReply)
	if err != nil {
		return 0, err
	}
	n, err := util.WriteSSHString(buf[consumed:], m.ErrorUTF8)
	if err != nil {
		return 0, err
	}
	consumed += n
	return consumed, nil
}
