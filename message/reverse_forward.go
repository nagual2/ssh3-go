package message

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	util "github.com/francoismichel/ssh3/util"
)

// Channel types for reverse port forwarding (-R). A client opens a
// "reverse-forward" control channel towards the server carrying a
// RequestReverseForward as channel data; for every connection or datagram the
// server then accepts on the requested bind, it opens a server-initiated
// "forwarded-tcp"/"forwarded-udp" channel whose additional header bytes carry
// the client-side target address (same layout as direct-tcp/direct-udp).
const (
	ChannelTypeReverseForward = "reverse-forward"
	ChannelTypeForwardedTCP   = "forwarded-tcp"
	ChannelTypeForwardedUDP   = "forwarded-udp"
)

// RequestReverseForward is the payload a client sends as channel data on a
// "reverse-forward" channel to ask the server to bind a listener for it. It
// deliberately travels as channel data (not as a new message-type id):
// ParseMessage panics on unknown message-type ids, so routing a new id
// through it would crash older peers instead of letting them reject the
// request gracefully. BindAddress is an IP literal, "*" (wildcard) or empty
// (server default: loopback only).
type RequestReverseForward struct {
	Protocol      util.SSHForwardingProtocol
	BindAddress   string
	BindPort      uint16
	TargetAddress string
	TargetPort    uint16
}

func ParseRequestReverseForward(buf util.Reader) (*RequestReverseForward, error) {
	protocol, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, err
	}
	if protocol != util.SSHProtocolUDP && protocol != util.SSHForwardingProtocolTCP {
		return nil, fmt.Errorf("invalid reverse forwarding protocol number: %d", protocol)
	}
	bindAddress, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, err
	}
	var bindPortBuf [2]byte
	if _, err := io.ReadFull(buf, bindPortBuf[:]); err != nil {
		return nil, err
	}
	targetAddress, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, err
	}
	var targetPortBuf [2]byte
	if _, err := io.ReadFull(buf, targetPortBuf[:]); err != nil {
		return nil, err
	}
	return &RequestReverseForward{
		Protocol:      protocol,
		BindAddress:   bindAddress,
		BindPort:      binary.BigEndian.Uint16(bindPortBuf[:]),
		TargetAddress: targetAddress,
		TargetPort:    binary.BigEndian.Uint16(targetPortBuf[:]),
	}, nil
}

func (m *RequestReverseForward) Length() int {
	return int(util.VarIntLen(uint64(m.Protocol))) +
		util.SSHStringLen(m.BindAddress) + 2 +
		util.SSHStringLen(m.TargetAddress) + 2
}

func (m *RequestReverseForward) Write(buf []byte) (consumed int, err error) {
	if len(buf) < m.Length() {
		return 0, errors.New("buffer too small to write reverse forwarding request")
	}

	var tbuf [8]byte
	varintBuf := util.AppendVarInt(tbuf[:0], uint64(m.Protocol))
	consumed += copy(buf[consumed:], varintBuf)

	n, err := util.WriteSSHString(buf[consumed:], m.BindAddress)
	if err != nil {
		return 0, err
	}
	consumed += n

	var bindPortBuf [2]byte
	binary.BigEndian.PutUint16(bindPortBuf[:], m.BindPort)
	consumed += copy(buf[consumed:], bindPortBuf[:])

	n, err = util.WriteSSHString(buf[consumed:], m.TargetAddress)
	if err != nil {
		return 0, err
	}
	consumed += n

	var targetPortBuf [2]byte
	binary.BigEndian.PutUint16(targetPortBuf[:], m.TargetPort)
	consumed += copy(buf[consumed:], targetPortBuf[:])

	return consumed, nil
}

// ReverseForwardReply is the payload the server sends back as channel data on
// the "reverse-forward" control channel. An empty ErrorUTF8 means the bind
// succeeded (BoundPort is the actual bound port, which differs from the
// requested one when the client asked for port 0); otherwise it carries a
// human-readable reason (port busy, permission denied, ...).
type ReverseForwardReply struct {
	BoundPort uint16
	ErrorUTF8 string
}

func (m *ReverseForwardReply) Success() bool { return m.ErrorUTF8 == "" }

func ParseReverseForwardReply(buf util.Reader) (*ReverseForwardReply, error) {
	var boundPortBuf [2]byte
	if _, err := io.ReadFull(buf, boundPortBuf[:]); err != nil {
		return nil, err
	}
	errorUTF8, err := util.ParseSSHString(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return &ReverseForwardReply{
		BoundPort: binary.BigEndian.Uint16(boundPortBuf[:]),
		ErrorUTF8: errorUTF8,
	}, err
}

func (m *ReverseForwardReply) Length() int {
	return 2 + util.SSHStringLen(m.ErrorUTF8)
}

func (m *ReverseForwardReply) Write(buf []byte) (consumed int, err error) {
	if len(buf) < m.Length() {
		return 0, errors.New("buffer too small to write reverse forwarding reply")
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
