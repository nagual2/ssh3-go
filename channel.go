package ssh3

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/francoismichel/ssh3/compress"

	ssh3 "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"

	"github.com/quic-go/quic-go"
)

type ChannelOpenFailure struct {
	ReasonCode uint64
	ErrorMsg   string
}

func (e ChannelOpenFailure) Error() string {
	return fmt.Sprintf("Channel open failure: reason: %d: %s", e.ReasonCode, e.ErrorMsg)
}

type MessageOnNonConfirmedChannel struct {
	message ssh3.Message
}

func (e MessageOnNonConfirmedChannel) Error() string {
	return fmt.Sprintf("A message of type %T has been received on a non-confirmed channel", e.message)
}

type ReceivedDatagramOnNonDatagramChannel struct {
	channelID uint64
}

func (e ReceivedDatagramOnNonDatagramChannel) Error() string {
	return fmt.Sprintf("a datagram has been received on non-datagram channel %d", e.channelID)
}

type SentDatagramOnNonDatagramChannel struct {
	channelID uint64
}

func (e SentDatagramOnNonDatagramChannel) Error() string {
	return fmt.Sprintf("a datagram has been sent on non-datagram channel %d", e.channelID)
}

type PtyReqHandler func(channel Channel, request ssh3.PtyRequest, wantReply bool)
type X11ReqHandler func(channel Channel, request ssh3.X11Request, wantReply bool)
type ShellReqHandler func(channel Channel, request ssh3.ShellRequest, wantReply bool)
type ExecReqHandler func(channel Channel, request ssh3.ExecRequest, wantReply bool)
type SubsystemReqHandler func(channel Channel, request ssh3.SubsystemRequest, wantReply bool)
type WindowChangeReqHandler func(channel Channel, request ssh3.WindowChangeRequest, wantReply bool)
type SignalReqHandler func(channel Channel, request ssh3.SignalRequest, wantReply bool)
type ExitStatusReqHandler func(channel Channel, request ssh3.ExitStatusRequest, wantReply bool)
type ExitSignalReqHandler func(channel Channel, request ssh3.ExitSignalRequest, wantReply bool)

type ChannelDataHandler func(channel Channel, dataType ssh3.SSHDataType, data string)

type channelCloseListener interface {
	onChannelClose(channel Channel)
}

type ChannelInfo struct {
	MaxPacketSize        uint64
	ConversationStreamID uint64
	ConversationID       ConversationID
	ChannelID            uint64
	ChannelType          string

	// CompressAlgorithm is the codec of the compressed data frames of
	// this channel (the compression of the channel body, PLAN.md 9 B8);
	// zero means the channel carries the plain frames only.
	CompressAlgorithm uint64
}

type Channel interface {
	ChannelID() util.ChannelID
	ConversationID() ConversationID
	ConversationStreamID() uint64
	NextMessage() (ssh3.Message, error)
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	SendDatagram(datagram []byte) error
	SendRequest(r *ssh3.ChannelRequestMessage) error
	CancelRead()
	Close()
	MaxPacketSize() uint64
	WriteData(dataBuf []byte, dataType ssh3.SSHDataType) (int, error)
	ChannelType() string
	confirmChannel(maxPacketSize uint64) error
	setDatagramSender(func(datagram []byte) error)
	waitAddDatagram(ctx context.Context, datagram []byte) error
	addDatagram(datagram []byte) bool
	maybeSendHeader() error
	setDgramQueue(*util.DatagramsQueue)
}

type channelImpl struct {
	ChannelInfo
	confirmSent     bool
	confirmReceived bool
	header          []byte

	datagramSender util.SSH3DatagramSenderFunc

	channelCloseListener

	recv           *quic.Stream
	send           io.WriteCloser
	datagramsQueue *util.DatagramsQueue
	PtyReqHandler
	X11ReqHandler
	ShellReqHandler
	ExecReqHandler
	SubsystemReqHandler
	WindowChangeReqHandler
	SignalReqHandler
	ExitStatusReqHandler
	ExitSignalReqHandler

	ChannelDataHandler
}

type UDPForwardingChannelImpl struct {
	RemoteAddr *net.UDPAddr
	Channel
}

type TCPForwardingChannelImpl struct {
	RemoteAddr *net.TCPAddr
	Channel
}

func buildHeader(conversationStreamID uint64, channelType string, maxPacketSize uint64, additionalBytes []byte) []byte {
	channelTypeBuf := make([]byte, util.SSHStringLen(channelType))
	util.WriteSSHString(channelTypeBuf, channelType)

	buf := util.AppendVarInt(nil, 0xaf3627e6)
	buf = util.AppendVarInt(buf, conversationStreamID)
	buf = append(buf, channelTypeBuf...)
	buf = util.AppendVarInt(buf, maxPacketSize)
	if additionalBytes != nil {
		buf = append(buf, additionalBytes...)
	}
	return buf
}

func buildForwardingChannelAdditionalBytes(remoteAddr net.IP, port uint16) []byte {
	var buf []byte

	// The resolver hands out IPv4 as the mapped ::ffff:a.b.c.d form (a
	// 16-byte net.IP), so the family cannot be picked by slice length:
	// a mapped address would go out as IPv6 with the v4 bytes inside,
	// and a peer following the wire contract (the family is the only
	// length promise) refuses it. To4() names the v4 reality of both
	// the 4-byte and the mapped form.
	var addressFamily util.SSHForwardingAddressFamily
	if v4 := remoteAddr.To4(); v4 != nil {
		remoteAddr = v4
		addressFamily = util.SSHAFIpv4
	} else {
		addressFamily = util.SSHAFIpv6
	}

	buf = util.AppendVarInt(buf, addressFamily)

	buf = append(buf, remoteAddr...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	buf = append(buf, portBuf[:]...)
	return buf
}

// minPeerMaxPacketSize floors a peer-advertised maxPacketSize (P3-02): below
// the empty data-frame length the outbound chunk size in WriteData
// (MaxPacketSize - emptyMsgLen) underflows uint64 and sends whole buffers as
// one oversized frame, and a 0/1-byte read buffer deadlocks the channel
// anyway. The confirmation announces the floored value, so the peer sees
// what this endpoint actually accepts.
const minPeerMaxPacketSize = 4096

// clampPeerMaxPacketSize bounds a peer-advertised maxPacketSize from both
// sides: by the local endpoint's own advertised value from above — the
// channel-open confirmation already announces the local value, so lowering
// an inflated peer request is protocol-consistent — and by
// minPeerMaxPacketSize from below. Without the bounds the peer picks the
// size of every per-channel read buffer the endpoint allocates, and the
// number of channels is only bounded by the QUIC stream limit (S2-01).
func clampPeerMaxPacketSize(peer, local uint64) uint64 {
	if peer < minPeerMaxPacketSize {
		peer = minPeerMaxPacketSize
	}
	return util.MinUint64(peer, local)
}

// clampLocalMaxPacketSize floors the locally advertised value at channel
// construction (P4-04): WriteData chunks at MaxPacketSize - emptyMsgLen, so a
// local value at or below the empty-frame length spins the write loop or
// underflows it. Every opener passes the same 30000 constant, which kept the
// invariant a property of the call sites; pinning it here — where the header
// and the ChannelInfo are built — holds it for any future caller. Inbound
// channels arrive with the already-floored peer value, so this is a no-op
// for them.
func clampLocalMaxPacketSize(local uint64) uint64 {
	if local < minPeerMaxPacketSize {
		return minPeerMaxPacketSize
	}
	return local
}

// The channel-type role table as allow-lists (S2-03/P3-03): an endpoint
// accepts only the channel types the peer's role may open. The negative
// checks this replaces refused the four known cross-role names, while any
// other unknown string fell through to the session branch and occupied a
// real session slot.
//
// The two sets must cover exactly what the dispatch layers handle: the
// server's accept loop in cmd/ssh3-server.go consumes the client-opened
// set, the client's acceptLoop in client/reverse_forward.go the
// server-opened one (channel_types_test.go pins the table).

// serverAcceptsChannelType reports whether a client may open channelType
// towards the server.
func serverAcceptsChannelType(channelType string) bool {
	switch channelType {
	case "session", "sftp", "direct-tcp", "direct-udp",
		ssh3.ChannelTypeReverseForward, ssh3.ChannelTypeDynamicForward, ssh3.ChannelTypeDynamicForwardTCP:
		return true
	default:
		return false
	}
}

// clientAcceptsChannelType reports whether the server may open channelType
// towards the client.
func clientAcceptsChannelType(channelType string) bool {
	switch channelType {
	case ssh3.ChannelTypeForwardedTCP, ssh3.ChannelTypeForwardedUDP, "agent-connection":
		return true
	default:
		return false
	}
}

func parseHeader(channelID uint64, r util.Reader) (conversationControlStreamID ControlStreamID, channelType string, maxPacketSize uint64, err error) {
	conversationControlStreamID, err = util.ReadVarInt(r)
	if err != nil {
		return 0, "", 0, err
	}
	channelType, err = util.ParseSSHString(r)
	if err != nil {
		return 0, "", 0, err
	}
	maxPacketSize, err = util.ReadVarInt(r)
	if err != nil {
		return 0, "", 0, err
	}
	// the peer's advertised packet size bounds the data messages it may send
	// on the channel; left unbounded it is a second unvalidated allocation
	// knob (data messages parse through ParseSSHString)
	if maxPacketSize > util.MaxSSHStringLen {
		return 0, "", 0, fmt.Errorf("peer max packet size %d exceeds %d", maxPacketSize, util.MaxSSHStringLen)
	}
	return conversationControlStreamID, channelType, maxPacketSize, nil
}

func parseForwardingHeader(channelID uint64, buf util.Reader) (net.IP, uint16, error) {
	addressFamily, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, 0, err
	}

	var address net.IP
	if addressFamily == util.SSHAFIpv4 {
		address = make([]byte, 4)
	} else if addressFamily == util.SSHAFIpv6 {
		address = make([]byte, 16)
	} else {
		return nil, 0, fmt.Errorf("invalid address family: %d", addressFamily)
	}

	_, err = buf.Read(address)
	if err != nil {
		return nil, 0, err
	}

	var portBuf [2]byte
	_, err = buf.Read(portBuf[:])
	if err != nil {
		return nil, 0, err
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	return address, port, nil
}

func parseUDPForwardingHeader(channelID uint64, buf util.Reader) (*net.UDPAddr, error) {
	address, port, err := parseForwardingHeader(channelID, buf)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{
		IP:   address,
		Port: int(port),
	}, nil
}

func parseTCPForwardingHeader(channelID uint64, buf util.Reader) (*net.TCPAddr, error) {
	address, port, err := parseForwardingHeader(channelID, buf)
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{
		IP:   address,
		Port: int(port),
	}, nil
}

func NewChannel(conversationStreamID uint64, conversationID ConversationID, channelID uint64, channelType string, maxPacketSize uint64, recv *quic.Stream,
	send io.WriteCloser, datagramSender util.SSH3DatagramSenderFunc, channelCloseListener channelCloseListener, sendHeader bool, confirmSent bool,
	confirmReceived bool, datagramsQueueSize uint64, compressAlgorithm uint64, additonalHeaderBytes []byte) Channel {
	// P4-04: floor the local advertisement before it reaches the header and
	// the ChannelInfo; see clampLocalMaxPacketSize
	maxPacketSize = clampLocalMaxPacketSize(maxPacketSize)
	var header []byte = nil
	if sendHeader {
		header = buildHeader(conversationStreamID, channelType, maxPacketSize, additonalHeaderBytes)
	}
	return &channelImpl{
		ChannelInfo: ChannelInfo{
			MaxPacketSize:        maxPacketSize,
			ConversationStreamID: conversationStreamID,
			ConversationID:       conversationID,
			ChannelID:            channelID,
			ChannelType:          channelType,
			CompressAlgorithm:    compressAlgorithm,
		},
		recv:                 recv,
		send:                 send,
		datagramsQueue:       util.NewDatagramsQueue(datagramsQueueSize),
		datagramSender:       datagramSender,
		channelCloseListener: channelCloseListener,
		header:               header,
		confirmSent:          confirmSent,
		confirmReceived:      confirmReceived,
	}
}

func (c *channelImpl) ChannelID() util.ChannelID {
	return c.ChannelInfo.ChannelID
}

func (c *channelImpl) ConversationStreamID() uint64 {
	return c.ChannelInfo.ConversationStreamID
}

func (c *channelImpl) ConversationID() ConversationID {
	return c.ChannelInfo.ConversationID
}

// / The error is EOF only if no bytes were read. If an EOF happens
// / after reading some but not all the bytes, nextMessage returns
// / ErrUnexpectedEOF.
func (c *channelImpl) nextMessage() (ssh3.Message, error) {
	return ssh3.ParseMessage(util.NewReader(c.recv))
}

// The returned  message will neither be ChannelOpenConfirmationMessage nor ChannelOpenFailureMessage
// as this function handles it internally
func (c *channelImpl) NextMessage() (ssh3.Message, error) {
	genericMessage, err := c.nextMessage()
	if err != nil {
		return nil, err
	}

	switch message := genericMessage.(type) {
	case *ssh3.ChannelOpenConfirmationMessage:
		c.confirmReceived = true
		// let's read the next message
		return c.NextMessage()
	case *ssh3.ChannelOpenFailureMessage:
		return nil, ChannelOpenFailure{ReasonCode: message.ReasonCode, ErrorMsg: message.ErrorMessageUTF8}
	}

	// TODO: might be problematic if a peer already sends data along the channel opening
	if !c.confirmSent {
		return nil, MessageOnNonConfirmedChannel{message: genericMessage}
	}
	return genericMessage, nil
}

func (c *channelImpl) maybeSendHeader() error {
	if len(c.header) > 0 {
		written, err := c.send.Write(c.header)
		if err != nil {
			return err
		}
		c.header = c.header[written:]
	}
	return nil
}

// headerBufs recycles the per-chunk frame header buffer of WriteData: a
// stack array would escape through the interface call of send.Write (one
// heap allocation per chunk), a pooled heap buffer escapes for free
// (ROADMAP.local.md §R9).
var headerBufs = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 16)
		return &b
	},
}

func (c *channelImpl) WriteData(dataBuf []byte, dataType ssh3.SSHDataType) (int, error) {
	err := c.maybeSendHeader()
	if err != nil {
		return 0, err
	}
	written := 0
	emptyMsgLen := uint64((&ssh3.DataOrExtendedDataMessage{DataType: dataType, Data: ""}).Length())
	// P4-04: a MaxPacketSize at or below the frame's own header length leaves
	// the chunk at zero — or underflows it — and the loop below would spin
	// forever without writing a byte. The construction-time floor makes this
	// unreachable for well-formed channels; the check keeps it unreachable
	// for every other.
	if c.ChannelInfo.MaxPacketSize <= emptyMsgLen {
		return 0, fmt.Errorf("channel %d: max packet size %d does not exceed the %d-byte data frame header",
			c.ChannelID(), c.ChannelInfo.MaxPacketSize, emptyMsgLen)
	}
	chunkSize := c.ChannelInfo.MaxPacketSize - emptyMsgLen
	dataMsg := &ssh3.DataOrExtendedDataMessage{DataType: dataType}
	hp := headerBufs.Get().(*[]byte)
	defer func() {
		*hp = (*hp)[:0]
		headerBufs.Put(hp)
	}()
	for len(dataBuf) > 0 {
		msgLen := util.MinUint64(chunkSize, uint64(len(dataBuf)))
		chunk := dataBuf[:msgLen]
		dataBuf = dataBuf[msgLen:]

		// the compression of the channel body (PLAN.md 9, B8): the
		// chunk is compressed when the peer announced the codec and the
		// compressed form is smaller - the cutoff of the ZFS fast
		// levels, already compressed data is not compressed twice.  The
		// stderr stream keeps the plain frames.
		if c.CompressAlgorithm != compress.AlgorithmNone && dataType == ssh3.SSH_EXTENDED_DATA_NONE {
			if packed, ok := compress.Compress(c.CompressAlgorithm, chunk); ok && len(packed) < len(chunk) {
				h := ssh3.AppendCompressedDataHeader((*hp)[:0], c.CompressAlgorithm, uint64(len(packed)))
				if _, err := c.send.Write(h); err != nil {
					return written, err
				}
				n, err := c.send.Write(packed)
				written += n
				if err != nil {
					return written, err
				}
				continue
			}
		}

		// marshal only the small frame header and write the payload as-is:
		// copying 30 KiB per message (string conversion + buffer marshal)
		// showed up as memmove/GC pressure in the data-path profile
		// (docs/PROFILE-2026-09-29.md); the byte stream is identical
		h := dataMsg.AppendHeader((*hp)[:0], uint64(msgLen))
		if _, err := c.send.Write(h); err != nil {
			return written, err
		}
		n, err := c.send.Write(chunk)
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func (c *channelImpl) confirmChannel(maxPacketSize uint64) error {
	err := c.sendMessage(&ssh3.ChannelOpenConfirmationMessage{MaxPacketSize: maxPacketSize})
	if err == nil {
		c.confirmSent = true
	}
	return err
}

// sendMessageBufs recycles the marshalling buffer of every control message:
// the per-message make showed up as allocation pressure on the control path
// (ROADMAP.local.md §R9). Buffers grow on demand and come back here right
// after send.Write — the QUIC stream copies the bytes into its own packet
// buffers, so the write never aliases the caller's slice.
var sendMessageBufs = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 512)
		return &b
	},
}

func (c *channelImpl) sendMessage(m ssh3.Message) error {
	err := c.maybeSendHeader()
	if err != nil {
		return err
	}
	size := m.Length()
	bp := sendMessageBufs.Get().(*[]byte)
	buf := *bp
	if cap(buf) < size {
		buf = make([]byte, size)
	}
	buf = buf[:size]
	_, err = m.Write(buf)
	if err == nil {
		c.send.Write(buf)
	}
	*bp = buf[:0]
	sendMessageBufs.Put(bp)
	return err
}

// blocks until the datagram is added
func (c *channelImpl) waitAddDatagram(ctx context.Context, datagram []byte) error {
	return c.datagramsQueue.WaitAdd(ctx, datagram)
}

// blocks until the datagram is added
func (c *channelImpl) addDatagram(datagram []byte) bool {
	return c.datagramsQueue.Add(datagram)
}

func (c *channelImpl) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.datagramsQueue.WaitNext(ctx)
}

func (c *channelImpl) SendDatagram(datagram []byte) error {
	c.maybeSendHeader()
	if c.datagramSender == nil {
		return SentDatagramOnNonDatagramChannel{c.ChannelID()}
	}
	return c.datagramSender(datagram)
}

func (c *channelImpl) SendRequest(r *ssh3.ChannelRequestMessage) error {
	//TODO: make it thread safe
	return c.sendMessage(r)
}

func (c *channelImpl) CancelRead() {
	c.recv.CancelRead(42)
}

func (c *channelImpl) Close() {
	c.send.Close()
	// P4-02: the listener was wired at construction but nothing invoked it,
	// so the manager kept every channel — including ones the budget refused
	// right after AcceptChannel registered them — until the conversation
	// died; prune on close. removeChannel deletes under the manager's lock
	// and is idempotent, so a repeated close is safe.
	if c.channelCloseListener != nil {
		c.channelCloseListener.onChannelClose(c)
	}
}

func (c *channelImpl) MaxPacketSize() uint64 {
	return c.ChannelInfo.MaxPacketSize
}

func (c *channelImpl) ChannelType() string {
	return c.ChannelInfo.ChannelType
}

func (c *channelImpl) setDatagramSender(datagramSender func(datagram []byte) error) {
	c.datagramSender = datagramSender
}

func (c *channelImpl) setDgramQueue(q *util.DatagramsQueue) {
	c.datagramsQueue = q
}
