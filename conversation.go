package ssh3

import (
	"github.com/francoismichel/ssh3/compress"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/francoismichel/ssh3/util"
	"golang.org/x/exp/slices"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
)

const SSH_FRAME_TYPE = 0xaf3627e6

type ConversationID [32]byte

func (cid ConversationID) String() string {
	return base64.StdEncoding.EncodeToString(cid[:])
}

// controlStreamHandle is the surface of the conversation's control stream the
// Conversation needs. On the client the control stream is an
// *http3.RequestStream, on the server an *http3.Stream; both provide this
// minimal API.
type controlStreamHandle interface {
	Close() error
	StreamID() quic.StreamID
}

type Conversation struct {
	controlStream             controlStreamHandle
	maxPacketSize             uint64
	defaultDatagramsQueueSize uint64
	streamCreator             streamOpener
	messageSender             util.DatagramSender
	channelsManager           *channelsManager
	context                   context.Context
	cancelContext             context.CancelCauseFunc
	conversationID            ConversationID // generated using TLS exporters
	peerVersion               Version

	channelsAcceptQueue *util.AcceptQueue[Channel]

	multiplexed atomic.Bool // set by a control master's CONNECT (stage 3.5)
}

// compressAlgorithm returns the codec of the compressed data frames of
// this conversation: the algorithm both sides derive from the
// capability the peer announced in its version string (the compression
// of the channel body, PLAN.md 9 B8).  A peer that announced nothing
// gets the plain frames.
func (c *Conversation) compressAlgorithm() uint64 {
	return compress.Choose(c.peerVersion.GetCompressAlgorithms())
}

func GenerateConversationID(tls *tls.ConnectionState) (convID ConversationID, err error) {
	ret, err := tls.ExportKeyingMaterial("EXPORTER-SSH3", nil, 32)
	if err != nil {
		return convID, err
	}
	if len(ret) != len(convID) {
		return convID, fmt.Errorf("TLS returned a tls-exporter with the wrong length (%d instead of %d)", len(ret), len(convID))
	}
	copy(convID[:], ret)
	return convID, err
}

func NewClientConversation(maxPacketsize uint64, defaultDatagramsQueueSize uint64, tls *tls.ConnectionState) (*Conversation, error) {
	convID, err := GenerateConversationID(tls)
	if err != nil {
		log.Error().Msgf("could not generate conversation ID: %s", err)
		return nil, err
	}
	backgroundCtx, backgroundCancelCauseFunc := context.WithCancelCause(context.Background())
	conv := &Conversation{
		controlStream:             nil,
		channelsAcceptQueue:       util.NewAcceptQueue[Channel](),
		streamCreator:             nil,
		maxPacketSize:             maxPacketsize,
		defaultDatagramsQueueSize: defaultDatagramsQueueSize,
		channelsManager:           newChannelsManager(),
		context:                   backgroundCtx,
		cancelContext:             backgroundCancelCauseFunc,
		conversationID:            convID,

		// peerVersion set afterwards
	}
	return conv, nil
}

func (c *Conversation) EstablishClientConversation(req *http.Request, qconn *quic.Conn, transport *http3.Transport, supportedVersions []Version) error {

	// quic-go v0.63 no longer spawns accept loops nor offers a StreamHijacker
	// for raw connections: the application drives them itself, and it must do so
	// before the request is sent so that the server's HTTP/3 control and QPACK
	// unidirectional streams are consumed while the response headers are decoded.
	rawConn := transport.NewRawClientConn(qconn)
	connCtx := qconn.Context()
	go func() {
		defer util.PanicGuard("conversation.go:100")()
		for {
			str, err := qconn.AcceptUniStream(connCtx)
			if err != nil {
				return
			}
			go rawConn.HandleUnidirectionalStream(str)
		}
	}()
	// The server only opens bidirectional streams to expose SSH3 channels to the
	// client (e.g. "agent-connection" for ssh-agent forwarding). They must be
	// handled here: (*http3.ClientConn).HandleBidirectionalStream closes the
	// whole connection with STREAM_CREATION_ERROR on any server-initiated
	// bidirectional stream.
	go func() {
		defer util.PanicGuard("conversation.go:114")()
		for {
			str, err := qconn.AcceptStream(connCtx)
			if err != nil {
				return
			}
			go c.handleIncomingChannelStream(str)
		}
	}()

	cc := rawConn.ClientConn

	doReq := func(version Version, req *http.Request) (*http.Response, *http3.RequestStream, Version, error) {
		req.Header.Set("User-Agent", version.GetVersionString())
		log.Debug().Msgf("send %s request on URL %s, User-Agent=\"%s\"", req.Method, req.URL, req.Header.Get("User-Agent"))
		// the v0.49 http3 client API: the extended-CONNECT stream is opened
		// explicitly and stays open, so it can serve as the conversation's
		// control stream
		rs, err := cc.OpenRequestStream(c.Context())
		if err != nil {
			return nil, nil, Version{}, err
		}
		if err := rs.SendRequestHeader(req); err != nil {
			return nil, nil, Version{}, err
		}
		rsp, err := rs.ReadResponse()
		if err != nil {
			return nil, nil, Version{}, err
		}

		log.Debug().Msgf("got response with %s status code", rsp.Status)

		serverVersionStr := rsp.Header.Get("Server")
		serverVersion, err := ParseVersionString(serverVersionStr)
		if err != nil {
			log.Error().Msgf("Could not parse server version: \"%s\"", serverVersionStr)
			if rsp.StatusCode == 200 {
				return rsp, rs, Version{}, InvalidSSHVersion{versionString: serverVersionStr}
			}
		} else {
			log.Debug().Msgf("server has valid version \"%s\" (protocol version = %s, software version = %s)",
				serverVersionStr, serverVersion.GetProtocolVersion(), serverVersion.GetSoftwareVersion())
		}
		return rsp, rs, serverVersion, nil
	}

	rsp, controlStream, serverVersion, err := doReq(ThisVersion(), req)
	if err != nil {
		return err
	}

	serverProtocolVersion := serverVersion.GetProtocolVersion()
	thisProtocolVersion := ThisVersion().GetProtocolVersion()
	if rsp.StatusCode == http.StatusForbidden && serverProtocolVersion != thisProtocolVersion {
		// This version negotiation code might feel a bit heavy but is only there for a smooth transition
		// between early versions and versions coming from an actual IETF specification that include
		// proper version negotiation. Older version of this implementation strictly check the exact protocol
		// version (i.e. must be 3.0) and then check the software version. In next iterations, everything will be
		// based on the protocol version for better interoperability.

		// see if there is an exact version match (including software version, which is useful
		// for old versions that do not support version negotiation based on the protocol version)
		matchingVersionIndex := slices.Index(supportedVersions, serverVersion)

		// there is no exact match, the implementation/software version might differ, but the
		// protocol version may still match
		if matchingVersionIndex == -1 {
			matchingVersionIndex = slices.IndexFunc(supportedVersions, func(supportedVersion Version) bool {
				return serverProtocolVersion == supportedVersion.GetProtocolVersion()
			})
		}
		if matchingVersionIndex != -1 {
			log.Warn().Msgf("The server runs an old version of the protocol (%s). This software is still experimental, "+
				"you may want to update the server version before support is removed. Also, note that connecting to old "+
				"servers may increase the connection establishment time.", serverVersion.GetVersionString())
			// now retry the request with the compatible version
			rsp, controlStream, serverVersion, err = doReq(supportedVersions[matchingVersionIndex], req)
			if err != nil {
				return err
			}
		}
	}

	if rsp.StatusCode == 200 {
		if !IsVersionSupported(serverVersion) {
			log.Warn().Msgf("The server runs an unsupported SSH version (%s), you may want to consider to update the client (currently %s)",
				serverVersion.GetProtocolVersion(), ThisVersion().GetProtocolVersion())
		}
		c.controlStream = controlStream
		// *quic.Conn satisfies the streamOpener facade and provides the
		// quic-level datagram API the loop below needs
		c.streamCreator = qconn
		c.messageSender = qconn
		c.context, c.cancelContext = context.WithCancelCause(qconn.Context())
		go func() {
			defer util.PanicGuard("conversation.go:208")()
			// TODO: this hijacks the datagrams for the whole quic connection, so the server
			//		 currently does not work for several conversations in the same QUIC connection

			for {
				dgram, err := qconn.ReceiveDatagram(c.Context())
				if err != nil {
					if err != context.Canceled {
						log.Error().Msgf("could not receive message from conn: %s", err)
					}
					return
				}
				buf := &util.BytesReadCloser{Reader: bytes.NewReader(dgram)}
				convID, err := util.ReadVarInt(buf)
				if err != nil {
					// F-19: one malformed datagram must not end the
					// conversation's datagram reception; drop it and carry on
					log.Warn().Msgf("dropping malformed datagram on conversation %d: %s", c.controlStream.StreamID(), err)
					continue
				}
				if convID == uint64(c.controlStream.StreamID()) {
					err = c.AddDatagram(c.Context(), dgram[buf.Size()-int64(buf.Len()):])
					if err != nil {
						switch e := err.(type) {
						case util.ChannelNotFound:
							// F-14: a datagram for an unknown channel is a
							// per-channel condition — the channel may have
							// been closed and pruned (P4-02) while the
							// datagram was in flight. Mirroring the server
							// loop (server.go), it is dropped with a warning
							// instead of killing every channel's datagram
							// delivery on this conversation.
							log.Warn().Msgf("dropping datagram for unknown channel %d on conversation %d",
								e.ChannelID, c.controlStream.StreamID())
						case util.DatagramMalformed:
							// F-19: garbage payload — same treatment as an
							// unknown channel: drop the datagram, keep the loop
							log.Warn().Msgf("dropping malformed datagram on conversation %d: %s",
								c.controlStream.StreamID(), e)
						default:
							log.Error().Msgf("could not add datagram to conv id %d: %s", c.controlStream.StreamID(), err)
							return
						}
					}
				} else {
					log.Error().Msgf("discarding datagram with invalid conv id %d", convID)
				}
			}
		}()
		c.peerVersion = serverVersion
		return nil
	} else if rsp.StatusCode == http.StatusUnauthorized {
		return util.Unauthorized{}
	} else {
		bodyContent, err := io.ReadAll(rsp.Body)
		rsp.Body.Close()
		if err != nil {
			log.Error().Msgf("could not read response body from server: %s", err)
		}

		return util.OtherHTTPError{
			HasBody:    rsp.ContentLength > 0,
			Body:       string(bodyContent),
			StatusCode: rsp.StatusCode,
		}
	}
}

// handleIncomingChannelStream processes a server-initiated SSH3 channel
// stream, formerly handled by the v0.49 RoundTripper.StreamHijacker. The first
// QUIC varint of the stream must be the SSH3 frame type; the stream is
// consumed from its beginning, unlike the v0.49 hijacker which received the
// stream with the frame type already parsed by http3.
func (c *Conversation) handleIncomingChannelStream(stream *quic.Stream) {
	frameType, err := util.ReadVarInt(&StreamByteReader{stream})
	if err != nil {
		log.Error().Msgf("could not read frame type of incoming stream %d: %s", uint64(stream.StreamID()), err)
		return
	}
	if frameType != SSH_FRAME_TYPE {
		log.Error().Msgf("bad frame type %d on incoming stream %d, canceling stream", frameType, uint64(stream.StreamID()))
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.CancelWrite(quic.StreamErrorCode(0))
		return
	}
	if c.controlStream == nil {
		// cannot happen with valid peers: the server only opens channels after
		// answering the CONNECT request, and the control stream is registered
		// before that. Keep the old hijacker's assumption explicit instead of
		// panicking on a nil dereference.
		log.Error().Msgf("received channel on stream %d before the conversation was established, canceling stream", uint64(stream.StreamID()))
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.CancelWrite(quic.StreamErrorCode(0))
		return
	}

	controlStreamID, channelType, maxPacketSize, err := parseHeader(uint64(stream.StreamID()), &StreamByteReader{stream})
	if err != nil {
		log.Error().Msgf("could not parse channel header on stream %d: %s", uint64(stream.StreamID()), err)
		return
	}
	// a malicious server must not pick the size of the client's read buffers
	// either: bound the peer's value by the locally advertised one (S2-01)
	maxPacketSize = clampPeerMaxPacketSize(maxPacketSize, c.maxPacketSize)
	if !clientAcceptsChannelType(channelType) {
		// the allow-list gate (S2-03/P3-03), symmetric to the server's: a
		// server-opened channel of a client-to-server type is cancelled
		// here, before any channel allocation
		log.Warn().Msgf("refusing server-opened channel %d of type %q: not a server-to-client channel type",
			uint64(stream.StreamID()), channelType)
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.CancelWrite(quic.StreamErrorCode(0))
		return
	}
	// todo: handle several conversations for the same client on the same connection ?
	// This can be done by defining the conversation ID as a combination between the control stream ID
	// and the tls exporter value, or computing the exporter value depending on the stream ID
	if controlStreamID != uint64(c.controlStream.StreamID()) {
		err := fmt.Errorf("wrong conversation control stream ID: %d instead of expected %d", controlStreamID, c.controlStream.StreamID())
		log.Error().Msgf("%s", err)
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.CancelWrite(quic.StreamErrorCode(0))
		return
	}
	channelInfo := &ChannelInfo{
		ConversationID:       c.ConversationID(),
		ConversationStreamID: controlStreamID,
		ChannelID:            uint64(stream.StreamID()),
		ChannelType:          channelType,
		MaxPacketSize:        maxPacketSize,
	}

	newChannel := NewChannel(channelInfo.ConversationStreamID, channelInfo.ConversationID, uint64(stream.StreamID()), channelInfo.ChannelType, channelInfo.MaxPacketSize, stream, stream, nil, c.channelsManager, false, false, true, c.defaultDatagramsQueueSize, c.compressAlgorithm(), nil)
	newChannel.setDatagramSender(c.getDatagramSenderForChannel(newChannel.ChannelID()))
	switch channelType {
	case "forwarded-tcp":
		// reverse port forwarding (-R): the additional header bytes carry the
		// client-side target the channel must be bridged to
		targetAddr, err := parseTCPForwardingHeader(channelInfo.ChannelID, &StreamByteReader{stream})
		if err != nil {
			log.Error().Msgf("could not parse forwarded-tcp header on channel %d: %s", channelInfo.ChannelID, err)
			stream.CancelRead(quic.StreamErrorCode(0))
			stream.CancelWrite(quic.StreamErrorCode(0))
			return
		}
		newChannel = &TCPForwardingChannelImpl{Channel: newChannel, RemoteAddr: targetAddr}
	case "forwarded-udp":
		// same as forwarded-tcp, but datagram-based
		targetAddr, err := parseUDPForwardingHeader(channelInfo.ChannelID, &StreamByteReader{stream})
		if err != nil {
			log.Error().Msgf("could not parse forwarded-udp header on channel %d: %s", channelInfo.ChannelID, err)
			stream.CancelRead(quic.StreamErrorCode(0))
			stream.CancelWrite(quic.StreamErrorCode(0))
			return
		}
		newChannel = &UDPForwardingChannelImpl{Channel: newChannel, RemoteAddr: targetAddr}
	}
	c.channelsAcceptQueue.Add(newChannel)
}

func NewServerConversation(ctx context.Context, controlStream *http3.Stream, qconn *quic.Conn, messageSender util.DatagramSender, maxPacketsize uint64, peerVersion Version) (*Conversation, error) {
	backgroundContext, backgroundCancelFunc := context.WithCancelCause(ctx)

	tls := qconn.ConnectionState().TLS
	convID, err := GenerateConversationID(&tls)
	if err != nil {
		log.Error().Msgf("could not generate conversation ID on server")
		backgroundCancelFunc(nil)
		return nil, err
	}

	conv := &Conversation{
		controlStream:       controlStream,
		channelsAcceptQueue: util.NewAcceptQueue[Channel](),
		streamCreator:       qconn,
		maxPacketSize:       maxPacketsize,
		messageSender:       messageSender,
		channelsManager:     newChannelsManager(),
		context:             backgroundContext,
		cancelContext:       backgroundCancelFunc,
		conversationID:      convID,
		peerVersion:         peerVersion,
	}
	return conv, nil
}

type StreamByteReader struct {
	*quic.Stream
}

// rawQUICConn is the quic-level connection surface the Conversation needs for
// datagrams and context management; *quic.Conn provides it on both sides.
type rawQUICConn interface {
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	SendDatagram(b []byte) error
	Context() context.Context
}

// streamOpener is the slice of the connection the Conversation needs to open
// new channels: *quic.Conn satisfies it on both the client and the server.
type streamOpener interface {
	OpenStream() (*quic.Stream, error)
}

func (r *StreamByteReader) ReadByte() (byte, error) {
	buf := [1]byte{0}
	_, err := r.Stream.Read(buf[:])
	if err != nil {
		return 0, err
	}
	return buf[0], nil
}

func (c *Conversation) OpenChannel(channelType string, maxPacketSize uint64, datagramsQueueSize uint64) (Channel, error) {
	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), channelType, maxPacketSize, str, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, c.compressAlgorithm(), nil)
	c.channelsManager.addChannel(channel)
	return channel, nil
}

func (c *Conversation) OpenUDPForwardingChannel(maxPacketSize uint64, datagramsQueueSize uint64, localAddr *net.UDPAddr, remoteAddr *net.UDPAddr) (Channel, error) {

	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	additionalBytes := buildForwardingChannelAdditionalBytes(remoteAddr.IP, uint16(remoteAddr.Port))

	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "direct-udp", maxPacketSize, str, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, c.compressAlgorithm(), additionalBytes)
	channel.setDatagramSender(c.getDatagramSenderForChannel(channel.ChannelID()))
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &UDPForwardingChannelImpl{Channel: channel, RemoteAddr: remoteAddr}, nil
}

func (c *Conversation) OpenTCPForwardingChannel(maxPacketSize uint64, datagramsQueueSize uint64, localAddr *net.TCPAddr, remoteAddr *net.TCPAddr) (Channel, error) {

	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	additionalBytes := buildForwardingChannelAdditionalBytes(remoteAddr.IP, uint16(remoteAddr.Port))

	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "direct-tcp", maxPacketSize, str, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, c.compressAlgorithm(), additionalBytes)
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &TCPForwardingChannelImpl{Channel: channel, RemoteAddr: remoteAddr}, nil
}

// openForwardedChannel opens a server-initiated forwarded-* channel whose
// additional header bytes carry targetIP:targetPort, the client-side endpoint
// the channel must be bridged to. Used by the server to implement reverse
// port forwarding (-R): each connection or datagram accepted on a bound
// listener becomes one such channel towards the client.
func (c *Conversation) openForwardedChannel(channelType string, maxPacketSize uint64, datagramsQueueSize uint64, targetIP net.IP, targetPort uint16) (Channel, error) {
	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	additionalBytes := buildForwardingChannelAdditionalBytes(targetIP, targetPort)

	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), channelType, maxPacketSize, str, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, c.compressAlgorithm(), additionalBytes)
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return channel, nil
}

// OpenForwardedTCPChannel opens a "forwarded-tcp" channel towards the client,
// which must bridge it to targetAddr (the local -R target). Server-side only.
func (c *Conversation) OpenForwardedTCPChannel(maxPacketSize uint64, datagramsQueueSize uint64, targetAddr *net.TCPAddr) (Channel, error) {
	return c.openForwardedChannel("forwarded-tcp", maxPacketSize, datagramsQueueSize, targetAddr.IP, uint16(targetAddr.Port))
}

// OpenForwardedUDPChannel opens a "forwarded-udp" channel towards the client,
// which must bridge it to targetAddr (the local -R target). Server-side only.
func (c *Conversation) OpenForwardedUDPChannel(maxPacketSize uint64, datagramsQueueSize uint64, targetAddr *net.UDPAddr) (Channel, error) {
	channel, err := c.openForwardedChannel("forwarded-udp", maxPacketSize, datagramsQueueSize, targetAddr.IP, uint16(targetAddr.Port))
	if err != nil {
		return nil, err
	}
	channel.setDatagramSender(c.getDatagramSenderForChannel(channel.ChannelID()))
	return &UDPForwardingChannelImpl{Channel: channel, RemoteAddr: targetAddr}, nil
}

func (c *Conversation) AcceptChannel(ctx context.Context) (Channel, error) {
	for {
		if channel := c.channelsAcceptQueue.Next(); channel != nil {
			channel.confirmChannel(c.maxPacketSize)
			c.channelsManager.addChannel(channel)
			return channel, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.channelsAcceptQueue.Chan():
		}
	}

}

// blocks until the datagram is added
// the first field must be the channel ID
func (c *Conversation) AddDatagram(ctx context.Context, datagram []byte) error {
	buf := &util.BytesReadCloser{Reader: bytes.NewReader(datagram)}
	channelID, err := util.ReadVarInt(buf)
	if err != nil {
		// F-19: an unparseable datagram is per-datagram garbage; classify it
		// so the receive loops drop it with a warning instead of terminating
		return util.DatagramMalformed{Err: err}
	}
	channel, ok := c.channelsManager.getChannel(channelID)
	if !ok {
		// the datagram raced ahead of the channel registration; buffer it so the
		// channel picks it up in addChannel instead of dropping it on the floor
		c.channelsManager.addDanglingDatagramsQueue(channelID, datagram[buf.Size()-int64(buf.Len()):])
		return util.ChannelNotFound{ChannelID: channelID}
	}
	return channel.waitAddDatagram(ctx, datagram[buf.Size()-int64(buf.Len()):])
}

func (c *Conversation) Close() {
	c.controlStream.Close()
	c.cancelContext(nil)
}

// SetMultiplexed marks the conversation as shared by a control master
// (stage 3.5): its session channels come and go while the connection stays
// up, so the per-session teardown must not fire; the conversation is
// released when the master disconnects. Idempotent.
func (c *Conversation) SetMultiplexed() {
	if !c.multiplexed.CompareAndSwap(false, true) {
		return
	}
	if qconn, ok := c.streamCreator.(*quic.Conn); ok {
		go func() {
			defer util.PanicGuard("conversation.go:510")()
			<-qconn.Context().Done()
			c.Close()
		}()
	}
}

// IsMultiplexed reports whether the conversation belongs to a control
// master (see SetMultiplexed).
func (c *Conversation) IsMultiplexed() bool {
	return c.multiplexed.Load()
}

// DrainAndClose waits for the peer to finish reading in-flight stream data
// and close the connection, then closes the conversation. A conversation
// teardown drops whatever the transport has not packed and sent yet, so a
// server finishing a session must give the peer time to consume the tail of
// the streams (e.g. command output followed by the exit status) before the
// forced close; the timeout only bounds a peer that never goes away.
func (c *Conversation) DrainAndClose(drain time.Duration) {
	if qconn, ok := c.streamCreator.(*quic.Conn); ok {
		select {
		case <-qconn.Context().Done():
			// the peer closed the connection: everything deliverable has been
			// delivered, a forced close no longer destroys anything
		case <-time.After(drain):
		}
	}
	c.Close()
}

func (c *Conversation) Context() context.Context {
	return c.context
}

func (c *Conversation) getDatagramSenderForChannel(channelID util.ChannelID) func(datagram []byte) error {
	return func(datagram []byte) error {
		buf := util.AppendVarInt(nil, uint64(c.controlStream.StreamID()))
		buf = util.AppendVarInt(buf, channelID)
		buf = append(buf, datagram...)
		return c.messageSender.SendDatagram(buf)
	}
}

func (c *Conversation) ConversationID() ConversationID {
	return c.conversationID
}
