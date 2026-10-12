package ssh3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3/util"
)

type ServerConversationHandler func(authenticatedUsername string, conversation *Conversation) error

// conversationRegistrationTimeout bounds how long the channel accept loop waits
// for the conversation of a freshly accepted connection to show up in the
// server's map.
const conversationRegistrationTimeout = 2 * time.Second

// conversationRegistrationPollInterval is the retry granularity used while waiting
// for that registration.
const conversationRegistrationPollInterval = 200 * time.Microsecond

type Server struct {
	maxPacketSize            uint64
	defaultDatagramQueueSize uint64
	h3Server                 *http3.Server
	conversations            map[*quic.Conn]*conversationsManager
	conversationHandler      ServerConversationHandler
	lock                     sync.Mutex
}

// quicConnContextKey is the context key under which the server's ConnContext
// hook exposes the *quic.Conn to the HTTP handlers.
type quicConnContextKey struct{}

// QuicConnFromContext returns the QUIC connection attached to an HTTP/3
// request context. quic-go v0.63 no longer exposes the underlying connection
// through http3.Hijacker, so it is injected via http3.Server.ConnContext.
func QuicConnFromContext(ctx context.Context) (*quic.Conn, bool) {
	qconn, ok := ctx.Value(quicConnContextKey{}).(*quic.Conn)
	return qconn, ok
}

// Creates a new server handling http requests for SSH conversations

func NewServer(maxPacketSize uint64, defaultDatagramQueueSize uint64, h3Server *http3.Server, conversationHandler ServerConversationHandler) *Server {
	ssh3Server := &Server{
		maxPacketSize:            maxPacketSize,
		defaultDatagramQueueSize: defaultDatagramQueueSize,
		h3Server:                 h3Server,
		conversations:            make(map[*quic.Conn]*conversationsManager),
		conversationHandler:      conversationHandler,
	}

	h3Server.ConnContext = func(ctx context.Context, c *quic.Conn) context.Context {
		return context.WithValue(ctx, quicConnContextKey{}, c)
	}
	return ssh3Server
}

// ServeQUICConn drives the accept loops of a single QUIC connection, replacing
// the v0.49 http3.Server.StreamHijacker dispatch which no longer exists in
// quic-go v0.63. Every bidirectional stream is classified by its first QUIC
// varint, except the very first one: the client sends its CONNECT request
// before opening any channel (channels only follow the 200 response), so the
// first bidirectional stream is always an HTTP/3 request stream and must be
// handed to http3 unread, as HandleRequestStream parses the HEADERS frame from
// the beginning of the stream. Subsequent bidirectional streams start with the
// SSH3 frame type and carry a channel. Unidirectional streams always belong to
// HTTP/3 (control, QPACK) and are forwarded to http3. Blocks until the
// connection closes.
func (s *Server) ServeQUICConn(ctx context.Context, qconn *quic.Conn, hconn *http3.RawServerConn) error {
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			str, err := qconn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			go hconn.HandleUnidirectionalStream(str)
		}
	})
	defer wg.Wait()

	firstRequestStream := true
	for {
		str, err := qconn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		if firstRequestStream {
			firstRequestStream = false
			go hconn.HandleRequestStream(str)
			continue
		}
		go s.handleChannelStream(qconn, str)
	}
}

// handleChannelStream processes a client-initiated SSH3 channel stream,
// formerly handled by the v0.49 http3.Server.StreamHijacker.
func (s *Server) handleChannelStream(qconn *quic.Conn, stream *quic.Stream) {
	frameType, err := util.ReadVarInt(&StreamByteReader{stream})
	if err != nil {
		log.Error().Msgf("could not read frame type of incoming stream %d: %s", uint64(stream.StreamID()), err)
		return
	}
	if frameType != SSH_FRAME_TYPE {
		log.Error().Msgf("bad HTTP frame type: %d", frameType)
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.CancelWrite(quic.StreamErrorCode(0))
		return
	}

	conversationsManager, ok := s.getConversationsManager(qconn)
	if !ok {
		// The client opens a channel as soon as it gets the 200 response to its
		// CONNECT request, while the conversation is registered by the handler
		// serving that request on another goroutine. Both events concern the
		// same QUIC connection but nothing orders them, so the channel can be
		// accepted before the registration is visible. Wait for it instead of
		// rejecting the channel: a hard failure here makes the server cancel
		// the stream (H3_REQUEST_INCOMPLETE) and the client aborts.
		conversationsManager, ok = s.waitForConversationsManager(qconn, conversationRegistrationTimeout)
	}
	if !ok {
		err := fmt.Errorf("could not find SSH3 conversation for new channel %d", uint64(stream.StreamID()))
		log.Error().Msgf("%s", err)
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.CancelWrite(quic.StreamErrorCode(0))
		return
	}

	conversationControlStreamID, channelType, maxPacketSize, err := parseHeader(uint64(stream.StreamID()), &StreamByteReader{stream})
	if err != nil {
		log.Error().Msgf("could not parse channel header on stream %d: %s", uint64(stream.StreamID()), err)
		return
	}

	conversation, ok := conversationsManager.getConversation(conversationControlStreamID)
	if !ok {
		err := fmt.Errorf("could not find SSH3 conversation with control stream id %d for new channel %d", conversationControlStreamID,
			uint64(stream.StreamID()))
		log.Error().Msgf("%s", err)
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.CancelWrite(quic.StreamErrorCode(0))
		return
	}

	if !serverAcceptsChannelType(channelType) {
		// the allow-list gate (S2-03/P3-03): anything the client may not
		// open towards the server is cancelled here, before any channel
		// allocation, instead of falling through to the session branch
		log.Warn().Msgf("refusing client-opened channel %d of type %q: not a client-to-server channel type",
			uint64(stream.StreamID()), channelType)
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.CancelWrite(quic.StreamErrorCode(0))
		return
	}

	// the peer advertises its own maxPacketSize; bound it by the server's own
	// value, otherwise the peer picks the size of every per-channel read
	// buffer the server allocates (S2-01: ~100 streams × 16 MiB per
	// connection). The confirmation already announces the server's value, so
	// lowering is protocol-consistent.
	peerMaxPacketSize := maxPacketSize
	maxPacketSize = clampPeerMaxPacketSize(maxPacketSize, s.maxPacketSize)
	if maxPacketSize != peerMaxPacketSize {
		log.Debug().Msgf("lowered peer maxPacketSize %d to the server's %d on channel %d",
			peerMaxPacketSize, maxPacketSize, uint64(stream.StreamID()))
	}

	log.Debug().Msgf(
		"accepted SSH3 channel %d of type %q for control stream %d",
		uint64(stream.StreamID()),
		channelType,
		conversationControlStreamID,
	)

	channelInfo := &ChannelInfo{
		ConversationID:       conversation.conversationID,
		ConversationStreamID: conversationControlStreamID,
		ChannelID:            uint64(stream.StreamID()),
		ChannelType:          channelType,
		MaxPacketSize:        maxPacketSize,
	}

	newChannel := NewChannel(channelInfo.ConversationStreamID, channelInfo.ConversationID, uint64(stream.StreamID()), channelInfo.ChannelType, channelInfo.MaxPacketSize,
		stream, stream, nil, conversation.channelsManager, false, false, true, s.defaultDatagramQueueSize, nil)

	switch channelInfo.ChannelType {
	case "direct-udp":
		udpAddr, err := parseUDPForwardingHeader(channelInfo.ChannelID, &StreamByteReader{stream})
		if err != nil {
			log.Error().Msgf("could not parse UDP forwarding header on channel %d: %s", channelInfo.ChannelID, err)
			return
		}
		newChannel.setDatagramSender(conversation.getDatagramSenderForChannel(channelInfo.ChannelID))
		newChannel = &UDPForwardingChannelImpl{Channel: newChannel, RemoteAddr: udpAddr}
	case "direct-tcp":
		tcpAddr, err := parseTCPForwardingHeader(channelInfo.ChannelID, &StreamByteReader{stream})
		if err != nil {
			log.Error().Msgf("could not parse TCP forwarding header on channel %d: %s", channelInfo.ChannelID, err)
			return
		}
		newChannel = &TCPForwardingChannelImpl{Channel: newChannel, RemoteAddr: tcpAddr}
	}
	conversation.channelsAcceptQueue.Add(newChannel)
}

func (s *Server) getConversationsManager(qconn *quic.Conn) (*conversationsManager, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	conversations, ok := s.conversations[qconn]
	return conversations, ok
}

// waitForConversationsManager polls the conversation map until the conversation for
// the given connection is registered or the timeout expires. A channel stream can
// reach the accept loop before the CONNECT request handler that registers the
// conversation has run, because both are handled concurrently on the same QUIC
// connection.
func (s *Server) waitForConversationsManager(qconn *quic.Conn, timeout time.Duration) (*conversationsManager, bool) {
	deadline := time.Now().Add(timeout)
	for {
		conversationsManager, ok := s.getConversationsManager(qconn)
		if ok {
			return conversationsManager, true
		}
		if !time.Now().Before(deadline) {
			return nil, false
		}
		time.Sleep(conversationRegistrationPollInterval)
	}
}

func (s *Server) getOrCreateConversationsManager(qconn *quic.Conn) *conversationsManager {
	s.lock.Lock()
	defer s.lock.Unlock()
	conversationsManager, ok := s.conversations[qconn]
	if !ok {
		s.conversations[qconn] = newConversationManager(qconn)
		conversationsManager = s.conversations[qconn]
	}
	return conversationsManager
}

func (s *Server) removeConnection(qconn *quic.Conn) {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.conversations, qconn)
}

type AuthenticatedHandlerFunc func(authenticatedUserName string, newConv *Conversation, w http.ResponseWriter, r *http.Request)

type UnauthenticatedBearerFunc func(unauthenticatedBearerString string, base64ConversationID string, w http.ResponseWriter, r *http.Request)

func (s *Server) GetHTTPHandlerFunc(ctx context.Context) AuthenticatedHandlerFunc {

	return func(authenticatedUsername string, newConv *Conversation, w http.ResponseWriter, r *http.Request) {
		log.Info().Msgf("got request: method: %s, URL: %s", r.Method, r.URL.String())
		if r.Method == http.MethodConnect {
			if r.Proto != "ssh3" {
				log.Debug().Msgf("accepting CONNECT request with proto %q as SSH3", r.Proto)
			}
			qconn, ok := QuicConnFromContext(r.Context())
			if !ok { // should never happen, unless quic-go change their API
				log.Error().Msg("failed to get the QUIC connection from the request context: is ConnContext set on the http3 server ?")
				return
			}
			conversationsManager := s.getOrCreateConversationsManager(qconn)
			conversationsManager.addConversation(newConv)

			// a control master shares the conversation across slave
			// sessions (stage 3.5): mark it so the per-session teardown
			// in the session handler does not kill the shared connection
			if r.URL.Query().Get("mux") == "1" {
				newConv.SetMultiplexed()
			}

			w.WriteHeader(200)
			log.Debug().Msgf(
				"accepted SSH3 CONNECT for user %s on control stream %d",
				authenticatedUsername,
				newConv.controlStream.StreamID(),
			)

			go func() {
				defer util.PanicGuard("server.go:272")()
				// TODO: this hijacks the datagrams for the whole quic connection, so the server
				//		 currently does not work for several conversations in the same QUIC connection
				for {
					dgram, err := qconn.ReceiveDatagram(ctx)
					if err != nil {
						if !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
							log.Error().Msgf("could not receive message from conn: %s", err)
						}
						return
					}
					buf := &util.BytesReadCloser{Reader: bytes.NewReader(dgram)}
					convID, err := util.ReadVarInt(buf)
					if err != nil {
						// F-19: one malformed datagram must not end the
						// conversation's datagram reception; drop it and carry on
						log.Warn().Msgf("dropping malformed datagram on conversation %d: %s", newConv.controlStream.StreamID(), err)
						continue
					}
					if convID == uint64(newConv.controlStream.StreamID()) {
						err = newConv.AddDatagram(ctx, dgram[buf.Size()-int64(buf.Len()):])
						if err != nil {
							switch e := err.(type) {
							case util.ChannelNotFound:
								log.Warn().Msgf("could not find channel %d, queue datagram in the meantime", e.ChannelID)
							case util.DatagramMalformed:
								// F-19: garbage payload — drop the datagram, keep
								// the loop alive (mirror of the client loop)
								log.Warn().Msgf("dropping malformed datagram on conversation %d: %s",
									newConv.controlStream.StreamID(), e)
							default:
								log.Error().Msgf("could not add datagram to conv id %d: %s", newConv.controlStream.StreamID(), err)
								return
							}
						}
					} else {
						log.Error().Msgf("discarding datagram with invalid conv id %d", convID)
					}
				}
			}()
			go func() {
				defer util.PanicGuard("server.go:305")()
				defer newConv.Close()
				defer conversationsManager.removeConversation(newConv)
				defer s.removeConnection(qconn)
				if err := s.conversationHandler(authenticatedUsername, newConv); err != nil {
					if errors.Is(err, context.Canceled) {
						log.Info().Msgf("conversation canceled for conversation id %s, user %s", newConv.ConversationID(), authenticatedUsername)
					} else {
						log.Error().Msgf("error while handing new conversation: %s for user %s: %s", newConv.ConversationID(), authenticatedUsername, err)
					}
					return
				}
			}()
		}
	}
}
