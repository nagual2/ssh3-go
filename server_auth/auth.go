package server_auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/util/unix_util"

	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
)

func HandleAuths(ctx context.Context, enablePasswordLogin bool, defaultMaxPacketSize uint64, handlerFunc ssh3.AuthenticatedHandlerFunc) (http.HandlerFunc, error) {
	if runtime.GOOS != "linux" && enablePasswordLogin {
		return nil, fmt.Errorf("password login not supported on %s/%s systems", runtime.GOOS, runtime.GOARCH)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", ssh3.GetCurrentVersionString())
		ua := r.UserAgent()
		peerVersion, err := ssh3.ParseVersionString(ua)
		if err != nil {
			// a short unparseable User-Agent must not slice out of bounds:
			// quic-go recovers the panic, but every bogus CONNECT then costs a
			// 64 KiB stack trace in the log
			if len(ua) > 100 {
				ua = ua[:100]
			}
			http.Error(w, fmt.Sprintf("Unsupported user-agent: %s", ua), http.StatusForbidden)
			return
		}
		log.Debug().Msgf("received request from User-Agent %s", ua)
		log.Debug().Msgf("peer version: protocol version %s, software version %s", peerVersion.GetProtocolVersion(), peerVersion.GetSoftwareVersion())
		if !ssh3.IsVersionSupported(peerVersion) {
			http.Error(w, fmt.Sprintf("Unsupported version: %s not supported by server with version %s", peerVersion.GetProtocolVersion(), ssh3.ThisVersion().GetProtocolVersion()), http.StatusForbidden)
			return
		}
		// Only call Flush() here, as calling flush prevents from adding the Content-Length header to the response
		// The Content-Length can be useful upon receiving an error response
		defer w.(http.Flusher).Flush()

		// quic-go v0.63 removed http3.Hijacker: the QUIC connection is retrieved
		// from the request context, where the http3.Server.ConnContext hook put it
		qconn, ok := ssh3.QuicConnFromContext(r.Context())
		if !ok {
			log.Error().Msgf("failed to get the QUIC connection from the request context")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !qconn.ConnectionState().TLS.HandshakeComplete {
			// do not process early data (0-RTT) when performing authorization
			// to avoid replay attacks
			w.WriteHeader(http.StatusTooEarly)
			return
		}

		// the unauthenticated phase holds a DoS slot (the MaxStartups
		// analog): the slot is acquired before any per-request work worth
		// protecting (conversation allocation, user lookup, identity-file
		// reads) and is always released when the auth phase ends, whatever
		// the verdict — the slot must never survive a successful
		// authentication, or 100 logins brick the whole server with 503s
		if !TryAcquireUnauthenticatedConversation() {
			log.Warn().Msgf("too many unauthenticated conversations (%d active), refusing the request for user %s",
				MaxUnauthenticatedConversations, r.URL.User.Username())
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer ReleaseUnauthenticatedConversation()

		// the identity resolution runs BEFORE the HTTP stream is taken:
		// w.(http3.HTTPStreamer).HTTPStream() flushes the response headers
		// to the wire (the implicit 200), so every refusal that happens
		// after it reaches the client as a success - the client opens its
		// channels and hangs until the conversation teardown cancels them
		// (the B13 finding of the 2026-10-22 cross run). The user lookup
		// and the identities read answer their own 401s while the
		// response is still clean.
		username := r.URL.User.Username()
		if username == "" {
			username = r.URL.Query().Get("user")
		}
		user, err := unix_util.GetUser(username)
		if err != nil {
			log.Warn().Msgf("unknown user %q: refusing before the response headers flush", username)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		identityVerifiers, err := GetAuthorizedIdentities(user)
		if err != nil {
			log.Error().Msgf("error in JWT auth handling when retrieving authorized identities: %s", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// the conversation id derives from the tls exporters alone, the
		// stream is not needed for it: the verifiers below take the id
		// while the response is still clean, and the stream takeover
		// (the implicit-200 flush, the B13 finding) waits for the
		// positive verdict - a refusal riding after the takeover
		// reaches the client as a success (the lost 401 of the B11-3)
		tlsState := qconn.ConnectionState().TLS
		convID, err := ssh3.GenerateConversationID(&tlsState)
		if err != nil {
			log.Error().Msgf("could not generate conversation ID on server")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		base64ConvID := base64.StdEncoding.EncodeToString(convID[:])

		// the takeover and the conversation creation run only on the
		// positive verdict.  The conversation context must derive from
		// the QUIC connection's: when the connection dies without an
		// application-level close (client crash, network loss), the
		// conversation handler blocked in AcceptChannel has to wake up
		// and release the conversation's external resources
		// (reverse-forwarding binds, forwarded agent sockets).  A
		// conversation-create failure after the headers flushed is
		// internal and leaves the stream to the teardown.
		serveConversation := func(username string) {
			str := w.(http3.HTTPStreamer).HTTPStream()
			conv, err := ssh3.NewServerConversation(qconn.Context(), str, qconn, qconn, defaultMaxPacketSize, peerVersion)
			if err != nil {
				log.Error().Msgf("could not create new server conversation")
				return
			}
			handlerFunc(username, conv, w, r)
		}

		// first, handle the HTTP request verifiers (often plugins)
		for _, abstractVerifier := range identityVerifiers {
			switch verifier := abstractVerifier.(type) {
			case *WrappedPluginVerifier:
				if verifier.Verify(r, base64ConvID) {
					log.Debug().Msgf("request for user %s successfully verified by plugin", username)
					serveConversation(username)
					return
				}
			}
		}

		log.Debug().Msgf("no suitable plugin found to authenticate the request")

		authorization := r.Header.Get("Authorization")
		if enablePasswordLogin && strings.HasPrefix(authorization, "Basic ") {
			if CheckBasicAuth(username, w, r) {
				serveConversation(username)
			}
			return
		} else if strings.HasPrefix(authorization, "Bearer ") {
			if VerifyJWT(identityVerifiers, base64ConvID, w, r) {
				serveConversation(username)
			}
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}, nil
}

func HandleBasicAuth(handlerFunc ssh3.AuthenticatedHandlerFunc, conv *ssh3.Conversation) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// the sshd PermitRootLogin prohibit-password analog: root never
		// authenticates by password
		if PasswordLoginRefused(username) {
			log.Warn().Msgf("password auth for %s refused: the root account authenticates by key only (PermitRootLogin prohibit-password)", username)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ok, err := unix_util.UserPasswordAuthentication(username, password)
		if err != nil || !ok {
			if err != nil {
				log.Error().Msgf("user authentication failed: %s", err)
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handlerFunc(username, conv, w, r)
	}
}
