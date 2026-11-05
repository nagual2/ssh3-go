// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/auth/oidc"
	client_config "github.com/francoismichel/ssh3/client/config"
	"github.com/francoismichel/ssh3/client/winsize"
	"github.com/francoismichel/ssh3/internal"
	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
	"github.com/francoismichel/ssh3/util/ttymodes"
)

type ExitStatus struct {
	StatusCode int
}

func (e ExitStatus) Error() string {
	return fmt.Sprintf("exited with status %d", e.StatusCode)
}

type ExitSignal struct {
	Signal           string
	ErrorMessageUTF8 string
}

func (e ExitSignal) Error() string {
	return fmt.Sprintf("exited with signal %s: %s", e.Signal, e.ErrorMessageUTF8)
}

type NoSuitableIdentity struct{}

func (e NoSuitableIdentity) Error() string {
	return "no suitable identity found"
}

func sendWindowChangeRequest(channel ssh3.Channel, tty *os.File) error {
	windowSize, err := winsize.GetWinsize(tty)
	if err != nil {
		return err
	}
	return channel.SendRequest(
		&ssh3Messages.ChannelRequestMessage{
			WantReply: false,
			ChannelRequest: &ssh3Messages.WindowChangeRequest{
				CharWidth:   uint64(windowSize.NCols),
				CharHeight:  uint64(windowSize.NRows),
				PixelWidth:  uint64(windowSize.PixelWidth),
				PixelHeight: uint64(windowSize.PixelHeight),
			},
		},
	)
}

func forwardAgent(parent context.Context, channel ssh3.Channel) error {
	c, err := AgentDial()
	if err != nil {
		return fmt.Errorf("cannot connect to the local SSH agent: %w", err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancelCause(parent)
	go func() {
		defer util.PanicGuard("client/client.go:90")()
		var err error = nil
		var genericMessage ssh3Messages.Message
		for {
			select {
			case <-ctx.Done():
				err = context.Cause(ctx)
				if err != nil {
					log.Error().Msgf("reading message stopped on channel %d: %s", channel.ChannelID(), err.Error())
				}
				return
			default:
				genericMessage, err = channel.NextMessage()
				if err != nil && err != io.EOF {
					err = fmt.Errorf("error when getting message on channel %d: %s", channel.ChannelID(), err.Error())
					cancel(err)
					return
				}
				if genericMessage == nil {
					return
				}
				switch message := genericMessage.(type) {
				case *ssh3Messages.DataOrExtendedDataMessage:
					_, err = c.Write([]byte(message.Data))
					if err != nil {
						err = fmt.Errorf("error when writing on unix socker for agent forwarding channel %d: %s", channel.ChannelID(), err.Error())
						cancel(err)
						return
					}
				default:
					err = fmt.Errorf("unhandled message type on agent channel %d: %T", channel.ChannelID(), message)
					cancel(err)
					return
				}
			}
		}
	}()

	buf := make([]byte, channel.MaxPacketSize())
	for {
		select {
		case <-ctx.Done():
			err = context.Cause(ctx)
			if err != nil {
				log.Error().Msgf("ending agent forwarding on channel %d: %s", channel.ChannelID(), err.Error())
			}
			return err
		default:
			n, err := c.Read(buf)
			if err == io.EOF {
				log.Debug().Msgf("unix socket for ssh agent closed")
				return nil
			} else if err != nil {
				cancel(err)
				log.Error().Msgf("could not read on unix socket: %s", err.Error())
				return err
			}
			_, err = channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE)
			if err != nil {
				cancel(err)
				log.Error().Msgf("could not write on ssh channel: %s", err.Error())
				return err
			}
		}
	}
}

func forwardTCPInBackground(ctx context.Context, channel ssh3.Channel, conn *net.TCPConn) {
	go func() {
		defer util.PanicGuard("client/client.go:158")()
		defer conn.CloseWrite()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			genericMessage, err := channel.NextMessage()
			if err == io.EOF {
				log.Info().Msgf("eof on tcp-forwarding channel %d", channel.ChannelID())
			} else if err != nil {
				log.Error().Msgf("could get message from tcp forwarding channel: %s", err)
				return
			}

			// nothing to process
			if genericMessage == nil {
				return
			}

			switch message := genericMessage.(type) {
			case *ssh3Messages.DataOrExtendedDataMessage:
				if message.DataType == ssh3Messages.SSH_EXTENDED_DATA_NONE {
					_, err := conn.Write([]byte(message.Data))
					if err != nil {
						log.Error().Msgf("could not write data on TCP socket: %s", err)
						// signal the write error to the peer
						channel.CancelRead()
						return
					}
				} else {
					log.Warn().Msgf("ignoring message data of unexpected type %d on TCP forwarding channel %d", message.DataType, channel.ChannelID())
				}
			default:
				log.Warn().Msgf("ignoring message of type %T on TCP forwarding channel %d", message, channel.ChannelID())
			}
		}
	}()

	go func() {
		defer util.PanicGuard("client/client.go:198")()
		defer channel.Close()
		defer conn.CloseRead()
		buf := make([]byte, channel.MaxPacketSize())
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := conn.Read(buf)
			if err != nil && err != io.EOF {
				log.Error().Msgf("could read data on TCP socket: %s", err)
				return
			}
			_, errWrite := channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE)
			if errWrite != nil {
				switch quicErr := errWrite.(type) {
				case *quic.StreamError:
					if quicErr.Remote && quicErr.ErrorCode == 42 {
						log.Info().Msgf("writing was canceled by the remote, closing the socket: %s", errWrite)
					} else {
						log.Error().Msgf("unhandled quic stream error: %+v", quicErr)
					}
				default:
					log.Error().Msgf("could send data on channel: %s", errWrite)
				}
				return
			}
			if err == io.EOF {
				return
			}
		}
	}()
}

type Client struct {
	qconn *quic.Conn
	*ssh3.Conversation

	// reverse forwarding (-R) state; see reverse_forward.go
	reverseForwards []ReverseForward
	forwardAgent    atomic.Bool
	acceptOnce      sync.Once
}

// Close tears the conversation AND the underlying QUIC connection down.
// Conversation.Close() alone only closes the control stream: without a QUIC
// close frame the server may learn about the client's death very late (no
// idle timeout is configured), which would keep the -R binds held long after
// the client is gone. Shadows the embedded Conversation.Close.
func (c *Client) Close() {
	c.Conversation.Close()
	c.qconn.CloseWithError(quic.ApplicationErrorCode(0), "closed by the client")
}

// DialOption customizes a client.Dial call.
type DialOption func(*dialOptions)

type dialOptions struct {
	multiplexed bool

	// compressAnnounce is the literal "compress=" value of the
	// client's version string (the -C of the CLI, the resolved value
	// of ssh3.ResolveCompressAnnounce): nil keeps the build's codec
	// list, the empty value keeps the field out (the compression
	// off), a codec name pins the list to it
	compressAnnounce *string
}

// WithMultiplexed marks the conversation as shared by a control master:
// the server keeps it alive across session channels and releases it when
// the master disconnects (stage 3.5).
func WithMultiplexed() DialOption {
	return func(o *dialOptions) { o.multiplexed = true }
}

// WithCompressAnnounce carries the -C of the CLI into the version
// exchange: announce becomes the "compress=" field of the version
// string the client sends, verbatim.
func WithCompressAnnounce(announce string) DialOption {
	return func(o *dialOptions) { o.compressAnnounce = &announce }
}

func Dial(ctx context.Context, config *client_config.Config, qconn *quic.Conn,
	transport *http3.Transport,
	sshAgent agent.ExtendedAgent, opts ...DialOption) (*Client, error) {

	var dialOpts dialOptions
	for _, opt := range opts {
		opt(&dialOpts)
	}

	hostUrl := url.URL{}
	hostUrl.Scheme = "https"
	hostUrl.Host = config.URLHostnamePort()
	hostUrl.Path = config.UrlPath()
	urlQuery := hostUrl.Query()
	urlQuery.Set("user", config.Username())
	if dialOpts.multiplexed {
		urlQuery.Set("mux", "1")
	}
	hostUrl.RawQuery = urlQuery.Encode()
	requestUrl := hostUrl.String()

	var qconf quic.Config

	qconf.MaxIncomingStreams = 10
	qconf.Allow0RTT = true
	qconf.EnableDatagrams = true
	qconf.KeepAlivePeriod = 1 * time.Second

	var agentKeys []ssh.PublicKey
	if sshAgent != nil {
		keys, err := sshAgent.List()
		if err != nil {
			log.Error().Msgf("Failed to list agent keys: %s", err)
			return nil, err
		}
		for _, key := range keys {
			agentKeys = append(agentKeys, key)
		}
	}

	// the transport is not used for dialing: the raw client conn is created
	// directly on the QUIC connection dialed above, so there is no need for the
	// one-connection hack anymore

	// The 0-RTT stage 2 (the early CONNECT, RFC 8470): when the ticket of
	// this server rides the cache and its last session held the
	// 425-retry contract (an ssh3-c server), the CONNECT leaves before
	// the handshake completes — the flight is protected by the ticket
	// PSK, and the auth stays out of the replay window (the bare CONNECT
	// carries no credentials). The retry contract reroutes the flight on
	// the server; after the handshake the fresh-CONNECT path (the
	// conversation established below) reuses the preauth record — the
	// one-shot retry shape of the ssh3-c canon. A rejected 0-RTT (the
	// server lost the session) drops the early stream silently: the
	// conversation below carries the full CONNECT.
	rawConn := transport.NewRawClientConn(qconn)
	if GetTicketCache().RetryContract() {
		earlyReq, err := http.NewRequest("CONNECT", requestUrl, nil)
		if err == nil {
			earlyReq.Proto = "ssh3"
			earlyReq.Header.Set("User-Agent", ssh3.ThisVersion().GetVersionString())
			if rs, err := rawConn.ClientConn.OpenRequestStream(ctx); err == nil {
				if err := rs.SendRequestHeader(earlyReq); err == nil {
					log.Debug().Msgf("the early CONNECT rides the 0-RTT window")
					go func() {
						rsp, err := rs.ReadResponse()
						if err != nil {
							// the 0-RTT rejection of a dead ticket rides here too
							log.Debug().Msgf("the early CONNECT drew no response: %s", err)
							return
						}
						log.Debug().Msgf("the early CONNECT got %s (the retry rides the conversation)", rsp.Status)
					}()
				}
			}
		}
	}

	qconn.HandshakeComplete()
	log.Debug().Msgf("QUIC handshake complete")
	if qconn.ConnectionState().Used0RTT {
		log.Debug().Msgf("SSH3-SESSION-REUSED 1 (the 0-RTT flight rode the resumed ticket)")
	}
	// Now, we're 1-RTT, we can get the TLS exporter and create the conversation
	tls := qconn.ConnectionState().TLS
	conv, err := ssh3.NewClientConversation(30000, 10, &tls)
	if err != nil {
		return nil, err
	}

	// the connection struct is created, now build the request used to establish the connection
	req, err := http.NewRequest("CONNECT", requestUrl, nil)
	if err != nil {
		log.Fatal().Msgf("%s", err)
	}
	req.Proto = "ssh3"

	// TODO: replace this by a loop actually performing the requests for qeach auth method of each plugin
	foundSuitableAuthPlugin := false
	plugins := internal.GetClientAuthPlugins()
	for _, plugin := range plugins {
		authMethods, err := plugin.PluginFunc(req, sshAgent, config, transport)
		if err != nil {
			return nil, err
		}
		for _, authMethod := range authMethods {
			err = authMethod.PrepareRequestForAuth(req, sshAgent, transport, config.Username(), conv)
			if err != nil {
				log.Error().Msgf("error when preparing request for auth plugin %T: %s", plugin, err)
				return nil, err
			}
			foundSuitableAuthPlugin = true
			log.Debug().Msgf("found suitable auth plugin")
		}
	}

	if !foundSuitableAuthPlugin {

		var identity ssh3.Identity
		for _, method := range config.AuthMethods() {
			switch m := method.(type) {
			case *ssh3.PasswordAuthMethod:
				log.Debug().Msgf("try password-based auth")
				fmt.Printf("password for %s:", hostUrl.String())
				password, err := term.ReadPassword(int(syscall.Stdin))
				fmt.Println()
				if err != nil {
					log.Error().Msgf("could not get password: %s", err)
					return nil, err
				}
				identity = m.IntoIdentity(string(password))
			case *ssh3.PrivkeyFileAuthMethod:
				log.Debug().Msgf("try file-based pubkey auth using file %s", m.Filename())
				identity, err = m.IntoIdentityWithoutPassphrase()
				// could not identify without passphrase, try agent authentication by using the key's public key
				if passphraseErr, ok := err.(*ssh.PassphraseMissingError); ok {
					// the pubkey may be contained in the privkey file
					pubkey := passphraseErr.PublicKey
					if pubkey == nil {
						// if it is not the case, try to find a .pub equivalent, like OpenSSH does
						pubkeyBytes, err := os.ReadFile(fmt.Sprintf("%s.pub", m.Filename()))
						if err == nil {
							filePubkey, _, _, _, err := ssh.ParseAuthorizedKey(pubkeyBytes)
							if err == nil {
								pubkey = filePubkey
							}
						}
					}

					// now, try to see of the agent manages this key
					foundAgentKey := false
					if pubkey != nil {
						for _, agentKey := range agentKeys {
							if bytes.Equal(agentKey.Marshal(), pubkey.Marshal()) {
								log.Debug().Msgf("found key in agent: %s", agentKey)
								identity = ssh3.NewAgentAuthMethod(pubkey).IntoIdentity(sshAgent)
								foundAgentKey = true
								break
							}
						}
					}

					// key not handled by agent, let's try to decrypt it ourselves
					if !foundAgentKey {
						fmt.Printf("passphrase for private key stored in %s:", m.Filename())
						var passphraseBytes []byte
						passphraseBytes, err = term.ReadPassword(int(syscall.Stdin))
						fmt.Println()
						if err != nil {
							log.Error().Msgf("could not get passphrase: %s", err)
							return nil, err
						}
						passphrase := string(passphraseBytes)
						identity, err = m.IntoIdentityPassphrase(passphrase)
						if err != nil {
							log.Error().Msgf("could not load private key: %s", err)
							return nil, err
						}
					}
				} else if err != nil {
					log.Warn().Msgf("Could not load private key: %s", err)
				}
			case *ssh3.AgentAuthMethod:
				log.Debug().Msgf("try ssh-agent-based auth")
				identity = m.IntoIdentity(sshAgent)
			case *ssh3.OidcAuthMethod:
				log.Debug().Msgf("try OIDC auth to issuer %s", m.OIDCConfig().IssuerUrl)
				token, err := oidc.Connect(context.Background(), m.OIDCConfig(), m.OIDCConfig().IssuerUrl, m.DoPKCE(), conv.ConversationID().String())
				if err != nil {
					log.Error().Msgf("could not get token: %s", err)
					return nil, err
				}
				identity = m.IntoIdentity(token)
			}
			// currently only tries a single identity (the first one), but the goal is to
			// try several identities, similarly to OpenSSH
			log.Debug().Msgf("we only try the first specified auth method for now")
			break
		}

		if identity == nil {
			return nil, NoSuitableIdentity{}
		}

		log.Debug().Msgf("try the following Identity: %s", identity)
		err = identity.SetAuthorizationHeader(req, config.Username(), conv)
		if err != nil {
			log.Error().Msgf("could not set authorization header in HTTP request: %s", err)
			return nil, err
		}
	}

	log.Debug().Msgf("establish conversation with the server")
	err = conv.EstablishClientConversation(req, qconn, transport, ssh3.AVAILABLE_CLIENT_VERSIONS, dialOpts.compressAnnounce, rawConn)
	if errors.Is(err, util.Unauthorized{}) {
		log.Error().Msgf("Access denied from the server: unauthorized")
		return nil, err
	} else if err != nil {
		log.Error().Msgf("Could not establish conversation: %+v", err)
		return nil, err
	}

	// the server flag of the retry contract rides the Server header of
	// the established session (the next dial of this process reads it
	// back)
	GetTicketCache().NoteServerFlag(conv.PeerVersion().GetVersionString())
	if errors.Is(err, util.Unauthorized{}) {
		log.Error().Msgf("Access denied from the server: unauthorized")
		return nil, err
	} else if err != nil {
		log.Error().Msgf("Could not establish conversation: %+v", err)
		return nil, err
	}

	return &Client{
		qconn:        qconn,
		Conversation: conv,
	}, nil
}

func (c *Client) ForwardUDP(ctx context.Context, localUDPAddr *net.UDPAddr, remoteUDPAddr *net.UDPAddr) (*net.UDPAddr, error) {
	log.Debug().Msgf("start UDP forwarding from %s to %s", localUDPAddr, remoteUDPAddr)
	conn, err := net.ListenUDP("udp", localUDPAddr)
	if err != nil {
		log.Error().Msgf("could not listen on UDP socket: %s", err)
		return nil, err
	}
	forwardings := make(map[string]ssh3.Channel)
	go func() {
		defer util.PanicGuard("client/client.go:471")()
		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				log.Error().Msgf("could not read on UDP socket: %s", err)
				return
			}
			channel, ok := forwardings[addr.String()]
			if !ok {
				channel, err = c.OpenUDPForwardingChannel(30000, 10, localUDPAddr, remoteUDPAddr)
				if err != nil {
					log.Error().Msgf("could open new UDP forwarding channel: %s", err)
					return
				}
				forwardings[addr.String()] = channel

				go func() {
					defer util.PanicGuard("client/client.go:488")()
					for {
						dgram, err := channel.ReceiveDatagram(ctx)
						if err != nil {
							log.Error().Msgf("could open receive datagram on channel: %s", err)
							return
						}
						_, err = conn.WriteToUDP(dgram, addr)
						if err != nil {
							log.Error().Msgf("could open write datagram on socket: %s", err)
							return
						}
					}
				}()
			}
			err = channel.SendDatagram(buf[:n])
			if err != nil {
				log.Error().Msgf("could not send datagram: %s", err)
				return
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr), nil
}

func (c *Client) ForwardTCP(ctx context.Context, localTCPAddr *net.TCPAddr, remoteTCPAddr *net.TCPAddr) (*net.TCPAddr, error) {
	log.Debug().Msgf("start TCP forwarding from %s to %s", localTCPAddr, remoteTCPAddr)
	conn, err := net.ListenTCP("tcp", localTCPAddr)
	if err != nil {
		log.Error().Msgf("could listen on TCP socket: %s", err)
		return nil, err
	}
	go func() {
		defer util.PanicGuard("client/client.go:520")()
		for {
			conn, err := conn.AcceptTCP()
			if err != nil {
				log.Error().Msgf("could read on UDP socket: %s", err)
				return
			}
			forwardingChannel, err := c.OpenTCPForwardingChannel(30000, 10, localTCPAddr, remoteTCPAddr)
			if err != nil {
				log.Error().Msgf("could open new UDP forwarding channel: %s", err)
				return
			}
			forwardTCPInBackground(ctx, forwardingChannel, conn)
		}
	}()
	return conn.Addr().(*net.TCPAddr), nil
}

// DefaultTermType is the terminal type reported to the server when neither the
// caller nor the local TERM environment variable provide one: TERM is
// practically only unset for GUI-launched clients on Windows, whose consoles
// are 256-color capable.
const DefaultTermType = "xterm-256color"

func (c *Client) RunSession(tty *os.File, forwardSSHAgent bool, requestTTY string, resolvedTerm string, escape *EscapeConfig, command ...string) error {

	ctx := c.Context()

	// console inspection comes first: the pty request mirrors the local
	// terminal, and raw-mode/signal forwarding below needs isATTY/hasWinSize.
	// The pty gate follows the RequestTTY policy (OpenSSH ssh_config
	// semantics): auto (the default) requests one for interactive shells over
	// a TTY, yes whenever the local side has a TTY, no never, and force —
	// when the local side has no TTY — is served by the forced-pty path
	// before RunSession and behaves like yes here.
	spec := SessionSpec{Command: command, ForwardAgent: forwardSSHAgent}
	interactive := len(command) == 0
	isATTY := term.IsTerminal(int(tty.Fd()))
	hasWinSize := false
	// A PTY session is interactive: its stdin never "finishes" while the user
	// keeps the session open, so an exit status arriving with input still
	// pending is the normal end of the session, not a truncated pipe transfer.
	var wantPty bool
	switch requestTTY {
	case "no":
		wantPty = false
	case "yes", "force":
		wantPty = true
	default: // auto
		wantPty = interactive && isATTY
	}
	if wantPty {
		windowSize, err := winsize.GetWinsize(tty)
		hasWinSize = err == nil
		if !hasWinSize {
			// some consoles do not expose a queryable size via stdin: a PTY
			// with a default geometry still beats a raw-pipe session
			log.Warn().Msgf("could not get window size: %+v, using 80x24", err)
			windowSize.NCols = 80
			windowSize.NRows = 24
		}
		// the caller-resolved type (-o Term / ~/.ssh/config Term) wins over
		// the local environment; library callers may pass an empty type
		termType := resolvedTerm
		if termType == "" {
			termType = os.Getenv("TERM")
		}
		if termType == "" {
			// remote ncurses programs expect a terminal type to be set;
			// TERM is practically only unset for GUI-launched clients on
			// Windows, whose consoles are 256-color capable
			termType = DefaultTermType
		}
		spec.Pty = &PtySpec{
			Term:        termType,
			Columns:     uint64(windowSize.NCols),
			Rows:        uint64(windowSize.NRows),
			PixelWidth:  uint64(windowSize.PixelWidth),
			PixelHeight: uint64(windowSize.PixelHeight),
			Modes:       ttymodes.LocalTermiosModes(tty),
		}
	}

	channel, ptyRequested, err := c.OpenSession(ctx, spec)
	if err != nil {
		if channel == nil {
			fmt.Fprintf(os.Stderr, "Could not open channel: %+v", err)
			os.Exit(-1)
		}
		return err
	}

	// avoid making the terminal raw if the session carries no pty or stdin
	// is not a TTY; similar behaviour to OpenSSH: the pty/shell requests are
	// already on the wire at this point
	if ptyRequested && isATTY {
		fd := os.Stdin.Fd()
		oldState, err := term.MakeRaw(int(fd))
		if err != nil {
			log.Warn().Msgf("cannot make tty raw: %s", err)
		} else {
			defer term.Restore(int(fd), oldState)

			// the ~^Z suspend needs the console owner: restore the
			// terminal, SIGTSTP the client and re-enter raw mode on resume
			if escape != nil && escape.Char != 0 && escape.Suspend == nil {
				escape.Suspend = LocalSuspendFunc(os.Stdin, oldState)
			}
		}
		// full-screen remote apps (vim, mc) speak ANSI: the local console
		// must interpret escape sequences too
		defer enableConsoleVT()()
		go forwardSessionSignals(ctx, channel)
		if hasWinSize {
			go forwardWindowChanges(ctx, channel, tty)
		}
	}

	// A trailing carriage return restores the prompt position after an
	// interactive PTY session; in exec mode stdout is data, not a terminal,
	// so it must stay byte-exact (e.g. piping through sha256sum).
	if ptyRequested {
		defer fmt.Printf("\r")
	}

	// drive the session with the process stdio; a ControlMaster (stage 3.5)
	// bridges other pipes into the same pump via PumpSession
	err = c.PumpSession(channel, os.Stdin, os.Stdout, os.Stderr, ptyRequested, escape)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrEscapeDisconnect) {
		// the user tore the session down with the ~. escape sequence: the
		// Disconnect callback closed the connection, the exit code is the
		// caller's decision (255, like a closed connection)
		return err
	}
	switch err.(type) {
	case ExitStatus, ExitSignal:
		return err
	}
	fmt.Fprintf(os.Stderr, "Could not get message: %+v\n", err)
	os.Exit(-1)
	return nil
}
