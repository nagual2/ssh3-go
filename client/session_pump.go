package client

// The transport-agnostic core of an SSH3 session: the stdin pump and the
// message drain. Kept free of process-stdio and terminal assumptions so a
// ControlMaster (stage 3.5) can drive sessions over arbitrary pipes.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
	"github.com/rs/zerolog/log"
)

// sessionIO carries the local endpoints of one session. The CLI passes the
// process stdio; a ControlMaster passes pipes bridged to the control socket.
type sessionIO struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

// truncationGrace bounds the wait for the stdin pump when an exit status
// arrives while input is still pending (stage 1, bug 3); shortened in tests.
var truncationGrace = 2 * time.Second

// ptyExitGrace bounds the post-exit-status output drain of a PTY session
// (stage 1, bug 5); shortened in tests.
var ptyExitGrace = 1 * time.Second

// sessionChannel is the slice of ssh3.Channel the session pump needs. Narrow
// on purpose: ssh3.Channel carries unexported methods, so tests satisfy this
// consumer-side interface with an in-memory fake instead.
type sessionChannel interface {
	MaxPacketSize() uint64
	WriteData(dataBuf []byte, dataType ssh3Messages.SSHDataType) (int, error)
	NextMessage() (ssh3Messages.Message, error)
	Close()
	CancelRead()
}

// writeSessionData routes one channel data message to stdout/stderr.
func writeSessionData(sio sessionIO, data *ssh3Messages.DataOrExtendedDataMessage) {
	switch data.DataType {
	case ssh3Messages.SSH_EXTENDED_DATA_NONE:
		if _, err := sio.stdout.Write([]byte(data.Data)); err != nil {
			log.Fatal().Msgf("%s", err)
		}
	case ssh3Messages.SSH_EXTENDED_DATA_STDERR:
		if _, err := sio.stderr.Write([]byte(data.Data)); err != nil {
			log.Fatal().Msgf("%s", err)
		}
	}
}

// pumpSessionStreams drives one established session channel until the remote
// side terminates it. It returns ExitStatus/ExitSignal as the terminal event;
// any other error is a stream failure, for the caller to report.
func pumpSessionStreams(channel sessionChannel, sio sessionIO, ptyRequested bool, escape *EscapeConfig) error {
	// Synchronized between the stdin pump below and the session loop: the send
	// half is closed (QUIC FIN) only after every local input byte was handed
	// to the channel. An exit status received while it is still open means the
	// remote command stopped consuming input early and the transfer was
	// truncated (CTO task stage 1, bug 3).
	var inputSent atomic.Bool
	// set when the stdin pump failed to write to the channel: the truncation
	// verdict then fires too, but the channel's send side is in an error
	// state and must not be half-closed by the verdict (transient flow
	// control failures must keep the channel open for the drain)
	var writeFailed atomic.Bool
	// closed on every return path of the stdin pump: an exit status that
	// arrives while the pump is still running waits for it before deciding
	// whether the transfer was truncated
	pumpDone := make(chan struct{})
	// set when the stdin pump tore the session down with the escape
	// sequence: the drain loop then surfaces the sentinel instead of the
	// raw transport error of the closed connection, so the caller keeps the
	// ~. verdict distinct from a connection loss
	var escaped atomic.Bool

	// the interactive escape filter (OpenSSH-style ~. / ~^Z / ~~): one
	// instance for the whole pump so a sequence split across reads still
	// fires; nil for exec traffic and when no escape character is set
	var filter *escapeFilter
	if escape != nil && ptyRequested && escape.Char != 0 {
		filter = newEscapeFilter(escape)
	}

	go func() {
		defer util.PanicGuard("client/session_pump.go:87")()
		defer close(pumpDone)
		buf := make([]byte, channel.MaxPacketSize())
		for {
			n, err := sio.stdin.Read(buf)
			if n > 0 {
				payload := buf[:n]
				if filter != nil {
					var action string
					payload, action = filter.Feed(buf[:n])

					if action == "disconnect" {
						escaped.Store(true)
						if len(payload) > 0 {
							if _, err2 := channel.WriteData(payload, ssh3Messages.SSH_EXTENDED_DATA_NONE); err2 != nil {
								writeFailed.Store(true)
							}
						}

						if err2 := escape.Disconnect(); err2 != nil {
							fmt.Fprintf(sio.stderr, "escape disconnect failed: %+v", err2)
						}

						return
					}

					if action == "suspend" {
						if err2 := escape.Suspend(); err2 != nil {
							fmt.Fprintf(sio.stderr, "escape suspend failed: %+v", err2)
						}
					}
				}

				if len(payload) > 0 {
					_, err2 := channel.WriteData(payload, ssh3Messages.SSH_EXTENDED_DATA_NONE)
					if err2 != nil {
						fmt.Fprintf(sio.stderr, "could not write data on channel: %+v", err2)
						writeFailed.Store(true)
						return
					}
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					// local stdin is exhausted: half-close the send side of the channel
					// (QUIC FIN) so the remote command sees the end of its input,
					// otherwise a command reading until EOF (e.g. `cat > file`) hangs.
					// The receive half stays open for the command output and exit status.
					inputSent.Store(true)
					channel.Close()
					return
				}
				if errors.Is(err, os.ErrDeadlineExceeded) {
					// the deliberate unblock of a stale pump (the reconnect
					// dispatch reclaims the console from a dead session's
					// pump with a past read deadline): quiet return, the
					// error noise would land in the hold window
					return
				}
				fmt.Fprintf(sio.stderr, "could not read data from stdin: %+v", err)
				return
			}
		}
	}()

	for {
		genericMessage, err := channel.NextMessage()
		if err != nil {
			if escaped.Load() {
				// the stdin pump tore the session down with the escape
				// sequence: the transport error of the closed connection
				// rides the ~. verdict instead
				return ErrEscapeDisconnect
			}
			return err
		}
		switch message := genericMessage.(type) {
		case *ssh3Messages.ChannelRequestMessage:
			switch requestMessage := message.ChannelRequest.(type) {
			case *ssh3Messages.PtyRequest:
				fmt.Fprintf(sio.stderr, "receiving a pty request on the client is not implemented\n")
			case *ssh3Messages.X11Request:
				fmt.Fprintf(sio.stderr, "receiving a x11 request on the client is not implemented\n")
			case *ssh3Messages.ShellRequest:
				fmt.Fprintf(sio.stderr, "receiving a shell request on the client is not implemented\n")
			case *ssh3Messages.ExecRequest:
				fmt.Fprintf(sio.stderr, "receiving a exec request on the client is not implemented\n")
			case *ssh3Messages.SubsystemRequest:
				fmt.Fprintf(sio.stderr, "receiving a subsystem request on the client is not implemented\n")
			case *ssh3Messages.WindowChangeRequest:
				fmt.Fprintf(sio.stderr, "receiving a windowchange request on the client is not implemented\n")
			case *ssh3Messages.SignalRequest:
				fmt.Fprintf(sio.stderr, "receiving a signal request on the client is not implemented\n")
			case *ssh3Messages.ExitStatusRequest:
				log.Info().Msgf("ssh3: process exited with status: %d\n", requestMessage.ExitStatus)
				exitStatus := int(requestMessage.ExitStatus)
				if !ptyRequested && !inputSent.Load() {
					// the stdin pump's final EOF read races with a fast remote
					// exit: wait for the pump itself instead of a fixed grace,
					// then re-check whether all input really made it out
					select {
					case <-pumpDone:
					case <-time.After(truncationGrace):
					}
				}
				if !ptyRequested && !inputSent.Load() {
					fmt.Fprintf(sio.stderr, "ssh3: remote command exited before all input was sent; the transfer was truncated\n")
					// forward a distinct local error instead of the remote's
					// success status, which would mask the data loss
					exitStatus = 255
					// The remote command is gone, so no one will consume the
					// pending input: half-close the send side so the server
					// ends the stream and the drain below terminates. A
					// server only FINs after the client does, so without
					// this FIN a never-EOF stdin (CI/harness pipes) hangs
					// the client forever (stage 1, bug 3 follow-up; see
					// docs/BUG-STDIN-DRAIN-DEADLOCK.md). A failed stdin
					// write must not half-close the channel.
					if !writeFailed.Load() {
						channel.Close()
					}
				}
				// An exit status does not end the byte stream: command output
				// may still be in flight, and the channel ends with a
				// server-side EOF only. Keep reading until that EOF (or a
				// connection error) so the output tail is not silently dropped.
				if ptyRequested {
					// The remote shell is gone, so no further input can be
					// consumed: half-close the send side so the server is
					// free to end the channel. A raw console stdin never
					// EOFs on its own, and without this FIN the server may
					// keep the channel open forever (stage 1, bug 5).
					channel.Close()
					// Whatever the server does, the drain must not hang
					// forever: once the grace window elapses, cancel the
					// pending read and leave with the received status.
					time.AfterFunc(ptyExitGrace, channel.CancelRead)
				}
				for {
					message, err := channel.NextMessage()
					if err != nil || message == nil {
						break
					}
					if data, ok := message.(*ssh3Messages.DataOrExtendedDataMessage); ok {
						writeSessionData(sio, data)
						continue
					}
					if request, ok := message.(*ssh3Messages.ChannelRequestMessage); ok {
						if laterStatus, ok := request.ChannelRequest.(*ssh3Messages.ExitStatusRequest); ok {
							exitStatus = int(laterStatus.ExitStatus)
						}
					}
				}
				// forward the process' status code to the user
				return ExitStatus{StatusCode: exitStatus}
			case *ssh3Messages.ExitSignalRequest:
				log.Info().Msgf("ssh3: process exited with signal: %s: %s\n", requestMessage.SignalNameWithoutSig, requestMessage.ErrorMessageUTF8)
				return ExitSignal{Signal: requestMessage.SignalNameWithoutSig, ErrorMessageUTF8: requestMessage.ErrorMessageUTF8}
			}
		case *ssh3Messages.DataOrExtendedDataMessage:
			writeSessionData(sio, message)
			switch message.DataType {
			case ssh3Messages.SSH_EXTENDED_DATA_NONE:
				log.Trace().Msgf("received data %s", message.Data)
			case ssh3Messages.SSH_EXTENDED_DATA_STDERR:
				log.Trace().Msgf("received stderr data %s", message.Data)
			}
		}
	}
}
