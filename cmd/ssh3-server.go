// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	_ "net/http/pprof"

	"github.com/caddyserver/certmagic"
	"github.com/creack/pty"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	ssh3 "github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/internal"
	pprofutil "github.com/francoismichel/ssh3/internal/pprofutil"
	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/server_auth"
	util "github.com/francoismichel/ssh3/util"
	"github.com/francoismichel/ssh3/util/ttymodes"
	"github.com/francoismichel/ssh3/util/unix_util"
)

var signals = map[string]os.Signal{
	"SIGABRT":   syscall.Signal(0x6),
	"SIGALRM":   syscall.Signal(0xe),
	"SIGBUS":    syscall.Signal(0x7),
	"SIGCHLD":   syscall.Signal(0x11),
	"SIGCLD":    syscall.Signal(0x11),
	"SIGCONT":   syscall.Signal(0x12),
	"SIGFPE":    syscall.Signal(0x8),
	"SIGHUP":    syscall.Signal(0x1),
	"SIGILL":    syscall.Signal(0x4),
	"SIGINT":    syscall.Signal(0x2),
	"SIGIO":     syscall.Signal(0x1d),
	"SIGIOT":    syscall.Signal(0x6),
	"SIGKILL":   syscall.Signal(0x9),
	"SIGPIPE":   syscall.Signal(0xd),
	"SIGPOLL":   syscall.Signal(0x1d),
	"SIGPROF":   syscall.Signal(0x1b),
	"SIGPWR":    syscall.Signal(0x1e),
	"SIGQUIT":   syscall.Signal(0x3),
	"SIGSEGV":   syscall.Signal(0xb),
	"SIGSTKFLT": syscall.Signal(0x10),
	"SIGSTOP":   syscall.Signal(0x13),
	"SIGSYS":    syscall.Signal(0x1f),
	"SIGTERM":   syscall.Signal(0xf),
	"SIGTRAP":   syscall.Signal(0x5),
	"SIGTSTP":   syscall.Signal(0x14),
	"SIGTTIN":   syscall.Signal(0x15),
	"SIGTTOU":   syscall.Signal(0x16),
	"SIGUNUSED": syscall.Signal(0x1f),
	"SIGURG":    syscall.Signal(0x17),
	"SIGUSR1":   syscall.Signal(0xa),
	"SIGUSR2":   syscall.Signal(0xc),
	"SIGVTALRM": syscall.Signal(0x1a),
	"SIGWINCH":  syscall.Signal(0x1c),
	"SIGXCPU":   syscall.Signal(0x18),
	"SIGXFSZ":   syscall.Signal(0x19),
}

type channelType uint64

const (
	LARVAL = channelType(iota)
	OPEN
)

type openPty struct {
	pty     *os.File // pty used by the server/user to communicate with the running process
	tty     *os.File // tty used by the running process to communicate with the server/user
	winSize *pty.Winsize
	term    string
}

type runningCommand struct {
	exec.Cmd
	stdoutR io.Reader
	stderrR io.Reader
	stdinW  io.Writer
}

type runningSession struct {
	channelState        channelType
	pty                 *openPty
	runningCmd          *runningCommand
	runningCmdDone      chan struct{}
	authAgentSocketPath string
	closeInputOnce      sync.Once
	// closed when the exec goroutine finished (exit status sent or abandoned);
	// the session loop waits for it on input EOF so the exit status wins the
	// race against the deferred channel.Close()
	exitStatusSent chan struct{}
}

// var runningSessions = make(map[ssh3.Channel]*runningSession)
var runningSessions = util.NewSyncMap[ssh3.Channel, *runningSession]()

// admitSessionChannel registers a session channel in runningSessions before
// admission — the request handlers resolve the session through that map —
// and undoes the registration when the channel budget refuses the channel
// (P3-01): on a refusal the session goroutine, which owns the prune on
// normal termination, never starts. spawn is the conversation's
// budget-checked channel spawner; the seam keeps the insert/undo pairing
// testable instead of buried in the accept loop (P4-03).
func admitSessionChannel(sessions *util.SyncMap[ssh3.Channel, *runningSession], channels *budget, channel ssh3.Channel, spawn func(ssh3.Channel, func()) bool, run func()) bool {
	sessions.Insert(channel, &runningSession{
		channelState:   LARVAL,
		pty:            nil,
		runningCmd:     nil,
		exitStatusSent: make(chan struct{}),
	})
	if !spawn(channel, run) {
		sessions.Delete(channel)
		return false
	}
	return true
}

func setWinsize(f *os.File, charWidth, charHeight, pixWidth, pixHeight uint64) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(charHeight), uint16(charWidth), uint16(pixWidth), uint16(pixHeight)})))
}

// Size is needed by the /demo/upload handler to determine the size of the uploaded file
type Size interface {
	Size() int64
}

func setupEnv(user *unix_util.User, runningCommand *runningCommand, authAgentSocketPath string) {
	// TODO: set the environment like in do_setup_env of https://github.com/openssh/openssh-portable/blob/master/session.c
	runningCommand.Cmd.Env = append(runningCommand.Cmd.Env,
		fmt.Sprintf("HOME=%s", user.Dir),
		fmt.Sprintf("USER=%s", user.Username),
		fmt.Sprintf("PATH=%s", "/usr/bin:/bin:/usr/sbin:/sbin"),
	)
	// forward the locale settings configured on the server (e.g. via the
	// systemd unit environment) so that remote programs run in a UTF-8 locale
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "LANG=") || strings.HasPrefix(kv, "LC_") {
			runningCommand.Cmd.Env = append(runningCommand.Cmd.Env, kv)
		}
	}
	if authAgentSocketPath != "" {
		runningCommand.Cmd.Env = append(runningCommand.Cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", authAgentSocketPath))
	}
}

func forwardUDPInBackground(ctx context.Context, channel ssh3.Channel, conn *net.UDPConn) {
	go func() {
		defer util.PanicGuard("cmd/ssh3-server.go:156")()
		defer conn.Close()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			datagram, err := channel.ReceiveDatagram(ctx)
			if err != nil {
				log.Error().Msgf("could not receive datagram: %s", err)
				return
			}
			_, err = conn.Write(datagram)
			if err != nil {
				log.Error().Msgf("could not write datagram on UDP socket: %s", err)
				return
			}
		}
	}()

	go func() {
		defer util.PanicGuard("cmd/ssh3-server.go:177")()
		defer channel.Close()
		defer conn.Close()
		buf := make([]byte, 1500)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := conn.Read(buf)
			if err != nil {
				log.Error().Msgf("could read datagram on UDP socket: %s", err)
				return
			}
			err = channel.SendDatagram(buf[:n])
			if err != nil {
				log.Error().Msgf("could send datagram on channel: %s", err)
				return
			}
		}
	}()
}

func forwardTCPInBackground(ctx context.Context, channel ssh3.Channel, conn *net.TCPConn) {
	go func() {
		defer util.PanicGuard("cmd/ssh3-server.go:202")()
		defer conn.CloseWrite()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			genericMessage, err := channel.NextMessage()
			if errors.Is(err, io.EOF) {
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
		defer util.PanicGuard("cmd/ssh3-server.go:242")()
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
			if err != nil && !errors.Is(err, io.EOF) {
				log.Error().Msgf("could read data on TCP socket: %s", err)
				return
			}
			_, errWrite := channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE)
			if errWrite != nil {
				switch quicErr := errWrite.(type) {
				case *quic.StreamError:
					if quicErr.Remote && quicErr.ErrorCode == 42 {
						log.Info().Msgf("writing was canceled by the remote, closing the socket")
					} else {
						log.Error().Msgf("unhandled quic stream error: %+v", quicErr)
					}
				default:
					log.Error().Msgf("could send data on channel: %s", errWrite)
				}
				return
			}
			if errors.Is(err, io.EOF) {
				return
			}
		}
	}()
}

func closeRunningCommandInput(session *runningSession) {
	if session == nil || session.runningCmd == nil || session.pty != nil {
		return
	}
	stdinCloser, ok := session.runningCmd.stdinW.(io.Closer)
	if !ok {
		return
	}
	session.closeInputOnce.Do(func() {
		if err := stdinCloser.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			log.Debug().Msgf("could not close stdin for running command: %s", err)
		}
	})
}

func waitForRunningCommandAfterInputEOF(ctx context.Context, channel ssh3.Channel, session *runningSession) {
	if session == nil || session.channelState != OPEN || session.runningCmd == nil || session.pty != nil || session.runningCmdDone == nil {
		return
	}
	closeRunningCommandInput(session)
	log.Debug().Msgf("input closed on session channel %d, waiting for command completion", channel.ChannelID())
	select {
	case <-session.runningCmdDone:
	case <-ctx.Done():
	}
}

func execCmdInBackground(channel ssh3.Channel, user *unix_util.User, session *runningSession) error {
	// closed on every return path of this function; see runningSession
	defer close(session.exitStatusSent)
	runningCommand := session.runningCmd
	openPty := session.pty
	log.Debug().Msgf(
		"starting command for channel %d: path=%q args=%q pty=%t",
		channel.ChannelID(),
		runningCommand.Path,
		runningCommand.Args,
		openPty != nil,
	)
	setupEnv(user, runningCommand, session.authAgentSocketPath)
	if openPty != nil {
		err := unix_util.StartWithSizeAndPty(&runningCommand.Cmd, openPty.winSize, openPty.pty, openPty.tty)
		if err != nil {
			log.Debug().Msgf("failed to start PTY command on channel %d: %s", channel.ChannelID(), err)
			return err
		}
	} else {
		err := runningCommand.Start()
		if err != nil {
			log.Debug().Msgf("failed to start command on channel %d: %s", channel.ChannelID(), err)
			return err
		}
	}
	log.Debug().Msgf("started command for channel %d", channel.ChannelID())

	done := session.runningCmdDone
	go func() {
		defer util.PanicGuard("cmd/ssh3-server.go:334")()
		defer close(done)

		type readResult struct {
			data []byte
			err  error
			// raw is the pooled buffer backing data, returned to bufs by the
			// consumer after WriteData; nil for a buffer the pool will never
			// see again (reader error path).
			raw *[]byte
		}

		// Pool of per-read buffers instead of two allocations + a copy per
		// read (buf + out + copy showed up as memmove/GC pressure in the
		// data-path profile, docs/PROFILE-2026-09-29.md): the reader hands
		// ownership to the consumer, which returns the buffer after the
		// channel write. At most two buffers are in flight per stream.
		bufs := &sync.Pool{New: func() any {
			b := make([]byte, channel.MaxPacketSize())
			return &b
		}}

		stdoutChan := make(chan readResult, 1)
		stderrChan := make(chan readResult, 1)
		execExitStatus := uint64(0)

		readStdout := func() {
			defer close(stdoutChan)
			if runningCommand.stdoutR != nil {
				for {
					p := bufs.Get().(*[]byte)
					n, err := runningCommand.stdoutR.Read(*p)
					stdoutChan <- readResult{data: (*p)[:n], err: err, raw: p}
					if err != nil {
						return
					}
				}
			}
		}
		readStderr := func() {
			defer close(stderrChan)
			if runningCommand.stderrR != nil {
				for {
					p := bufs.Get().(*[]byte)
					n, err := runningCommand.stderrR.Read(*p)
					stderrChan <- readResult{data: (*p)[:n], err: err, raw: p}
					if err != nil {
						return
					}
				}
			}
		}

		go readStdout()
		go readStderr()

		for {
			select {
			case stdoutResult, ok := <-stdoutChan:
				if !ok {
					// disable the channel: a select on a nil is always blocking
					stdoutChan = nil
				} else {
					buf, err := stdoutResult.data, stdoutResult.err
					// an error could be returned but still with relevant data, so first send the data
					_, err2 := channel.WriteData(buf, ssh3Messages.SSH_EXTENDED_DATA_NONE)
					if stdoutResult.raw != nil {
						bufs.Put(stdoutResult.raw)
					}
					if err2 != nil {
						log.Error().Msgf("could not write the pty's output in an SSH message: %+v\n", err)
						return
					}
					if err != nil && !errors.Is(err, io.EOF) {
						log.Info().Msgf("could not read the pty's output, it might have been closed by the running process: %s", err)
					}
				}

			case stderrResult, ok := <-stderrChan:
				if !ok {
					// disable the channel: a select on a nil is always blocking
					stderrChan = nil
				} else {
					buf, err := stderrResult.data, stderrResult.err
					_, err2 := channel.WriteData(buf, ssh3Messages.SSH_EXTENDED_DATA_STDERR)
					if stderrResult.raw != nil {
						bufs.Put(stderrResult.raw)
					}
					if err2 != nil {
						log.Error().Msgf("could not write the pty's error output in an SSH message: %+v\n", err)
						return
					}
					if err != nil && !errors.Is(err, io.EOF) {
						log.Info().Msgf("could not read the pty's error output, it might have been closed by the running process: %s", err)
					}
				}

			}
			if stdoutChan == nil && stderrChan == nil {
				// All pipe readers have drained: only now is Wait safe. os/exec
				// closes the pipe readers when Wait returns, so calling it
				// earlier races the output pumps and truncates command output.
				waitErr := runningCommand.Wait()
				execExitStatus = uint64(0)
				if waitErr != nil {
					if exitError, ok := waitErr.(*exec.ExitError); ok {
						if signalName, coreDumped, signaled := signalExit(exitError); signaled {
							// OpenSSH parity: a signal death reports the
							// RFC 4254 section 6.10 exit-signal request
							// instead of a 255 exit status
							log.Debug().Msgf("sending exit-signal %s on channel %d", signalName, channel.ChannelID())
							err := channel.SendRequest(&ssh3Messages.ChannelRequestMessage{
								WantReply: false,
								ChannelRequest: &ssh3Messages.ExitSignalRequest{
									SignalNameWithoutSig: signalName,
									CoreDumped:           coreDumped,
								},
							})
							if err != nil {
								log.Error().Msgf("Could not send exit signal message to the peer: %s", err)
							}
							// both channels are closed, nothing else to do, return
							return
						}
						execExitStatus = safeExitStatus(exitError.ExitCode())
					}
				}
				log.Debug().Msgf("sending exit-status %d on channel %d", execExitStatus, channel.ChannelID())
				err := channel.SendRequest(&ssh3Messages.ChannelRequestMessage{
					WantReply:      false,
					ChannelRequest: &ssh3Messages.ExitStatusRequest{ExitStatus: execExitStatus},
				})
				if err != nil {
					log.Error().Msgf("Could not send exit status message to the peer: %s", err)
				}
				// both channels are closed, nothing else to do, return
				return
			}
		}
	}()
	return nil
}

// signalExit reports how a command's process state ended: a signal death
// comes back with the wire signal name (no SIG prefix, like the exit-signal
// request carries) and the core-dump flag; a normal exit is not signaled.
func signalExit(exitError *exec.ExitError) (signalName string, coreDumped bool, signaled bool) {
	ws, ok := exitError.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		return "", false, false
	}

	for name, signal := range signals {
		if signal == ws.Signal() {
			return strings.TrimPrefix(name, "SIG"), ws.CoreDump(), true
		}
	}

	return "", false, false
}

func newPtyReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.PtyRequest, wantReply bool) error {
	var session *runningSession
	session, ok := runningSessions.Get(channel)
	if !ok {
		return fmt.Errorf("internal error: cannot find session for current channel")
	}

	if session.channelState != LARVAL {
		return fmt.Errorf("cannot request new pty on already established session")
	}

	if session.pty != nil {
		return fmt.Errorf("cannot request new pty on a channel with an already existing pty")
	}
	winSize := &pty.Winsize{Rows: uint16(request.CharHeight), Cols: uint16(request.CharWidth), X: uint16(request.PixelWidth), Y: uint16(request.PixelHeight)}
	pty, tty, err := pty.Open()
	if err != nil {
		return err
	}

	setWinsize(pty, request.CharWidth, request.CharHeight, request.PixelWidth, request.PixelHeight)

	// the terminal modes ride the pty request (RFC 4254 section 8); a
	// payload we cannot parse or apply must not kill the session
	if len(request.EncodedTerminalModes) > 0 {
		modes, err := ttymodes.Parse([]byte(request.EncodedTerminalModes))
		if err != nil {
			log.Warn().Msgf("ignoring the pty terminal modes: %s", err)
		} else if err := ttymodes.ApplyToFile(tty, modes); err != nil {
			log.Warn().Msgf("could not apply the pty terminal modes: %s", err)
		}
	}

	session.pty = &openPty{
		pty:     pty,
		tty:     tty,
		term:    request.Term,
		winSize: winSize,
	}

	return nil
}

func newX11Req(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.X11Request, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newCommand(user *unix_util.User, channel ssh3.Channel, loginShell bool, command string, args ...string) error {
	var session *runningSession
	session, ok := runningSessions.Get(channel)
	if !ok {
		return fmt.Errorf("internal error: cannot find session for current channel")
	}

	if session.channelState != LARVAL {
		return fmt.Errorf("cannot request new shell on already established session")
	}
	log.Debug().Msgf(
		"preparing command for channel %d: login_shell=%t command=%q args=%q pty=%t",
		channel.ChannelID(),
		loginShell,
		command,
		args,
		session.pty != nil,
	)

	env := ""
	if session.pty != nil {
		env = fmt.Sprintf("TERM=%s", session.pty.term)
	}

	var stdoutR, stderrR, stdinR io.Reader
	var stdoutW, stderrW, stdinW io.Writer
	var closeParentPipes func()
	var err error = nil
	var cmd *exec.Cmd

	if session.pty != nil {
		stdoutW = session.pty.tty
		stderrW = session.pty.tty
		stdinR = session.pty.tty

		stdoutR = session.pty.pty
		stderrR = nil
		stdinW = session.pty.pty
		cmd, _, _, _, closeParentPipes, err = user.CreateCommand(env, stdoutW, stderrW, stdinR, loginShell, command, args...)
	} else {
		stdoutR, stdoutW, err = os.Pipe()
		if err != nil {
			return err
		}
		stderrR, stderrW, err = os.Pipe()
		if err != nil {
			return err
		}
		stdinR, stdinW, err = os.Pipe()
		if err != nil {
			return err
		}
		cmd, stdoutR, stderrR, stdinW, closeParentPipes, err = user.CreateCommandPipeOutput(env, loginShell, command, args...)
	}

	if err != nil {
		log.Debug().Msgf("failed to prepare command for channel %d: %s", channel.ChannelID(), err)
		return err
	}

	runningCommand := &runningCommand{
		Cmd:     *cmd,
		stdoutR: stdoutR,
		stderrR: stderrR,
		stdinW:  stdinW,
	}
	// The parent's write ends would keep the child's stdout/stderr pipes from
	// ever reaching EOF; hand the write ends to the child and drop ours.
	// nil in the PTY branch (the child writes to the pty directly).
	if closeParentPipes != nil {
		defer closeParentPipes()
	}

	session.runningCmd = runningCommand
	session.channelState = OPEN
	session.runningCmdDone = make(chan struct{})

	return execCmdInBackground(channel, user, session)
}

// sessionBanner returns a compact system stats block printed before the
// shell prompt on interactive logins.
func sessionBanner(user *unix_util.User) string {
	host, _ := os.Hostname()
	now := time.Now().Format("Mon 2006-01-02 15:04:05 MST")
	uptimeStr, loadStr := "unknown", "unknown"
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		if fields := strings.Fields(string(data)); len(fields) > 0 {
			if secs, err := strconv.ParseFloat(fields[0], 64); err == nil {
				uptimeStr = fmt.Sprintf("%dd %02dh %02dm", int(secs)/86400, (int(secs)%86400)/3600, (int(secs)%3600)/60)
			}
		}
	}
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		if fields := strings.Fields(string(data)); len(fields) >= 3 {
			loadStr = strings.Join(fields[:3], " ")
		}
	}
	memStr := "unknown"
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var totalKb, availKb uint64
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			value, _ := strconv.ParseUint(fields[1], 10, 64)
			switch {
			case strings.HasPrefix(line, "MemTotal:"):
				totalKb = value
			case strings.HasPrefix(line, "MemAvailable:"):
				availKb = value
			}
		}
		if totalKb > 0 && availKb <= totalKb {
			used := totalKb - availKb
			memStr = fmt.Sprintf("%.1f/%.1f GiB (%.0f%%)", float64(used)/(1<<20), float64(totalKb)/(1<<20), 100*float64(used)/float64(totalKb))
		}
	}
	diskStr := "unknown"
	if used, total, ok := rootDiskUsage(); ok {
		diskStr = fmt.Sprintf("%.0fG/%.0fG (%.0f%%)", float64(used)/1e9, float64(total)/1e9, 100*float64(used)/float64(total))
	}
	kernel := ""
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(data))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\r\n ssh3-go session: %s@%s\r\n", user.Username, host)
	fmt.Fprintf(&b, " -------------------------------------------------------\r\n")
	fmt.Fprintf(&b, "  date    : %s\r\n", now)
	fmt.Fprintf(&b, "  kernel  : Linux %s %s\r\n", kernel, runtime.GOARCH)
	fmt.Fprintf(&b, "  uptime  : %s (load: %s)\r\n", uptimeStr, loadStr)
	fmt.Fprintf(&b, "  memory  : %s\r\n", memStr)
	fmt.Fprintf(&b, "  disk /  : %s\r\n", diskStr)
	fmt.Fprintf(&b, " -------------------------------------------------------\r\n")
	return b.String()
}

func newShellReq(user *unix_util.User, channel ssh3.Channel, wantReply bool) error {
	// show system stats before the shell prompt (interactive sessions only,
	// exec requests go through newCommand and are not polluted)
	if _, err := channel.WriteData([]byte(sessionBanner(user)), ssh3Messages.SSH_EXTENDED_DATA_NONE); err != nil {
		log.Warn().Msgf("could not write session banner: %s", err)
	}
	return newCommand(user, channel, true, user.Shell)
}

// similar behaviour to OpenSSH; exec requests are just pasted in the user's shell
func newCommandInShellReq(user *unix_util.User, channel ssh3.Channel, wantReply bool, command string) error {
	return newCommand(user, channel, false, user.Shell, "-c", command)
}

func newSubsystemReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.SubsystemRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newWindowChangeReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.WindowChangeRequest, wantReply bool) error {
	runningSession, ok := runningSessions.Get(channel)
	if !ok {
		return fmt.Errorf("could not find running session for channel %d (conv %d)", channel.ChannelID(), channel.ConversationID())
	}

	if runningSession.pty == nil {
		return fmt.Errorf("cannot change window size without a requested pty on channel %d (conv %d)", channel.ChannelID(), channel.ConversationID())
	}

	runningSession.pty.winSize = &pty.Winsize{
		Rows: uint16(request.CharHeight),
		Cols: uint16(request.CharWidth),
		X:    uint16(request.PixelWidth),
		Y:    uint16(request.PixelHeight),
	}
	setWinsize(
		runningSession.pty.pty,
		request.CharWidth,
		request.CharHeight,
		request.PixelWidth,
		request.PixelHeight,
	)
	return nil
}

func newSignalReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.SignalRequest, wantReply bool) error {
	runningSession, ok := runningSessions.Get(channel)
	if !ok {
		return fmt.Errorf("could not find running session for channel %d (conv %d)", channel.ChannelID(), channel.ConversationID())
	}

	if runningSession.channelState == LARVAL {
		return fmt.Errorf("cannot send signal for channel in LARVAL state (channel %d, conv %d)", channel.ChannelID(), channel.ConversationID())
	}

	switch channel.ChannelType() {
	case "session":
		if runningSession.runningCmd == nil {
			return fmt.Errorf("there is no running command on Channel %d (conv %d) to feed the received data", channel.ChannelID(), channel.ConversationID())
		}
		signal, ok := signals["SIG"+request.SignalNameWithoutSig]
		if !ok {
			return fmt.Errorf("unhandled signal SIG%s", request.SignalNameWithoutSig)
		}
		runningSession.runningCmd.Process.Signal(signal)
	default:
		return fmt.Errorf("channel type %s not implemented", channel.ChannelType())
	}
	return nil
}

func newExitStatusReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.ExitStatusRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newExitSignalReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.ExitSignalRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func handleUDPForwardingChannel(ctx context.Context, user *unix_util.User, conv *ssh3.Conversation, channel *ssh3.UDPForwardingChannelImpl) error {
	// TODO: currently, the socket is opened with the process's uid and gid
	// Not sure how to handled that in go since we cannot temporarily change the uid/gid without potentially impacting every
	// other goroutine
	if err := checkForwardTarget("udp", channel.RemoteAddr.IP.String(), int(channel.RemoteAddr.Port)); err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, channel.RemoteAddr)
	if err != nil {
		return err
	}
	forwardUDPInBackground(ctx, channel, conn)
	return nil
}

func handleTCPForwardingChannel(ctx context.Context, user *unix_util.User, conv *ssh3.Conversation, channel *ssh3.TCPForwardingChannelImpl) error {
	// TODO: currently, the socket is opened with the process's uid and gid
	// Not sure how to handled that in go since we cannot temporarily change the uid/gid without potentially impacting every
	// other goroutine
	if err := checkForwardTarget("tcp", channel.RemoteAddr.IP.String(), channel.RemoteAddr.Port); err != nil {
		return err
	}
	conn, err := net.DialTCP("tcp", nil, channel.RemoteAddr)
	if err != nil {
		return err
	}
	forwardTCPInBackground(ctx, channel, conn)
	return nil
}

func newDataReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.DataOrExtendedDataMessage) error {
	runningSession, ok := runningSessions.Get(channel)
	if !ok {
		return fmt.Errorf("could not find running session for channel %d (conv %d)", channel.ChannelID(), channel.ConversationID())
	}

	if runningSession.channelState == LARVAL {
		return fmt.Errorf("cannot receive data for channel in LARVAL state (channel %d, conv %d)", channel.ChannelID(), channel.ConversationID())
	}

	switch channel.ChannelType() {
	case "session":
		if runningSession.runningCmd == nil {
			return fmt.Errorf("there is no running command on Channel %d (conv %d) to feed the received data", channel.ChannelID(), channel.ConversationID())
		}
		switch request.DataType {
		case ssh3Messages.SSH_EXTENDED_DATA_NONE:
			runningSession.runningCmd.stdinW.Write([]byte(request.Data))
		default:
			return fmt.Errorf("extended data type forbidden server PTY")
		}
	default:
		return fmt.Errorf("channel type %s not implemented", channel.ChannelType())
	}
	return nil
}

func handleAuthAgentSocketConn(conn net.Conn, conversation *ssh3.Conversation) {
	channel, err := conversation.OpenChannel("agent-connection", 30000, 10)
	if err != nil {
		log.Error().Msgf("could not open channel from server: %s", err.Error())
		return
	}
	go func() {
		defer util.PanicGuard("cmd/ssh3-server.go:816")()
		defer channel.Close()
		buf := make([]byte, channel.MaxPacketSize())
		for {
			n, err := conn.Read(buf)
			if err != nil {
				log.Info().Msgf("could not read data socket %d: %s", channel.ChannelID(), err.Error())
				return
			}
			_, err = channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE)
			if err != nil {
				log.Info().Msgf("could not write data on agent channel %d: %s", channel.ChannelID(), err.Error())
				return
			}
		}
	}()
	for {
		genericMessage, err := channel.NextMessage()
		if err != nil {
			log.Error().Msgf("could not get data from channel %d: %s", channel.ChannelID(), err.Error())
			return
		}
		switch message := genericMessage.(type) {
		case *ssh3Messages.DataOrExtendedDataMessage:
			_, err := conn.Write([]byte(message.Data))
			if err != nil {
				log.Error().Msgf("could not write data to channel %d: %s", channel.ChannelID(), err.Error())
				return
			}
		default:
			log.Error().Msgf("unhandled message type on agent channel %T", message)
			return
		}
	}
}

func listenAndAcceptAuthSockets(cancel context.CancelCauseFunc, conversation *ssh3.Conversation, listener net.Listener, maxSSHPacketSize uint64) {
	defer cancel(nil)
	defer listener.Close()
	for {
		log.Debug().Msg("waiting for new agent connections to forward")
		conn, err := listener.Accept()
		if err != nil {
			log.Error().Msgf("error while listening for agent connections: %s", err.Error())
			cancel(err)
			return
		}
		// new ssh agent client
		go handleAuthAgentSocketConn(conn, conversation)
	}
}

func openAgentSocketAndForwardAgent(parent context.Context, conv *ssh3.Conversation, user *unix_util.User) (string, error) {
	ctx, cancel := context.WithCancelCause(parent)
	sockPath, err := unix_util.NewUnixSocketPath()
	if err != nil {
		cancel(err)
		return "", err
	}

	var listener net.ListenConfig
	agentSock, err := listener.Listen(ctx, "unix", sockPath)
	if err != nil {
		log.Error().Msgf("could not listen on agent socket: %s", err.Error())
		cancel(err)
		return "", err
	}

	sockDir := path.Dir(sockPath)
	err = os.Chown(sockDir, int(user.Uid), int(user.Gid))
	if err != nil {
		log.Error().Msgf("could chown the directory of the listening socket at %s: %s", sockPath, err.Error())
		cancel(err)
		return "", err
	}
	err = os.Chown(sockPath, int(user.Uid), int(user.Gid))
	if err != nil {
		log.Error().Msgf("could chown the listening socket at %s: %s", sockPath, err.Error())
		cancel(err)
		return "", err
	}

	go listenAndAcceptAuthSockets(cancel, conv, agentSock, 30000)
	return sockPath, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

type autogenCertificates []string

func (i *autogenCertificates) String() string {
	return fmt.Sprint(*i)
}

func (i *autogenCertificates) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func ServerMain() int {
	// the plugin registration (init-time) logs run before ConfigureLogger:
	// keep the default startup quiet at the warnings-and-errors level until
	// the real level is resolved from -v/SSH3_LOG_LEVEL
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
	pprofutil.ServeIfEnabled(os.Getenv("SSH3_PPROF"))
	bindAddr := flag.String("bind", "[::]:443", "the address:port pair to listen to, e.g. 0.0.0.0:443")
	verbose := flag.Bool("v", false, "verbose mode, if set")
	displayVersionVar := false
	flag.BoolVar(&displayVersionVar, "version", false, "if set, displays the software version on standard output and exit")
	flag.BoolVar(&displayVersionVar, "V", false, "print the software version and exit (same as -version)")
	urlPath := flag.String("url-path", "/ssh3-term", "the secret URL path on which the ssh3 server listens")
	streamRxMiB := flag.Int("stream-rx-mb", 8, "initial per-stream flow control receive window in MiB")
	connRxMiB := flag.Int("conn-rx-mb", 16, "initial connection-level flow control receive window in MiB")
	initialPacketSize := flag.Int("initial-packet-size", 1350, "initial QUIC packet size in bytes")
	generateSelfSignedCert := flag.Bool("generate-selfsigned-cert", false, "if set, generates a self-self-signed cerificate and key "+
		"that will be stored at the paths indicated by the -cert and -key args (they must not already exist)")
	certPath := flag.String("cert", "./cert.pem", "the filename of the server certificate (or fullchain)")
	keyPath := flag.String("key", "./priv.key", "the filename of the certificate private key")
	// the sshd(8)-shaped aliases (CLI-parity wave, CTO_TASK §7c item 9/10):
	// -h for the host key, -c for the host certificate, -p for the port
	certAlias := flag.String("c", "", "host certificate file (sshd -c; same as -cert)")
	keyAlias := flag.String("h", "", "host key file (sshd -h; same as -key)")
	serverPort := flag.Int("p", 0, "port to listen on (sshd -p; overrides the -bind port, the bind address stays -bind)")
	var autogenCertificates autogenCertificates
	flag.Var(&autogenCertificates, "generate-public-cert", "Automatically produce and use a valid public certificate using"+
		"Let's Encrypt for the provided domain name. The flag can be used several times to generate several certificates."+
		"If certificates have already been generated previously using this flag, "+
		"they will simply be reused without being regenerated. The public certificates are automatically renewed as long as the "+
		"server is running. Automatically-generated IP public certificates are not available yet.")
	// Password auth is enabled by default on builds that ship the backend
	// (the amd64 release server): the admin turns it off explicitly with
	// SSH3_ENABLE_PASSWORD_LOGIN=0 or -enable-password-login=false. Brute
	// force stays bounded by the per-account lockout (SSH3_MAX_PASSWORD_
	// FAILURES / SSH3_PASSWORD_LOCKOUT_SECONDS) and the unauthenticated
	// conversation cap.
	enablePasswordLogin := true
	if env, ok := os.LookupEnv("SSH3_ENABLE_PASSWORD_LOGIN"); ok {
		enablePasswordLogin, _ = strconv.ParseBool(env)
	}
	if unix_util.PasswordAuthAvailable() {
		flag.BoolVar(&enablePasswordLogin, "enable-password-login", enablePasswordLogin, "enable password authentication (enabled by default; SSH3_ENABLE_PASSWORD_LOGIN=0 or -enable-password-login=false turn it off)")
	}
	// The GatewayPorts policy of the reverse (-R) forwards, the sshd_config
	// semantics; the env default lets systemd installs opt into wide binds
	// without editing the unit's ExecStart.
	gatewayPorts := os.Getenv("SSH3_GATEWAY_PORTS")
	if gatewayPorts == "" {
		gatewayPorts = gatewayPortsNo
	}
	flag.StringVar(&gatewayPorts, "gateway-ports", gatewayPorts, "GatewayPorts policy for reverse (-R) forwarding: no (force loopback, default), clientspecified or yes; SSH3_GATEWAY_PORTS sets it too")
	maxReverseForwards := 10
	if envMax, err := strconv.Atoi(os.Getenv("SSH3_MAX_REVERSE_FORWARDS")); err == nil {
		maxReverseForwards = envMax
	}
	flag.IntVar(&maxReverseForwards, "max-reverse-forwards", maxReverseForwards, "maximum active reverse (-R) listeners per user (SSH3_MAX_REVERSE_FORWARDS sets it too)")
	maxUnauthConversations := 100
	if envMax, err := strconv.Atoi(os.Getenv("SSH3_MAX_UNAUTH_CONVERSATIONS")); err == nil {
		maxUnauthConversations = envMax
	}
	flag.IntVar(&maxUnauthConversations, "max-unauth-conversations", maxUnauthConversations, "maximum conversations sitting unauthenticated before refusals (the MaxStartups analog; SSH3_MAX_UNAUTH_CONVERSATIONS sets it too)")
	maxPasswordFailures := 10
	if envMax, err := strconv.Atoi(os.Getenv("SSH3_MAX_PASSWORD_FAILURES")); err == nil {
		maxPasswordFailures = envMax
	}
	flag.IntVar(&maxPasswordFailures, "max-password-failures", maxPasswordFailures, "failed password attempts before the account lockout (SSH3_MAX_PASSWORD_FAILURES sets it too)")
	passwordLockoutSeconds := 60
	if envSecs, err := strconv.Atoi(os.Getenv("SSH3_PASSWORD_LOCKOUT_SECONDS")); err == nil {
		passwordLockoutSeconds = envSecs
	}
	flag.IntVar(&passwordLockoutSeconds, "password-lockout-seconds", passwordLockoutSeconds, "password brute-force lockout duration in seconds (SSH3_PASSWORD_LOCKOUT_SECONDS sets it too)")
	// the sftp path-isolation mode: chroot (default, the sshd model) re-execs
	// a per-session child that chroots into the user's home and drops to its
	// uid/gid; lexical keeps the historical in-process jail
	sftpJail := os.Getenv("SSH3_SFTP_JAIL")
	if sftpJail == "" {
		sftpJail = sftpJailChroot
	}
	flag.StringVar(&sftpJail, "sftp-jail", sftpJail, "sftp path isolation: chroot (default, the sshd model: a per-session child chroots into the user's home and drops to its uid/gid) or lexical (in-process jail; the server's own privileges apply)")
	sftpServerInternal := flag.Bool("sftp-server-internal", false, "internal: run the sftp child server on stdin/stdout (set by the server itself, not for direct use)")
	sftpChrootDir := flag.String("sftp-chroot", "", "internal: chroot directory of the sftp child; empty disables the chroot")
	sftpRootDir := flag.String("sftp-root", "", "internal: path root of the sftp child when it runs without a chroot")
	sftpChildUID := flag.Uint64("sftp-uid", 0, "internal: uid the sftp child drops to")
	sftpChildGID := flag.Uint64("sftp-gid", 0, "internal: gid the sftp child drops to")
	// the PermitOpen analog bounding server-side TCP/UDP/dynamic forwarding;
	// empty (default) keeps the historical unrestricted behavior
	permitOpenSpec := os.Getenv("SSH3_PERMIT_OPEN")
	flag.StringVar(&permitOpenSpec, "permit-open", permitOpenSpec, "comma/space-separated host:port targets allowed for server-side forwarding (* wildcards, ! negates; e.g. \"*.example.org:443,!10.0.0.0:*\"; empty: unrestricted; SSH3_PERMIT_OPEN sets it too)")
	// the PermitListen analog bounding the binds the reverse (-R) forwards
	// take on the server; governs binds, while -permit-open governs dials
	permitListenSpec := os.Getenv("SSH3_PERMIT_LISTEN")
	flag.StringVar(&permitListenSpec, "permit-listen", permitListenSpec, "comma/space-separated host:port binds allowed for reverse (-R) forwarding listeners (* wildcards, ! negates; e.g. \"127.0.0.1:*,!192.0.2.*:*\"; empty: unrestricted; governs binds, not dials; SSH3_PERMIT_LISTEN sets it too)")
	maxChannelsPerConversation := 64
	if envMax, err := strconv.Atoi(os.Getenv("SSH3_MAX_CHANNELS_PER_CONVERSATION")); err == nil {
		maxChannelsPerConversation = envMax
	}
	flag.IntVar(&maxChannelsPerConversation, "max-channels-per-conversation", maxChannelsPerConversation, "maximum concurrently open channels per conversation, 0 for no limit (SSH3_MAX_CHANNELS_PER_CONVERSATION sets it too)")
	maxSFTPSessionsPerUser := 16
	if envMax, err := strconv.Atoi(os.Getenv("SSH3_MAX_SFTP_SESSIONS_PER_USER")); err == nil {
		maxSFTPSessionsPerUser = envMax
	}
	flag.IntVar(&maxSFTPSessionsPerUser, "max-sftp-sessions-per-user", maxSFTPSessionsPerUser, "maximum concurrent sftp sessions per user, 0 for no limit (SSH3_MAX_SFTP_SESSIONS_PER_USER sets it too)")
	maxConnections := 0
	if envMax, err := strconv.Atoi(os.Getenv("SSH3_MAX_CONNECTIONS")); err == nil {
		maxConnections = envMax
	}
	flag.IntVar(&maxConnections, "max-connections", maxConnections, "maximum concurrent QUIC connections, 0 for no limit (SSH3_MAX_CONNECTIONS sets it too)")
	// the ssh2 behavioral canon (§7c item 11): sshd never kills an idle
	// session (ClientAliveInterval=0) and gives LoginGraceTime=120s for the
	// handshake; quic-go has no "unset" (0 → its 30s default), so the canon
	// is expressed as explicit large defaults. The keepalive a client sends
	// keeps a live connection alive regardless of these values.
	maxIdleTimeoutSecs := int(ssh2IdleTimeout.Seconds())
	if envSecs, err := strconv.Atoi(os.Getenv("SSH3_MAX_IDLE_TIMEOUT")); err == nil {
		maxIdleTimeoutSecs = envSecs
	}
	flag.IntVar(&maxIdleTimeoutSecs, "max-idle-timeout", maxIdleTimeoutSecs, "QUIC idle timeout in seconds before a quiet connection is closed; the default follows the ssh2 canon (ClientAliveInterval=0: do not kill the idle) (SSH3_MAX_IDLE_TIMEOUT sets it too)")
	handshakeIdleTimeoutSecs := int(ssh2HandshakeTimeout.Seconds())
	if envSecs, err := strconv.Atoi(os.Getenv("SSH3_HANDSHAKE_IDLE_TIMEOUT")); err == nil {
		handshakeIdleTimeoutSecs = envSecs
	}
	flag.IntVar(&handshakeIdleTimeoutSecs, "handshake-idle-timeout", handshakeIdleTimeoutSecs, "QUIC handshake timeout in seconds; the default follows the ssh2 LoginGraceTime scale (SSH3_HANDSHAKE_IDLE_TIMEOUT sets it too)")
	maxIncomingStreams := 100
	if envMax, err := strconv.Atoi(os.Getenv("SSH3_MAX_INCOMING_STREAMS")); err == nil {
		maxIncomingStreams = envMax
	}
	flag.IntVar(&maxIncomingStreams, "max-incoming-streams", maxIncomingStreams, "maximum concurrent peer-initiated bidirectional QUIC streams per connection (SSH3_MAX_INCOMING_STREAMS sets it too)")
	maxIncomingUniStreams := 100
	if envMax, err := strconv.Atoi(os.Getenv("SSH3_MAX_INCOMING_UNI_STREAMS")); err == nil {
		maxIncomingUniStreams = envMax
	}
	flag.IntVar(&maxIncomingUniStreams, "max-incoming-uni-streams", maxIncomingUniStreams, "maximum concurrent peer-initiated unidirectional QUIC streams per connection (SSH3_MAX_INCOMING_UNI_STREAMS sets it too)")
	flag.Parse()

	// -p (sshd canon): only the port moves, the bind address stays -bind's
	if *serverPort != 0 {
		if *serverPort < 0 || *serverPort > 0xFFFF {
			fmt.Fprintf(os.Stderr, "the -p port %d is out of range\n", *serverPort)
			return -1
		}
		merged, err := mergeBindPort(*bindAddr, uint16(*serverPort))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			return -1
		}
		*bindAddr = merged
	}

	// -c/-h (sshd canon): apply the aliases; giving both forms of the same
	// knob is an error instead of a silent last-one-wins
	certFlagSet := false
	keyFlagSet := false
	certAliasSet := false
	keyAliasSet := false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "cert":
			certFlagSet = true
		case "key":
			keyFlagSet = true
		case "c":
			certAliasSet = true
		case "h":
			keyAliasSet = true
		}
	})
	certPathValue, keyPathValue, aliasesErr := resolveServerCertKeyAliases(certFlagSet, keyFlagSet, certAliasSet, keyAliasSet, *certPath, *keyPath, *certAlias, *keyAlias)
	if aliasesErr != nil {
		fmt.Fprintf(os.Stderr, "%s\n", aliasesErr)
		return -1
	}
	*certPath = certPathValue
	*keyPath = keyPathValue

	policy, policyErr := parsePermitOpen(permitOpenSpec)
	if policyErr != nil {
		log.Error().Msgf("%s", policyErr)
		return 1
	}
	permitOpen = policy

	listenPolicy, listenPolicyErr := parsePermitOpen(permitListenSpec)
	if listenPolicyErr != nil {
		log.Error().Msgf("%s", listenPolicyErr)
		return 1
	}
	permitListen = listenPolicy

	sftpChildrenBudgets = newUserBudgets(maxSFTPSessionsPerUser)

	sftpJailMode = sftpJail
	switch sftpJailMode {
	case sftpJailChroot, sftpJailLexical:
	default:
		log.Error().Msgf("invalid -sftp-jail %q: must be %q or %q", sftpJailMode, sftpJailChroot, sftpJailLexical)
		return 1
	}
	if *sftpServerInternal {
		return runInternalSFTPServer(*sftpChrootDir, *sftpRootDir, *sftpChildUID, *sftpChildGID)
	}

	server_auth.MaxUnauthenticatedConversations = maxUnauthConversations
	server_auth.MaxPasswordAuthFailures = maxPasswordFailures
	server_auth.PasswordLockoutDuration = time.Duration(passwordLockoutSeconds) * time.Second

	if policy, err := parseGatewayPorts(gatewayPorts); err != nil {
		fmt.Fprintf(os.Stderr, "the -gateway-ports/SSH3_GATEWAY_PORTS value is invalid: %v\n", err)
		return -1
	} else {
		gatewayPortsPolicy = policy
	}
	if maxReverseForwards < 0 {
		fmt.Fprintf(os.Stderr, "the -max-reverse-forwards/SSH3_MAX_REVERSE_FORWARDS value must not be negative\n")
		return -1
	}
	maxReverseForwardsPerUser = maxReverseForwards

	if displayVersionVar {
		fmt.Fprintln(os.Stdout, filepath.Base(os.Args[0]), "version", ssh3.GetCurrentSoftwareVersion())
		return 0
	}

	internal.CloseClientPluginsRegistry()
	internal.CloseServerPluginsRegistry()

	if !enablePasswordLogin {
		fmt.Fprintln(os.Stderr, "password login is disabled")
	}

	certPathExists := fileExists(*certPath)
	keyPathExists := fileExists(*keyPath)

	// handle bad case where one of the cert or key path is valid but not the other
	badCertificatesConf := (certPathExists && !keyPathExists) ||
		(!certPathExists && keyPathExists) ||
		(!certPathExists && !keyPathExists && !*generateSelfSignedCert && len(autogenCertificates) == 0) // no certificate available whatsoever

	if badCertificatesConf {
		if !certPathExists {
			fmt.Fprintf(os.Stderr, "the \"%s\" certificate file does not exist\n", *certPath)
		}
		if !keyPathExists {
			fmt.Fprintf(os.Stderr, "the \"%s\" certificate private key file does not exist\n", *keyPath)
		}
		fmt.Fprintln(os.Stderr, "No certificate available for the QUIC connection.")
		fmt.Fprintln(os.Stderr, "If you have no certificate and want a security comparable to traditional SSH host keys, "+
			"you can generate a self-signed certificate using the -generate-selfsigned-cert arg or using the following script:")
		fmt.Fprintln(os.Stderr, "https://github.com/francoismichel/ssh3/blob/main/generate_openssl_selfsigned_certificate.sh")
		return -1
	} else if *generateSelfSignedCert {
		if certPathExists {
			fmt.Fprintf(os.Stderr, "asked for generating a certificate but the \"%s\" file already exists\n", *certPath)
		}
		if keyPathExists {
			fmt.Fprintf(os.Stderr, "asked for generating a private key but the \"%s\" file already exists\n", *keyPath)
		}
		if certPathExists || keyPathExists {
			return -1
		}
		pubkey, privkey, err := util.GenerateKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not generate private key: %s\n", err)
			return -1
		}
		cert, err := util.GenerateCert(privkey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not generate certificate: %s\n", err)
			return -1
		}

		err = util.DumpCertAndKeyToFiles(cert, pubkey, privkey, *certPath, *keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not save certificate and key to files: %s\n", err)
			return -1
		}

		certPathExists = true
		keyPathExists = true
	}

	if *verbose {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		util.ConfigureLogger("debug")
	} else if os.Getenv("INVOCATION_ID") != "" {
		// running under systemd: emit plain JSON lines to stderr so journald
		// captures structured, colorless records; the log file is skipped
		util.ConfigureLogger(os.Getenv("SSH3_LOG_LEVEL"))
	} else {
		util.ConfigureLogger(os.Getenv("SSH3_LOG_LEVEL"))

		logFileName := os.Getenv("SSH3_LOG_FILE")
		if logFileName == "" {
			logFileName = "/var/log/ssh3.log"
		}
		logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open log file %s: %s\n", logFileName, err.Error())
			return -1
		}
		log.Logger = log.Output(logFile)
	}

	tlsConfig := &tls.Config{}
	if len(autogenCertificates) > 0 {
		var zapLevel zapcore.Level
		switch zerolog.GlobalLevel() {
		case zerolog.TraceLevel:
			fallthrough
		case zerolog.DebugLevel:
			zapLevel = zap.DebugLevel
		case zerolog.InfoLevel:
			zapLevel = zap.InfoLevel
		case zerolog.WarnLevel:
			zapLevel = zap.WarnLevel
		case zerolog.ErrorLevel:
			zapLevel = zap.ErrorLevel
		}
		certmagic.Default.Logger = zap.New(zapcore.NewCore(
			zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
			os.Stderr,
			zapLevel,
		))
		certmagic.Default.Logger = certmagic.Default.Logger.Named("github.com/caddyserver/certmagic")

		var err error
		fmt.Fprintln(os.Stderr, "Generate public certificates...")
		tlsConfig, err = certmagic.TLS(autogenCertificates)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not generate public certificates: %s\n", err)
			return -1
		}
		fmt.Fprintln(os.Stderr, "Successfully generated public certificates")
	}

	if certPathExists && keyPathExists {
		certificate, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not load -cert and -key pair: %s\n", err)
			return -1
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, certificate)
	}

	log.Debug().Msgf("version %s", ssh3.GetCurrentSoftwareVersion())

	quicConf := &quic.Config{
		Allow0RTT: true,
		// ssh3 tunnels its own datagrams (UDP forwarding) straight over the QUIC
		// datagram API. The HTTP/3 datagram layer must stay disabled: it starts a
		// second reader on the same connection-wide datagram queue and would steal
		// roughly half of the datagrams ssh3 needs.
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     uint64(*streamRxMiB) << 20,
		MaxStreamReceiveWindow:         uint64(*streamRxMiB) << 21,
		InitialConnectionReceiveWindow: uint64(*connRxMiB) << 20,
		MaxConnectionReceiveWindow:     uint64(*connRxMiB) << 21,
		// explicit resource posture (S2-06): the defaults below equal the
		// quic-go defaults, but are now documented operator knobs rather than
		// an invisible library choice
		MaxIdleTimeout:          time.Duration(maxIdleTimeoutSecs) * time.Second,
		HandshakeIdleTimeout:    time.Duration(handshakeIdleTimeoutSecs) * time.Second,
		MaxIncomingStreams:      int64(maxIncomingStreams),
		MaxIncomingUniStreams:   int64(maxIncomingUniStreams),
		InitialPacketSize:       uint16(*initialPacketSize),
		DisablePathMTUDiscovery: true,
	}

	var err error

	server := http3.Server{
		Handler:    nil,
		Addr:       *bindAddr,
		QUICConfig: quicConf,
		// deliberately NOT EnableDatagrams: see quicConf above
		TLSConfig: tlsConfig,
	}

	mux := http.NewServeMux()
	ssh3Server := ssh3.NewServer(30000, 10, &server, func(authenticatedUsername string, conv *ssh3.Conversation) error {
		authenticatedUser, err := unix_util.GetUser(authenticatedUsername)
		if err != nil {
			return err
		}

		// S2-02: the channel accept loop used to be unbounded — every
		// accepted channel became a goroutine (and, for sftp, a child
		// process), so one account drove goroutine/process/heap growth by
		// opening channels. Admit channels while the conversation stays under
		// the cap; a refused channel is torn down with a stream error.
		channels := newBudget(maxChannelsPerConversation)
		// run the channel's handler on its own goroutine under a PanicGuard;
		// the budget slot is held for the handler's lifetime. Returns false
		// when the budget refuses the channel: it is torn down here and no
		// goroutine is started, so the caller must undo any per-channel
		// registration it made before admission.
		spawnChannel := func(channel ssh3.Channel, run func()) bool {
			if !channels.tryAcquire() {
				log.Warn().Msgf("conversation %s: refusing channel %d of type %q: the %d-channel budget is exhausted",
					conv.ConversationID(), channel.ChannelID(), channel.ChannelType(), maxChannelsPerConversation)
				channel.CancelRead()
				channel.Close()
				return false
			}
			go func() {
				defer util.PanicGuard("cmd/ssh3-server.go:channel-handler")()
				defer channels.release()
				run()
			}()
			return true
		}

		for {
			channel, err := conv.AcceptChannel(conv.Context())
			if err != nil {
				return err
			}

			switch c := channel.(type) {
			case *ssh3.UDPForwardingChannelImpl:
				log.Debug().Msgf("accepted UDP forwarding channel %d to %s", channel.ChannelID(), c.RemoteAddr)
				spawnChannel(channel, func() {
					handleUDPForwardingChannel(conv.Context(), authenticatedUser, conv, c)
				})
			case *ssh3.TCPForwardingChannelImpl:
				log.Debug().Msgf("accepted TCP forwarding channel %d to %s", channel.ChannelID(), c.RemoteAddr)
				spawnChannel(channel, func() {
					handleTCPForwardingChannel(conv.Context(), authenticatedUser, conv, c)
				})
			default:
				if channel.ChannelType() == sftpChannelType {
					log.Debug().Msgf("accepted sftp channel %d", channel.ChannelID())
					// own goroutine, own lifetime: closing the transfer channel
					// must not end the conversation the way a session does
					spawnChannel(channel, func() {
						serveSFTPSubsystem(authenticatedUser, channel)
					})
					continue
				}
				if channel.ChannelType() == ssh3Messages.ChannelTypeReverseForward {
					log.Debug().Msgf("accepted reverse-forward control channel %d", channel.ChannelID())
					// own goroutine, own lifetime: serving the -R bind request
					// and its listener must not end the conversation the way a
					// session does
					spawnChannel(channel, func() {
						handleReverseForwardChannel(conv, channel, authenticatedUser)
					})
					continue
				}
				if channel.ChannelType() == ssh3Messages.ChannelTypeDynamicForward {
					log.Debug().Msgf("accepted dynamic-forward control channel %d", channel.ChannelID())
					// own goroutine, own lifetime: the control channel's
					// lifetime is the dynamic forwarding (-D) session
					spawnChannel(channel, func() {
						handleDynamicForwardChannel(conv, channel)
					})
					continue
				}
				if channel.ChannelType() == ssh3Messages.ChannelTypeDynamicForwardTCP {
					log.Debug().Msgf("accepted dynamic-forward-tcp channel %d", channel.ChannelID())
					// own goroutine, own lifetime: each bridged connection
					// ends on its own, the conversation stays up
					spawnChannel(channel, func() {
						serveDynamicForwardDataChannel(conv.Context(), getActiveDynamicForwardState(conv), channel)
					})
					continue
				}
				log.Debug().Msgf("accepted session channel %d of type %q", channel.ChannelID(), channel.ChannelType())
				admitSessionChannel(&runningSessions, channels, channel, spawnChannel, func() {
					defer util.PanicGuard("cmd/ssh3-server.go:1197")()
					// handle the main sessionChannel, once it ends, the whole conversation ends
					// LIFO order matters: the channel (with its buffered exit-status
					// frame) must close with a FIN before the conversation teardown,
					// otherwise the conversation close resets the stream and the
					// client loses the exit status of fast-exiting commands.
					// DrainAndClose then keeps the conversation alive long enough
					// for the peer to consume the tail of the stream data before
					// the forced close.
					// A multiplexing conversation (control master, stage 3.5)
					// outlives every single session: its teardown happens when
					// the master disconnects (SetMultiplexed watcher).
					defer func() {
						channel.Close()
						// S2-02: the process-global session map used to grow by
						// one entry per session channel for the server's whole
						// lifetime; prune the entry when the session ends
						runningSessions.Delete(channel)
						if conv.IsMultiplexed() {
							log.Debug().Msgf("muxed conversation: skipping per-session teardown for channel %d", channel.ChannelID())
							return
						}
						conv.DrainAndClose(3 * time.Second)
					}()
					for {
						genericMessage, err := channel.NextMessage()
						if errors.Is(err, net.ErrClosed) {
							log.Debug().Msgf("the connection was closed by the application: %s", err)
							return
						} else if err != nil && !errors.Is(err, io.EOF) {
							log.Error().Msgf("error when getting message: %s", err)
							return
						}
						if genericMessage == nil {
							if errors.Is(err, io.EOF) {
								runningSession, ok := runningSessions.Get(channel)
								if ok {
									waitForRunningCommandAfterInputEOF(conv.Context(), channel, runningSession)
									// the exec goroutine sends the exit status once the
									// command completes; its send races with the deferred
									// channel.Close() below, so wait for it — otherwise the
									// channel FIN would go out before the status frame was
									// even written (fast commands like `exit 42` lost it)
									if runningSession.runningCmd != nil {
										// the timeout bounds a wedged exec goroutine
										select {
										case <-runningSession.exitStatusSent:
										case <-time.After(time.Second):
										}
										// The exit-status frame was written to the QUIC send
										// stream above; the stack flushes it without further
										// help: a stream write wakes the connection run loop
										// (SendStream.onHasStreamData -> Conn.scheduleSending),
										// so the frame is packed and emitted within
										// microseconds. QUIC exposes no flush callback, but
										// none is needed: the teardown below (DrainAndClose)
										// waits for the peer to close the connection, which
										// only happens after the client read the status and
										// the channel FIN (QUIC orders the FIN after the
										// stream bytes, so a bare EOF without status is
										// impossible on a live connection). An earlier 100ms
										// yield here predates DrainAndClose: back then the
										// conversation was closed right after the FIN and
										// still-buffered frames were dropped; the drain
										// window supersedes it, and the flat 100ms is no
										// longer paid on every one-shot exec (the client
										// drains the channel until the FIN before exiting).
									}
								}
							}
							return
						}
						log.Debug().Msgf("received message of type %T on channel %d", genericMessage, channel.ChannelID())
						switch message := genericMessage.(type) {
						case *ssh3Messages.ChannelRequestMessage:
							switch requestMessage := message.ChannelRequest.(type) {
							case *ssh3Messages.PtyRequest:
								err = newPtyReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.X11Request:
								err = newX11Req(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.ShellRequest:
								err = newShellReq(authenticatedUser, channel, message.WantReply)
							case *ssh3Messages.ExecRequest:
								err = newCommandInShellReq(authenticatedUser, channel, message.WantReply, requestMessage.Command)
							case *ssh3Messages.SubsystemRequest:
								err = newSubsystemReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.WindowChangeRequest:
								err = newWindowChangeReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.SignalRequest:
								err = newSignalReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.ExitStatusRequest:
								err = newExitStatusReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.ExitSignalRequest:
								err = newExitSignalReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							}
						case *ssh3Messages.DataOrExtendedDataMessage:
							runningSession, ok := runningSessions.Get(channel)
							if ok && runningSession.channelState == LARVAL {
								if message.Data == string("forward-agent") {
									runningSession.authAgentSocketPath, err = openAgentSocketAndForwardAgent(conv.Context(), conv, authenticatedUser)
								} else {
									// invalid data on larval state
									err = fmt.Errorf("invalid data on ssh channel with LARVAL state")
								}
							} else {
								err = newDataReq(authenticatedUser, channel, *message)
							}
						}
						if err != nil {
							log.Error().Msgf("error while processing message: %+v: %+v\n", genericMessage, err)
							return
						}
					}
				})
			}

		}
	})
	ssh3Handler := ssh3Server.GetHTTPHandlerFunc(context.Background())
	handler, err := server_auth.HandleAuths(context.Background(), enablePasswordLogin, 30000, ssh3Handler)
	if err != nil {
		log.Error().Msgf("Could not get authentication handlers: %s", err)
		return -1
	}
	mux.HandleFunc(*urlPath, handler)
	server.Handler = mux
	outputMessage := fmt.Sprintf("Server started, listening on %s%s", *bindAddr, *urlPath)
	fmt.Fprintln(os.Stderr, outputMessage)
	log.Info().Msg(outputMessage)

	// quic-go v0.63 removed http3.Server.StreamHijacker, so the http3 server
	// can no longer dispatch foreign (SSH3 channel) streams itself. Accept QUIC
	// connections here and let the ssh3 server drive the HTTP/3 accept loops,
	// dispatching SSH3 channel streams in its own accept loop.
	listener, err := quic.ListenAddrEarly(*bindAddr, http3.ConfigureTLSConfig(tlsConfig), quicConf)
	if err != nil {
		log.Error().Msgf("error while starting the QUIC listener: %s", err)
		return -1
	}

	// graceful shutdown (stage 3): SIGTERM/SIGINT stop accepting new
	// connections, then active connections drain up to SSH3_SHUTDOWN_DRAIN
	// seconds (default 5, 0 closes them immediately) before being terminated
	serveCtx, stopServe := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopServe()

	var conns sync.WaitGroup
	var connsMu sync.Mutex
	activeConns := make(map[*quic.Conn]struct{})
	for {
		qconn, err := listener.Accept(serveCtx)
		if err != nil {
			if serveCtx.Err() != nil {
				log.Info().Msgf("shutdown signal received: no longer accepting new connections")
				break
			}
			log.Error().Msgf("error while accepting a QUIC connection: %s", err)
			return -1
		}
		connsMu.Lock()
		// S2-06: bound how many QUIC connections the server holds at once;
		// 0 (the default) keeps the historical unbounded behavior
		if maxConnections > 0 && len(activeConns) >= maxConnections {
			connsMu.Unlock()
			log.Warn().Msgf("refusing a new QUIC connection: the %d-connection limit is reached", maxConnections)
			qconn.CloseWithError(quic.ApplicationErrorCode(0), "too many connections")
			continue
		}
		activeConns[qconn] = struct{}{}
		connsMu.Unlock()
		conns.Add(1)
		go func() {
			defer util.PanicGuard("cmd/ssh3-server.go:1356")()
			defer conns.Done()
			defer func() {
				connsMu.Lock()
				delete(activeConns, qconn)
				connsMu.Unlock()
			}()
			hconn, err := server.NewRawServerConn(qconn)
			if err != nil {
				log.Error().Msgf("could not create the HTTP/3 connection: %s", err)
				qconn.CloseWithError(quic.ApplicationErrorCode(0), "internal error")
				return
			}
			if err := ssh3Server.ServeQUICConn(context.Background(), qconn, hconn); err != nil {
				log.Debug().Msgf("QUIC connection closed: %s", err)
			}
		}()
	}
	listener.Close()

	drain := shutdownDrainPeriod()
	if drain > 0 {
		log.Info().Msgf("shutdown: draining active connections up to %s", drain)
		drained := make(chan struct{})
		go func() {
			defer util.PanicGuard("cmd/ssh3-server.go:1380")()
			conns.Wait()
			close(drained)
		}()
		select {
		case <-drained:
			log.Info().Msgf("shutdown: all connections finished")
		case <-time.After(drain):
			connsMu.Lock()
			remaining := len(activeConns)
			for qc := range activeConns {
				qc.CloseWithError(quic.ApplicationErrorCode(0), "server shutdown")
			}
			connsMu.Unlock()
			log.Info().Msgf("shutdown: drain timeout, closing %d remaining connections", remaining)
		}
	}
	log.Info().Msgf("shutdown complete")
	return 0
}

// shutdownDrainPeriod returns the graceful-shutdown drain window: how long
// the server waits for active connections after a shutdown signal before
// closing them. Configured by SSH3_SHUTDOWN_DRAIN in seconds; the default
// is 5, a negative or unparsable value falls back to the default.
func shutdownDrainPeriod() time.Duration {
	if v := os.Getenv("SSH3_SHUTDOWN_DRAIN"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil {
			if secs >= 0 {
				return time.Duration(secs) * time.Second
			}
		}
		log.Warn().Msgf("invalid SSH3_SHUTDOWN_DRAIN %q, using the default", v)
	}
	return 5 * time.Second
}
