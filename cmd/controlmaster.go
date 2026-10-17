package cmd

// ControlMaster CLI plumbing (stage 3.5, increment 6): flag semantics and
// the slave-side console handling. The master itself is a detached re-exec
// of this binary (SSH3_CM_DAEMON=1) that serves the control socket and
// never runs sessions; invoking clients act as slaves through it.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/term"

	"github.com/francoismichel/ssh3/client"
	"github.com/francoismichel/ssh3/client/winsize"
)

// cmDaemonEnv marks a re-executed process as the detached control master.
const cmDaemonEnv = "SSH3_CM_DAEMON"

// controlOpTimeout bounds one `-O <op>` operation. check returns as soon as
// the master answers; stop additionally waits for the socket to be released,
// so the deadline also caps that wait instead of hanging on a stuck master.
const controlOpTimeout = 5 * time.Second

// runControlOp executes one `ssh -O <op>` operation against the master
// listening on controlPath and returns the process exit status: 0 on success,
// -1 (process exit code 255) on any failure, with the reason logged. A check
// also prints the master status line on stdout, so scripts can read the pid.
func runControlOp(ctx context.Context, controlPath, op string) int {
	opCtx, cancel := context.WithTimeout(ctx, controlOpTimeout)
	defer cancel()
	status, err := client.RunControlOp(opCtx, controlPath, op)
	if err != nil {
		log.Error().Msgf("control operation %q failed: %s", op, err)
		return -1
	}
	if op == client.ControlOpCheck {
		fmt.Fprintln(os.Stdout, status.String())
	}
	return 0
}

// parseControlPersistStrict maps a ControlPersist value ("", no, yes or a
// number of seconds) to (idle timeout, persist?): "no" gives (0, false)
// meaning no master at all, "yes" gives (0, true) meaning persist forever.
// An invalid token is an error, unlike parseControlPersist which degrades to
// "no" with a warning.
func parseControlPersistStrict(value string) (time.Duration, bool, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "", "no":
		return 0, false, nil
	case "yes":
		return 0, true, nil
	}
	secs, err := strconv.Atoi(normalized)
	if err != nil || secs < 0 {
		return 0, false, fmt.Errorf("invalid ControlPersist value %q: want no, yes or a number of seconds", value)
	}
	return time.Duration(secs) * time.Second, true, nil
}

// parseControlPersist maps -control-persist to an idle timeout: "no" gives
// (0, false) meaning no master at all, "yes" gives (0, true) meaning
// persist forever, a number of seconds gives that idle timeout.
func parseControlPersist(value string) (time.Duration, bool) {
	persist, ok, err := parseControlPersistStrict(value)
	if err != nil {
		log.Warn().Msgf("invalid -control-persist %q, treating as no", value)
		return 0, false
	}
	return persist, ok
}

// startDetachedMaster re-executes this binary detached, with the daemon env
// marker; the child connects and serves the control socket.
func startDetachedMaster() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, os.Args[1:]...)
	cmd.Env = append(os.Environ(), cmDaemonEnv+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	cmd.SysProcAttr = daemonSysProcAttr()
	return cmd.Start()
}

// runSlaveCommand runs one session through the control master with the
// process stdio. Interactive sessions request a pty through the master and
// set the local console raw; window changes and out-of-band signals are
// relayed to the master as control frames (raw-mode input bytes reach the
// remote pty through the io stream).
func runSlaveCommand(ctx context.Context, controlPath string, command []string, tty *os.File) int {
	spec := client.SessionSpec{Command: command}
	if len(command) == 0 && tty != nil && term.IsTerminal(int(tty.Fd())) {
		windowSize, err := winsize.GetWinsize(tty)
		hasWinSize := err == nil
		if !hasWinSize {
			log.Warn().Msgf("could not get window size: %+v, using 80x24", err)
			windowSize.NCols, windowSize.NRows = 80, 24
		}
		// a control-master slave has no -o Term context of its own: the
		// local environment applies, then the built-in default
		termType := resolveTermType("", "")
		spec.Pty = &client.PtySpec{
			Term:        termType,
			Columns:     uint64(windowSize.NCols),
			Rows:        uint64(windowSize.NRows),
			PixelWidth:  uint64(windowSize.PixelWidth),
			PixelHeight: uint64(windowSize.PixelHeight),
		}
		fd := os.Stdin.Fd()
		oldState, err := term.MakeRaw(int(fd))
		if err != nil {
			log.Warn().Msgf("cannot make tty raw: %s", err)
		} else {
			defer term.Restore(int(fd), oldState)
		}
		defer fmt.Printf("\r")
	}
	code, err := client.RunSlaveSession(ctx, controlPath, spec, os.Stdin, os.Stdout, os.Stderr, tty)
	if err != nil {
		log.Error().Msgf("control-master session: %s", err)
		return -1
	}
	return code
}

// waitForMaster polls the control socket until a master answers or the
// deadline passes. The socket file appears when the master binds (net.Listen
// creates it atomically), so attempts before that fail fast with ENOENT or
// ECONNREFUSED; a 2ms poll keeps the slave startup at the millisecond scale
// while each retry stays one cheap failed dial between sleeps (no busy-spin).
func waitForMaster(ctx context.Context, controlPath string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for !client.PingMaster(ctx, controlPath) {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
	return true
}
