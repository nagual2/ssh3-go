package cmd

// The ssh2 `-f` background mode (ssh(1): go to background just before
// command execution). The Go runtime cannot fork an established connection,
// so the parent re-execs a detached child (the ControlMaster daemon
// mechanics) that runs the full startup itself; the child cannot prompt,
// so the parent refuses every configuration that would need an interactive
// answer instead of letting the session die silently in the background.

import (
	"fmt"
	"runtime"

	ssh3 "github.com/francoismichel/ssh3"
)

// backgroundEnv marks a re-executed process as the `-f` background child:
// it skips the detach step and runs the session straight away.
const backgroundEnv = "SSH3_F_DAEMON"

// backgroundOptions carries the facts the parent needs to judge whether the
// detached child can come up without a terminal: what keeps running, which
// authentication methods were asked for, the resolved host key policy and
// whether the host is already pinned.
type backgroundOptions struct {
	PasswordAuth  bool   // -use-password: a tty prompt the child cannot serve
	OIDC          bool   // the OIDC flow opens a browser
	ControlMaster string // "no" or yes/auto: the master backgrounds itself already
	Strict        ssh3.StrictHostKeyChecking
	HostPinned    bool // the target is in known_hosts
	HasCommand    bool // a remote command was given
	NoSession     bool // -N
	HasForwards   bool // -L/-D/-R/-transfer: anything long-lived
}

// validateBackgroundMode returns the reason the detached child cannot come
// up on its own, or nil when `-f` may detach.
func validateBackgroundMode(o backgroundOptions) error {
	if !o.HasCommand && !o.NoSession && !o.HasForwards {
		return fmt.Errorf("-f: nothing to keep running in the background: give a remote command, -N or a forward (-L/-D/-R/-transfer)")
	}
	if o.PasswordAuth {
		return fmt.Errorf("-f: password authentication needs a prompt and cannot run in the background: use a key or the agent")
	}
	if o.OIDC {
		return fmt.Errorf("-f: the OIDC flow opens a browser and cannot run in the background")
	}
	if o.ControlMaster != "" && o.ControlMaster != "no" {
		return fmt.Errorf("-f: the control master already goes to the background with -control-persist: drop -f")
	}
	if o.Strict == ssh3.StrictHostKeyCheckingAsk && !o.HostPinned {
		return fmt.Errorf("-f: the default ask policy cannot prompt in the background and the host is not pinned yet: pin it (run once without -f) or pass -o StrictHostKeyChecking=accept-new")
	}
	return nil
}

// backgroundSupportedOnOS reports whether the platform can detach a child at
// all: unix gets setsid, Windows has no session detach yet (the control
// master takes the same stance).
func backgroundSupportedOnOS() bool {
	return runtime.GOOS != "windows"
}
