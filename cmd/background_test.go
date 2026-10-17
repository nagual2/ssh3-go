package cmd

import (
	"runtime"
	"strings"
	"testing"

	ssh3 "github.com/francoismichel/ssh3"
)

// The detached `-f` child cannot prompt: every configuration that would need
// an interactive answer must be refused by the parent instead of dying
// silently in the background.
func TestValidateBackgroundMode(t *testing.T) {
	usable := backgroundOptions{
		Strict:     ssh3.StrictHostKeyCheckingAcceptNew,
		HasCommand: true,
	}
	if err := validateBackgroundMode(usable); err != nil {
		t.Fatalf("a key-authenticated background command was refused: %s", err)
	}

	tests := []struct {
		name    string
		mutate  func(*backgroundOptions)
		contain string
	}{
		{"password", func(o *backgroundOptions) { o.PasswordAuth = true }, "password"},
		{"oidc", func(o *backgroundOptions) { o.OIDC = true }, "OIDC"},
		{"master", func(o *backgroundOptions) { o.ControlMaster = "yes" }, "control master"},
		{"ask unpinned", func(o *backgroundOptions) { o.Strict = ssh3.StrictHostKeyCheckingAsk; o.HostPinned = false }, "ask"},
		{"nothing to run", func(o *backgroundOptions) { o.HasCommand = false }, "nothing to keep running"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := usable
			tt.mutate(&o)
			err := validateBackgroundMode(o)
			if err == nil {
				t.Fatalf("%s was accepted, want a refusal", tt.name)
			}
			if !strings.Contains(err.Error(), tt.contain) {
				t.Fatalf("refusal %q does not mention %q", err.Error(), tt.contain)
			}
		})
	}
}

func TestValidateBackgroundModeAccepts(t *testing.T) {
	tests := []struct {
		name string
		o    backgroundOptions
	}{
		{"forward-only no-session", backgroundOptions{
			Strict:      ssh3.StrictHostKeyCheckingNo,
			NoSession:   true,
			HasForwards: true,
		}},
		{"pinned host under ask", backgroundOptions{
			Strict:     ssh3.StrictHostKeyCheckingAsk,
			HostPinned: true,
			HasCommand: true,
		}},
		{"transfer in background", backgroundOptions{
			Strict:      ssh3.StrictHostKeyCheckingAcceptNew,
			HasForwards: true, // -transfer counts as long-lived
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateBackgroundMode(tt.o); err != nil {
				t.Fatalf("%s was refused: %s", tt.name, err)
			}
		})
	}
}

func TestBackgroundSupportedOnOS(t *testing.T) {
	// unix detaches with setsid; Windows takes the CM stance (warn + run in
	// the foreground) inside the caller
	if runtime.GOOS != "windows" && !backgroundSupportedOnOS() {
		t.Fatal("unix must support background")
	}
	if runtime.GOOS == "windows" && backgroundSupportedOnOS() {
		t.Fatal("windows must not claim background support")
	}
}
