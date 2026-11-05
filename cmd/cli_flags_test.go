package cmd

import (
	"path"
	"strings"
	"testing"

	ssh3 "github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/client"
)

// -D accepts [bind_address:]port, like OpenSSH: an omitted address binds the
// loopback interface only, "*" asks for every interface.
func TestParseDynamicForwardSpec(t *testing.T) {
	tests := []struct {
		spec        string
		wantAddress string
		wantPort    uint16
		wantErr     bool
	}{
		{spec: "1080", wantAddress: "", wantPort: 1080},
		{spec: "0", wantAddress: "", wantPort: 0},
		{spec: "127.0.0.1:1080", wantAddress: "127.0.0.1", wantPort: 1080},
		{spec: "localhost:1080", wantAddress: "localhost", wantPort: 1080},
		{spec: "[::1]:1080", wantAddress: "::1", wantPort: 1080},
		{spec: "*:1080", wantAddress: "*", wantPort: 1080},
		{spec: "127.0.0.1:65535", wantAddress: "127.0.0.1", wantPort: 65535},
		{spec: "", wantErr: true},
		{spec: "   ", wantErr: true},
		{spec: "ssh", wantErr: true},
		{spec: "-1", wantErr: true},
		{spec: "70000", wantErr: true},
		{spec: "127.0.0.1:70000", wantErr: true},
		{spec: "127.0.0.1:1080:extra", wantErr: true},
		{spec: "::1:1080", wantErr: true},
	}
	for _, test := range tests {
		spec, err := parseDynamicForwardSpec(test.spec)
		if test.wantErr {
			if err == nil {
				t.Errorf("parseDynamicForwardSpec(%q) = %+v, want an error", test.spec, spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDynamicForwardSpec(%q) returned error: %s", test.spec, err)
			continue
		}
		if spec.BindAddress != test.wantAddress || spec.BindPort != test.wantPort {
			t.Errorf("parseDynamicForwardSpec(%q) = %+v, want {%q %d}",
				test.spec, spec, test.wantAddress, test.wantPort)
		}
	}
}

// The loopback default and the wildcard must resolve to distinct bind
// addresses, otherwise -D 1080 would unexpectedly listen on every interface.
func TestDynamicForwardSpecListenAddress(t *testing.T) {
	loopback, err := parseDynamicForwardSpec("1080")
	if err != nil {
		t.Fatalf("parseDynamicForwardSpec(1080) returned error: %s", err)
	}
	if got := loopback.ListenAddress(); got != "127.0.0.1" {
		t.Errorf("default listen address = %q, want 127.0.0.1", got)
	}
	wildcard, err := parseDynamicForwardSpec("*:1080")
	if err != nil {
		t.Fatalf("parseDynamicForwardSpec(*:1080) returned error: %s", err)
	}
	if got := wildcard.ListenAddress(); got != "" {
		t.Errorf("wildcard listen address = %q, want the empty address (every interface)", got)
	}
}

// -s takes a subsystem name; an empty or malformed one must be refused before
// any connection is attempted.
func TestParseSubsystemName(t *testing.T) {
	valid := []string{"sftp", "netconf", "sftp-server", "a"}
	for _, name := range valid {
		parsed, err := parseSubsystemName(name)
		if err != nil {
			t.Errorf("parseSubsystemName(%q) returned error: %s", name, err)
			continue
		}
		if parsed != name {
			t.Errorf("parseSubsystemName(%q) = %q", name, parsed)
		}
	}
	// a name is sent verbatim inside an SSH string field: no trimming, and
	// nothing that could be read as an option or split the field
	invalid := []string{"", "   ", "sf tp", "sftp\n", "sftp\x00", "-sftp", "a\tb", "  sftp"}
	for _, name := range invalid {
		if parsed, err := parseSubsystemName(name); err == nil {
			t.Errorf("parseSubsystemName(%q) = %q, want an error", name, parsed)
		}
	}
}

// -F replaces the default ~/.ssh/config path.
func TestResolveConfigPath(t *testing.T) {
	defaultPath := path.Join(homedir(), ".ssh", "config")
	if got := resolveConfigPath(""); got != defaultPath {
		t.Errorf("resolveConfigPath(\"\") = %q, want %q", got, defaultPath)
	}
	if got := resolveConfigPath("  "); got != defaultPath {
		t.Errorf("resolveConfigPath(blank) = %q, want %q", got, defaultPath)
	}
	custom := path.Join("tmp", "custom-config")
	if got := resolveConfigPath(custom); got != custom {
		t.Errorf("resolveConfigPath(%q) = %q, want %q", custom, got, custom)
	}
}

// -O only accepts the operations the control master implements, and the error
// must name them so the mistake is obvious.
func TestValidateControlOperation(t *testing.T) {
	for _, op := range []string{client.ControlOpCheck, client.ControlOpStop, client.ControlOpExit} {
		if err := validateControlOperation(op); err != nil {
			t.Errorf("validateControlOperation(%q) returned error: %s", op, err)
		}
	}
	for _, op := range []string{"", "restart", "CHECK", "stop "} {
		err := validateControlOperation(op)
		if err == nil {
			t.Errorf("validateControlOperation(%q) = nil, want an error", op)
			continue
		}
		for _, expected := range []string{client.ControlOpCheck, client.ControlOpStop, client.ControlOpExit} {
			if !strings.Contains(err.Error(), expected) {
				t.Errorf("validateControlOperation(%q) error %q does not mention %q", op, err, expected)
			}
		}
	}
}

// VerifyHostKeyDNS follows OpenSSH, including its "yes:algorithm" form.
func TestParseVerifyHostKeyDNSValue(t *testing.T) {
	tests := []struct {
		value   string
		want    ssh3.VerifyHostKeyDNS
		wantErr bool
	}{
		{value: "", want: ssh3.VerifyHostKeyDNSNo},
		{value: "no", want: ssh3.VerifyHostKeyDNSNo},
		{value: "off", want: ssh3.VerifyHostKeyDNSNo},
		{value: "ask", want: ssh3.VerifyHostKeyDNSAsk},
		{value: "yes", want: ssh3.VerifyHostKeyDNSYes},
		{value: "YES", want: ssh3.VerifyHostKeyDNSYes},
		{value: "on", want: ssh3.VerifyHostKeyDNSYes},
		{value: " yes ", want: ssh3.VerifyHostKeyDNSYes},
		{value: "yes:sha256", want: ssh3.VerifyHostKeyDNSYes},
		{value: "yes:rsa,ecdsa", want: ssh3.VerifyHostKeyDNSYes},
		{value: "yes:ssh-ed25519", want: ssh3.VerifyHostKeyDNSYes},
		{value: "ask:sha1", want: ssh3.VerifyHostKeyDNSAsk},
		{value: "maybe", wantErr: true},
		{value: "yes:", wantErr: true},
		{value: "yes:bogus", wantErr: true},
		{value: "no:sha256", want: ssh3.VerifyHostKeyDNSNo},
	}
	for _, test := range tests {
		setting, err := parseVerifyHostKeyDNSValue(test.value)
		if test.wantErr {
			if err == nil {
				t.Errorf("parseVerifyHostKeyDNSValue(%q) = %+v, want an error", test.value, setting)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseVerifyHostKeyDNSValue(%q) returned error: %s", test.value, err)
			continue
		}
		if setting.Mode != test.want {
			t.Errorf("parseVerifyHostKeyDNSValue(%q) = %q, want %q", test.value, setting.Mode, test.want)
		}
	}
}

// The algorithm restriction of "yes:algo" decides whether the SSHFP lookup
// applies to a host key at all: a key type outside the list has no usable
// record, exactly like OpenSSH skipping the lookup.
func TestVerifyHostKeyDNSAllowsAlgorithm(t *testing.T) {
	rsaKey := ssh3.SSHFPAlgorithmRSA
	ed25519Key := ssh3.SSHFPAlgorithmEd25519

	disabled, err := parseVerifyHostKeyDNSValue("no")
	if err != nil {
		t.Fatalf("parseVerifyHostKeyDNSValue(no) returned error: %s", err)
	}
	if !disabled.AllowsAlgorithm(nil) {
		t.Error("a disabled verification must never restrict an algorithm")
	}

	any, err := parseVerifyHostKeyDNSValue("yes")
	if err != nil {
		t.Fatalf("parseVerifyHostKeyDNSValue(yes) returned error: %s", err)
	}
	if !any.AllowsAlgorithm(&rsaKey) || !any.AllowsAlgorithm(&ed25519Key) {
		t.Error("yes without an algorithm list must allow every key")
	}

	rsaOnly, err := parseVerifyHostKeyDNSValue("yes:rsa")
	if err != nil {
		t.Fatalf("parseVerifyHostKeyDNSValue(yes:rsa) returned error: %s", err)
	}
	if !rsaOnly.AllowsAlgorithm(&rsaKey) {
		t.Error("yes:rsa must allow an rsa host key")
	}
	if rsaOnly.AllowsAlgorithm(&ed25519Key) {
		t.Error("yes:rsa must refuse an ed25519 host key")
	}
}

// --password user:pass: the split rides the first colon (the password may
// contain colons), both halves are mandatory and the case stays untouched.
func TestParsePasswordCredentials(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		wantUser    string
		wantPass    string
		wantErr     bool
		errContains string
	}{
		{name: "plain", value: "user:pass", wantUser: "user", wantPass: "pass"},
		{name: "password with colons", value: "user:pa:ss:word", wantUser: "user", wantPass: "pa:ss:word"},
		{name: "case rides untouched", value: "User:PaSS", wantUser: "User", wantPass: "PaSS"},
		{name: "empty user", value: ":pass", wantErr: true, errContains: "user"},
		{name: "empty password", value: "user:", wantErr: true, errContains: "password"},
		{name: "no colon", value: "userpass", wantErr: true, errContains: "user:pass"},
		{name: "empty value", value: "", wantErr: true, errContains: "user:pass"},
		{name: "only a colon", value: ":", wantErr: true, errContains: "user"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, pass, err := parsePasswordCredentials(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parsePasswordCredentials(%q) accepted the value", tt.value)
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("refusal %q does not mention %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePasswordCredentials(%q) returned error: %s", tt.value, err)
			}
			if user != tt.wantUser || pass != tt.wantPass {
				t.Fatalf("parsePasswordCredentials(%q) = (%q, %q), want (%q, %q)", tt.value, user, pass, tt.wantUser, tt.wantPass)
			}
		})
	}
}

// --password stays alone: every competing authentication source refuses with
// the name of the conflicting flag, an empty set rides.
func TestPasswordConflictsFirst(t *testing.T) {
	if got := (passwordConflicts{}).first(); got != "" {
		t.Fatalf("no conflicting flag reported %q, want an empty ride", got)
	}
	tests := []struct {
		name      string
		conflicts passwordConflicts
		want      string
	}{
		{"identity file", passwordConflicts{IdentityFile: true}, "-i"},
		{"agent key", passwordConflicts{PubkeyForAgent: true}, "-pubkey-for-agent"},
		{"interactive prompt", passwordConflicts{UsePassword: true}, "-use-password"},
		{"oidc issuer", passwordConflicts{OIDCIssuer: true}, "-use-oidc"},
		{"oidc config", passwordConflicts{OIDCConfig: true}, "-oidc-config"},
		{"first wins", passwordConflicts{UsePassword: true, OIDCIssuer: true}, "-use-password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.conflicts.first(); got != tt.want {
				t.Fatalf("first() = %q, want %q", got, tt.want)
			}
		})
	}
}
