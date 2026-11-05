package cmd

// Tests for the ssh2-shaped (ssh(1)/sshd(8) canon) option parsers added by
// the CLI-parity wave (CTO_TASK §7c). The parsers are pure functions: every
// malformed option must be rejected before a connection is attempted.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/francoismichel/ssh3/util"
)

func TestParseLocalForwardSpecSSH2Shapes(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want localForwardSpec
	}{
		{name: "plain", spec: "2222:host.example:22",
			want: localForwardSpec{BindPort: 2222, TargetHost: "host.example", TargetPort: 22, Protocol: util.SSHForwardingProtocolTCP}},
		{name: "bind", spec: "127.0.0.1:2222:host.example:22",
			want: localForwardSpec{BindAddress: "127.0.0.1", BindPort: 2222, TargetHost: "host.example", TargetPort: 22, Protocol: util.SSHForwardingProtocolTCP}},
		{name: "ipv6 brackets", spec: "[::1]:2222:[::1]:22",
			want: localForwardSpec{BindAddress: "::1", BindPort: 2222, TargetHost: "::1", TargetPort: 22, Protocol: util.SSHForwardingProtocolTCP}},
		{name: "wildcard bind", spec: "*:2222:host.example:22",
			want: localForwardSpec{BindAddress: "*", BindPort: 2222, TargetHost: "host.example", TargetPort: 22, Protocol: util.SSHForwardingProtocolTCP}},
		{name: "ephemeral bind port", spec: "0:host.example:22",
			want: localForwardSpec{BindPort: 0, TargetHost: "host.example", TargetPort: 22, Protocol: util.SSHForwardingProtocolTCP}},
		{name: "udp extension", spec: "udp://5353:192.0.2.1:53",
			want: localForwardSpec{BindPort: 5353, TargetHost: "192.0.2.1", TargetPort: 53, Protocol: util.SSHProtocolUDP}},
		{name: "udp extension with bind", spec: "udp://127.0.0.1:5353:192.0.2.1:53",
			want: localForwardSpec{BindAddress: "127.0.0.1", BindPort: 5353, TargetHost: "192.0.2.1", TargetPort: 53, Protocol: util.SSHProtocolUDP}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLocalForwardSpec(tt.spec)
			if err != nil {
				t.Fatalf("parseLocalForwardSpec(%q) returned error: %s", tt.spec, err)
			}
			if got != tt.want {
				t.Fatalf("parseLocalForwardSpec(%q) = %+v, want %+v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestParseLocalForwardSpecRejects(t *testing.T) {
	specs := []string{
		"",                           // empty
		"host:22",                    // two parts, no local port
		"2222:host",                  // two parts, no target port
		"2222:",                      // empty target host
		"2222:host.example:0",        // target port 0
		"2222:host.example:abc",      // target port not a number
		"2222:host.example:22:extra", // five parts
		"::1:2222:host:22",           // unbracketed IPv6 bind
		"https://2222:host:22",       // unknown scheme
		"udp://2222:host:abc",        // udp prefix, bad target port
		"127.0.0.1 2222:host:22",     // whitespace in bind
	}
	for _, spec := range specs {
		if _, err := parseLocalForwardSpec(spec); err == nil {
			t.Fatalf("parseLocalForwardSpec(%q) accepted an invalid specification", spec)
		}
	}
}

func TestLocalForwardFlagsRepeatable(t *testing.T) {
	var flags localForwardFlags
	for _, spec := range []string{"2222:a.example:22", "udp://5353:192.0.2.1:53", "127.0.0.1:8080:b.example:80"} {
		if err := flags.Set(spec); err != nil {
			t.Fatalf("Set(%q) returned error: %s", spec, err)
		}
	}
	if len(flags) != 3 {
		t.Fatalf("expected 3 accumulated forwards, got %d", len(flags))
	}
	if flags[2].BindAddress != "127.0.0.1" || flags[2].BindPort != 8080 {
		t.Fatalf("third forward = %+v, want the 127.0.0.1:8080 one", flags[2])
	}
}

// -R already uses the ssh(1) shape for TCP ([bind:]port:host:port); verify it
// accepts the plain ssh2 form without any ssh3-specific marker.
func TestReverseForwardAcceptsSSH2Shape(t *testing.T) {
	forward, err := parseReverseForwardSpec("2222:localhost:22")
	if err != nil {
		t.Fatalf("parseReverseForwardSpec(\"2222:localhost:22\") returned error: %s", err)
	}
	if forward.BindHost != "" || forward.BindPort != 2222 || forward.TargetHost != "localhost" || forward.TargetPort != 22 {
		t.Fatalf("parsed -R = %+v, want the ssh2-shaped 2222:localhost:22", forward)
	}
	if forward.Protocol != util.SSHForwardingProtocolTCP {
		t.Fatalf("parsed -R protocol = %d, want TCP", forward.Protocol)
	}
}

func TestParseProxyJumpChain(t *testing.T) {
	hops, err := parseProxyJumpChain("user@j1.example:2222,user@j2.example")
	if err != nil {
		t.Fatalf("parseProxyJumpChain returned error: %s", err)
	}
	if len(hops) != 2 || hops[0] != "user@j1.example:2222" || hops[1] != "user@j2.example" {
		t.Fatalf("hops = %v, want the two -J destinations", hops)
	}
	single, err := parseProxyJumpChain("j1.example")
	if err != nil || len(single) != 1 || single[0] != "j1.example" {
		t.Fatalf("single hop = %v, err = %v, want one bare host", single, err)
	}
}

func TestParseProxyJumpChainRejects(t *testing.T) {
	specs := []string{
		"",           // empty
		",",          // empty hops
		"j1,,j2",     // empty middle hop
		"j1, ,j2",    // whitespace-only hop
		"j1 example", // whitespace inside a hop
	}
	for _, spec := range specs {
		if _, err := parseProxyJumpChain(spec); err == nil {
			t.Fatalf("parseProxyJumpChain(%q) accepted an invalid chain", spec)
		}
	}
}

func TestParseControlMasterPolicy(t *testing.T) {
	for value, want := range map[string]string{"no": "no", "yes": "yes", "auto": "auto", " YES ": "yes"} {
		got, err := parseControlMasterPolicy(value)
		if err != nil || got != want {
			t.Fatalf("parseControlMasterPolicy(%q) = %q, %v; want %q, nil", value, got, err, want)
		}
	}
	if _, err := parseControlMasterPolicy("maybe"); err == nil {
		t.Fatal("parseControlMasterPolicy accepted an unknown policy")
	}
}

func TestParsePortKeyword(t *testing.T) {
	if port, err := parsePortKeyword(" 2222 "); err != nil || port != 2222 {
		t.Fatalf("parsePortKeyword(\" 2222 \") = %d, %v; want 2222, nil", port, err)
	}
	for _, value := range []string{"", "0", "-1", "65536", "abc"} {
		if _, err := parsePortKeyword(value); err == nil {
			t.Fatalf("parsePortKeyword(%q) accepted an invalid port", value)
		}
	}
}

func TestMergeBindPort(t *testing.T) {
	tests := []struct {
		bind string
		port uint16
		want string
	}{
		{bind: "[::]:443", port: 8443, want: "[::]:8443"},
		{bind: "0.0.0.0:443", port: 8443, want: "0.0.0.0:8443"},
		{bind: "example.lan:443", port: 8443, want: "example.lan:8443"},
		{bind: "[::1]", port: 443, want: "[::1]:443"},
		{bind: "localhost", port: 443, want: "localhost:443"},
	}
	for _, tt := range tests {
		got, err := mergeBindPort(tt.bind, tt.port)
		if err != nil {
			t.Fatalf("mergeBindPort(%q, %d) returned error: %s", tt.bind, tt.port, err)
		}
		if got != tt.want {
			t.Fatalf("mergeBindPort(%q, %d) = %q, want %q", tt.bind, tt.port, got, tt.want)
		}
	}
}

func TestMergeBindPortRejects(t *testing.T) {
	if _, err := mergeBindPort("[::]:443", 0); err == nil {
		t.Fatal("mergeBindPort accepted port 0")
	}
	// a bare unbracketed IPv6 literal is ambiguous: refuse instead of guessing
	if _, err := mergeBindPort("::1:443", 8443); err == nil {
		t.Fatal("mergeBindPort accepted an unbracketed IPv6 -bind address")
	}
	if _, err := mergeBindPort("[::1]junk", 8443); err == nil {
		t.Fatal("mergeBindPort accepted junk after the bracketed host")
	}
}

func TestResolveServerCertKeyAliases(t *testing.T) {
	cert, key, err := resolveServerCertKeyAliases(true, false, false, true, "./cert.pem", "./priv.key", "", "./host.key")
	if err != nil {
		t.Fatalf("aliases returned error: %s", err)
	}
	if cert != "./cert.pem" || key != "./host.key" {
		t.Fatalf("cert = %q key = %q, want -key left at its default and -h in place", cert, key)
	}
	if _, _, err := resolveServerCertKeyAliases(true, true, true, true, "./cert.pem", "./priv.key", "./c.pem", "./h.key"); err == nil {
		t.Fatal("aliases accepted -cert together with -c")
	}
	if _, _, err := resolveServerCertKeyAliases(true, true, false, true, "./cert.pem", "./priv.key", "", "./h.key"); err == nil {
		t.Fatal("aliases accepted -key together with -h")
	}
}

func TestParseConnectTimeoutKeywordAccepts(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  int
	}{
		{name: "default scale", value: "30", want: 30},
		{name: "deadline removed", value: "0", want: 0},
		{name: "surrounding blanks", value: " 60 ", want: 60},
		{name: "the day cap", value: "86400", want: 86400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseConnectTimeoutKeyword(tt.value)
			if err != nil {
				t.Fatalf("parseConnectTimeoutKeyword(%q) returned error: %s", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("parseConnectTimeoutKeyword(%q) = %d, want %d", tt.value, got, tt.want)
			}
		})
	}
}

func TestParseConnectTimeoutKeywordRejects(t *testing.T) {
	specs := []string{
		"",       // empty
		"abc",    // not a number
		"1.5",    // fractional seconds
		"30s",    // a suffixed duration (the keyword takes bare seconds)
		"-1",     // negative
		"86401",  // one second past the cap
		"999999", // far past the cap
	}
	for _, spec := range specs {
		_, err := parseConnectTimeoutKeyword(spec)
		if err == nil {
			t.Fatalf("parseConnectTimeoutKeyword(%q) accepted an invalid value", spec)
		}
		// the refusal must name the keyword, like every other -o rejection
		if !strings.Contains(err.Error(), "ConnectTimeout") {
			t.Fatalf("parseConnectTimeoutKeyword(%q) error does not name the keyword: %s", spec, err)
		}
	}
}

func TestResolveConnectTimeoutPrecedence(t *testing.T) {
	tests := []struct {
		name        string
		optionSet   bool
		optionValue int
		configValue string
		want        int
	}{
		{name: "the 30 s default when nothing is set", optionSet: false, optionValue: 0, configValue: "", want: 30},
		{name: "-o wins over the config keyword", optionSet: true, optionValue: 5, configValue: "60", want: 5},
		{name: "-o 0 removes the deadline despite the config", optionSet: true, optionValue: 0, configValue: "60", want: 0},
		{name: "the config keyword fills what -o leaves empty", optionSet: false, optionValue: 0, configValue: "45", want: 45},
		{name: "the config keyword can remove the deadline too", optionSet: false, optionValue: 0, configValue: "0", want: 0},
		{name: "the config value may carry blanks", optionSet: false, optionValue: 0, configValue: " 45 ", want: 45},
		{name: "a blank config value falls back to the default", optionSet: false, optionValue: 0, configValue: "   ", want: 30},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveConnectTimeout(tt.optionSet, tt.optionValue, tt.configValue)
			if err != nil {
				t.Fatalf("resolveConnectTimeout(%v, %d, %q) returned error: %s", tt.optionSet, tt.optionValue, tt.configValue, err)
			}
			if got != tt.want {
				t.Fatalf("resolveConnectTimeout(%v, %d, %q) = %d, want %d", tt.optionSet, tt.optionValue, tt.configValue, got, tt.want)
			}
		})
	}
}

func TestResolveConnectTimeoutRejectsBadConfig(t *testing.T) {
	// a malformed ~/.ssh/config value aborts like a malformed -o value
	_, err := resolveConnectTimeout(false, 0, "later")
	if err == nil {
		t.Fatal("resolveConnectTimeout accepted a non-numeric config value")
	}
	if !strings.Contains(err.Error(), "ConnectTimeout") {
		t.Fatalf("the error does not name the keyword: %s", err)
	}
	// an explicit -o 0 means "no deadline", never a config fallback
	got, err := resolveConnectTimeout(true, 0, "")
	if err != nil || got != 0 {
		t.Fatalf("resolveConnectTimeout(true, 0, %q) = %d, %v; want 0, nil", "", got, err)
	}
}

func TestReportSetupTimeoutVerdict(t *testing.T) {
	live, liveCancel := context.WithTimeout(context.Background(), time.Minute)
	defer liveCancel()
	if reportSetupTimeout(live, 30) {
		t.Fatal("reportSetupTimeout fired on a live deadline")
	}
	expired, expiredCancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer expiredCancel()
	<-expired.Done()
	if !reportSetupTimeout(expired, 30) {
		t.Fatal("reportSetupTimeout missed an expired deadline")
	}
	// seconds == 0 means the deadline was never armed: no verdict can fire
	if reportSetupTimeout(expired, 0) {
		t.Fatal("reportSetupTimeout fired for an unarmed deadline")
	}
	// a cancellation is not the ConnectTimeout verdict
	canceled, canceledCancel := context.WithCancel(context.Background())
	canceledCancel()
	<-canceled.Done()
	if reportSetupTimeout(canceled, 30) {
		t.Fatal("reportSetupTimeout fired on a plain cancellation")
	}
}
