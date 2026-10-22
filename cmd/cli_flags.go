package cmd

// Parsing and validation of the command-line flags that ssh(1) accepts but
// ssh3 did not implement (-D, -t, -s, -F) plus the VerifyHostKeyDNS value of
// the repeatable -o option. Everything here is a pure function: the flags are
// parsed and rejected before a single packet is sent, so a typo costs a
// process start and nothing else.

import (
	"fmt"
	"net"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	ssh3 "github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/client"
	client_config "github.com/francoismichel/ssh3/client/config"
)

// optionParsersByKeyword maps the configuration keywords of the registered
// option parsers (the auth plugins) to the option name that serves them.
//
// The mapping has to be deterministic: the option parsers live in a map, so
// the iteration order changes from run to run. Two parsers claim the
// IdentityFile keyword - the privkey plugin (a private key file) and the
// agent plugin (a public key file) - and a random winner made -i and
// -o IdentityFile= work only half of the time. The ssh(1) canon settles it:
// IdentityFile names a private key file, so the privkey plugin owns the
// keyword; the agent plugin keeps its own -pubkey-for-agent flag. The option
// names are therefore visited in sorted order, which puts "privkey" first.
func optionParsersByKeyword(cliParsers map[client_config.OptionName]client_config.CLIOptionParser) map[string]client_config.OptionName {
	optionNames := make([]string, 0, len(cliParsers))
	for optionName := range cliParsers {
		optionNames = append(optionNames, string(optionName))
	}
	sort.Strings(optionNames)

	parsersByKeyword := make(map[string]client_config.OptionName, len(optionNames))
	for _, optionName := range optionNames {
		keyword := strings.ToLower(cliParsers[client_config.OptionName(optionName)].OptionConfigName())
		if _, dup := parsersByKeyword[keyword]; !dup {
			parsersByKeyword[keyword] = client_config.OptionName(optionName)
		}
	}
	return parsersByKeyword
}

// dynamicForwardSpec is a parsed -D value: the local SOCKS listener to open.
type dynamicForwardSpec struct {
	// BindAddress is the address to bind: "" means the OpenSSH default
	// (loopback only) and "*" means every interface.
	BindAddress string
	BindPort    uint16
}

// ListenAddress turns BindAddress into the address passed to net.Listen: the
// wildcard becomes the empty address and the empty address becomes loopback,
// so a -D without a bind address never exposes the proxy to the network.
func (s dynamicForwardSpec) ListenAddress() string {
	if s.BindAddress == "*" {
		return ""
	}
	if s.BindAddress == "" {
		return "127.0.0.1"
	}
	return s.BindAddress
}

// SpecString renders the forward back into its -D form, for log messages.
func (s dynamicForwardSpec) SpecString() string {
	address := s.BindAddress
	if address == "" {
		address = "127.0.0.1"
	}
	return net.JoinHostPort(address, strconv.Itoa(int(s.BindPort)))
}

// parseDynamicForwardSpec accepts the OpenSSH "-D [bind_address:]port" syntax.
// IPv6 literals must be bracketed, which splitOutsideBrackets enforces: a bare
// "::1:1080" is refused instead of being silently read as address "::" and
// port "1".
func parseDynamicForwardSpec(spec string) (dynamicForwardSpec, error) {
	value := strings.TrimSpace(spec)
	if value == "" {
		return dynamicForwardSpec{}, fmt.Errorf("empty -D specification (expected [bind_address:]port)")
	}

	bindAddress := ""
	portPart := value
	parts := splitOutsideBrackets(value, ':')
	switch len(parts) {
	case 1:
	case 2:
		bindAddress = unbracket(parts[0])
		portPart = parts[1]
	default:
		return dynamicForwardSpec{}, fmt.Errorf(
			"invalid -D specification %q (expected [bind_address:]port, IPv6 addresses must be bracketed)", spec)
	}
	if bindAddress == "*" {
		bindAddress = "*"
	} else if bindAddress != "" && strings.ContainsAny(bindAddress, " \t") {
		return dynamicForwardSpec{}, fmt.Errorf("invalid bind address %q in -D %q", bindAddress, spec)
	}

	port, err := parsePort(portPart)
	if err != nil {
		return dynamicForwardSpec{}, fmt.Errorf("invalid -D specification %q: %s", spec, err)
	}
	return dynamicForwardSpec{BindAddress: bindAddress, BindPort: port}, nil
}

// dynamicForwardFlags backs the repeatable -D flag and the -o DynamicForward
// keyword.
type dynamicForwardFlags []dynamicForwardSpec

func (f *dynamicForwardFlags) String() string {
	specs := make([]string, len(*f))
	for i, spec := range *f {
		specs[i] = spec.SpecString()
	}
	return strings.Join(specs, ",")
}

func (f *dynamicForwardFlags) Set(value string) error {
	spec, err := parseDynamicForwardSpec(value)
	if err != nil {
		return err
	}
	*f = append(*f, spec)
	return nil
}

// maxSubsystemNameLength is the length a subsystem name may not exceed: the
// value ends up in a single SSH string field, and OpenSSH refuses anything
// longer than the packet it can send.
const maxSubsystemNameLength = 255

// parseSubsystemName validates the -s value. The name is sent verbatim inside
// an SSH string field, so it is neither trimmed nor escaped: anything that is
// not a single plain token is refused, because silently normalizing it would
// request a subsystem whose name differs from what the user typed.
func parseSubsystemName(value string) (string, error) {
	name := value
	if name == "" {
		return "", fmt.Errorf("empty subsystem name (expected a name such as \"sftp\")")
	}
	if len(name) > maxSubsystemNameLength {
		return "", fmt.Errorf("subsystem name is too long (%d bytes, at most %d)", len(name), maxSubsystemNameLength)
	}
	if strings.HasPrefix(name, "-") {
		return "", fmt.Errorf("invalid subsystem name %q", value)
	}
	for _, r := range name {
		if r <= ' ' || r == 0x7f {
			return "", fmt.Errorf("invalid subsystem name %q (it must be a single token)", value)
		}
	}
	return name, nil
}

// resolveConfigPath returns the SSH configuration file to read: the -F value
// when given, ~/.ssh/config otherwise. The path is used verbatim, exactly
// like OpenSSH: it is not resolved against the home directory, so a relative
// -F path stays relative to the current directory.
func resolveConfigPath(flagValue string) string {
	if strings.TrimSpace(flagValue) != "" {
		return flagValue
	}
	return path.Join(homedir(), ".ssh", "config")
}

// validateControlOperation checks the -O value against the operations the
// control master implements. The error lists them, because "unknown operation
// foo" is the least helpful message a user can get from a wrapper around an
// existing binary.
func validateControlOperation(op string) error {
	switch op {
	case client.ControlOpCheck, client.ControlOpStop, client.ControlOpExit:
		return nil
	case "":
		return fmt.Errorf("no control operation given (expected %s, %s or %s)",
			client.ControlOpCheck, client.ControlOpStop, client.ControlOpExit)
	default:
		return fmt.Errorf("unsupported control operation %q (expected %s, %s or %s)",
			op, client.ControlOpCheck, client.ControlOpStop, client.ControlOpExit)
	}
}

// sshfpAlgorithmsByName maps the names OpenSSH accepts in the algorithm list of
// "VerifyHostKeyDNS yes:algorithm" to their SSHFP algorithm numbers (RFC 4255
// section 5). Both the short names and the full public-key algorithm names are
// accepted, because OpenSSH accepts both.
var sshfpAlgorithmsByName = map[string]uint8{
	"rsa":                    ssh3.SSHFPAlgorithmRSA,
	"ssh-rsa":                ssh3.SSHFPAlgorithmRSA,
	"dsa":                    ssh3.SSHFPAlgorithmDSA,
	"ssh-dss":                ssh3.SSHFPAlgorithmDSA,
	"ssh-dsa":                ssh3.SSHFPAlgorithmDSA,
	"ecdsa":                  ssh3.SSHFPAlgorithmECDSA,
	"ecdsa-sha2-nistp256":    ssh3.SSHFPAlgorithmECDSA,
	"ecdsa-sha2-nistp384":    ssh3.SSHFPAlgorithmECDSA,
	"ecdsa-sha2-nistp521":    ssh3.SSHFPAlgorithmECDSA,
	"ed25519":                ssh3.SSHFPAlgorithmEd25519,
	"ssh-ed25519":            ssh3.SSHFPAlgorithmEd25519,
	"sk-ecdsa-sha2-nistp256": ssh3.SSHFPAlgorithmECDSA,
}

// sshfpDigestsByName maps the digest names OpenSSH also accepts in the same
// algorithm list (readconf's parse_verify_host_key_dns falls back from
// sshkey_type_from_name to ssh_digest_from_name). A digest name can never match
// a host key's SSHFP algorithm number, so such an entry never restricts
// anything: it is accepted for compatibility, not because it filters.
var sshfpDigestsByName = map[string]uint8{
	"sha1":   ssh3.SSHFPDigestSHA1,
	"sha256": ssh3.SSHFPDigestSHA256,
}

// parseVerifyHostKeyDNSValue parses an OpenSSH VerifyHostKeyDNS value: yes, no,
// ask, optionally followed by ":algorithm[,algorithm...]". The base value is
// delegated to the library parser; only the algorithm suffix, which the library
// does not know about, is handled here.
func parseVerifyHostKeyDNSValue(value string) (verifyHostKeyDNSSetting, error) {
	setting := verifyHostKeyDNSSetting{Mode: ssh3.VerifyHostKeyDNSNo}
	base := strings.TrimSpace(value)

	if separator := strings.IndexByte(base, ':'); separator >= 0 {
		rawAlgorithms := base[separator+1:]
		base = strings.TrimSpace(base[:separator])
		if rawAlgorithms == "" {
			return setting, fmt.Errorf("invalid VerifyHostKeyDNS value: %q (no algorithm after \":\")", value)
		}
		for _, raw := range strings.Split(rawAlgorithms, ",") {
			name := strings.ToLower(strings.TrimSpace(raw))
			if name == "" {
				return setting, fmt.Errorf("invalid VerifyHostKeyDNS value: %q (empty algorithm name)", value)
			}
			if algorithm, ok := sshfpAlgorithmsByName[name]; ok {
				setting.Algorithms = append(setting.Algorithms, algorithm)
				continue
			}
			if digest, ok := sshfpDigestsByName[name]; ok {
				setting.Algorithms = append(setting.Algorithms, digest)
				continue
			}
			return setting, fmt.Errorf("invalid VerifyHostKeyDNS value: %q (unknown algorithm %q)", value, name)
		}
	}

	mode, err := ssh3.ParseVerifyHostKeyDNS(base)
	if err != nil {
		return setting, err
	}
	setting.Mode = mode
	return setting, nil
}

// verifyHostKeyDNSSetting is a parsed VerifyHostKeyDNS value: when the SSHFP
// check runs (Mode) and which host key algorithms it covers (Algorithms, empty
// meaning "every algorithm").
type verifyHostKeyDNSSetting struct {
	Mode       ssh3.VerifyHostKeyDNS
	Algorithms []uint8
}

// AllowsAlgorithm reports whether an SSHFP lookup has to be performed for a
// host key signed with the given algorithm. A nil algorithm (no host key)
// means "no reason to skip", and a disabled verification never restricts
// anything.
func (s verifyHostKeyDNSSetting) AllowsAlgorithm(algorithm *uint8) bool {
	if s.Mode == ssh3.VerifyHostKeyDNSNo {
		return true
	}
	if algorithm == nil || len(s.Algorithms) == 0 {
		return true
	}
	for _, allowed := range s.Algorithms {
		if allowed == *algorithm {
			return true
		}
	}
	return false
}

// parseRequestTTY validates the RequestTTY policy (-o RequestTTY=... and the
// ~/.ssh/config keyword) and returns its canonical lower-case form: auto
// (the default), no, yes or force, with the OpenSSH ssh_config semantics.
func parseRequestTTY(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "auto":
		return "auto", nil
	case "no":
		return "no", nil
	case "yes":
		return "yes", nil
	case "force":
		return "force", nil
	default:
		return "", fmt.Errorf("invalid RequestTTY policy %q: want auto, no, yes or force", value)
	}
}

// parseTermType validates the Term value (-o Term=... and the ~/.ssh/config
// keyword): a non-empty terminal name without whitespace or control
// characters, at most 64 bytes, which is the size the servers keep for it as
// a session extra.
func parseTermType(value string) (string, error) {
	term := strings.TrimSpace(value)
	if term == "" {
		return "", fmt.Errorf("empty Term value: want a terminal name, e.g. xterm-256color")
	}
	if len(term) > 64 {
		return "", fmt.Errorf("Term value %q is too long (max 64 bytes)", value)
	}
	for i := 0; i < len(term); i++ {
		if c := term[i]; c <= ' ' || c == 0x7f {
			return "", fmt.Errorf("invalid Term value %q: whitespace and control characters are not allowed", value)
		}
	}
	return term, nil
}

// resolveTermType applies the Term precedence: the -o option overrides the
// ~/.ssh/config keyword, which overrides the local TERM environment variable;
// client.DefaultTermType is the last resort.
func resolveTermType(option, config string) string {
	if option != "" {
		return option
	}
	if config != "" {
		return config
	}
	if env := os.Getenv("TERM"); env != "" {
		return env
	}
	return client.DefaultTermType
}

// parseEscapeChar validates the EscapeChar value (-o EscapeChar=... and the
// ~/.ssh/config keyword) and returns its byte: a single ASCII printable
// character, a control form (^A..^Z, ^[, ^], ^? with ^? = 127) or "none"
// (0 = the escape sequences are disabled, the OpenSSH default is ~).
func parseEscapeChar(value string) (byte, error) {
	switch {
	case strings.EqualFold(strings.TrimSpace(value), "none"), strings.TrimSpace(value) == "":
		return 0, nil
	case len(value) == 2 && value[0] == '^':
		switch upper := value[1]; {
		case upper >= 'A' && upper <= 'Z':
			return upper - 'A' + 1, nil
		case upper == '[':
			return 27, nil
		case upper == ']':
			return 29, nil
		case upper == '?':
			return 127, nil
		}
		return 0, fmt.Errorf("invalid EscapeChar control form %q: want ^A..^Z, ^[, ^] or ^?", value)
	case len(value) == 1 && value[0] >= 0x21 && value[0] <= 0x7e:
		return value[0], nil
	default:
		return 0, fmt.Errorf("invalid EscapeChar %q: want one ASCII printable character, a ^X control form or none", value)
	}
}
