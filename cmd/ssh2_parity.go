package cmd

// Parsers and validators for the ssh(1)-shaped (ssh2 canon) client options
// added by the CLI-parity wave (CTO_TASK §7c): -L local forwards, -J proxy
// jump chains, the -o keywords Port/User/ControlMaster, and the server-side
// helpers backing sshd's -p/-h/-c. Everything here is a pure function so a
// malformed option is rejected before a single packet is sent.

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/francoismichel/ssh3/util"
)

// localForwardSpec is one parsed -L value: the local listener plus the remote
// target the server dials for every accepted connection (or datagram, for the
// UDP extension).
type localForwardSpec struct {
	// BindAddress is the local address to listen on: "" means the OpenSSH
	// default (loopback) and "*" means every interface.
	BindAddress string
	BindPort    uint16
	TargetHost  string
	TargetPort  uint16
	// Protocol is TCP for the ssh(1) shape; the udp:// prefix selects UDP,
	// which ssh(1) does not have (documented ssh3 extension).
	Protocol util.SSHForwardingProtocol
}

// localForwardFlags backs the repeatable -L flag and the -o LocalForward
// keyword.
type localForwardFlags []localForwardSpec

func (f *localForwardFlags) String() string {
	specs := make([]string, len(*f))
	for i, forward := range *f {
		protocol := ""
		if forward.Protocol == util.SSHProtocolUDP {
			protocol = "udp://"
		}
		bind := ""
		if forward.BindAddress != "" {
			bind = forward.BindAddress + ":"
		}
		specs[i] = fmt.Sprintf("%s%s%d:%s:%d", protocol, bind, forward.BindPort, forward.TargetHost, forward.TargetPort)
	}
	return strings.Join(specs, ",")
}

func (f *localForwardFlags) Set(value string) error {
	spec, err := parseLocalForwardSpec(value)
	if err != nil {
		return err
	}
	*f = append(*f, spec)
	return nil
}

// parseLocalForwardSpec accepts the ssh(1) "-L [bind_address:]port:host:hostport"
// syntax, extended with an optional "udp://" prefix for UDP forwarding (the
// ssh2 canon has no UDP forward). IPv6 literals must be bracketed, which
// splitOutsideBrackets enforces.
func parseLocalForwardSpec(spec string) (localForwardSpec, error) {
	value := strings.TrimSpace(spec)
	protocol := util.SSHForwardingProtocolTCP
	if rest, found := strings.CutPrefix(value, "udp://"); found {
		protocol = util.SSHProtocolUDP
		value = rest
	} else if rest, found := strings.CutPrefix(value, "tcp://"); found {
		value = rest
	}

	parts := splitOutsideBrackets(value, ':')
	if len(parts) != 3 && len(parts) != 4 {
		return localForwardSpec{}, fmt.Errorf(
			"invalid -L specification %q (expected [bind_address:]port:host:hostport, IPv6 addresses must be bracketed)", spec)
	}
	bindAddress := ""
	portPart := parts[0]
	if len(parts) == 4 {
		bindAddress = unbracket(parts[0])
		portPart = parts[1]
	}
	if bindAddress != "" && strings.ContainsAny(bindAddress, " \t") {
		return localForwardSpec{}, fmt.Errorf("invalid bind address %q in -L %q", bindAddress, spec)
	}
	targetHost := unbracket(parts[len(parts)-2])
	if targetHost == "" {
		return localForwardSpec{}, fmt.Errorf("invalid -L specification %q: the target host cannot be empty", spec)
	}

	bindPort, err := parsePort(portPart)
	if err != nil {
		return localForwardSpec{}, fmt.Errorf("invalid -L specification %q: %s", spec, err)
	}
	targetPort, err := parsePort(parts[len(parts)-1])
	if err != nil {
		return localForwardSpec{}, fmt.Errorf("invalid -L specification %q: %s", spec, err)
	}
	if targetPort == 0 {
		return localForwardSpec{}, fmt.Errorf("invalid -L specification %q: the target port cannot be 0", spec)
	}
	return localForwardSpec{
		BindAddress: bindAddress,
		BindPort:    bindPort,
		TargetHost:  targetHost,
		TargetPort:  targetPort,
		Protocol:    protocol,
	}, nil
}

// parseProxyJumpChain accepts the ssh(1) "-J destination[,destination...]"
// syntax and returns the raw hop specifications in order. Each hop keeps the
// fork's user@host[:port] form; URL validation happens in ClientMain, which
// prefixes the https:// scheme hop by hop.
func parseProxyJumpChain(spec string) ([]string, error) {
	var hops []string
	for _, hop := range strings.Split(spec, ",") {
		hop = strings.TrimSpace(hop)
		if hop == "" {
			return nil, fmt.Errorf("invalid -J specification %q: empty destination", spec)
		}
		if strings.ContainsAny(hop, " \t") {
			return nil, fmt.Errorf("invalid -J destination %q in %q", hop, spec)
		}
		hops = append(hops, hop)
	}
	return hops, nil
}

// parseControlMasterPolicy validates the ControlMaster value (-M maps to the
// flag, -o ControlMaster=... and the ~/.ssh/config keyword share this): no,
// yes or auto.
func parseControlMasterPolicy(value string) (string, error) {
	switch policy := strings.ToLower(strings.TrimSpace(value)); policy {
	case "no", "yes", "auto":
		return policy, nil
	default:
		return "", fmt.Errorf("invalid ControlMaster policy %q: want no, yes or auto", value)
	}
}

// parsePortKeyword validates the -o Port=... value: a TCP port in the
// 1..65535 range (0 is a listener allocation, not a connect port).
func parsePortKeyword(value string) (uint16, error) {
	port, err := parsePort(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("invalid Port value %q: %s", value, err)
	}
	if port == 0 {
		return 0, fmt.Errorf("invalid Port value %q: the port cannot be 0", value)
	}
	return port, nil
}

// resolveServerCertKeyAliases applies the sshd(8)-shaped -c/-h aliases to the
// fork's -cert/-key values: the ssh2 alias wins when only it is given, and
// giving both forms of the same knob is an error instead of a silent
// last-one-wins.
func resolveServerCertKeyAliases(certSet, keySet, certAliasSet, keyAliasSet bool, certFlag, keyFlag, certAlias, keyAlias string) (string, string, error) {
	if certSet && certAliasSet {
		return "", "", fmt.Errorf("-c and -cert are mutually exclusive")
	}
	if keySet && keyAliasSet {
		return "", "", fmt.Errorf("-h and -key are mutually exclusive")
	}
	if certAliasSet {
		certFlag = certAlias
	}
	if keyAliasSet {
		keyFlag = keyAlias
	}
	return certFlag, keyFlag, nil
}

// urlHostPort renders the destination URL as host:port, filling the fork's
// default port 443 when the -J destination carries none.
func urlHostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// localListenTCPAddr resolves the local listener for a -L TCP forward: an
// explicit bind address is resolved, "*" means every interface and the
// OpenSSH default (no address) binds the loopback of the target's family.
func localListenTCPAddr(forward localForwardSpec, remoteIP net.IP) (*net.TCPAddr, error) {
	port := int(forward.BindPort)
	switch {
	case forward.BindAddress == "*":
		return &net.TCPAddr{Port: port}, nil
	case forward.BindAddress != "":
		return net.ResolveTCPAddr("tcp", net.JoinHostPort(unbracket(forward.BindAddress), strconv.Itoa(port)))
	case remoteIP.To4() != nil:
		return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, nil
	default:
		return &net.TCPAddr{IP: net.IPv6loopback, Port: port}, nil
	}
}

// localListenUDPAddr is the UDP twin of localListenTCPAddr.
func localListenUDPAddr(forward localForwardSpec, remoteIP net.IP) (*net.UDPAddr, error) {
	port := int(forward.BindPort)
	switch {
	case forward.BindAddress == "*":
		return &net.UDPAddr{Port: port}, nil
	case forward.BindAddress != "":
		return net.ResolveUDPAddr("udp", net.JoinHostPort(unbracket(forward.BindAddress), strconv.Itoa(port)))
	case remoteIP.To4() != nil:
		return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, nil
	default:
		return &net.UDPAddr{IP: net.IPv6loopback, Port: port}, nil
	}
}

// mergeBindPort replaces the port part of the server's -bind address with the
// -p port (sshd canon: -p only carries the port; the bind address stays
// project-specific because QUIC needs it). Bracketed IPv6 hosts keep their
// brackets; a bare IPv6 literal with more than one colon is refused as
// ambiguous.
func mergeBindPort(bindAddr string, port uint16) (string, error) {
	if port == 0 {
		return "", fmt.Errorf("invalid -p port 0")
	}
	if bracketEnd := strings.LastIndexByte(bindAddr, ']'); bracketEnd >= 0 {
		rest := bindAddr[bracketEnd+1:]
		if rest == "" {
			return fmt.Sprintf("%s:%d", bindAddr, port), nil
		}
		if strings.HasPrefix(rest, ":") {
			return fmt.Sprintf("%s:%d", bindAddr[:bracketEnd+1], port), nil
		}
		return "", fmt.Errorf("invalid -bind address %q (expected [host]:port)", bindAddr)
	}
	switch colons := strings.Count(bindAddr, ":"); colons {
	case 0:
		return fmt.Sprintf("%s:%d", bindAddr, port), nil
	case 1:
		host, _, _ := strings.Cut(bindAddr, ":")
		return fmt.Sprintf("%s:%d", host, port), nil
	default:
		return "", fmt.Errorf("invalid -bind address %q: bracket the IPv6 literal to use -p", bindAddr)
	}
}
