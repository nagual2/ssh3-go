// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	osuser "os/user"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/auth/oidc"
	"github.com/francoismichel/ssh3/client"
	client_config "github.com/francoismichel/ssh3/client/config"
	matchcfg "github.com/francoismichel/ssh3/client/config/matchcfg"
	"github.com/francoismichel/ssh3/internal"
	pprofutil "github.com/francoismichel/ssh3/internal/pprofutil"
	"github.com/francoismichel/ssh3/util"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/ssh/agent"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func homedir() string {
	user, err := osuser.Current()
	if err == nil {
		return user.HomeDir
	} else {
		return os.Getenv("HOME")
	}
}

// Prepares the QUIC connection that will be used by SSH3
// If non-nil, use udpConn as transport (can be used for proxy jump)
// Otherwise, create a UDPConn from udp://host:port
// quicTuning groups the QUIC transport keys exposed for bulk-transfer tuning
// (stage 1.5): large flow control windows and initial packet size.
type quicTuning struct {
	InitialPacketSize uint16
	StreamRxWindowMiB int
	ConnRxWindowMiB   int
	// KeepAlivePeriod overrides the default QUIC keepalive (1s);
	// populated from ~/.ssh/config ServerAliveInterval
	KeepAlivePeriod time.Duration
	// MaxIncomingStreams overrides the default limit (10) on the concurrent
	// streams the peer may open; reverse forwarding (-R) raises it to leave
	// headroom for the server-initiated forwarded channels
	MaxIncomingStreams int64
}

// The datagram budget of a proxy-jump hop: the QUIC packets of a tunneled
// connection travel as SSH3 datagrams of the outer connection, and the
// datagram payload must fit into the outer connection's QUIC packet budget
// (quic-go sends a datagram only if it fits into a single packet: the
// budget is the initial packet size minus the 37 bytes of packet overhead
// it reserves). The SSH3 framing costs two varints per datagram (the
// conversation and the channel id), so every tunnel level eats a few bytes
// of the budget of the level below it. quic-go sizes the datagram budget
// from the initial packet size and only grows it with the path MTU
// discovery, which cannot help the very first datagram of a tunneled
// connection: the budget has to be reserved upfront.
const (
	// tunnelDatagramOverhead is the per-level cost of the datagram budget:
	// the QUIC packet overhead quic-go reserves on every packet (the type
	// byte, the maximum connection id and the AEAD tag: 37 bytes in
	// quic-go v0.63) plus the SSH3 datagram framing (the conversation id
	// and the channel id varints), rounded up.
	tunnelDatagramOverhead = 48
	// minQUICPacketSize is the QUIC minimum: a smaller Initial packet is
	// refused by the protocol (RFC 9000, section 14).
	minQUICPacketSize = 1200
	// maxQUICPacketSize is the QUIC maximum packet size (the payload of a
	// 1500-byte MTU path): the outermost connection of a proxy-jump chain
	// takes it, so that its datagram budget can carry the tunneled packets.
	maxQUICPacketSize = 1452
)

// tunnelOuterSize returns the initial QUIC packet size of the outermost
// connection of a proxy-jump chain of the given depth. Every level of
// the chain eats tunnelDatagramOverhead bytes of the datagram budget of
// the level below it, so the outermost connection takes a bigger packet
// and the innermost level stays above the QUIC minimum. The size is
// capped at the QUIC maximum, so a chain that does not fit is refused
// instead of silently breaking.
func tunnelOuterSize(baseSize uint16, tunnelDepth int) uint16 {
	outer := int(baseSize) + tunnelDepth*tunnelDatagramOverhead
	if outer > int(maxQUICPacketSize) {
		outer = int(maxQUICPacketSize)
	}
	return uint16(outer)
}

// tunneledPacketSize returns the initial QUIC packet size of the
// connection at the given level of the chain (level 0 is the outermost
// one, the level of the destination is the number of hops).
func tunneledPacketSize(outerSize uint16, level int) (uint16, error) {
	size := int(outerSize) - level*tunnelDatagramOverhead
	if size < minQUICPacketSize {
		return 0, fmt.Errorf("the proxy jump chain is too long for the QUIC datagram budget: %d levels need more than the %d-byte minimum packet size",
			level, minQUICPacketSize)
	}
	return uint16(size), nil
}

// The ssh2 behavioral canon for timeouts (CTO_TASK §7c item 11): sshd never
// kills an idle session (ClientAliveInterval=0) and gives the login 120 s
// (LoginGraceTime). quic-go has no "unset" (a zero MaxIdleTimeout becomes its
// 30 s default), so the canon is expressed as explicit large values on both
// endpoints — QUIC negotiates the smaller of the two.
const (
	ssh2IdleTimeout      = 24 * time.Hour
	ssh2HandshakeTimeout = 120 * time.Second
)

func setupQUICConnection(ctx context.Context, skipHostVerification bool, keylog io.Writer, ssh3Dir string, certPool *x509.CertPool, knownHostsPath string, knownHosts ssh3.KnownHosts,
	strictHostKeyChecking ssh3.StrictHostKeyChecking, verifyHostKeyDNS verifyHostKeyDNSSetting,
	oidcConfig []*oidc.OIDCConfig, options *client_config.Config, proxyRemoteAddr *net.UDPAddr, tty *os.File, tuning quicTuning, addressFamily int) (*quic.Conn, int) {

	var err error
	remoteAddr := proxyRemoteAddr
	if remoteAddr == nil {
		remoteAddr, err = net.ResolveUDPAddr("udp", options.URLHostnamePort())
		if err != nil {
			log.Error().Msgf("could not resolve UDP address: %s", err)
			return nil, -1
		}
	}

	// -4/-6 (ssh2 address family): a forced family must match the resolved
	// peer address, otherwise the dial would fail with an opaque socket error
	if addressFamily == 4 && remoteAddr.IP.To4() == nil {
		log.Error().Msgf("-4: %s resolves to an IPv6 address", options.Hostname())
		return nil, -1
	}
	if addressFamily == 6 && remoteAddr.IP.To4() != nil {
		log.Error().Msgf("-6: %s resolves to an IPv4 address", options.Hostname())
		return nil, -1
	}

	netString := "udp"
	switch {
	case addressFamily == 4:
		netString = "udp4"
	case addressFamily == 6:
		netString = "udp6"
	case runtime.GOOS == "darwin":
		// on MacOS, the don't fragment (DF) bit is not set on dual-stack socket ("udp")
		// This causes quic-go to not perform MTU discovery which can prevent the proxy jump from working at all.
		// cf: - https://github.com/francoismichel/ssh3/issues/129
		//     - https://github.com/quic-go/quic-go/issues/3793
		//
		// The fix here is to not use a dual-stack socket on MacOS and detect the IP version from the resolved peer address.

		if remoteAddr.IP.To4() != nil {
			// it is a v4 address
			netString = "udp4"
		} else {
			// it is a v6 address
			netString = "udp6"
		}
	}

	udpConn, err := net.ListenUDP(netString, nil)
	if err != nil {
		log.Error().Msgf("could not create UDP connection: %s", err)
		return nil, -1
	}

	tlsConf := &tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: skipHostVerification,
		NextProtos:         []string{http3.NextProtoH3},
		KeyLogWriter:       keylog,
		ServerName:         options.Hostname(),
	}

	var qconf quic.Config

	qconf.MaxIncomingStreams = 10
	if tuning.MaxIncomingStreams > 0 {
		qconf.MaxIncomingStreams = tuning.MaxIncomingStreams
	}
	qconf.Allow0RTT = true
	qconf.EnableDatagrams = true
	// the initial packet size drives the QUIC datagram budget: a datagram
	// is only sent when it fits into a single packet (quic-go reserves 37
	// bytes of packet overhead). The proxy-jump hops rely on it: the
	// tunneled packets travel as datagrams of the outer connection.
	if tuning.InitialPacketSize >= minQUICPacketSize {
		qconf.InitialPacketSize = tuning.InitialPacketSize
	}
	if proxyRemoteAddr != nil {
		// A tunneled connection must not grow its packets: the path MTU
		// discovery would push them to the QUIC maximum (1452 bytes), and
		// the datagram carrying them would no longer fit into a single
		// packet of the outer connection (the datagram budget of the outer
		// connection is the outer initial packet size minus the packet
		// overhead). The tunnel therefore keeps the initial packet size.
		qconf.DisablePathMTUDiscovery = true
	}
	qconf.KeepAlivePeriod = time.Second
	if tuning.KeepAlivePeriod > 0 {
		qconf.KeepAlivePeriod = tuning.KeepAlivePeriod
	}
	// ssh2 canon (§7c item 11): do not kill an idle session (the negotiated
	// idle timeout is the smaller of the endpoints' values, so the client
	// must raise its side too), and give the handshake the LoginGraceTime
	// scale instead of the quic-go 5 s default
	qconf.MaxIdleTimeout = ssh2IdleTimeout
	qconf.HandshakeIdleTimeout = ssh2HandshakeTimeout

	hostKey := options.CanonicalHostFormat()
	if certs, ok := knownHosts[hostKey]; ok {
		foundSelfsignedSSH3 := false

		for _, cert := range certs {
			certPool.AddCert(cert)
			if cert.VerifyHostname("selfsigned.ssh3") == nil {
				foundSelfsignedSSH3 = true
			}
		}

		// If no IP SAN was in the cert, then assume the self-signed cert at least matches the .ssh3 TLD
		if foundSelfsignedSSH3 {
			// Put "ssh3" as ServerName so that the TLS verification can succeed
			// Otherwise, TLS refuses to validate a certificate without IP SANs
			// if the hostname is an IP address.
			tlsConf.ServerName = "selfsigned.ssh3"
		}
	}

	// trustCertificate makes the next handshake verify the server against cert:
	// the certificate is added to the pool and, when it fits the .ssh3
	// self-signed naming, ServerName is switched so that hostname verification
	// can succeed without IP SANs.
	trustCertificate := func(cert *x509.Certificate) {
		certPool.AddCert(cert)
		if cert.VerifyHostname("selfsigned.ssh3") == nil {
			tlsConf.ServerName = "selfsigned.ssh3"
		}
	}

	// logCertificateMismatch emits the OpenSSH-style host key warning when a
	// known host presents a certificate that matches none of the pinned ones.
	logCertificateMismatch := func(received *x509.Certificate) {
		log.Error().Msgf(
			"WARNING: the certificate presented by %s does not match the one pinned in %s. "+
				"If you did not change the server certificate, it could be a machine-in-the-middle attack. "+
				"Pinned: %s. Received: SHA256:%s. "+
				"If this change is legitimate, remove the host from %s or run again with -o StrictHostKeyChecking=no.",
			hostKey, knownHostsPath,
			strings.Join(knownHosts.Fingerprints(hostKey), ", "),
			util.Sha256Fingerprint(received.Raw),
			knownHostsPath)
	}

	log.Debug().Msgf("dialing QUIC host at %s", remoteAddr)
	qClient, err := quic.DialEarly(ctx,
		udpConn,
		remoteAddr,
		tlsConf,
		&qconf)
	if err == nil {
		// A successful handshake only proves that the chain is trusted (system
		// CAs or a pinned certificate as anchor): compare the leaf against the
		// pins ourselves so that a silently rotated certificate is detected.
		if !skipHostVerification {
			if peerCerts := qClient.ConnectionState().TLS.PeerCertificates; len(peerCerts) > 0 {
				switch knownHosts.CheckCertificate(hostKey, peerCerts[0]) {
				case ssh3.HostCertificateChanged:
					if strictHostKeyChecking == ssh3.StrictHostKeyCheckingNo {
						log.Warn().Msgf("StrictHostKeyChecking=no: the certificate of %s differs from the one pinned in %s (received: SHA256:%s), connecting anyway (insecure)",
							hostKey, knownHostsPath, util.Sha256Fingerprint(peerCerts[0].Raw))
					} else {
						logCertificateMismatch(peerCerts[0])
						qClient.CloseWithError(quic.ApplicationErrorCode(0), "server certificate does not match the pinned one")
						return nil, -1
					}
				case ssh3.HostCertificateUnknown:
					// first contact on a verifiable certificate: accept-new
					// pins it, like OpenSSH records new host keys
					if strictHostKeyChecking == ssh3.StrictHostKeyCheckingAcceptNew {
						if err := ssh3.AppendKnownHost(knownHostsPath, hostKey, peerCerts[0]); err != nil {
							log.Error().Msgf("could not append known host to %s: %s", knownHostsPath, err)
							qClient.CloseWithError(quic.ApplicationErrorCode(0), "could not pin the server certificate")
							return nil, -1
						}
						log.Info().Msgf("accept-new: pinned the first-use certificate of %s in %s", hostKey, knownHostsPath)
					}
				case ssh3.HostCertificateMatches:
					// the pinned certificate is the one being used
				}

				// SSHFP (VerifyHostKeyDNS) is checked on the very same
				// certificate: the pinned-certificate check answers "is this the
				// key we saw last time?", SSHFP answers "does the zone vouch for
				// this key?". options.Hostname() is used rather than the
				// canonical host key because SSHFP records are published for the
				// bare DNS name (user@ and :port carry no DNS meaning).
				if _, err := checkHostKeySSHFP(ctx, options.Hostname(), peerCerts[0], verifyHostKeyDNS, strictHostKeyChecking); err != nil {
					qClient.CloseWithError(quic.ApplicationErrorCode(0), "the SSHFP records of the server do not match its host key")
					return nil, -1
				}
			}
		}
		return qClient, 0
	}

	if transportErr, ok := err.(*quic.TransportError); ok {
		if transportErr.ErrorCode.IsCryptoError() {
			log.Debug().Msgf("received QUIC crypto error on first connection attempt: %s", err)
			_, hostPinned := knownHosts[hostKey]

			if hostPinned && strictHostKeyChecking != ssh3.StrictHostKeyCheckingNo {
				// The pinned certificate(s) did not verify the server: the
				// certificate changed, which can be a machine-in-the-middle attack.
				// This covers yes and ask; accept-new also refuses changed pins.
				log.Error().Msgf("the server certificate cannot be verified using the one pinned in %s (pinned: %s). "+
					"If you did not change the server certificate, it could be a machine-in-the-middle attack. "+
					"TLS error: %s", knownHostsPath, strings.Join(knownHosts.Fingerprints(hostKey), ", "), err)
				log.Error().Msgf("Aborting.")
				return nil, -1
			}

			// yes: never connect to a host whose certificate cannot be verified
			if strictHostKeyChecking == ssh3.StrictHostKeyCheckingYes {
				log.Error().Msgf("StrictHostKeyChecking=yes: the certificate of %s could not be verified and the host is not pinned in %s, refusing to connect. "+
					"TLS error: %s", hostKey, knownHostsPath, err)
				log.Error().Msgf("Aborting.")
				return nil, -1
			}

			// ask keeps the historical non-interactive guard; accept-new and no
			// decide without any user interaction
			if tty == nil && strictHostKeyChecking == ssh3.StrictHostKeyCheckingAsk {
				log.Error().Msgf("insecure server cert in non-terminal session, aborting")
				return nil, -1
			}

			// capture the actual peer certificate: dial once more with the
			// verification disabled and grab the certificate through the
			// verify callback
			captureConf := tlsConf.Clone()
			captureConf.InsecureSkipVerify = true
			var peerCertificate *x509.Certificate
			certError := fmt.Errorf("we don't want to start a totally insecure connection")
			captureConf.VerifyConnection = func(ctx tls.ConnectionState) error {
				peerCertificate = ctx.PeerCertificates[0]
				return certError
			}

			_, err := quic.DialEarly(ctx,
				udpConn,
				remoteAddr,
				captureConf,
				&qconf)
			if !errors.Is(err, certError) {
				log.Error().Msgf("could not create client QUIC connection: %s", err)
				return nil, -1
			}

			// no: the explicitly allowed insecure behaviour
			if strictHostKeyChecking == ssh3.StrictHostKeyCheckingNo {
				if hostPinned {
					log.Warn().Msgf("StrictHostKeyChecking=no: the certificate of %s differs from the one pinned in %s (pinned: %s, received: SHA256:%s), connecting anyway (insecure)",
						hostKey, knownHostsPath, strings.Join(knownHosts.Fingerprints(hostKey), ", "),
						util.Sha256Fingerprint(peerCertificate.Raw))
				} else if peerCertificate.CheckSignatureFrom(peerCertificate) == nil {
					// pin the self-signed first-use certificate so that later
					// sessions can detect a certificate change
					if err := ssh3.AppendKnownHost(knownHostsPath, hostKey, peerCertificate); err != nil {
						log.Error().Msgf("could not append known host to %s: %s", knownHostsPath, err)
						return nil, -1
					}
					log.Warn().Msgf("StrictHostKeyChecking=no: pinned the first-use certificate of %s in %s", hostKey, knownHostsPath)
				}
				captureConf.VerifyConnection = nil
				qClient, err := quic.DialEarly(ctx, udpConn, remoteAddr, captureConf, &qconf)
				if err != nil {
					log.Error().Msgf("could not establish client QUIC connection: %s", err)
					return nil, -1
				}
				return qClient, 0
			}

			// let's first check that the certificate is self-signed
			// (ask and accept-new only ever pin self-signed certificates)
			if err := peerCertificate.CheckSignatureFrom(peerCertificate); err != nil {
				log.Error().Msgf("the peer provided an unknown, insecure certificate, that is not self-signed: %s", err)
				return nil, -1
			}

			// accept-new: pin automatically, then reconnect with the pinned
			// certificate actually verified
			if strictHostKeyChecking == ssh3.StrictHostKeyCheckingAcceptNew {
				if err := ssh3.AppendKnownHost(knownHostsPath, hostKey, peerCertificate); err != nil {
					log.Error().Msgf("could not append known host to %s: %s", knownHostsPath, err)
					return nil, -1
				}
				trustCertificate(peerCertificate)
				qClient, err := quic.DialEarly(ctx, udpConn, remoteAddr, tlsConf, &qconf)
				if err != nil {
					log.Error().Msgf("could not establish client QUIC connection: %s", err)
					return nil, -1
				}
				log.Info().Msgf("accept-new: pinned the first-use certificate of %s in %s", hostKey, knownHostsPath)
				return qClient, 0
			}

			// ask: historical interactive TOFU flow
			// first, carriage return
			_, _ = tty.WriteString("\r")
			_, err = tty.WriteString("Received an unknown self-signed certificate from the server.\n\r" +
				"We recommend not using self-signed certificates.\n\r" +
				"This session is vulnerable a machine-in-the-middle attack.\n\r" +
				"Certificate fingerprint: " +
				"SHA256 " + util.Sha256Fingerprint(peerCertificate.Raw) + "\n\r" +
				"Do you want to add this certificate to ~/.ssh3/known_hosts (yes/no)? ")
			if err != nil {
				log.Error().Msgf("cound not write on /dev/tty: %s", err)
				return nil, -1
			}

			answer := ""
			reader := bufio.NewReader(tty)
			for {
				answer, _ = reader.ReadString('\n')
				answer = strings.TrimSpace(answer)
				_, _ = tty.WriteString("\r") // always ensure a carriage return
				if answer == "yes" || answer == "no" {
					break
				}
				tty.WriteString("Invalid answer, answer \"yes\" or \"no\" ")
			}
			if answer == "no" {
				log.Info().Msg("Connection aborted")
				return nil, 0
			}
			if err := ssh3.AppendKnownHost(knownHostsPath, hostKey, peerCertificate); err != nil {
				log.Error().Msgf("could not append known host to %s: %s", knownHostsPath, err)
				return nil, -1
			}
			tty.WriteString(fmt.Sprintf("Successfully added the certificate to %s, please rerun the command\n\r", knownHostsPath))
			return nil, 0
		}
	}
	log.Error().Msgf("could not establish client QUIC connection: %s", err)
	return nil, -1
}

func parseAddrPort(addrPort string) (localPort int, remoteIP net.IP, remotePort int, err error) {
	array := strings.Split(addrPort, "/")
	localPort, err = strconv.Atoi(array[0])
	if err != nil {
		return 0, nil, 0, fmt.Errorf("could not convert %s to int: %s", array[0], err)
	} else if localPort > 0xFFFF {
		return 0, nil, 0, fmt.Errorf("UDP port too large %d", localPort)
	}
	array = strings.Split(array[1], "@")
	remoteIP = net.ParseIP(array[0])
	if remoteIP == nil {
		return 0, nil, 0, fmt.Errorf("could not parse IP %s", array[0])
	}
	remotePort, err = strconv.Atoi(array[1])
	if err != nil {
		return 0, nil, 0, fmt.Errorf("could not convert %s to int: %s", array[1], err)
	} else if remotePort > 0xFFFF {
		return 0, nil, 0, fmt.Errorf("UDP port too large %d", remotePort)
	}
	return localPort, remoteIP, remotePort, err
}

// getConfigOptions resolves the effective username/hostname/port/urlpath for
// the target: the -p/-o Port override beats the operand port, which beats the
// ~/.ssh/config port; for the username the operand user@ beats the -o User
// override, which beats the config user.
func getConfigOptions(hostUrl *url.URL, sshConfig *matchcfg.Resolver, optionParsers map[client_config.OptionName]client_config.OptionParser, portOverride uint16, userOverride string) (*client_config.Config, error) {
	urlHostname, urlPort := hostUrl.Hostname(), hostUrl.Port()
	// The user known before reading the config: it feeds the Match user
	// criterion and the default username resolution below.
	urlUser := hostUrl.User.Username()
	if urlUser == "" {
		urlUser = hostUrl.Query().Get("user")
	}

	configHostname, configPort, configUser, configUrlPath, configAuthMethods, pluginOptions, err := ssh3.GetConfigForHost(urlHostname, urlUser, sshConfig, optionParsers)
	if err != nil {
		log.Error().Msgf("Could not get config for %s: %s", urlHostname, err)
		return nil, err
	}

	hostname := configHostname
	if hostname == "" {
		hostname = urlHostname
	}

	port := 443
	switch {
	case portOverride > 0:
		// -p / -o Port: the ssh2 CLI override wins over everything
		port = int(portOverride)
	case urlPort != "":
		if parsedPort, err := strconv.Atoi(urlPort); err == nil && parsedPort < 0xffff {
			// There is a port in the CLI and the port is valid. Use the CLI port.
			port = parsedPort
		} else {
			// There is a port in the CLI but it is not valid.
			// use WithLevel(zerolog.FatalLevel) to log a fatal level, but let us handle
			// program termination. log.Fatal() exits with os.Exit(1).
			log.WithLevel(zerolog.FatalLevel).Str("Port", urlPort).Err(err).Msg("cli contains an invalid port")
			fmt.Fprintf(os.Stderr, "Bad port '%s'\n", urlPort)
			return nil, err
		}
	case configPort != -1:
		// There is no port in the CLI, but one in a config file. Use the config port.
		port = configPort
	}

	username := urlUser
	if username == "" {
		username = userOverride
	}
	if username == "" {
		username = configUser
	}
	if username == "" {
		u, err := osuser.Current()
		if err == nil {
			username = u.Username
		} else {
			log.Error().Msgf("could not get current username: %s", err)
		}
	}
	if username == "" {
		return nil, fmt.Errorf("no username could be found")
	}

	urlPath := hostUrl.Path
	if urlPath == "" {
		urlPath = configUrlPath
	}
	return client_config.NewConfig(username, hostname, port, urlPath, configAuthMethods, pluginOptions)
}

func getConnectionMaterialFromURL(hostUrl *url.URL, sshConfig *matchcfg.Resolver, cliAuthMethods []interface{}, cliOptions map[client_config.OptionName]client_config.Option, optionParsers map[client_config.OptionName]client_config.OptionParser, portOverride uint16, userOverride string) (agent.ExtendedAgent, *client_config.Config, error) {
	configOptions, err := getConfigOptions(hostUrl, sshConfig, optionParsers, portOverride, userOverride)
	if err != nil {
		return nil, nil, fmt.Errorf("could not apply config to %s: %s", hostUrl, err)
	}

	var agentClient agent.ExtendedAgent
	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if socketPath != "" {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open SSH_AUTH_SOCK: %s", err)
		}
		agentClient = agent.NewClient(conn)
	}

	var authMethods []interface{}
	authMethods = append(authMethods, cliAuthMethods...)
	authMethods = append(authMethods, configOptions.AuthMethods()...)

	pluginOptionsFromConfig := configOptions.Options()
	for k, v := range cliOptions {
		if _, ok := pluginOptionsFromConfig[k]; ok {
			log.Debug().Msgf("override config option %s by the value provided by the CLI", k)
		}
		pluginOptionsFromConfig[k] = v
	}

	options, err := client_config.NewConfig(configOptions.Username(), configOptions.Hostname(), configOptions.Port(), configOptions.UrlPath(), authMethods, configOptions.Options())
	if err != nil {
		return nil, nil, fmt.Errorf("could not instantiate invalid options: %s", err)
	}
	return agentClient, options, nil
}

// cliOptionFlags gathers repeatable -o Key=Value options, mimicking OpenSSH.
type cliOptionFlags []string

func (o *cliOptionFlags) String() string {
	if o == nil {
		return ""
	}
	return strings.Join(*o, ",")
}

func (o *cliOptionFlags) Set(value string) error {
	if _, _, found := strings.Cut(value, "="); !found {
		return fmt.Errorf("option must be in the Key=Value form, got %q", value)
	}
	*o = append(*o, value)
	return nil
}

type FlagValue struct {
	pluginOptionName client_config.OptionName
	val              string
	parsedOption     client_config.Option
	client_config.CLIOptionParser
}

func NewFlagValue(optionName client_config.OptionName, parser client_config.CLIOptionParser) *FlagValue {
	return &FlagValue{
		pluginOptionName: optionName,
		CLIOptionParser:  parser,
	}
}

func (v *FlagValue) String() string {
	if v == nil {
		return ""
	}
	return v.val
}

func (v *FlagValue) Set(s string) (err error) {
	if v.CLIOptionParser.IsBoolFlag() {
		switch s {
		case "true":
			s = "yes"
		case "false":
			s = "no"
		default:
			return fmt.Errorf("when parsing a boolean flag, the input should be \"true\" or \"false\"")
		}
	}
	v.val = s
	v.parsedOption, err = v.CLIOptionParser.Parse([]string{s})
	if err != nil {
		return err
	}
	return nil
}

func (v *FlagValue) IsBoolFlag() bool {
	return v.CLIOptionParser.IsBoolFlag()
}

func ClientMain() int {
	// the plugin registration (init-time) logs run before ConfigureLogger:
	// keep the default startup quiet at the ssh(1) level (warnings and errors
	// only until the real level is resolved from -v/-q/SSH3_LOG_LEVEL)
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
	pprofutil.ServeIfEnabled(os.Getenv("SSH3_PPROF"))
	internal.CloseClientPluginsRegistry()
	internal.CloseServerPluginsRegistry()

	// for other auth-related CLI args, go see auth/plugins, as they define plugin-specific auth CLI args and config options, such a pubkey/privkey-based auth
	// The ssh2 canon (ssh(1)) forms are primary; the fork's own names stay as
	// deprecated aliases so existing installs and scripts keep working
	// (CLI-parity wave, CTO_TASK §7c).
	keyLogFile := flag.String("keylog", "", "Write QUIC TLS keys and master secret in the specified keylog file: only for debugging purpose")
	passwordAuthentication := flag.Bool("use-password", false, "if set, do classical password authentication")
	insecure := flag.Bool("insecure", false, "if set, skip server certificate verification")
	strictHostKeyCheckingFlag := flag.String("strict-host-key-checking", "",
		"StrictHostKeyChecking policy: yes, accept-new, no or ask (default: ask; overrides -o and ~/.ssh/config)")
	optionOverrides := cliOptionFlags{}
	flag.Var(&optionOverrides, "o", "configuration option as Key=Value, e.g. -o StrictHostKeyChecking=accept-new (can be repeated)")
	issuerUrl := flag.String("use-oidc", "", "if set, force the use of OpenID Connect with the specified issuer url as parameter (it opens a browser window)")
	oidcConfigFileName := flag.String("oidc-config", "", "OpenID Connect json config file containing the \"client_id\" and \"client_secret\" fields needed for most identity providers")
	verbose := flag.Bool("v", false, "if set, enable verbose mode")
	quiet := flag.Bool("q", false, "quiet mode: suppress diagnostic log messages, errors are still logged (ssh2 -q)")
	displayVersionVar := false
	flag.BoolVar(&displayVersionVar, "version", false, "if set, displays the software version on standard output and exit")
	flag.BoolVar(&displayVersionVar, "V", false, "print the software version and exit (ssh2 -V; same as -version)")
	forwardAgentVar := false
	flag.BoolVar(&forwardAgentVar, "forward-agent", false, "if set, forwards ssh agent to be used with sshv2 connections on the remote host")
	flag.BoolVar(&forwardAgentVar, "A", false, "enable agent forwarding (ssh2 -A; same as -forward-agent)")
	streamRxMiB := flag.Int("stream-rx-mb", 8, "initial per-stream flow control receive window in MiB")
	connRxMiB := flag.Int("conn-rx-mb", 16, "initial connection-level flow control receive window in MiB")
	controlOp := flag.String("O", "", "control operation on an existing control master: check, stop or exit")
	controlMaster := flag.String("control-master", "no", "share one connection across invocations: no, yes or auto (reuse a running master, else start one in background; not compatible with -J; unsupported on windows)")
	controlPathFlag := flag.String("control-path", "", "control master unix socket path (default ~/.ssh3/cm-<user>@<host>:<port>)")
	controlPersist := flag.String("control-persist", "no", "keep the master in background after the session ends: no, yes or a number of seconds (idle timeout)")
	masterMode := flag.Bool("M", false, "control master mode (ssh2 -M; same as -control-master yes)")
	controlSocket := flag.String("S", "", "control master unix socket path (ssh2 -S; same as -control-path)")
	identityFile := flag.String("i", "", "selects the private key file for public key authentication (ssh2 -i; same as -privkey)")
	clientPort := flag.Int("p", 0, "port to connect to on the remote host (ssh2 -p; overrides -o Port, the operand port and ~/.ssh/config)")
	packetSize := flag.Int("packet-size", 1200, "initial QUIC packet size in bytes (the QUIC minimum; "+
		"the path MTU discovery grows it when the path allows)")
	noPKCE := flag.Bool("no-pkce", false, "if set perform PKCE challenge-response with oidc")
	proxyJump := flag.String("proxy-jump", "", "if set, performs a proxy jump using the specified remote host as proxy (deprecated alias of -J; requires server with version >= 0.1.5)")
	jumpDestination := flag.String("J", "", "proxy jump: destination[,destination...] (ssh2 -J; every hop must run ssh3-server)")
	var localForwardsFlag localForwardFlags
	flag.Var(&localForwardsFlag, "L", "local forwarding: [bind_address:]port:host:hostport, prefix udp:// for UDP (can be repeated; ssh2 -L shape)")
	var dynamicForwardsFlag dynamicForwardFlags
	flag.Var(&dynamicForwardsFlag, "D", "dynamic (SOCKS5) port forwarding: [bind_address:]port (can be repeated; an empty or \"*\" bind address listens on every interface, no address means localhost)")
	var reverseForwardsFlag reverseForwardFlags
	flag.Var(&reverseForwardsFlag, "R", "reverse forwarding: [bind_address:]bind_port[/udp]:target_host:target_port, the server binds the port and forwards to the local target (can be repeated; the ssh2 -R shape without the /udp marker)")
	transferMode := flag.Bool("transfer", false, "file transfer mode: ssh3 -transfer SRC DST, with exactly one operand in the user@host:remote_path form (uploads towards it) and the other one local (downloads from it)")
	backgroundFlag := flag.Bool("f", false, "go to background after startup (ssh2 -f): the session detaches from the terminal and keeps running; non-interactive authentication only (key/agent), and the host must be pinned under the ask policy")
	transferPort := flag.Int("P", 443, "file transfer mode: server port for the user@host:remote_path operand (deprecated alias of -p)")
	transferURLPath := flag.String("U", "/ssh3-term", "file transfer mode: server URL path for the user@host:remote_path operand")
	recursive := flag.Bool("r", false, "file transfer mode: transfer directories recursively")
	resumeMode := flag.Bool("continue", false, "file transfer mode: resume interrupted transfers instead of overwriting")
	verifyChecksum := flag.Bool("checksum", false, "file transfer mode: verify the transfer with a SHA-256 re-read (automatic for files over 32 MiB)")
	forwardUDP := flag.String("forward-udp", "", "if set, take a localport/remoteip@remoteport forwarding localhost@localport towards remoteip@remoteport (deprecated alias of -L udp://)")
	forwardTCP := flag.String("forward-tcp", "", "if set, take a localport/remoteip@remoteport forwarding localhost@localport towards remoteip@remoteport (deprecated alias of -L)")
	noSession := flag.Bool("N", false, "do not execute a remote command or session; hold the connection open for the forwards (use with -L/-D/-R)")
	configFileFlag := flag.String("F", "", "specifies an alternative per-user configuration file (default ~/.ssh/config)")
	forcePTY := flag.Bool("t", false, "force pseudo-terminal allocation, even when the local standard input is not a terminal")
	noPTY := flag.Bool("T", false, "disable pseudo-terminal allocation, even for an interactive session (RequestTTY=no)")
	subsystem := flag.String("s", "", "request a remote subsystem: \"sftp\" opens the interactive SFTP client, any other name requests that subsystem")
	v4Only := flag.Bool("4", false, "use IPv4 addresses only (ssh2 -4)")
	v6Only := flag.Bool("6", false, "use IPv6 addresses only (ssh2 -6)")

	var flagValues []*FlagValue
	cliParsers, err := internal.GetPluginsCLIArgs()
	if err != nil {
		log.Error().Msgf("error when retrieving plugins-defined CLI args: %s", err)
		return -1
	}
	for name, parser := range cliParsers {
		log.Debug().Msgf("Adding plugin-provided CLI arg: \"%s\"", parser.FlagName())
		flagValue := NewFlagValue(name, parser)
		flagValues = append(flagValues, flagValue)
		flag.Var(flagValue, parser.FlagName(), parser.Usage())
	}

	flag.Parse()
	args := flag.Args()

	// detect which flags were explicitly set on the command line: an explicit
	// flag takes precedence over -o and ssh config (OpenSSH precedence)
	strictFlagSet := false
	subsystemFlagSet := false
	controlMasterFlagSet := false
	controlPathFlagSet := false
	controlPersistFlagSet := false
	clientPortFlagSet := false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "strict-host-key-checking":
			strictFlagSet = true
		case "s":
			subsystemFlagSet = true
		case "control-master":
			controlMasterFlagSet = true
		case "control-path":
			controlPathFlagSet = true
		case "control-persist":
			controlPersistFlagSet = true
		case "p":
			clientPortFlagSet = true
		}
	})

	if *v4Only && *v6Only {
		fmt.Fprintln(os.Stderr, "-4 and -6 are mutually exclusive")
		return -1
	}
	if *clientPort != 0 && (*clientPort < 0 || *clientPort > 0xFFFF) {
		fmt.Fprintf(os.Stderr, "Bad port '%d'\n", *clientPort)
		return -1
	}

	// -O is validated up front so that a typo is reported with the list of
	// supported operations instead of reaching the control socket layer
	if *controlOp != "" {
		if err := validateControlOperation(*controlOp); err != nil {
			log.Error().Msgf("%s", err)
			return -1
		}
	}

	// -s requests a subsystem instead of a shell/command: the subsystem name is
	// validated here for the same reason
	subsystemName := ""
	if *subsystem != "" || subsystemFlagSet {
		name, err := parseSubsystemName(*subsystem)
		if err != nil {
			log.Error().Msgf("%s", err)
			return -1
		}
		subsystemName = name
	}

	cliOptions := make(map[client_config.OptionName]client_config.Option)
	// gather the parsed CLI options
	for _, v := range flagValues {
		cliOptions[v.pluginOptionName] = v.parsedOption
	}

	// apply the -o Key=Value overrides: the ssh2 keywords handled natively
	// come first, the remaining ones are routed to the registered option
	// parsers (the auth plugins' config keywords, e.g. IdentityFile)
	strictOptionValue := ""
	verifyHostKeyDNSOptionValue := ""
	verifyHostKeyDNSOptionSet := false
	requestTTYOption := "" // the -o RequestTTY=... value, empty when unset
	termTypeOption := ""   // the -o Term=... value, empty when unset
	escapeCharOption := "" // the -o EscapeChar=... value, empty when unset
	portOption := uint16(0)
	userOption := ""
	proxyJumpOption := ""
	controlMasterOption := ""
	controlPathOption := ""
	controlPersistOption := ""
	parsersByKeyword := optionParsersByKeyword(cliParsers)
	for _, keyValuePair := range optionOverrides {
		key, value, _ := strings.Cut(keyValuePair, "=")
		key = strings.TrimSpace(key)
		switch {
		case strings.EqualFold(key, "StrictHostKeyChecking"):
			if _, err := ssh3.ParseStrictHostKeyChecking(value); err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			strictOptionValue = strings.TrimSpace(value)
			continue
		case strings.EqualFold(key, "EscapeChar"):
			// validated here so a bad -o value is rejected like every other
			// malformed option, before the connection is set up
			if _, err := parseEscapeChar(value); err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			escapeCharOption = strings.TrimSpace(value)
			continue
		case strings.EqualFold(key, "RequestTTY"):
			policy, err := parseRequestTTY(value)
			if err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			requestTTYOption = policy
			continue
		case strings.EqualFold(key, "Term"):
			term, err := parseTermType(value)
			if err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			termTypeOption = term
			continue
		case strings.EqualFold(key, "VerifyHostKeyDNS"):
			if _, err := parseVerifyHostKeyDNSValue(value); err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			verifyHostKeyDNSOptionValue = strings.TrimSpace(value)
			verifyHostKeyDNSOptionSet = true
			continue
		case strings.EqualFold(key, "Port"):
			port, err := parsePortKeyword(value)
			if err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			portOption = port
			continue
		case strings.EqualFold(key, "User"):
			if strings.TrimSpace(value) == "" {
				fmt.Fprintln(os.Stderr, "Bad configuration option 'User': the value cannot be empty")
				return -1
			}
			userOption = strings.TrimSpace(value)
			continue
		case strings.EqualFold(key, "LocalForward"):
			if err := localForwardsFlag.Set(value); err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			continue
		case strings.EqualFold(key, "RemoteForward"):
			forward, err := parseReverseForwardSpec(value)
			if err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			reverseForwardsFlag = append(reverseForwardsFlag, forward)
			continue
		case strings.EqualFold(key, "DynamicForward"):
			if err := dynamicForwardsFlag.Set(value); err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			continue
		case strings.EqualFold(key, "ProxyJump"):
			if _, err := parseProxyJumpChain(value); err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			proxyJumpOption = strings.TrimSpace(value)
			continue
		case strings.EqualFold(key, "ControlMaster"):
			policy, err := parseControlMasterPolicy(value)
			if err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			controlMasterOption = policy
			continue
		case strings.EqualFold(key, "ControlPath"):
			controlPathOption = strings.TrimSpace(value)
			continue
		case strings.EqualFold(key, "ControlPersist"):
			if _, _, err := parseControlPersistStrict(value); err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			controlPersistOption = strings.TrimSpace(value)
			continue
		}
		if optionName, ok := parsersByKeyword[strings.ToLower(key)]; ok {
			option, err := cliParsers[optionName].Parse([]string{value})
			if err != nil {
				log.Error().Msgf("could not parse option %s: %s", key, err)
				return -1
			}
			cliOptions[optionName] = option
			continue
		}
		fmt.Fprintf(os.Stderr, "Bad configuration option '%s'\n", key)
		return -1
	}

	// -i is the ssh2 spelling of the privkey plugin's IdentityFile option
	if *identityFile != "" {
		optionName, ok := parsersByKeyword["identityfile"]
		if !ok {
			log.Error().Msgf("-i: the privkey authentication plugin providing the IdentityFile option is not available")
			return -1
		}
		option, err := cliParsers[optionName].Parse([]string{*identityFile})
		if err != nil {
			log.Error().Msgf("could not parse -i %s: %s", *identityFile, err)
			return -1
		}
		cliOptions[optionName] = option
	}

	// CLI flag > -o keyword, resolved once so every later use sees the merged
	// value (OpenSSH precedence; ~/.ssh/config fills what is left empty)
	controlMasterResolved := "no"
	if controlMasterOption != "" {
		controlMasterResolved = controlMasterOption
	}
	if controlMasterFlagSet {
		controlMasterResolved = *controlMaster
	}
	if *masterMode {
		controlMasterResolved = "yes"
	}
	controlPathResolved := controlPathOption
	if controlPathFlagSet {
		controlPathResolved = *controlPathFlag
	}
	if *controlSocket != "" {
		controlPathResolved = *controlSocket
	}
	controlPersistResolved := controlPersistOption
	if controlPersistFlagSet {
		controlPersistResolved = *controlPersist
	}
	proxyJumpResolved := proxyJumpOption
	if *proxyJump != "" {
		proxyJumpResolved = *proxyJump
	}
	if *jumpDestination != "" {
		proxyJumpResolved = *jumpDestination
	}
	portOverride := portOption
	if clientPortFlagSet && *clientPort != 0 {
		portOverride = uint16(*clientPort)
	}
	addressFamily := 0
	if *v4Only {
		addressFamily = 4
	}
	if *v6Only {
		addressFamily = 6
	}

	if proxyJumpResolved != "" {
		if _, err := parseProxyJumpChain(proxyJumpResolved); err != nil {
			log.Error().Msgf("%s", err)
			return -1
		}
	}
	if len(reverseForwardsFlag) > 0 && controlMasterResolved != "no" {
		log.Error().Msgf("-R is not compatible with -M/-control-master")
		return -1
	}
	if len(reverseForwardsFlag) > 0 && *transferMode {
		fmt.Fprintln(os.Stderr, "-R cannot be combined with -transfer")
		return -1
	}
	if controlMasterResolved != "no" && proxyJumpResolved != "" {
		log.Error().Msgf("-M/-control-master is not compatible with -J/-proxy-jump")
		return -1
	}

	// ControlMaster fast path (stage 3.5): an explicit control path needs no
	// server-side material (keys, known hosts, cert pools) - a slave only
	// dials the control socket, so skip the heavy initialization entirely.
	// The default control path stays on the slow road below: it must be
	// computed from the full configuration to match the master's exactly.
	fastCM := runtime.GOOS != "windows" &&
		os.Getenv(cmDaemonEnv) != "1" &&
		controlPathResolved != "" &&
		(*controlOp != "" || controlMasterResolved == "yes" || controlMasterResolved == "auto")
	if fastCM {
		cmCtx := context.Background()
		if *controlOp != "" {
			opCtx, cancel := context.WithTimeout(cmCtx, 5*time.Second)
			defer cancel()
			return runControlOp(opCtx, controlPathResolved, *controlOp)
		}
		if !client.PingMaster(cmCtx, controlPathResolved) {
			if err := startDetachedMaster(); err != nil {
				log.Error().Msgf("could not start the detached control master: %s", err)
				return -1
			}
			if !waitForMaster(cmCtx, controlPathResolved, 10*time.Second) {
				log.Error().Msgf("the control master did not start")
				return -1
			}
			if len(args) <= 1 {
				return 0
			}
		}
		var cmTTY *os.File
		if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
			cmTTY = f
		}
		return runSlaveCommand(cmCtx, controlPathResolved, args[1:], cmTTY)
	}

	// dereference the tuning keys only after flag.Parse
	tuning := quicTuning{
		InitialPacketSize: uint16(*packetSize),
		StreamRxWindowMiB: *streamRxMiB,
		ConnRxWindowMiB:   *connRxMiB,
	}
	if len(reverseForwardsFlag) > 0 {
		// the server opens one forwarded channel per accepted -R connection
		// or UDP peer; the client's default incoming-stream limit (10) would
		// throttle them well below the server-side cap
		tuning.MaxIncomingStreams = 128
	}

	if displayVersionVar {
		fmt.Fprintln(os.Stdout, filepath.Base(os.Args[0]), "version", ssh3.GetCurrentSoftwareVersion())
		return 0
	}

	useOIDC := *issuerUrl != ""

	ssh3Dir := path.Join(homedir(), ".ssh3")
	os.MkdirAll(ssh3Dir, 0700)

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	switch {
	case *quiet && os.Getenv("SSH3_LOG_LEVEL") != "trace":
		util.ConfigureLogger("error")
	case *verbose && os.Getenv("SSH3_LOG_LEVEL") != "trace":
		util.ConfigureLogger("debug")
	default:
		util.ConfigureLogger(os.Getenv("SSH3_LOG_LEVEL"))
	}

	if len(args) == 0 {
		log.Error().Msgf("no remote host specified, exit")
		flag.Usage()
		os.Exit(-1)
	}

	log.Debug().Msgf("version %s", ssh3.GetCurrentSoftwareVersion())

	if *noPKCE {
		log.Warn().Msgf("Disabling PKCE is considered insecure to machine-in-the-middle attacks. Consider enabling PKCE by default!")
	}

	knownHostsPath := path.Join(ssh3Dir, "known_hosts")
	knownHosts, skippedLines, err := ssh3.ParseKnownHosts(knownHostsPath)
	if len(skippedLines) != 0 {
		stringSkippedLines := []string{}
		for _, lineNumber := range skippedLines {
			stringSkippedLines = append(stringSkippedLines, fmt.Sprintf("%d", lineNumber))
		}
		log.Warn().Msgf("the following lines in %s are invalid: %s", knownHostsPath, strings.Join(stringSkippedLines, ", "))
	}
	if err != nil {
		log.Error().Msgf("there was an error when parsing known hosts: %s", err)
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		if runtime.GOOS == "windows" {
			// there is no /dev/tty on Windows: the console is reached
			// through the standard input handle
			tty = os.Stdin
		} else {
			tty = nil
		}
	}

	fileTransferTarget := transferTarget{}
	fileTransferLocal := ""
	fileTransferUpload := false
	urlFromParam := args[0]
	command := args[1:]

	if *noSession && *transferMode {
		fmt.Fprintln(os.Stderr, "-N cannot be combined with -transfer")
		return -1
	}

	if subsystemName != "" {
		// a subsystem owns the session channel: it cannot be combined with the
		// modes that also want it, nor with a remote command to run instead
		if *transferMode {
			fmt.Fprintln(os.Stderr, "-s cannot be combined with -transfer")
			return -1
		}
		if *noSession {
			fmt.Fprintln(os.Stderr, "-s cannot be combined with -N")
			return -1
		}
		if len(args) > 1 {
			fmt.Fprintln(os.Stderr, "-s cannot be combined with a remote command")
			return -1
		}
		if forwardAgentVar || len(reverseForwardsFlag) > 0 {
			fmt.Fprintln(os.Stderr, "-s cannot be combined with -A/-forward-agent or -R")
			return -1
		}
	}

	// the transfer-mode port: the ssh2 -p wins over the deprecated -P
	transferDefaultPort := *transferPort
	if portOverride != 0 {
		transferDefaultPort = int(portOverride)
	}

	if *transferMode {
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "file transfer mode expects exactly two operands: one user@host:remote_path and one local path")
			return -1
		}
		switch {
		case isRemoteTransferSpec(args[0]) && !isRemoteTransferSpec(args[1]):
			// remote operand is the source: download to the local path
			target, _, _, err := parseRemoteTransferSpec(args[0], transferDefaultPort, *transferURLPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
				return -1
			}
			fileTransferTarget, fileTransferLocal, fileTransferUpload = target, args[1], false
		case isRemoteTransferSpec(args[1]) && !isRemoteTransferSpec(args[0]):
			// remote operand is the destination: upload from the local path
			target, _, _, err := parseRemoteTransferSpec(args[1], transferDefaultPort, *transferURLPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
				return -1
			}
			fileTransferTarget, fileTransferLocal, fileTransferUpload = target, args[0], true
		default:
			fmt.Fprintln(os.Stderr, "file transfer mode expects exactly one remote operand in the user@host:remote_path form")
			return -1
		}
		urlFromParam = buildTransferURL(fileTransferTarget).String()
		command = nil
	} else if !strings.HasPrefix(urlFromParam, "https://") {
		urlFromParam = fmt.Sprintf("https://%s", urlFromParam)
	}

	if *noSession && len(command) > 0 {
		fmt.Fprintln(os.Stderr, "-N does not accept a remote command")
		return -1
	}

	// the deprecated fork-form forward flags join the ssh2 -L list, parsed
	// with their historical localport/remoteip@remoteport shape; unlike the
	// old code, a parse error aborts instead of continuing with nil addresses
	if *forwardUDP != "" {
		localPort, remoteIP, remotePort, err := parseAddrPort(*forwardUDP)
		if err != nil {
			log.Error().Msgf("UDP forwarding parsing error %s", err)
			return -1
		}
		localForwardsFlag = append(localForwardsFlag, localForwardSpec{
			BindPort:   uint16(localPort),
			TargetHost: remoteIP.String(),
			TargetPort: uint16(remotePort),
			Protocol:   util.SSHProtocolUDP,
		})
	}
	if *forwardTCP != "" {
		localPort, remoteIP, remotePort, err := parseAddrPort(*forwardTCP)
		if err != nil {
			log.Error().Msgf("TCP forwarding parsing error %s", err)
			return -1
		}
		localForwardsFlag = append(localForwardsFlag, localForwardSpec{
			BindPort:   uint16(localPort),
			TargetHost: remoteIP.String(),
			TargetPort: uint16(remotePort),
			Protocol:   util.SSHForwardingProtocolTCP,
		})
	}

	var sshConfig *matchcfg.Resolver
	var configBytes []byte
	configPath := resolveConfigPath(*configFileFlag)
	configBytes, err = os.ReadFile(configPath)
	if err == nil {
		sshConfig, err = matchcfg.New(configPath, configBytes)
		if err != nil {
			log.Warn().Msgf("could not parse %s: %s, ignoring config", configPath, err)
			sshConfig = nil
		}
	} else if !os.IsNotExist(err) {
		log.Warn().Msgf("could not open %s: %s, ignoring config", configPath, err)
		sshConfig = nil
	}

	// default to oidc if no password or privkey
	var oidcConfig oidc.OIDCIssuerConfig = nil
	var oidcConfigFile *os.File = nil
	if *oidcConfigFileName == "" {
		defaultFileName := path.Join(ssh3Dir, "oidc_config.json")
		log.Debug().Msgf("no OIDC config file specified, use default file: %s", defaultFileName)
		oidcConfigFile, err = os.Open(defaultFileName)
		if os.IsNotExist(err) {
			log.Debug().Msgf("%s does not exist", defaultFileName)
		} else if err != nil {
			log.Warn().Msgf("could not open %s: %s", defaultFileName, err.Error())
		}
	} else {
		log.Debug().Msgf("open OIDC config from %s", *oidcConfigFileName)
		oidcConfigFile, err = os.Open(*oidcConfigFileName)
		if err != nil {
			log.Error().Msgf("could not open %s: %s", *oidcConfigFileName, err.Error())
			return -1
		}
	}

	if oidcConfigFile != nil {
		data, err := io.ReadAll(oidcConfigFile)
		if err != nil {
			log.Error().Msgf("could not read oidc config file: %s", err.Error())
			return -1
		}
		if err = json.Unmarshal(data, &oidcConfig); err != nil {
			log.Error().Msgf("could not parse oidc config file: %s", err.Error())
			return -1
		}
		log.Debug().Msgf("successfully parsed OIDC config")
	}

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal().Msgf("%s", err)
		}
		defer f.Close()
		keyLog = f
	}

	var cliAuthMethods []interface{}
	// Only do privkey and agent auth if OIDC is not asked explicitly
	if !useOIDC {
		if *passwordAuthentication {
			cliAuthMethods = append(cliAuthMethods, ssh3.NewPasswordAuthMethod())
		}
	} else {
		// for now, only perform OIDC if it was explicitly asked by the user
		if *issuerUrl != "" {
			log.Debug().Msgf("add OIDC auth, %d issuers in configs", len(oidcConfig))
			for _, issuerConfig := range oidcConfig {
				if *issuerUrl == issuerConfig.IssuerUrl {
					log.Debug().Msgf("found issuer %s matching the issuer specified in the command-line", issuerConfig.IssuerUrl)
					cliAuthMethods = append(cliAuthMethods, ssh3.NewOidcAuthMethod(!*noPKCE, issuerConfig))
				} else {
					log.Debug().Msgf("issuer %s does not match issuer URL %s specified in the command-line", issuerConfig.IssuerUrl, *issuerUrl)
				}
			}
		} else {
			log.Error().Msgf("OIDC was asked explicitly but did not find suitable issuer URL")
			return -1
		}
	}

	parsedUrl, err := url.Parse(urlFromParam)
	if err != nil {
		log.Error().Msgf("could not parse URL: %s", err)
		return -1
	}

	ctx := context.Background()

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal().Msgf("%s", err)
	}

	optionsParsers, err := internal.GetPluginsClientOptionsParsers()
	if err != nil {
		log.Error().Msgf("Could not get plugins options parsers: %s", err)
		return -1
	}
	agentClient, options, err := getConnectionMaterialFromURL(parsedUrl, sshConfig, cliAuthMethods, cliOptions, optionsParsers, portOverride, userOption)
	if err != nil {
		log.Error().Msgf("Could not get connection material for %s: %s", parsedUrl, err)
		return -1
	}

	// ~/.ssh/config extensions (stage 3): ServerAliveInterval tunes the QUIC
	// keepalive, ForwardAgent defaults the -forward-agent flag, ProxyJump is
	// honored as an alias of the fork's UDPProxyJump (the jump host must run
	// ssh3-server). Include directives are resolved by the config library.
	tuning.KeepAlivePeriod = time.Second
	requestTTYConfig := "" // the ~/.ssh/config RequestTTY value, empty when unset
	termTypeConfig := ""   // the ~/.ssh/config Term value, empty when unset
	escapeCharConfig := "" // the ~/.ssh/config EscapeChar value, empty when unset
	if sshConfig != nil {
		hostname := parsedUrl.Hostname()
		if v, err := sshConfig.Get(hostname, "ServerAliveInterval"); err == nil && v != "" {
			if secs, convErr := strconv.Atoi(v); convErr == nil && secs > 0 {
				tuning.KeepAlivePeriod = time.Duration(secs) * time.Second
				log.Debug().Msgf("ServerAliveInterval=%d from ~/.ssh/config", secs)
			}
		}
		if v, err := sshConfig.Get(hostname, "ForwardAgent"); err == nil && strings.EqualFold(v, "yes") {
			forwardAgentVar = true
		}
		if v, err := sshConfig.Get(hostname, "RequestTTY"); err == nil && v != "" {
			policy, policyErr := parseRequestTTY(v)
			if policyErr != nil {
				log.Error().Msgf("%s", policyErr)
				return -1
			}
			requestTTYConfig = policy
		}
		if v, err := sshConfig.Get(hostname, "Term"); err == nil && v != "" {
			term, termErr := parseTermType(v)
			if termErr != nil {
				log.Error().Msgf("%s", termErr)
				return -1
			}
			termTypeConfig = term
		}
		if v, err := sshConfig.Get(hostname, "EscapeChar"); err == nil && v != "" {
			if _, err := parseEscapeChar(v); err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			escapeCharConfig = v
		}
		if proxyJumpResolved == "" {
			if v, err := sshConfig.Get(hostname, "UDPProxyJump"); err == nil && v != "" {
				proxyJumpResolved = v
			} else if v, err := sshConfig.Get(hostname, "ProxyJump"); err == nil && v != "" {
				proxyJumpResolved = v
			}
		}
	}

	// StrictHostKeyChecking resolution (OpenSSH parity): an explicit
	// -strict-host-key-checking wins over -o StrictHostKeyChecking, which wins
	// over the ~/.ssh/config keyword; the default "ask" keeps the historical
	// interactive TOFU behaviour
	var strictConfigValue string
	var verifyHostKeyDNSConfigValue string
	if strictSshConfig, err := sshConfig.ConfigForHost(parsedUrl.Hostname(), options.Username()); err == nil && strictSshConfig != nil {
		if v, err := strictSshConfig.Get(parsedUrl.Hostname(), "StrictHostKeyChecking"); err == nil {
			strictConfigValue = v
		}
		if v, err := strictSshConfig.Get(parsedUrl.Hostname(), "VerifyHostKeyDNS"); err == nil {
			verifyHostKeyDNSConfigValue = v
		}
	}
	strictHostKeyChecking, err := ssh3.ResolveStrictHostKeyChecking(strictFlagSet, *strictHostKeyCheckingFlag, strictOptionValue, strictConfigValue)
	if err != nil {
		log.Error().Msgf("could not resolve StrictHostKeyChecking: %s", err)
		return -1
	}

	// VerifyHostKeyDNS resolution: -o wins over the ssh config keyword, and
	// the default "no" keeps the historical silent behaviour (an explicit
	// "no" in -o must still override a "yes" coming from the config file).
	verifyHostKeyDNSValue := verifyHostKeyDNSConfigValue
	if verifyHostKeyDNSOptionSet {
		verifyHostKeyDNSValue = verifyHostKeyDNSOptionValue
	}
	verifyHostKeyDNS, err := parseVerifyHostKeyDNSValue(verifyHostKeyDNSValue)
	if err != nil {
		log.Error().Msgf("could not resolve VerifyHostKeyDNS: %s", err)
		return -1
	}
	if verifyHostKeyDNS.Mode != ssh3.VerifyHostKeyDNSNo {
		log.Debug().Msgf("VerifyHostKeyDNS=%s", describeVerifyHostKeyDNS(verifyHostKeyDNS))
	}
	if (controlMasterResolved == "yes" || controlMasterResolved == "auto") && proxyJumpResolved != "" {
		log.Error().Msgf("-M/-control-master is not compatible with -J/-proxy-jump (from the command line or ~/.ssh/config)")
		return -1
	}

	// The ssh2 `-f` background form: re-exec a detached child that runs the
	// full startup itself (the Go runtime cannot fork an established
	// connection). Every refusal happens here, in the parent — the child has
	// no terminal and would die silently instead of reporting. Windows stays
	// in the foreground like the control master.
	if *backgroundFlag && os.Getenv(backgroundEnv) != "1" {
		if !backgroundSupportedOnOS() {
			log.Warn().Msgf("-f: backgrounding is unavailable on windows, running the session in the foreground")
		} else {
			_, pinned := knownHosts[options.CanonicalHostFormat()]
			bgErr := validateBackgroundMode(backgroundOptions{
				PasswordAuth:  *passwordAuthentication,
				OIDC:          useOIDC,
				ControlMaster: controlMasterResolved,
				Strict:        strictHostKeyChecking,
				HostPinned:    pinned,
				HasCommand:    len(command) > 0,
				NoSession:     *noSession,
				HasForwards:   len(localForwardsFlag) > 0 || len(dynamicForwardsFlag) > 0 || len(reverseForwardsFlag) > 0 || *transferMode,
			})
			if bgErr != nil {
				log.Error().Msgf("%s", bgErr)
				return -1
			}
			pid, err := startDetached(backgroundEnv)
			if err != nil {
				log.Error().Msgf("-f: could not start the background session: %s", err)
				return -1
			}
			log.Info().Msgf("-f: the session continues in the background (pid %d)", pid)
			return 0
		}
	}

	// --- ControlMaster (stage 3.5) ---
	controlPath := controlPathResolved
	if controlPath == "" {
		controlPath = path.Join(ssh3Dir, fmt.Sprintf("cm-%s@%s:%d", options.Username(), options.Hostname(), options.Port()))
	}
	if *controlOp != "" {
		opCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return runControlOp(opCtx, controlPath, *controlOp)
	}
	if controlMasterResolved == "yes" || controlMasterResolved == "auto" {
		if runtime.GOOS == "windows" {
			log.Warn().Msgf("control-master is not supported on windows yet, running a direct session")
		} else if os.Getenv(cmDaemonEnv) == "1" {
			// this process is the detached master: connect and serve the
			// control socket; it never runs sessions itself
			idleTimeout, _ := parseControlPersist(controlPersistResolved)
			qconn, status := setupQUICConnection(ctx, *insecure, keyLog, ssh3Dir, pool, knownHostsPath, knownHosts, strictHostKeyChecking, verifyHostKeyDNS, oidcConfig, options, nil, nil, tuning, addressFamily)
			if qconn == nil {
				return status
			}
			transport := &http3.Transport{}
			c, err := client.Dial(ctx, options, qconn, transport, nil, client.WithMultiplexed())
			if err != nil {
				log.Error().Msgf("the control master could not establish its connection: %s", err)
				return -1
			}
			defer c.Close()
			ln, err := client.ListenControlMaster(controlPath)
			if err != nil {
				log.Error().Msgf("could not listen on the control socket: %s", err)
				return -1
			}
			log.Debug().Msgf("control master serving on %s", controlPath)
			serveCtx := context.Background() // detached: only -O exit or the idle timeout end it
			if err := client.ServeControlMaster(serveCtx, c, ln, &client.MasterOptions{IdleTimeout: idleTimeout}); err != nil {
				log.Error().Msgf("control master stopped: %s", err)
				return -1
			}
			return 0
		} else if client.PingMaster(ctx, controlPath) {
			// a master is already serving: run this invocation as a slave
			return runSlaveCommand(ctx, controlPath, command, tty)
		} else if _, ok := parseControlPersist(controlPersistResolved); ok {
			// no master yet: spawn one detached, then run as a slave
			if err := startDetachedMaster(); err != nil {
				log.Error().Msgf("could not start the detached control master: %s", err)
				return -1
			}
			if !waitForMaster(ctx, controlPath, 10*time.Second) {
				log.Error().Msgf("the control master did not start")
				return -1
			}
			if len(command) == 0 {
				return 0
			}
			return runSlaveCommand(ctx, controlPath, command, tty)
		}
		// control-master requested with control-persist=no: a master without
		// persist cannot outlive this process, run a direct session instead
	}

	// -J / -proxy-jump: the hop chain tunnels UDP hop by hop, the last hop
	// towards the final destination. The -p/-o Port and -o User overrides do
	// not apply to the hops: each -J destination carries its own user@host.
	var proxyAddress *net.UDPAddr
	var outerSize uint16
	proxyHopCount := 0
	if proxyJumpResolved != "" {
		hops, err := parseProxyJumpChain(proxyJumpResolved)
		if err != nil {
			log.Error().Msgf("%s", err)
			return -1
		}
		proxyHopCount = len(hops)
		outerSize = tunnelOuterSize(uint16(*packetSize), proxyHopCount)
		for hopIndex, hop := range hops {
			hopUrl := hop
			if !strings.HasPrefix(hopUrl, "https://") {
				hopUrl = fmt.Sprintf("https://%s", hopUrl)
			}
			proxyParsedUrl, err := url.Parse(hopUrl)
			if err != nil {
				log.Error().Msgf("Could not parse proxy host URL %s: %s", hopUrl, err)
				return -1
			}
			proxyAgentClient, proxyOptions, err := getConnectionMaterialFromURL(proxyParsedUrl, sshConfig, cliAuthMethods, cliOptions, optionsParsers, 0, "")
			if err != nil {
				log.Error().Msgf("Could not get connection material for proxy %s: %s", hopUrl, err)
				return -1
			}
			// the hop is dialed through the previous hops: its QUIC packets
			// travel as SSH3 datagrams of the outer connection, so its packet
			// size has to leave room for the datagram framing
			hopTuning := tuning
			hopPacketSize, err := tunneledPacketSize(outerSize, hopIndex)
			if err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			hopTuning.InitialPacketSize = hopPacketSize
			qconn, status := setupQUICConnection(ctx, *insecure, keyLog, ssh3Dir, pool, knownHostsPath, knownHosts, strictHostKeyChecking, verifyHostKeyDNS, oidcConfig, proxyOptions, proxyAddress, tty, hopTuning, addressFamily)

			if qconn == nil {
				if status != 0 {
					log.Error().Msgf("could not setup transport for proxy hop %s.", hop)
				}
				return status
			}

			// no EnableDatagrams: ssh3 carries UDP forwarding over the raw QUIC
			// datagram API, and the HTTP/3 datagram layer would compete with it for
			// datagrams on the same connection
			transport := &http3.Transport{}

			proxyClient, err := client.Dial(ctx, proxyOptions, qconn, transport, proxyAgentClient)
			if err != nil {
				log.Error().Msgf("could not establish SSH3 proxy conversation: %s", err)
				return -1
			}

			// each hop tunnels UDP towards the next one; the last hop tunnels
			// towards the final destination
			udpTarget := options.URLHostnamePort()
			if hopIndex+1 < len(hops) {
				nextUrl := hops[hopIndex+1]
				if !strings.HasPrefix(nextUrl, "https://") {
					nextUrl = fmt.Sprintf("https://%s", nextUrl)
				}
				nextParsedUrl, err := url.Parse(nextUrl)
				if err != nil {
					log.Error().Msgf("Could not parse proxy host URL %s: %s", nextUrl, err)
					return -1
				}
				udpTarget = urlHostPort(nextParsedUrl)
			}
			baseAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
			if err != nil {
				log.Error().Msgf("Could not resolve 127.0.0.1:0: %s", err)
				return -1
			}
			remoteAddr, err := net.ResolveUDPAddr("udp", udpTarget)
			if err != nil {
				log.Error().Msgf("Could not resolve remote address %s: %s", udpTarget, err)
				return -1
			}
			addr, err := proxyClient.ForwardUDP(ctx, baseAddr, remoteAddr)
			if err != nil {
				log.Error().Msgf("Could not forward UDP for proxy jump: %s", err)
				return -1
			}
			proxyAddress = addr
			log.Debug().Msgf("proxy hop %d (%s) forwards UDP towards %s", hopIndex+1, hop, udpTarget)
		}
	}

	// the destination is dialed through every proxy hop: its QUIC packets
	// travel as SSH3 datagrams of the last hop, so its packet size has to
	// leave room for the datagram framing of every level
	destinationTuning := tuning
	if proxyJumpResolved != "" {
		destinationPacketSize, err := tunneledPacketSize(outerSize, proxyHopCount)
		if err != nil {
			log.Error().Msgf("%s", err)
			return -1
		}
		destinationTuning.InitialPacketSize = destinationPacketSize
	}

	qconn, status := setupQUICConnection(ctx, *insecure, keyLog, ssh3Dir, pool, knownHostsPath, knownHosts, strictHostKeyChecking, verifyHostKeyDNS, oidcConfig, options, proxyAddress, tty, destinationTuning, addressFamily)

	if qconn == nil {
		if status != 0 {
			log.Error().Msgf("could not setup transport for client")
		}
		return status
	}

	// no EnableDatagrams: ssh3 carries UDP forwarding over the raw QUIC datagram
	// API, and the HTTP/3 datagram layer would compete with it for datagrams on
	// the same connection
	transport := &http3.Transport{}

	c, err := client.Dial(ctx, options, qconn, transport, agentClient)
	if err != nil {
		log.Error().Msgf("could not dial %s: %s", options.CanonicalHostFormat(), err)
		return -1
	}
	if len(reverseForwardsFlag) > 0 {
		if err := c.SetReverseForwards(reverseForwardsFlag); err != nil {
			log.Error().Msgf("could not set up reverse forwarding: %s", err)
			return -1
		}
		for _, forward := range reverseForwardsFlag {
			if err := c.RequestReverseForward(forward); err != nil {
				log.Error().Msgf("reverse forwarding request for -R %s failed: %s", forward.SpecString(), err)
				return -1
			}
		}
	}
	// -L/-D: the local listeners ride the connection just established. They
	// only need the SSH3 conversation, so they are set up before any session
	// channel and stay usable for the whole lifetime of the invocation.
	for _, forward := range localForwardsFlag {
		switch forward.Protocol {
		case util.SSHForwardingProtocolTCP:
			remoteTCPAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(forward.TargetHost, strconv.Itoa(int(forward.TargetPort))))
			if err != nil {
				log.Error().Msgf("could not resolve -L target %s:%d: %s", forward.TargetHost, forward.TargetPort, err)
				return -1
			}
			localTCPAddr, err := localListenTCPAddr(forward, remoteTCPAddr.IP)
			if err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			if _, err := c.ForwardTCP(ctx, localTCPAddr, remoteTCPAddr); err != nil {
				log.Error().Msgf("could not set up local TCP forwarding: %s", err)
				return -1
			}
			log.Debug().Msgf("local TCP forwarding from %s to %s", localTCPAddr, remoteTCPAddr)
		case util.SSHProtocolUDP:
			remoteUDPAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(forward.TargetHost, strconv.Itoa(int(forward.TargetPort))))
			if err != nil {
				log.Error().Msgf("could not resolve -L UDP target %s:%d: %s", forward.TargetHost, forward.TargetPort, err)
				return -1
			}
			localUDPAddr, err := localListenUDPAddr(forward, remoteUDPAddr.IP)
			if err != nil {
				log.Error().Msgf("%s", err)
				return -1
			}
			if _, err := c.ForwardUDP(ctx, localUDPAddr, remoteUDPAddr); err != nil {
				log.Error().Msgf("could not set up local UDP forwarding: %s", err)
				return -1
			}
			log.Debug().Msgf("local UDP forwarding from %s to %s", localUDPAddr, remoteUDPAddr)
		}
	}

	// -D: open one local SOCKS5 listener per specification.
	var dynamicForwarders []*dynamicForwarder
	for _, spec := range dynamicForwardsFlag {
		forwarder, err := startDynamicForward(ctx, c.Conversation, spec)
		if err != nil {
			log.Error().Msgf("could not set up dynamic forwarding: %s", err)
			return -1
		}
		dynamicForwarders = append(dynamicForwarders, forwarder)
		defer func() {
			forwarder.Close()
			forwarder.Wait()
		}()
		if spec.BindPort == 0 {
			log.Info().Msgf("dynamic SOCKS proxy listening on %s (allocated port)", forwarder.ListenAddr())
		} else {
			log.Info().Msgf("dynamic SOCKS proxy listening on %s", forwarder.ListenAddr())
		}
	}

	if *transferMode {
		return runFileTransfer(c, fileTransferTarget, fileTransferLocal, fileTransferUpload, *recursive, *resumeMode, *verifyChecksum)
	}

	// RequestTTY resolution (OpenSSH precedence): the -T/-t flags are the
	// CLI absolutes, the -o option overrides the ~/.ssh/config keyword, auto
	// is the default
	requestTYTPolicy := "auto"
	if requestTTYConfig != "" {
		requestTYTPolicy = requestTTYConfig
	}
	if requestTTYOption != "" {
		requestTYTPolicy = requestTTYOption
	}
	if *noPTY {
		requestTYTPolicy = "no"
	}
	if *forcePTY {
		if *noPTY {
			fmt.Fprintln(os.Stderr, "-t and -T are mutually exclusive")
			return -1
		}
		requestTYTPolicy = "force"
	}

	// Term resolution (OpenSSH precedence): the -o option overrides the
	// ~/.ssh/config keyword, then the local TERM environment variable applies,
	// then the built-in 256-color default
	termType := resolveTermType(termTypeOption, termTypeConfig)

	// the interactive escape character: the -o option overrides the
	// ~/.ssh/config keyword, ~ is the OpenSSH default, none disables
	escapeCharStr := "~"
	if escapeCharConfig != "" {
		escapeCharStr = escapeCharConfig
	}
	if escapeCharOption != "" {
		escapeCharStr = escapeCharOption
	}
	escapeChar, err := parseEscapeChar(escapeCharStr)
	if err != nil {
		log.Error().Msgf("%s", err)
		return -1
	}
	var escapeCfg *client.EscapeConfig
	if escapeChar != 0 {
		escapeCfg = &client.EscapeConfig{
			Char: escapeChar,
			Disconnect: func() error {
				log.Info().Msgf("connection closed by the %q escape sequence", string(escapeChar))
				c.Close()
				return nil
			},
		}
	}

	// -s requests a subsystem instead of a shell or a command: it owns the
	// session channel, so it is dispatched before the shell/exec path and is
	// mutually exclusive with it.
	if subsystemName != "" {
		if *noSession {
			fmt.Fprintln(os.Stderr, "-s cannot be combined with -N")
			return -1
		}
		if subsystemName == sftpSubsystemName {
			return runSFTPSubsystem(c.Conversation)
		}
		if err := runSubsystemSession(ctx, c, tty, subsystemName, requestTYTPolicy == "force", termType); err != nil {
			log.Error().Msgf("an error was encountered when running the %s subsystem: %s", subsystemName, err)
			return -1
		}
		return 0
	}

	if *noSession {
		log.Info().Msgf("-N: holding the connection open for the forwards until interrupted")
		if len(reverseForwardsFlag) > 0 || len(localForwardsFlag) > 0 || len(dynamicForwarders) > 0 {
			// no session channel to start the dispatch loop implicitly
			c.StartAcceptLoop()
		}
		sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		<-sigCtx.Done()
		log.Debug().Msgf("interrupted: closing the connection")
		c.Close()
		return 0
	}

	// -t forces a PTY even when the local input is not a terminal, which the
	// regular session path cannot do: RunSession only allocates one when it
	// finds a TTY.
	if *forcePTY || requestTYTPolicy == "force" {
		err = runForcedPtySession(ctx, c, tty, forwardAgentVar, escapeCfg, termType, command...)
		if errors.Is(err, client.ErrEscapeDisconnect) {
			return 255
		}
		switch sessionError := err.(type) {
		case client.ExitStatus:
			log.Info().Msgf("the process exited with status %d", sessionError.StatusCode)
			return sessionError.StatusCode
		case client.ExitSignal:
			log.Error().Msgf("the process exited with signal %s: %s", sessionError.Signal, sessionError.ErrorMessageUTF8)
			return exitCodeForExitSignal(sessionError.Signal)
		default:
			log.Error().Msgf("an error was encountered when running the session: %s", sessionError)
			return -1
		}
	}

	err = c.RunSession(tty, forwardAgentVar, requestTYTPolicy, termType, escapeCfg, command...)
	if errors.Is(err, client.ErrEscapeDisconnect) {
		// the user tore the session down with the ~. escape sequence:
		// the exit code matches a closed connection, as OpenSSH
		return 255
	}
	switch sessionError := err.(type) {
	case client.ExitStatus:
		log.Info().Msgf("the process exited with status %d", sessionError.StatusCode)
		return sessionError.StatusCode
	case client.ExitSignal:
		log.Error().Msgf("the process exited with signal %s: %s", sessionError.Signal, sessionError.ErrorMessageUTF8)
		return exitCodeForExitSignal(sessionError.Signal)
	default:
		log.Error().Msgf("an error was encountered when running the session: %s", sessionError)
		return -1
	}
}
