package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
)

// The per-address connect cap of the resolver walk (the C canon 6381b32,
// the v0.5.17 fetch walk): the shared deadline gave the first dead address
// the whole window — the blackhole prefixes (the SYN leaves, no answer)
// ate it and the reachable address never got its turn. The cap marks the
// path dead enough to move on while the whole-dial deadline stays.

// dialConnectCap is the per-address connect budget of a multi-address
// walk: five seconds either connect the address or mark it dead.
const dialConnectCap = 5 * time.Second

// walkStopsOnDialError classifies the dial error of the walk: a crypto
// error means the server answered with a broken handshake — the next
// address of the same name rides the same verdict, so the walk stops and
// the capture/AIA/TOFU flow takes over; any other error (the timeout of
// the cap, the unreachable network) marks the address dead and the walk
// moves on.
func walkStopsOnDialError(err error) bool {
	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) && transportErr.ErrorCode.IsCryptoError() {
		return true
	}
	return false
}

// walkResolvedAddrs walks the resolved addresses of the destination in the
// resolver order. When the destination resolves to several addresses, every
// attempt rides a dialConnectCap slice of the whole-dial deadline — a
// blackholed address cannot eat the whole window and the reachable address
// keeps its turn; a single-address walk hands the caller's context over
// unchanged (the R13-2 ConnectTimeout canon: there is no next address to
// save it for, so the whole deadline waits on the only address). The walk
// returns the first address that connected, or the address a crypto error
// stopped it on, or the last error when every address failed.
func walkResolvedAddrs(ctx context.Context, addrs []*net.UDPAddr, dial func(ctx context.Context, addr *net.UDPAddr) error) (*net.UDPAddr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var lastErr error
	for _, addr := range addrs {
		attemptCtx, cancel := ctx, context.CancelFunc(func() {})
		if len(addrs) > 1 {
			// WithTimeout cannot outlive the parent: the whole-dial deadline
			// stays when the cap is longer than the remaining budget
			attemptCtx, cancel = context.WithTimeout(ctx, dialConnectCap)
		}
		err := dial(attemptCtx, addr)
		cancel()
		if err == nil {
			return addr, nil
		}
		lastErr = err
		if walkStopsOnDialError(err) {
			return addr, err
		}
		log.Debug().Msgf("the address %s of the destination did not connect (%s), moving to the next resolved address", addr, err)
	}
	return nil, lastErr
}

// dialAddrsFromIPs builds the walk list of the resolved IPs: the resolver
// order stays, the forced -4/-6 family filters per address, and a filter
// that empties the list refuses with the ssh2 family mismatch wording of
// the single-address shape.
func dialAddrsFromIPs(ips []net.IP, port int, addressFamily int, host string) ([]*net.UDPAddr, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("no address for %s", host)
	}
	var addrs []*net.UDPAddr
	for _, ip := range ips {
		if addressFamily == 4 && ip.To4() == nil {
			continue
		}
		if addressFamily == 6 && ip.To4() != nil {
			continue
		}
		addrs = append(addrs, &net.UDPAddr{IP: ip, Port: port})
	}
	if len(addrs) == 0 {
		if addressFamily == 4 {
			return nil, fmt.Errorf("-4: %s resolves to an IPv6 address", host)
		}
		return nil, fmt.Errorf("-6: %s resolves to an IPv4 address", host)
	}
	return addrs, nil
}

// resolveDialAddrs resolves the destination into the whole address list of
// the walk: the resolver order (RFC 6724), the forced ssh2 family filter
// riding per address.
func resolveDialAddrs(ctx context.Context, host string, port int, addressFamily int) ([]*net.UDPAddr, error) {
	looked, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(looked))
	for _, addr := range looked {
		ips = append(ips, addr.IP)
	}
	return dialAddrsFromIPs(ips, port, addressFamily, host)
}
