package cmd

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// The per-address connect cap of the resolver walk (the C canon 6381b32,
// the v0.5.17 fetch walk): the shared deadline gave the first dead address
// the whole window — the blackhole prefixes ate it and the reachable
// address never got its turn. The cap marks the path dead enough to move
// on while the whole-dial deadline stays. The single-address walk keeps
// the whole setup deadline (the R13-2 ConnectTimeout canon: there is no
// next address to save it for).

func walkTestDialer(t *testing.T, budgets *[]time.Duration, outcomes map[string]error) func(context.Context, *net.UDPAddr) error {
	t.Helper()
	return func(attemptCtx context.Context, addr *net.UDPAddr) error {
		if attemptCtx == nil {
			t.Error("the walk passed a nil attempt context")
			return errors.New("nil attempt context")
		}
		if dl, ok := attemptCtx.Deadline(); ok {
			*budgets = append(*budgets, time.Until(dl))
		} else {
			*budgets = append(*budgets, 0)
		}
		return outcomes[addr.String()]
	}
}

func TestWalkResolvedAddrsCapsEachAddress(t *testing.T) {
	dead := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	live := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var budgets []time.Duration
	dial := walkTestDialer(t, &budgets, map[string]error{
		dead.String(): context.DeadlineExceeded, // the blackhole: the SYN leaves, no answer
		live.String(): nil,
	})

	chosen, err := walkResolvedAddrs(ctx, []*net.UDPAddr{dead, live}, dial)
	if err != nil {
		t.Fatalf("the walk returned an error: %s", err)
	}
	if chosen != live {
		t.Fatalf("the walk chose %s, want the live address %s", chosen, live)
	}
	if len(budgets) != 2 {
		t.Fatalf("the walk dialed %d times, want 2", len(budgets))
	}
	for i, budget := range budgets {
		if budget <= 0 {
			t.Errorf("attempt %d rode no deadline at all", i)
			continue
		}
		if budget > dialConnectCap+100*time.Millisecond {
			t.Errorf("attempt %d budget %v exceeds the per-address cap %v", i, budget, dialConnectCap)
		}
		if budget < dialConnectCap-500*time.Millisecond {
			t.Errorf("attempt %d budget %v is way below the per-address cap %v", i, budget, dialConnectCap)
		}
	}
}

func TestWalkResolvedAddrsSingleAddressKeepsWholeDeadline(t *testing.T) {
	only := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 3), Port: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var budgets []time.Duration
	dial := walkTestDialer(t, &budgets, map[string]error{only.String(): nil})

	chosen, err := walkResolvedAddrs(ctx, []*net.UDPAddr{only}, dial)
	if err != nil {
		t.Fatalf("the walk returned an error: %s", err)
	}
	if chosen != only {
		t.Fatalf("the walk chose %s, want %s", chosen, only)
	}
	if len(budgets) != 1 {
		t.Fatalf("the walk dialed %d times, want 1", len(budgets))
	}
	// the single-address walk hands the caller's context over unchanged: the
	// attempt budget stays the whole setup deadline (30 s), never the 5 s cap
	if budgets[0] <= dialConnectCap {
		t.Errorf("the single-address walk budget %v rode the per-address cap, want the whole setup deadline", budgets[0])
	}
}

func TestWalkResolvedAddrsStopsOnCryptoError(t *testing.T) {
	alive := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 4), Port: 1}
	next := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 5), Port: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cryptoErr := &quic.TransportError{ErrorCode: quic.TransportErrorCode(0x100)}
	dialedNext := false
	dial := func(attemptCtx context.Context, addr *net.UDPAddr) error {
		if addr == next {
			dialedNext = true
		}
		return cryptoErr
	}

	chosen, err := walkResolvedAddrs(ctx, []*net.UDPAddr{alive, next}, dial)
	if !errors.Is(err, cryptoErr) {
		t.Fatalf("the walk rode %v, want the crypto error", err)
	}
	if chosen != alive {
		t.Fatalf("the walk chose %s, want the crypto-stopped address %s", chosen, alive)
	}
	if dialedNext {
		t.Error("the walk moved past a crypto error: the server answered, the next address of the same name rides the same handshake verdict")
	}
}

func TestWalkResolvedAddrsExhaustsAndRidesLastError(t *testing.T) {
	first := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 6), Port: 1}
	second := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 7), Port: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	lastErr := errors.New("no route to host")
	var budgets []time.Duration
	dial := walkTestDialer(t, &budgets, map[string]error{
		first.String():  context.DeadlineExceeded,
		second.String(): lastErr,
	})

	chosen, err := walkResolvedAddrs(ctx, []*net.UDPAddr{first, second}, dial)
	if chosen != nil {
		t.Fatalf("the exhausted walk chose %s, want nil", chosen)
	}
	if !errors.Is(err, lastErr) {
		t.Fatalf("the exhausted walk rode %v, want the last address error", err)
	}
	if len(budgets) != 2 {
		t.Fatalf("the walk dialed %d times, want 2", len(budgets))
	}
}

func TestWalkResolvedAddrsSkipsDialOnSpentDeadline(t *testing.T) {
	any := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 8), Port: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cancel() // the setup deadline already spent before the walk started

	called := false
	dial := func(context.Context, *net.UDPAddr) error {
		called = true
		return nil
	}

	chosen, err := walkResolvedAddrs(ctx, []*net.UDPAddr{any}, dial)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("the spent walk rode %v, want the context error", err)
	}
	if chosen != nil {
		t.Fatalf("the spent walk chose %s, want nil", chosen)
	}
	if called {
		t.Error("the spent walk dialed an address anyway")
	}
}

func TestWalkStopsOnDialErrorClassification(t *testing.T) {
	cases := []struct {
		err   error
		stops bool
	}{
		{&quic.TransportError{ErrorCode: quic.TransportErrorCode(0x100)}, true}, // the CRYPTO frame error
		{&quic.TransportError{ErrorCode: quic.TransportErrorCode(0x1ff)}, true}, // the last CRYPTO frame error
		{&quic.TransportError{ErrorCode: quic.TransportErrorCode(0x0f)}, false}, // the NO_ERROR-style transport code
		{context.DeadlineExceeded, false},                                       // the blackhole timeout
		{errors.New("network is unreachable"), false},                           // the dead path
		{nil, false},
	}
	for _, c := range cases {
		if got := walkStopsOnDialError(c.err); got != c.stops {
			t.Errorf("walkStopsOnDialError(%v) = %v, want %v", c.err, got, c.stops)
		}
	}
}

func TestDialAddrsFromIPsFamilyFilter(t *testing.T) {
	v4 := net.IPv4(192, 0, 2, 10)
	v6 := net.ParseIP("2001:db8::10")
	if v4 == nil || v6 == nil {
		t.Fatal("the fixture addresses did not parse")
	}

	cases := []struct {
		family int
		want   []net.IP
	}{
		{0, []net.IP{v4, v6}}, // the auto rides the resolver order
		{4, []net.IP{v4}},     // the forced -4 keeps the v4 family only
		{6, []net.IP{v6}},     // the forced -6 keeps the v6 family only
	}
	for _, c := range cases {
		addrs, err := dialAddrsFromIPs([]net.IP{v4, v6}, 443, c.family, "walk.test")
		if err != nil {
			t.Fatalf("family %d: the filter returned an error: %s", c.family, err)
		}
		if len(addrs) != len(c.want) {
			t.Fatalf("family %d: the filter kept %d addresses, want %d", c.family, len(addrs), len(c.want))
		}
		for i, want := range c.want {
			if !addrs[i].IP.Equal(want) {
				t.Errorf("family %d: position %d carries %s, want %s", c.family, i, addrs[i].IP, want)
			}
		}
	}

	// the forced family over the wrong-only resolution refuses with the
	// ssh2 family mismatch wording of the single-address shape
	_, err := dialAddrsFromIPs([]net.IP{v6}, 443, 4, "walk.test")
	if err == nil {
		t.Error("the -4 filter over a v6-only resolution returned no error")
	} else if got := err.Error(); got != "-4: walk.test resolves to an IPv6 address" {
		t.Errorf("the -4 mismatch text = %q", got)
	}
	_, err = dialAddrsFromIPs([]net.IP{v4}, 443, 6, "walk.test")
	if err == nil {
		t.Error("the -6 filter over a v4-only resolution returned no error")
	} else if got := err.Error(); got != "-6: walk.test resolves to an IPv4 address" {
		t.Errorf("the -6 mismatch text = %q", got)
	}

	// the empty resolution refuses
	if _, err := dialAddrsFromIPs(nil, 443, 0, "walk.test"); err == nil {
		t.Error("the empty resolution returned no error")
	}
}
