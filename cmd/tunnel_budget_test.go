package cmd

// Tests for the proxy-jump datagram budget: the QUIC packets of a tunneled
// connection travel as SSH3 datagrams of the outer connection, and quic-go
// only sends a datagram that fits into a single packet. The budget has to
// be reserved upfront, because the path MTU discovery cannot help the
// first datagram of the tunneled connection.
//
// The chain keeps its depth: the outermost connection takes a bigger
// packet (the framing cost of every level), so the innermost level stays
// above the QUIC minimum of 1200 bytes. The cost of that is the path:
// the outermost packet of a chain of N hops is 48*N bytes bigger than
// the plain one.

import "testing"

func TestTunneledPacketSize(t *testing.T) {
	tests := []struct {
		name    string
		outer   uint16
		level   int
		want    uint16
		wantErr bool
	}{
		{name: "the outermost connection of a plain session", outer: 1200, level: 0, want: 1200},
		{name: "one tunnel level", outer: 1248, level: 1, want: 1248 - tunnelDatagramOverhead},
		{name: "two tunnel levels", outer: 1296, level: 2, want: 1296 - 2*tunnelDatagramOverhead},
		{name: "too deep chain", outer: 1452, level: 6, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tunneledPacketSize(tt.outer, tt.level)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("tunneledPacketSize(%d, %d) returned no error", tt.outer, tt.level)
				}
				return
			}
			if err != nil {
				t.Fatalf("tunneledPacketSize(%d, %d) returned error: %s", tt.outer, tt.level, err)
			}
			if got != tt.want {
				t.Fatalf("tunneledPacketSize(%d, %d) = %d, want %d", tt.outer, tt.level, got, tt.want)
			}
			// the tunneled packets plus the SSH3 datagram framing must fit
			// into the datagram budget of the outer connection (the outer
			// initial packet size minus the QUIC packet overhead)
			if tt.level > 0 {
				outerBudget := int(tt.outer) - 37
				if int(got)+4 > outerBudget {
					t.Fatalf("the tunneled packet size %d does not fit into the datagram budget %d of the outer connection", got, outerBudget)
				}
			}
		})
	}
}

func TestTunnelOuterSize(t *testing.T) {
	tests := []struct {
		name  string
		base  uint16
		depth int
		want  uint16
	}{
		{name: "no hop", base: 1200, depth: 0, want: 1200},
		{name: "one hop", base: 1200, depth: 1, want: 1200 + tunnelDatagramOverhead},
		{name: "five hops", base: 1200, depth: 5, want: 1200 + 5*tunnelDatagramOverhead},
		{name: "the cap of the QUIC maximum", base: 1200, depth: 10, want: maxQUICPacketSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tunnelOuterSize(tt.base, tt.depth)
			if got != tt.want {
				t.Fatalf("tunnelOuterSize(%d, %d) = %d, want %d", tt.base, tt.depth, got, tt.want)
			}
		})
	}
}
