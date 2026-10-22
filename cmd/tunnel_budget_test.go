package cmd

// Tests for the proxy-jump datagram budget: the QUIC packets of a tunneled
// connection travel as SSH3 datagrams of the outer connection, and quic-go
// only sends a datagram that fits into a single packet. The budget has to be
// reserved upfront, because the path MTU discovery cannot help the first
// datagram of the tunneled connection.

import "testing"

func TestTunneledPacketSize(t *testing.T) {
	tests := []struct {
		name    string
		base    uint16
		depth   int
		want    uint16
		wantErr bool
	}{
		{name: "direct connection", base: 1350, depth: 0, want: 1350},
		{name: "one tunnel level", base: 1452, depth: 1, want: 1452 - tunnelDatagramOverhead},
		{name: "two tunnel levels", base: 1452, depth: 2, want: 1452 - 2*tunnelDatagramOverhead},
		{name: "too deep chain", base: 1200, depth: 3, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tunneledPacketSize(tt.base, tt.depth)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("tunneledPacketSize(%d, %d) returned no error", tt.base, tt.depth)
				}
				return
			}
			if err != nil {
				t.Fatalf("tunneledPacketSize(%d, %d) returned error: %s", tt.base, tt.depth, err)
			}
			if got != tt.want {
				t.Fatalf("tunneledPacketSize(%d, %d) = %d, want %d", tt.base, tt.depth, got, tt.want)
			}
			// the tunneled packets plus the SSH3 datagram framing must fit
			// into the datagram budget of the outer connection (the outer
			// initial packet size minus the QUIC packet overhead)
			if tt.depth > 0 {
				outerBudget := int(tt.base) - 37
				if int(got)+4 > outerBudget {
					t.Fatalf("the tunneled packet size %d does not fit into the datagram budget %d of the outer connection", got, outerBudget)
				}
			}
		})
	}
}
