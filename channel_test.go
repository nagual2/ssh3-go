package ssh3

import (
	"encoding/hex"
	"net"
	"testing"
)

// The resolver hands out IPv4 as the 16-byte mapped ::ffff:a.b.c.d form,
// and the wire contract says the family is the only length promise: a
// mapped address must go out as family 4 with the four v4 bytes, not as
// family 6 with the v4 bytes hidden inside (the C port refuses that
// shape, the go server used to accept it - the divergence a cross run
// found).
func TestForwardingBytesNormalizeMappedV4(t *testing.T) {
	cases := []struct {
		name string
		ip   net.IP
		want string
	}{
		{"the plain 4-byte form", net.ParseIP("1.1.1.1").To4(), "04010101010050"},
		{"the resolver's mapped form", net.ParseIP("1.1.1.1").To16(), "04010101010050"},
		{
			"a real v6 stays v6",
			net.ParseIP("2a11:6c7:1102:f000::1fa"),
			"06" + "2a1106c71102f000" + "00000000000001fa" + "0050",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildForwardingChannelAdditionalBytes(tc.ip, 80)
			if hex.EncodeToString(got) != tc.want {
				t.Errorf("buildForwardingChannelAdditionalBytes(%s) = %s, want %s",
					tc.ip, hex.EncodeToString(got), tc.want)
			}
		})
	}
}
