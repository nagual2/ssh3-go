package cmd

import "testing"

// The bare-IPv6 operand hint (the C canon 35b2e64, the v0.5.15 ux wave):
// the unbracketed literal tears at the first colon — the host cuts to the
// first label and the dial fails with a misleading resolve or parse error.
// The honest shape check names the bracketed form before the branches: the
// colon with another colon in the remainder is the bare-IPv6 shape, the
// bracketed forms and the plain host:port splits stay out of it.

func TestOperandShapeBareIPv6(t *testing.T) {
	cases := []struct {
		operand string
		bare    bool
		coloned bool
	}{
		// the bare literals: the hint refuses them before the parse
		{"2001:db8::1", true, true},
		{"2001:db8:1", true, true},
		{"user@2001:db8::1", true, true},
		{"https://2001:db8::1", true, true},
		{"https://user@2001:db8::1", true, true},
		{"2001:db8::1/ssh3-term", true, true},
		{"https://2001:db8::1/ssh3-term", true, true},
		// the single colon is the host:port split, never the bare shape
		{"2001:443", false, true},
		{"example.com:443", false, true},
		{"https://example.com:8443/path", false, true},
		{"https://example.com", false, false},
		{"user@example.com", false, false},
		// the bracketed literal: the colons inside the brackets stay out
		{"[::1]:443", false, true},
		{"user@[2001:db8::1]:443", false, true},
		{"[2001:db8::1]", false, false},
		{"https://[2001:db8::1]:443/ssh3-term", false, true},
	}
	for _, c := range cases {
		bare, coloned := operandShape(c.operand)
		if bare != c.bare || coloned != c.coloned {
			t.Errorf("operandShape(%q) = (%v, %v), want (%v, %v)",
				c.operand, bare, coloned, c.bare, c.coloned)
		}
	}
}
