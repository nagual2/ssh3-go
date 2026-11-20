package cmd

import (
	"fmt"
	"os"
	"strings"
)

// The bare-IPv6 operand hint (the C canon 35b2e64, the v0.5.15 ux wave):
// the unbracketed literal tears at the first colon — the host cuts to the
// first label and the dial fails with a misleading resolve or parse error.
// The honest refusal names the bracketed form before the branches, and the
// bad-port branches carry the same hint.

const (
	// bareIPv6HintLine is the refusal of the bare (unbracketed) literal,
	// printed before the URL parse instead of the misleading error.
	bareIPv6HintLine = "ssh3: the bare IPv6 rides the bracketed form: user@[addr]:port"
	// ipv6LiteralHintLine is the hint the coloned parse failures carry
	// (the bad-port branches of the same canon).
	ipv6LiteralHintLine = "ssh3: the IPv6 literal rides the bracketed form: user@[addr]:port"
)

// operandAuthority cuts the authority of the destination operand the way
// the C canon parses it: the scheme prefix, the user@ part and the path
// suffix stay out, so the colon scan sees the host:port pair alone.
func operandAuthority(operand string) string {
	operand = strings.TrimPrefix(operand, "https://")
	if at := strings.IndexByte(operand, '@'); at >= 0 {
		operand = operand[at+1:]
	}
	if slash := strings.IndexByte(operand, '/'); slash >= 0 {
		operand = operand[:slash]
	}
	return operand
}

// operandShape classifies the host:port authority of the destination
// operand. bare names the unbracketed IPv6 literal: the first colon
// outside the brackets with another colon in the remainder (the port of
// the dial never carries a colon). coloned names any colon outside the
// brackets — the hint carrier of the parse failures, the bad-port
// branches of the same canon.
func operandShape(operand string) (bare, coloned bool) {
	authority := operandAuthority(operand)
	inBrackets := false
	colon := -1

scan:
	for i := 0; i < len(authority); i++ {
		switch authority[i] {
		case '[':
			inBrackets = true
		case ']':
			inBrackets = false
		case ':':
			if !inBrackets {
				colon = i
				break scan
			}
		}
	}

	if colon < 0 {
		return false, false
	}
	coloned = true
	if strings.IndexByte(authority[colon+1:], ':') >= 0 {
		bare = true
	}
	return bare, coloned
}

// printBareIPv6Refusal prints the honest refusal of the bare literal.
func printBareIPv6Refusal() {
	fmt.Fprintf(os.Stderr, "%s\n", bareIPv6HintLine)
}
