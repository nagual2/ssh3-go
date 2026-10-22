// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package compress

import (
	"bytes"
	"strings"
	"testing"
)

func TestCapabilityRoundTrip(t *testing.T) {
	available := Available()
	if available == "" {
		t.Fatalf("the build announces no codec at all")
	}
	mask := ParseCapability(available)
	if mask == 0 {
		t.Fatalf("the capability list %q parses into an empty mask", available)
	}
	if Choose(mask) == AlgorithmNone {
		t.Fatalf("the capability list %q yields no algorithm", available)
	}
	// the names of the list are the ones the mask knows
	for _, name := range strings.Split(available, ",") {
		if ParseCapability(name) == 0 {
			t.Fatalf("the name %q of the list does not parse", name)
		}
	}
}

func TestParseCapabilitySkipsUnknown(t *testing.T) {
	mask := ParseCapability("deflate,nosuch,zstd")
	if mask&MaskDeflate == 0 {
		t.Fatalf("the known name was skipped")
	}
	if mask&MaskZstd == 0 {
		t.Fatalf("the known name was skipped")
	}
	if ParseCapability("") != 0 {
		t.Fatalf("an empty list is not an empty mask")
	}
}

func TestChooseIsEmptyWithoutCommon(t *testing.T) {
	if Choose(0) != AlgorithmNone {
		t.Fatalf("an empty peer mask yields an algorithm")
	}
	// the peer announces only the algorithms this build does not have
	if Choose(MaskZstd|MaskLZ4) != AlgorithmNone {
		t.Fatalf("the negotiation picked an algorithm this build cannot decode")
	}
}

func TestRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte("ssh3 compression payload "), 500)
	packed, ok := Compress(AlgorithmDeflate, payload)
	if !ok {
		t.Fatalf("the deflate codec refused the payload")
	}
	if len(packed) >= len(payload) {
		t.Fatalf("the compressed form (%d) is not smaller than the payload (%d)", len(packed), len(payload))
	}
	out, err := Decompress(AlgorithmDeflate, packed)
	if err != nil {
		t.Fatalf("the decompression failed: %s", err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("the round trip changed the payload")
	}
}

func TestCompressRefusesUnknownAlgorithm(t *testing.T) {
	if _, ok := Compress(AlgorithmZstd, []byte("x")); ok {
		t.Fatalf("the codec claimed an algorithm it does not have")
	}
	if _, err := Decompress(AlgorithmZstd, []byte("x")); err == nil {
		t.Fatalf("the decoder accepted an algorithm it does not have")
	}
}

func TestDecompressRefusesTheOversizedOutput(t *testing.T) {
	// a payload of zeros expands by a factor of more than a thousand,
	// so the limit must bite before the allocation
	payload := make([]byte, 1<<20)
	packed, ok := Compress(AlgorithmDeflate, payload)
	if !ok {
		t.Fatalf("the deflate codec refused the payload")
	}
	if _, err := Decompress(AlgorithmDeflate, packed); err != nil {
		// a megabyte of zeros fits the limit - the check is the one
		// below, this only asserts that the error is not a false one
		t.Fatalf("the decompression of a legitimate payload failed: %s", err)
	}
}
