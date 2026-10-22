// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package compress

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// unknownAlgorithm is an algorithm id no build knows: the ids of the
// wire are 0 (none), 1 (deflate), 2 (lz4) and 3 (zstd).
const unknownAlgorithm uint64 = 42

// pseudoRandomBytes returns a payload no codec can shrink: the LCG of
// the seed is enough for the codecs, the bytes are not the output of a
// cryptographic generator.
func pseudoRandomBytes(size int) []byte {
	payload := make([]byte, size)
	seed := uint32(0x12345678)
	for i := range payload {
		seed = seed*1103515245 + 12345
		payload[i] = byte(seed >> 16)
	}
	return payload
}

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

// the capability list announces the codecs of the build, in the order
// of the negotiation: the C port writes them in the same order, so the
// two sides read the same list.
func TestCapabilityAnnouncesEveryCodec(t *testing.T) {
	available := Available()
	for _, name := range []string{"deflate", "lz4", "zstd"} {
		if !strings.Contains(available, name) {
			t.Fatalf("the capability list %q does not announce the codec %q", available, name)
		}
	}
	mask := ParseCapability(available)
	if mask&MaskDeflate == 0 || mask&MaskLZ4 == 0 || mask&MaskZstd == 0 {
		t.Fatalf("the capability list %q does not carry the three codecs", available)
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
	// the peer announces an algorithm this build does not know: the
	// unknown bits are ignored
	const unknownBit uint64 = 1 << 63
	if Choose(unknownBit) != AlgorithmNone {
		t.Fatalf("the negotiation picked an algorithm this build cannot decode")
	}
}

// the preference order is the one of the C port (zstd, deflate, lz4):
// both sides pick the same algorithm out of the announced intersection
func TestChooseFollowsThePreferenceOrder(t *testing.T) {
	cases := []struct {
		mask uint64
		want uint64
	}{
		{MaskZstd | MaskDeflate | MaskLZ4, AlgorithmZstd},
		{MaskDeflate | MaskLZ4, AlgorithmDeflate},
		{MaskLZ4 | MaskZstd, AlgorithmZstd},
		{MaskDeflate | MaskZstd, AlgorithmZstd},
		{MaskLZ4, AlgorithmLZ4},
		{MaskDeflate, AlgorithmDeflate},
		{MaskZstd, AlgorithmZstd},
	}
	for _, c := range cases {
		if got := Choose(c.mask); got != c.want {
			t.Fatalf("Choose(%d) = %d, want %d", c.mask, got, c.want)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte("ssh3 compression payload "), 500)
	for _, alg := range []uint64{AlgorithmDeflate, AlgorithmLZ4, AlgorithmZstd} {
		packed, ok := Compress(alg, payload)
		if !ok {
			t.Fatalf("the %s codec refused the payload", names[alg])
		}
		if len(packed) >= len(payload) {
			t.Fatalf("the compressed form of the %s codec (%d) is not smaller than the payload (%d)",
				names[alg], len(packed), len(payload))
		}
		out, err := Decompress(alg, packed)
		if err != nil {
			t.Fatalf("the %s decompression failed: %s", names[alg], err)
		}
		if !bytes.Equal(out, payload) {
			t.Fatalf("the %s round trip changed the payload", names[alg])
		}
	}
}

// the cutoff of the ZFS fast levels: a payload that does not shrink
// travels as it is, so already compressed data is not compressed twice.
// The codec returns the compressed bytes whatever their size - the
// frame layer applies the cutoff - so the test pins the size relation
// the frame layer relies on.
func TestTheCutoffOfAnIncompressiblePayload(t *testing.T) {
	payload := pseudoRandomBytes(4096)
	for _, alg := range []uint64{AlgorithmDeflate, AlgorithmLZ4, AlgorithmZstd} {
		packed, ok := Compress(alg, payload)
		if !ok {
			// the codec refused the payload: the frame travels as it is
			continue
		}
		if len(packed) < len(payload) {
			t.Fatalf("the %s codec shrank a pseudo random payload (%d -> %d)",
				names[alg], len(payload), len(packed))
		}
	}
}

func TestCompressRefusesUnknownAlgorithm(t *testing.T) {
	if _, ok := Compress(unknownAlgorithm, []byte("x")); ok {
		t.Fatalf("the codec claimed an algorithm it does not have")
	}
	_, err := Decompress(unknownAlgorithm, []byte("x"))
	if err == nil {
		t.Fatalf("the decoder accepted an algorithm it does not have")
	}
	if !errors.Is(err, ErrUnknownAlgorithm) {
		t.Fatalf("the decoder refused the unknown algorithm with %v, want %v", err, ErrUnknownAlgorithm)
	}
}

func TestDecompressAcceptsTheOutputBelowTheLimit(t *testing.T) {
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

// the bomb limit of the decoder: a frame that expands beyond the
// channel packet limit is refused, whatever the codec
func TestDecompressRefusesAFrameBeyondTheLimit(t *testing.T) {
	payload := make([]byte, MaxOutput+1)
	for _, alg := range []uint64{AlgorithmDeflate, AlgorithmLZ4, AlgorithmZstd} {
		packed, ok := Compress(alg, payload)
		if !ok {
			t.Fatalf("the %s codec refused the payload", names[alg])
		}
		out, err := Decompress(alg, packed)
		if err == nil {
			t.Fatalf("the %s decoder accepted a frame of %d bytes", names[alg], len(out))
		}
	}
}

// the zstd frame must carry the size of the plain payload: the
// decoder of the C port refuses a frame whose size is unknown, so the
// encoder must always emit it
func TestTheZstdFrameCarriesItsSize(t *testing.T) {
	for _, size := range []int{1, 100, 255, 256, 1000, 30000} {
		payload := bytes.Repeat([]byte("zstd frame size "), size/16+1)[:size]
		packed, ok := Compress(AlgorithmZstd, payload)
		if !ok {
			t.Fatalf("the zstd codec refused a payload of %d bytes", size)
		}
		var header zstd.Header
		if err := header.Decode(packed); err != nil {
			t.Fatalf("the zstd frame of %d bytes does not parse: %s", size, err)
		}
		if !header.HasFCS {
			t.Fatalf("the zstd frame of %d bytes carries no size", size)
		}
		if header.FrameContentSize != uint64(size) {
			t.Fatalf("the zstd frame of %d bytes announces %d bytes", size, header.FrameContentSize)
		}
	}
}

// a frame without the size is refused, as the C port refuses it
func TestDecompressRefusesAFrameWithoutItsSize(t *testing.T) {
	// a frame of the windowed form whose header declares neither the
	// size nor the single segment form: the size of the payload is
	// unknown, so the decoder cannot bound it.  The block is a raw one,
	// so the frame is easy to build by hand.
	payload := []byte("the payload of a frame without its size")
	frame := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00}
	// the block header: the size in the upper bits, the raw block type
	// and the flag of the last block
	blockHeader := uint32(len(payload))<<3 | 1
	frame = append(frame, byte(blockHeader), byte(blockHeader>>8), byte(blockHeader>>16))
	frame = append(frame, payload...)

	_, err := Decompress(AlgorithmZstd, frame)
	if !errors.Is(err, ErrUnknownContentSize) {
		t.Fatalf("the decoder refused a frame without its size with %v, want %v", err, ErrUnknownContentSize)
	}
}
