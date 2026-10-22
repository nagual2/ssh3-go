// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package compress

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The frames the reference libraries produce for the payload below -
// the very bytes the C port puts on the wire (LZ4_compress_default
// and ZSTD_compress of the level 3).  They are the fixtures of the
// wire contract: a drift of the codecs would decode them into
// something else.
const (
	referenceLZ4Block = "ff0b6162636465666768696a6b6c6d6e6f7071727374757677" +
		"78797a1a00ffcf506e6f707172"
	referenceZstdFrame = "28b52ffd6000010d0100d06162636465666768696a6b6c6d6e" +
		"6f707172737475767778797a01008eb73ac7"
)

// referencePayload is the payload of the fixtures above: the bytes
// 'a' to 'z', repeated.
func referencePayload() []byte {
	payload := make([]byte, 512)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	return payload
}

// the frames of the reference libraries must be read by the decoder of
// this port: the C port produces them and this port must decode them
func TestTheReferenceFramesAreDecoded(t *testing.T) {
	payload := referencePayload()
	cases := []struct {
		algorithm uint64
		frame     string
	}{
		{AlgorithmLZ4, referenceLZ4Block},
		{AlgorithmZstd, referenceZstdFrame},
	}
	for _, c := range cases {
		frame, err := hex.DecodeString(c.frame)
		if err != nil {
			t.Fatalf("the %s fixture is not valid hex: %s", names[c.algorithm], err)
		}
		out, err := Decompress(c.algorithm, frame)
		if err != nil {
			t.Fatalf("the %s frame of the reference library does not decode: %s", names[c.algorithm], err)
		}
		if !bytes.Equal(out, payload) {
			t.Fatalf("the %s frame of the reference library decodes into something else", names[c.algorithm])
		}
	}
}

// the lz4 codec is the block format (the bytes of
// LZ4_compress_default), not the frame format: the frames of the
// stream format start with their own magic number
func TestTheLZ4CodecEmitsABlockAndNotAFrame(t *testing.T) {
	payload := bytes.Repeat([]byte("ssh3 compression payload "), 500)
	packed, ok := Compress(AlgorithmLZ4, payload)
	if !ok {
		t.Fatalf("the lz4 codec refused the payload")
	}
	// the magic number of the LZ4 frame format
	frameMagic := []byte{0x04, 0x22, 0x4d, 0x18}
	if bytes.HasPrefix(packed, frameMagic) {
		t.Fatalf("the lz4 codec emitted a frame of the stream format, not a block")
	}
}

// the zstd codec is the frame format of the reference library: the
// frame starts with its magic number
func TestTheZstdCodecEmitsAFrame(t *testing.T) {
	payload := bytes.Repeat([]byte("ssh3 compression payload "), 500)
	packed, ok := Compress(AlgorithmZstd, payload)
	if !ok {
		t.Fatalf("the zstd codec refused the payload")
	}
	frameMagic := []byte{0x28, 0xb5, 0x2f, 0xfd}
	if !bytes.HasPrefix(packed, frameMagic) {
		t.Fatalf("the zstd codec did not emit a frame of the reference library")
	}
}
