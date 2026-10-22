// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"bytes"
	"testing"

	"github.com/francoismichel/ssh3/compress"
	"github.com/francoismichel/ssh3/util"
)

// The compressed data frame is the wire contract with the C port (the
// compression of the channel body, PLAN.md 9 B8): the message type 192,
// the algorithm id and the compressed payload.  The test pins the
// framing and the round trip through the dispatcher.

func compressedFrame(t *testing.T, algorithm uint64, payload []byte) []byte {
	t.Helper()
	packed, ok := compress.Compress(algorithm, payload)
	if !ok {
		t.Fatalf("the codec refused the payload")
	}
	buf := CompressedDataHeader(algorithm, uint64(len(packed)))
	return append(buf, packed...)
}

func TestCompressedDataRoundTrip(t *testing.T) {
	payload := []byte("the payload of the compressed frame of the channel body")
	frame := compressedFrame(t, compress.AlgorithmDeflate, payload)

	msg, err := ParseMessage(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("the compressed frame did not parse: %s", err)
	}
	data, ok := msg.(*DataOrExtendedDataMessage)
	if !ok {
		t.Fatalf("the compressed frame parsed into %T", msg)
	}
	if data.Data != string(payload) {
		t.Fatalf("the round trip changed the payload: %q", data.Data)
	}
}

func TestCompressedDataGoldenBytes(t *testing.T) {
	// the frame header of the compressed message: the type 192, the
	// algorithm and the length of the payload
	header := CompressedDataHeader(compress.AlgorithmDeflate, 42)
	want := []byte{0x40, 0xC0, 0x01, 0x2A}
	if !bytes.Equal(header, want) {
		t.Fatalf("the compressed frame header is %x, want %x", header, want)
	}
}

func TestCompressedDataUnknownAlgorithmIsRefused(t *testing.T) {
	// a frame of an algorithm this build does not have must be
	// refused, not misread
	buf := CompressedDataHeader(compress.AlgorithmZstd, 3)
	buf = append(buf, 0x00, 0x00, 0x00)
	if _, err := ParseMessage(bytes.NewReader(buf)); err == nil {
		t.Fatalf("the parser accepted a frame of an unknown algorithm")
	}
}

func TestCompressedDataHeaderIsSelfDescribing(t *testing.T) {
	// the header carries the algorithm and the length, so the decoder
	// needs no negotiation of its own
	header := CompressedDataHeader(compress.AlgorithmDeflate, 1234)
	algorithm, err := util.ReadVarInt(bytes.NewReader(header[2:]))
	if err != nil {
		t.Fatalf("the algorithm did not parse: %s", err)
	}
	if algorithm != compress.AlgorithmDeflate {
		t.Fatalf("the algorithm is %d, want %d", algorithm, compress.AlgorithmDeflate)
	}
	length, err := util.ReadVarInt(bytes.NewReader(header[3:]))
	if err != nil {
		t.Fatalf("the length did not parse: %s", err)
	}
	if length != 1234 {
		t.Fatalf("the length is %d, want 1234", length)
	}
}
