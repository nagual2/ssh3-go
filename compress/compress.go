// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

// Package compress implements the compression of the channel body: the
// capability field of the version string, the algorithm negotiation and
// the one-shot codec of a single data frame.
//
// The wire contract is shared with the C port (ssh3-c) and is written
// down in the protocol specification, section 15:
//
//   - the version string carries a "compress=<list>" field with the
//     algorithms the endpoint can decode; the list is comma separated
//     and the field is optional (an endpoint without it supports no
//     compression at all);
//   - a compressed data frame is the message type 192 (the private
//     range of RFC 4253), its body is the algorithm id and the
//     compressed payload as an SSH string;
//   - the frame unit is one data message: the payload is compressed
//     independently, so a plain frame and a compressed frame may share
//     the channel in any order and a lost frame never desynchronizes
//     the decoder;
//   - the cutoff follows the "fast" levels of ZFS: a frame whose
//     compressed form is not smaller travels as it is, so already
//     compressed data is not compressed twice.
//
// The algorithm ids are the same in both implementations:
//
//	0 = none, 1 = deflate, 2 = lz4, 3 = zstd
//
// The codecs available here are the ones of the Go standard library:
// deflate (the raw DEFLATE stream, the same bytes the C port produces
// with its window-less zlib wrapper).  The ids of the other algorithms
// are reserved so that a peer offering them is understood and refused
// cleanly rather than misread.
package compress

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"strings"
)

// The algorithm ids of the wire (the contract with the C port).
const (
	AlgorithmNone    uint64 = 0
	AlgorithmDeflate uint64 = 1
	AlgorithmLZ4     uint64 = 2
	AlgorithmZstd    uint64 = 3
)

// The capability mask bits.
const (
	MaskDeflate uint64 = 1 << 0
	MaskLZ4     uint64 = 1 << 1
	MaskZstd    uint64 = 1 << 2
)

// MaxOutput is the bomb limit of the decoder: a compressed frame may
// not expand beyond the channel packet limit (16 MiB), the same
// ceiling the C port uses.
const MaxOutput = 16 << 20

// The level of the deflate codec: the middle of the zlib range, the
// same level the C port uses (the gzip-6 of ZFS).
const deflateLevel = 6

// ErrUnknownAlgorithm is returned for an algorithm this build does not
// know.
var ErrUnknownAlgorithm = errors.New("unknown compression algorithm")

// ErrTooLarge is returned when a frame expands beyond MaxOutput.
var ErrTooLarge = errors.New("the compressed frame expands beyond the limit")

// names maps an algorithm id to the name of the capability list.
var names = map[uint64]string{
	AlgorithmDeflate: "deflate",
	AlgorithmLZ4:     "lz4",
	AlgorithmZstd:    "zstd",
}

// order is the preference order of the negotiation: the same order in
// both implementations, so that the two sides pick the same algorithm
// out of the announced intersection.
var order = []uint64{AlgorithmZstd, AlgorithmDeflate, AlgorithmLZ4}

// localMask is the mask of the codecs this build can decode.
func localMask() uint64 {
	// only the standard library codec so far; the ids of the others are
	// reserved, and a peer that offers them alone gets no compression
	// instead of a broken frame
	return MaskDeflate
}

// Available returns the capability list of this build.
func Available() string {
	parts := make([]string, 0, len(order))
	for _, alg := range order {
		if localMask()&maskOf(alg) == 0 {
			continue
		}
		parts = append(parts, names[alg])
	}
	return strings.Join(parts, ",")
}

// maskOf returns the capability bit of an algorithm id.
func maskOf(alg uint64) uint64 {
	switch alg {
	case AlgorithmDeflate:
		return MaskDeflate
	case AlgorithmLZ4:
		return MaskLZ4
	case AlgorithmZstd:
		return MaskZstd
	default:
		return 0
	}
}

// ParseCapability parses the value of the "compress=" field of a
// version string into a capability mask.  An unknown name is skipped: a
// newer peer may announce more than this build knows.
func ParseCapability(value string) uint64 {
	var mask uint64
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		for alg, algName := range names {
			if algName == name {
				mask |= maskOf(alg)
				break
			}
		}
	}
	return mask
}

// Choose returns the algorithm of the intersection of the peer's
// capability and the local codecs, or AlgorithmNone when the
// intersection is empty.  The order is the shared preference order, so
// that both sides end up with the same algorithm.
func Choose(peerMask uint64) uint64 {
	common := peerMask & localMask()
	for _, alg := range order {
		if common&maskOf(alg) != 0 {
			return alg
		}
	}
	return AlgorithmNone
}

// Compress compresses one frame payload with the given algorithm.  The
// second return value is false when the algorithm is not available in
// this build; the caller then sends the plain frame.
func Compress(alg uint64, data []byte) ([]byte, bool) {
	switch alg {
	case AlgorithmDeflate:
		var buf bytes.Buffer
		writer, err := flate.NewWriter(&buf, deflateLevel)
		if err != nil {
			return nil, false
		}
		if _, err := writer.Write(data); err != nil {
			return nil, false
		}
		if err := writer.Close(); err != nil {
			return nil, false
		}
		return buf.Bytes(), true
	default:
		return nil, false
	}
}

// Decompress expands one frame payload.  The output never crosses
// MaxOutput, so a hostile peer cannot make the receiver allocate more
// than one channel packet.
func Decompress(alg uint64, data []byte) ([]byte, error) {
	switch alg {
	case AlgorithmDeflate:
		reader := flate.NewReader(bytes.NewReader(data))
		defer reader.Close()
		out, err := io.ReadAll(io.LimitReader(reader, MaxOutput+1))
		if err != nil {
			return nil, err
		}
		if len(out) > MaxOutput {
			return nil, ErrTooLarge
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownAlgorithm, alg)
	}
}
