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
// The codecs compiled in here are deflate (the raw DEFLATE stream, the
// same bytes the C port produces with its window-less zlib wrapper),
// lz4 and zstd.  The three formats have their own quirks, and the
// bytes on the wire must match the C port:
//
//   - deflate is the raw DEFLATE stream (the window-less zlib wrapper,
//     the same bytes as the C port's deflateInit2 with a window of
//     -15);
//   - lz4 is the LZ4 *block* format (the bytes of
//     LZ4_compress_default), not the LZ4 frame format: the block
//     carries no size, so the decoder must be given a buffer big
//     enough, and the compressor must leave room for the worst case
//     (LZ4_compressBound);
//   - zstd is the zstd frame of the reference library, and the frame
//     must carry the size of the plain payload: the decoder of the C
//     port refuses a frame whose size is unknown, so the encoder
//     always emits the size (the one-shot encoder knows it) and the
//     decoder checks it.
package compress

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
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

// The level of the zstd codec: the ZFS default (the level map of the
// OpenZFS module), the best ratio per cpu among the zstd levels.  It
// is the level 3 of the reference library, the one the C port uses.
const zstdLevel = zstd.SpeedDefault

// The window of the zstd codec: the window of the level 3 of the
// reference library (2 MiB), the window of the frames of the C port.
const zstdWindowSize = 2 << 20

// zstdMinSingleSegment is the size under which a windowed zstd frame
// carries no size at all: the reference library writes the size field
// of a windowed frame only from 256 bytes on, and the decoder of the
// C port refuses a frame whose size is unknown.  The single-segment
// form always carries the size, so the frames below that size use it.
const zstdMinSingleSegment = 256

// lz4DecodeSizes are the sizes of the buffer the lz4 decoder is given,
// in the order they are tried: the LZ4 block format carries no size,
// so the decoder must be given a buffer big enough.  The first size
// covers the usual channel chunk, the last one is the bomb limit.
var lz4DecodeSizes = []int{64 << 10, 1 << 20, MaxOutput}

// ErrUnknownAlgorithm is returned for an algorithm this build does not
// know.
var ErrUnknownAlgorithm = errors.New("unknown compression algorithm")

// ErrTooLarge is returned when a frame expands beyond MaxOutput.
var ErrTooLarge = errors.New("the compressed frame expands beyond the limit")

// ErrUnknownContentSize is returned when a frame does not carry the
// size of its plain payload: the decoder of the C port refuses such a
// frame, so this port refuses it too.
var ErrUnknownContentSize = errors.New("the compressed frame does not carry its size")

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
	return MaskDeflate | MaskLZ4 | MaskZstd
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

// The zstd codecs are shared by the frames: the encoder of the
// reference library is safe for concurrent use (every frame is
// compressed on a single goroutine), and so is its decoder.  The
// encoders are built lazily, so a build that never compresses a zstd
// frame never pays for them.
var (
	zstdEncoder = sync.OnceValues(func() (*zstd.Encoder, error) {
		return zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstdLevel),
			zstd.WithEncoderConcurrency(1),
			// the reference library adds a checksum to every frame, the
			// C port does not: the checksum would cost four bytes and
			// a hash of the payload on every frame
			zstd.WithEncoderCRC(false),
			zstd.WithWindowSize(zstdWindowSize))
	})
	// the single-segment encoder: a windowed frame below 256 bytes
	// carries no size, and the decoder of the C port refuses a frame
	// without a size
	zstdSingleEncoder = sync.OnceValues(func() (*zstd.Encoder, error) {
		return zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstdLevel),
			zstd.WithEncoderConcurrency(1),
			zstd.WithEncoderCRC(false),
			zstd.WithWindowSize(zstdWindowSize),
			zstd.WithSingleSegment(true))
	})
	zstdDecoder = sync.OnceValues(func() (*zstd.Decoder, error) {
		return zstd.NewReader(nil,
			zstd.WithDecoderConcurrency(1),
			// the bomb limit: the decoder never expands a frame beyond
			// the channel packet limit, whatever the frame claims
			zstd.WithDecoderMaxMemory(MaxOutput))
	})
)

// The lz4 compressors are pooled: the compressor of the reference
// library keeps a hash table of its own, and a fresh one per frame
// would cost more than the compression itself.
var lz4CompressorPool = sync.Pool{
	New: func() any { return new(lz4.Compressor) },
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
	case AlgorithmLZ4:
		// the LZ4 block format (the bytes of LZ4_compress_default): the
		// buffer must hold the worst case, the bound of the reference
		// library
		dst := make([]byte, lz4.CompressBlockBound(len(data)))
		compressor := lz4CompressorPool.Get().(*lz4.Compressor)
		n, err := compressor.CompressBlock(data, dst)
		lz4CompressorPool.Put(compressor)
		if err != nil || n == 0 {
			// the codec refused the payload: the frame travels as it is
			// (the ZFS cutoff)
			return nil, false
		}
		return dst[:n], true
	case AlgorithmZstd:
		return compressZstd(data)
	default:
		return nil, false
	}
}

// compressZstd compresses one frame payload into a zstd frame.  The
// frame must carry the size of the plain payload, because the decoder
// of the C port (and the one of this port) refuses a frame whose size
// is unknown.
func compressZstd(data []byte) ([]byte, bool) {
	if len(data) == 0 {
		// the reference library emits no frame at all for an empty
		// payload
		return nil, false
	}
	encoder, err := zstdEncoder()
	if err != nil {
		return nil, false
	}
	if len(data) < zstdMinSingleSegment {
		// a windowed frame of that size carries no size field: the
		// single-segment form always carries it
		encoder, err = zstdSingleEncoder()
		if err != nil {
			return nil, false
		}
	}
	packed := encoder.EncodeAll(data, nil)
	var header zstd.Header
	if err := header.Decode(packed); err != nil || !header.HasFCS {
		// the frame does not carry its size: the peer would refuse it
		return nil, false
	}
	return packed, true
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
	case AlgorithmLZ4:
		return decompressLZ4(data)
	case AlgorithmZstd:
		return decompressZstd(data)
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownAlgorithm, alg)
	}
}

// decompressLZ4 expands an LZ4 block.  The block format carries no
// size, so the decoder is given a buffer of a growing size until the
// block fits; the last size is the bomb limit, and a block that does
// not fit it is refused.
func decompressLZ4(data []byte) ([]byte, error) {
	var lastErr error
	for _, size := range lz4DecodeSizes {
		dst := make([]byte, size)
		n, err := lz4.UncompressBlock(data, dst)
		if err != nil {
			lastErr = err
			continue
		}
		if n > len(dst) {
			// the decoder reported more than the buffer holds: the
			// block is not the one we can trust
			lastErr = lz4.ErrInvalidSourceShortBuffer
			continue
		}
		return dst[:n], nil
	}
	if lastErr == nil {
		lastErr = lz4.ErrInvalidSourceShortBuffer
	}
	return nil, fmt.Errorf("the lz4 frame does not decode: %w", lastErr)
}

// decompressZstd expands a zstd frame.  The frame must carry the size
// of its plain payload: the size is the bound of the decoder, and the
// decoder of the C port refuses a frame without it.
func decompressZstd(data []byte) ([]byte, error) {
	var header zstd.Header
	if err := header.Decode(data); err != nil {
		return nil, fmt.Errorf("the zstd frame does not parse: %w", err)
	}
	if !header.HasFCS {
		return nil, fmt.Errorf("%w: zstd", ErrUnknownContentSize)
	}
	if header.FrameContentSize > MaxOutput {
		return nil, fmt.Errorf("%w: the zstd frame announces %d bytes", ErrTooLarge, header.FrameContentSize)
	}
	decoder, err := zstdDecoder()
	if err != nil {
		return nil, err
	}
	out, err := decoder.DecodeAll(data, nil)
	if err != nil {
		return nil, fmt.Errorf("the zstd frame does not decode: %w", err)
	}
	if len(out) > MaxOutput {
		return nil, ErrTooLarge
	}
	return out, nil
}
