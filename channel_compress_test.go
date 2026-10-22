package ssh3

// The compression of the channel body on the write path (PLAN.md 9,
// B8): the data frame of a channel whose peer announced the codec
// travels compressed, and the frame that does not shrink travels as
// it is (the cutoff of the ZFS fast levels).

import (
	"bytes"
	"testing"

	"github.com/francoismichel/ssh3/compress"
	"github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
)

// the codecs of the wire: the frames of the three must be the same
// shape, the algorithm id is the only difference
var compressionAlgorithms = []uint64{
	compress.AlgorithmDeflate,
	compress.AlgorithmLZ4,
	compress.AlgorithmZstd,
}

func TestWriteDataCompressesTheFrame(t *testing.T) {
	payload := bytes.Repeat([]byte("the channel body of the compression "), 500)

	for _, algorithm := range compressionAlgorithms {
		w := &recordingWriter{}
		ch := &channelImpl{
			ChannelInfo: ChannelInfo{
				MaxPacketSize:     30000,
				CompressAlgorithm: algorithm,
			},
			send: w,
		}
		if _, err := ch.WriteData(payload, message.SSH_EXTENDED_DATA_NONE); err != nil {
			t.Fatalf("WriteData: %v", err)
		}

		stream := w.buf.Bytes()

		// the frame on the wire is the compressed one: the type 192
		typeID, err := util.ReadVarInt(bytes.NewReader(stream))
		if err != nil {
			t.Fatalf("the message type did not parse: %v", err)
		}
		if typeID != uint64(message.SSH_MSG_CHANNEL_DATA_COMPRESSED) {
			t.Fatalf("the frame type is %d, want %d", typeID, message.SSH_MSG_CHANNEL_DATA_COMPRESSED)
		}

		// and the payload is smaller than the plain one
		if len(stream) >= len(payload) {
			t.Fatalf("the compressed stream (%d bytes) is not smaller than the payload (%d bytes)",
				len(stream), len(payload))
		}
	}
}

func TestWriteDataKeepsThePlainFrameWhenItDoesNotShrink(t *testing.T) {
	// a payload of pseudo random bytes does not compress: the frame
	// travels as it is
	payload := make([]byte, 4096)
	seed := uint32(0x12345678)
	for i := range payload {
		seed = seed*1103515245 + 12345
		payload[i] = byte(seed >> 16)
	}

	for _, algorithm := range compressionAlgorithms {
		w := &recordingWriter{}
		ch := &channelImpl{
			ChannelInfo: ChannelInfo{
				MaxPacketSize:     30000,
				CompressAlgorithm: algorithm,
			},
			send: w,
		}
		if _, err := ch.WriteData(payload, message.SSH_EXTENDED_DATA_NONE); err != nil {
			t.Fatalf("WriteData: %v", err)
		}

		stream := w.buf.Bytes()
		typeID, err := util.ReadVarInt(bytes.NewReader(stream))
		if err != nil {
			t.Fatalf("the message type did not parse: %v", err)
		}
		if typeID != uint64(message.SSH_MSG_CHANNEL_DATA) {
			t.Fatalf("the frame type is %d, want the plain %d", typeID, message.SSH_MSG_CHANNEL_DATA)
		}
	}
}

func TestWriteDataKeepsTheStderrStreamPlain(t *testing.T) {
	payload := bytes.Repeat([]byte("the stderr stream of the compression "), 500)

	w := &recordingWriter{}
	ch := &channelImpl{
		ChannelInfo: ChannelInfo{
			MaxPacketSize:     30000,
			CompressAlgorithm: compress.AlgorithmDeflate,
		},
		send: w,
	}
	if _, err := ch.WriteData(payload, message.SSH_EXTENDED_DATA_STDERR); err != nil {
		t.Fatalf("WriteData: %v", err)
	}

	stream := w.buf.Bytes()
	typeID, err := util.ReadVarInt(bytes.NewReader(stream))
	if err != nil {
		t.Fatalf("the message type did not parse: %v", err)
	}
	if typeID != uint64(message.SSH_MSG_CHANNEL_EXTENDED_DATA) {
		t.Fatalf("the frame type is %d, want the extended %d", typeID, message.SSH_MSG_CHANNEL_EXTENDED_DATA)
	}
}
