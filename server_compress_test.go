package ssh3

// The compression of the channel body on the server side (PLAN.md 9,
// B8): the codec of the compressed frames is the one both sides
// negotiate out of the capability the peer announced in its version
// string, so the server compresses its own frames when the peer
// offers the codecs - and keeps the plain frames when it does not.

import (
	"bytes"
	"testing"

	"github.com/francoismichel/ssh3/compress"
	"github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
)

// peerVersionWithCompress builds the version of a peer that announces
// the given codecs in its version string.
func peerVersionWithCompress(t *testing.T, capability string) Version {
	t.Helper()
	version, err := ParseVersionString("SSH 3.0 francoismichel/ssh3 0.1.37 compress=" + capability)
	if err != nil {
		t.Fatalf("could not parse the peer version: %s", err)
	}
	return version
}

// serverChannel builds the channel of a client-opened channel the way
// the server does, with the codec both sides negotiated.
func serverChannel(t *testing.T, conversation *Conversation, w *recordingWriter) Channel {
	t.Helper()
	channelInfo := &ChannelInfo{
		ConversationID:       conversation.conversationID,
		ConversationStreamID: 1,
		ChannelID:            2,
		ChannelType:          "session",
		MaxPacketSize:        30000,
		CompressAlgorithm:    conversation.compressAlgorithm(),
	}
	return newServerChannel(conversation, channelInfo, nil, w, 1)
}

func TestTheServerChannelCompressesWhenThePeerOffersTheCodec(t *testing.T) {
	conversation := &Conversation{
		peerVersion:     peerVersionWithCompress(t, "zstd,deflate,lz4"),
		channelsManager: newChannelsManager(),
	}
	if conversation.compressAlgorithm() != compress.AlgorithmZstd {
		t.Fatalf("the negotiated codec is %d, want the zstd one (%d)",
			conversation.compressAlgorithm(), compress.AlgorithmZstd)
	}

	w := &recordingWriter{}
	channel := serverChannel(t, conversation, w)
	payload := bytes.Repeat([]byte("the server side of the compression "), 500)
	if _, err := channel.WriteData(payload, message.SSH_EXTENDED_DATA_NONE); err != nil {
		t.Fatalf("WriteData: %v", err)
	}

	typeID, err := util.ReadVarInt(bytes.NewReader(w.buf.Bytes()))
	if err != nil {
		t.Fatalf("the message type did not parse: %v", err)
	}
	if typeID != uint64(message.SSH_MSG_CHANNEL_DATA_COMPRESSED) {
		t.Fatalf("the frame type is %d, want the compressed %d", typeID, message.SSH_MSG_CHANNEL_DATA_COMPRESSED)
	}
}

func TestTheServerChannelKeepsThePlainFramesOfAnUnknownCodec(t *testing.T) {
	// a peer that announces a codec this build does not know gets the
	// plain frames instead of a broken frame
	conversation := &Conversation{
		peerVersion:     peerVersionWithCompress(t, "nosuchcodec"),
		channelsManager: newChannelsManager(),
	}
	if conversation.compressAlgorithm() != compress.AlgorithmNone {
		t.Fatalf("the negotiated codec is %d, want none (%d)",
			conversation.compressAlgorithm(), compress.AlgorithmNone)
	}
}

func TestTheServerChannelKeepsThePlainFramesOfAPeerWithoutTheCodec(t *testing.T) {
	// a peer that announces nothing at all (an old peer) gets the plain
	// frames
	version, err := ParseVersionString("SSH 3.0 francoismichel/ssh3 0.1.37")
	if err != nil {
		t.Fatalf("could not parse the peer version: %s", err)
	}
	conversation := &Conversation{
		peerVersion:     version,
		channelsManager: newChannelsManager(),
	}
	if conversation.compressAlgorithm() != compress.AlgorithmNone {
		t.Fatalf("the negotiated codec is %d, want none (%d)",
			conversation.compressAlgorithm(), compress.AlgorithmNone)
	}

	w := &recordingWriter{}
	channel := serverChannel(t, conversation, w)
	payload := bytes.Repeat([]byte("the server side of the compression "), 500)
	if _, err := channel.WriteData(payload, message.SSH_EXTENDED_DATA_NONE); err != nil {
		t.Fatalf("WriteData: %v", err)
	}

	typeID, err := util.ReadVarInt(bytes.NewReader(w.buf.Bytes()))
	if err != nil {
		t.Fatalf("the message type did not parse: %v", err)
	}
	if typeID != uint64(message.SSH_MSG_CHANNEL_DATA) {
		t.Fatalf("the frame type is %d, want the plain %d", typeID, message.SSH_MSG_CHANNEL_DATA)
	}
}
