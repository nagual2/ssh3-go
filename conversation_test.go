package ssh3

import (
	"context"
	"errors"
	"testing"

	"github.com/francoismichel/ssh3/util"
)

func testDatagram(channelID uint64, payload string) []byte {
	return append(util.AppendVarInt(nil, channelID), payload...)
}

// F-14: AddDatagram is the condition the client datagram loop must tolerate —
// a datagram for a channel that is not registered returns util.ChannelNotFound
// (and buffers the datagram as dangling), never a block or a panic.
func TestAddDatagramUnknownChannelReturnsChannelNotFound(t *testing.T) {
	conv := &Conversation{channelsManager: newChannelsManager(), context: context.Background()}
	err := conv.AddDatagram(context.Background(), testDatagram(42, "payload"))
	var notFound util.ChannelNotFound
	if !errors.As(err, &notFound) || notFound.ChannelID != 42 {
		t.Fatalf("AddDatagram for an unknown channel returned %v, want util.ChannelNotFound{42}", err)
	}
	if len(conv.channelsManager.danglingDgramQueues) != 1 {
		t.Fatalf("the datagram was not buffered as dangling (%d queues)", len(conv.channelsManager.danglingDgramQueues))
	}
}

// the exact F-14 shape: a channel registered, then closed (the P4-02 prune
// removes it from the manager), then an in-flight datagram arrives — it must
// come back as ChannelNotFound for the receive loop to drop with a warning,
// not tear the loop down
func TestAddDatagramClosedChannelReturnsChannelNotFound(t *testing.T) {
	conv := &Conversation{channelsManager: newChannelsManager(), context: context.Background()}
	ch := &channelImpl{
		ChannelInfo:          ChannelInfo{ChannelID: 9},
		send:                 &nopWriteCloser{},
		channelCloseListener: conv.channelsManager,
		datagramsQueue:       util.NewDatagramsQueue(8),
	}
	conv.channelsManager.addChannel(ch)
	ch.Close() // prunes from the manager (P4-02)

	err := conv.AddDatagram(context.Background(), testDatagram(9, "late"))
	var notFound util.ChannelNotFound
	if !errors.As(err, &notFound) || notFound.ChannelID != 9 {
		t.Fatalf("AddDatagram for a closed channel returned %v, want util.ChannelNotFound{9}", err)
	}
	if len(conv.channelsManager.channels) != 0 {
		t.Fatalf("the closed channel is still registered (%d entries)", len(conv.channelsManager.channels))
	}
}

// the loop goroutines themselves are not unit-drivable without a QUIC
// connection; their reaction to the error above is pinned by review symmetry
// with the server loop (server.go, warn+continue since ca4da52)

// F-19: a datagram whose channel id does not parse as a varint is per-datagram
// garbage, not a loop condition — AddDatagram must classify it (DatagramMalformed)
// so the receive loops can drop it with a warning instead of terminating
func TestAddDatagramMalformedInnerDatagramReturnsDatagramMalformed(t *testing.T) {
	conv := &Conversation{channelsManager: newChannelsManager(), context: context.Background()}
	// 0x80 sets the varint continuation bit and then the buffer ends
	err := conv.AddDatagram(context.Background(), []byte{0x80})
	var malformed util.DatagramMalformed
	if !errors.As(err, &malformed) {
		t.Fatalf("AddDatagram on an unparseable datagram returned %v, want util.DatagramMalformed", err)
	}
	if _, ok := conv.channelsManager.danglingDgramQueues[0]; ok {
		t.Error("garbage datagram must not create a dangling queue")
	}
	if len(conv.channelsManager.danglingDgramQueues) != 0 {
		t.Errorf("garbage datagram created %d dangling queues", len(conv.channelsManager.danglingDgramQueues))
	}
}
