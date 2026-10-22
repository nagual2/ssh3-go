package ssh3

import (
	"testing"
	"time"

	ssh3 "github.com/francoismichel/ssh3/message"
)

// clampPeerMaxPacketSize is the S2-01/P3-02 bound: the peer's advertised
// value sizes the endpoint's per-channel read buffers, so it must never
// exceed the locally advertised one, and it must never drop below the
// minimum sane packet size — below the empty data-frame length the outbound
// chunk size in WriteData (MaxPacketSize - emptyMsgLen) underflows uint64.
func TestClampPeerMaxPacketSize(t *testing.T) {
	const local = 30000
	cases := []struct {
		peer uint64
		want uint64
	}{
		{0, minPeerMaxPacketSize},    // a 0-byte buffer would deadlock the channel
		{1, minPeerMaxPacketSize},    // below the 2-byte empty data frame: uint64 underflow
		{4095, minPeerMaxPacketSize}, // just under the floor
		{4096, 4096},                 // exactly the floor stays as-is
		{29999, 29999},               // between floor and local stays as-is
		{30000, 30000},               // equal to the local value stays as-is
		{30001, 30000},               // slightly above is lowered
		{1 << 24, 30000},             // the 16 MiB ParseSSHString cap is lowered too
		{1 << 62, 30000},
	}
	for _, c := range cases {
		if got := clampPeerMaxPacketSize(c.peer, local); got != c.want {
			t.Errorf("clampPeerMaxPacketSize(%d, %d) = %d, want %d", c.peer, local, got, c.want)
		}
	}
}

// a local value under the floor must not be raised: the clamp bounds the
// peer by what the local endpoint itself advertises
func TestClampPeerMaxPacketSizeSmallLocal(t *testing.T) {
	const local = 2048
	if got := clampPeerMaxPacketSize(0, local); got != local {
		t.Errorf("clampPeerMaxPacketSize(0, %d) = %d, want %d", local, got, local)
	}
}

// P4-04: the peer-side floor protected the write loop only because every
// opener passed the 30000 constant; the local advertisement itself must be
// floored at construction, where both the header and the ChannelInfo are
// built, so the MaxPacketSize > emptyMsgLen invariant stops depending on
// call-site discipline
func TestNewChannelFloorsLocalMaxPacketSize(t *testing.T) {
	for _, local := range []uint64{0, 1, 2, 4095} {
		ch := NewChannel(0, ConversationID{}, 1, "session", local, nil, &nopWriteCloser{}, nil, nil, false, false, false, 1, 0, nil)
		if got := ch.MaxPacketSize(); got != minPeerMaxPacketSize {
			t.Errorf("NewChannel with local maxPacketSize %d advertises %d, want the floor %d", local, got, minPeerMaxPacketSize)
		}
	}
}

// P4-04: a MaxPacketSize at or below the empty data-frame length makes the
// chunk size zero (or, below it, underflow): the loop must fail instead of
// making no progress forever
func TestWriteDataRejectsMaxPacketSizeAtOrBelowHeaderLen(t *testing.T) {
	emptyMsgLen := uint64((&ssh3.DataOrExtendedDataMessage{DataType: ssh3.SSH_EXTENDED_DATA_NONE, Data: ""}).Length())
	for _, maxPacketSize := range []uint64{emptyMsgLen, emptyMsgLen - 1} {
		ch := &channelImpl{
			ChannelInfo: ChannelInfo{ChannelID: 1, MaxPacketSize: maxPacketSize},
			send:        &nopWriteCloser{},
		}
		done := make(chan error, 1)
		go func() {
			_, err := ch.WriteData([]byte("payload"), ssh3.SSH_EXTENDED_DATA_NONE)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("WriteData with MaxPacketSize %d must fail, not write zero-progress chunks", maxPacketSize)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("WriteData with MaxPacketSize %d did not return: the zero-progress write loop is back", maxPacketSize)
		}
	}
}
