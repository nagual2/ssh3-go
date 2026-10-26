package ssh3

// Allocation and byte-identity checks for the R9 zero-copy data path
// (ROADMAP.local.md §R9): sendMessage must ride a pooled buffer — zero
// allocations per call after the warmup — and must keep the byte stream
// identical to direct marshalling.

import (
	"bytes"
	"testing"

	ssh3 "github.com/francoismichel/ssh3/message"
)

// discardWriter swallows the bytes without keeping state: a recordingWriter
// holds a growing bytes.Buffer whose periodic growth allocates inside the
// measured window, so the allocation check needs a stable sink.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (discardWriter) Close() error                { return nil }

func TestSendMessageByteIdentity(t *testing.T) {
	msg := &ssh3.ChannelOpenConfirmationMessage{MaxPacketSize: 30000}
	ref := make([]byte, msg.Length())
	if _, err := msg.Write(ref); err != nil {
		t.Fatalf("reference marshal: %v", err)
	}
	w := &recordingWriter{}
	ch := &channelImpl{
		ChannelInfo: ChannelInfo{MaxPacketSize: 30000},
		send:        w,
	}
	if err := ch.sendMessage(msg); err != nil {
		t.Fatalf("sendMessage: %v", err)
	}
	if !bytes.Equal(w.buf.Bytes(), ref) {
		t.Fatalf("byte stream mismatch: got %x, want %x", w.buf.Bytes(), ref)
	}
}

func TestSendMessageNoAllocs(t *testing.T) {
	msg := &ssh3.ChannelOpenConfirmationMessage{MaxPacketSize: 30000}
	ch := &channelImpl{
		ChannelInfo: ChannelInfo{MaxPacketSize: 30000},
		send:        discardWriter{},
	}
	// warmup: fills the pool, drains the (empty) pending header state
	if err := ch.sendMessage(msg); err != nil {
		t.Fatalf("warmup sendMessage: %v", err)
	}
	bad := false
	allocs := testing.AllocsPerRun(100, func() {
		if err := ch.sendMessage(msg); err != nil {
			bad = true
		}
	})
	if bad {
		t.Fatalf("sendMessage failed during the measured runs")
	}
	if allocs > 0 {
		t.Fatalf("sendMessage allocates %.1f objects per call, want 0", allocs)
	}
}

// a message larger than the pooled buffer's initial capacity must still ride
// the pool once a big buffer has been recycled into it
func TestSendMessageNoAllocsLargeMessage(t *testing.T) {
	big := &ssh3.DataOrExtendedDataMessage{Data: string(make([]byte, 4096))}
	ch := &channelImpl{
		ChannelInfo: ChannelInfo{MaxPacketSize: 30000},
		send:        discardWriter{},
	}
	if err := ch.sendMessage(big); err != nil {
		t.Fatalf("warmup sendMessage: %v", err)
	}
	bad := false
	allocs := testing.AllocsPerRun(100, func() {
		if err := ch.sendMessage(big); err != nil {
			bad = true
		}
	})
	if bad {
		t.Fatalf("sendMessage failed during the measured runs")
	}
	if allocs > 0 {
		t.Fatalf("sendMessage (large message) allocates %.1f objects per call, want 0", allocs)
	}
}

// The R9 before/after pair: WriteData is the optimized path,
// referenceWrite (channel_write_test.go) is the byte-identical replica of
// the pre-optimization per-message marshalling.
var benchPayload = func() []byte {
	b := make([]byte, 1<<20)
	for i := range b {
		b[i] = byte(i*7 + i>>9)
	}
	return b
}()

func BenchmarkWriteData(b *testing.B) {
	ch := &channelImpl{
		ChannelInfo: ChannelInfo{MaxPacketSize: 30000},
		send:        discardWriter{},
	}
	b.SetBytes(int64(len(benchPayload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ch.WriteData(benchPayload, ssh3.SSH_EXTENDED_DATA_NONE); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReferenceWrite(b *testing.B) {
	b.SetBytes(int64(len(benchPayload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = referenceWrite(ssh3.SSH_EXTENDED_DATA_NONE, benchPayload, 30000)
	}
}

func BenchmarkSendMessage(b *testing.B) {
	msg := &ssh3.ChannelOpenConfirmationMessage{MaxPacketSize: 30000}
	ch := &channelImpl{
		ChannelInfo: ChannelInfo{MaxPacketSize: 30000},
		send:        discardWriter{},
	}
	if err := ch.sendMessage(msg); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ch.sendMessage(msg); err != nil {
			b.Fatal(err)
		}
	}
}
