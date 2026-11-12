package ssh3

// Read-side zero-copy tests for the R9 wave 4 (ROADMAP.local.md §R9): the
// receive ring parses data frames in place, NextData hands out views into the
// ring and Consume retires them. The byte stream the consumer sees must be
// identical to the frames the peer marshalled, the hot loop must not
// allocate, and the ring must never grow past its capacity (the QUIC flow
// control carries the backpressure).

import (
	"bytes"
	"io"
	"testing"

	ssh3 "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
)

// dataFrameBytes marshals the canonical wire form of one data frame — the
// reference bytes the read path must recover the payload from.
func dataFrameBytes(dataType ssh3.SSHDataType, payload string) []byte {
	msg := &ssh3.DataOrExtendedDataMessage{DataType: dataType, Data: payload}
	buf := make([]byte, msg.Length())
	if _, err := msg.Write(buf); err != nil {
		panic(err)
	}
	return buf
}

// confirmFrameBytes marshals a ChannelOpenConfirmationMessage — the smallest
// non-data frame, used to check the data path skips control frames.
func confirmFrameBytes(maxPacketSize uint64) []byte {
	msg := &ssh3.ChannelOpenConfirmationMessage{MaxPacketSize: maxPacketSize}
	buf := make([]byte, msg.Length())
	if _, err := msg.Write(buf); err != nil {
		panic(err)
	}
	return buf
}

// exitStatusFrameBytes marshals a ChannelRequestMessage carrying an
// exit-status request — a control frame parsed through ParseRequestMessage
// with SSH strings, exercising the reader-based control path.
func exitStatusFrameBytes(status uint64) []byte {
	msg := &ssh3.ChannelRequestMessage{
		ChannelRequest: &ssh3.ExitStatusRequest{ExitStatus: status},
	}
	buf := make([]byte, msg.Length())
	if _, err := msg.Write(buf); err != nil {
		panic(err)
	}
	return buf
}

// chunkSource hands out at most chunk bytes per Read — the byte-at-a-time
// mode walks the parser through every varint and payload boundary.
type chunkSource struct {
	data  []byte
	chunk int
	off   int
	reads int
}

func (s *chunkSource) Read(p []byte) (int, error) {
	s.reads++
	if s.off >= len(s.data) {
		return 0, io.EOF
	}
	n := s.chunk
	if len(p) < n {
		n = len(p)
	}
	if len(s.data)-s.off < n {
		n = len(s.data) - s.off
	}
	n = copy(p, s.data[s.off:s.off+n])
	s.off += n
	return n, nil
}

// newReadChannel builds a channel whose receive side rides a ring over src.
// ringCap <= 0 means the production size (two max packets).
func newReadChannel(src io.Reader, ringCap int) *channelImpl {
	ch := &channelImpl{
		ChannelInfo:     ChannelInfo{MaxPacketSize: 30000},
		confirmSent:     true,
		confirmReceived: true,
	}
	if ringCap <= 0 {
		ringCap = 2 * 30000
	}
	ch.ring = newChannelRecvRing(src, ringCap)
	return ch
}

// readAll drains every data frame, returning the payloads and data types.
func readAll(t *testing.T, ch *channelImpl) ([]byte, []ssh3.SSHDataType) {
	t.Helper()
	var out []byte
	var types []ssh3.SSHDataType
	for {
		dataType, view, err := ch.NextData()
		if err == io.EOF {
			return out, types
		}
		if err != nil {
			t.Fatalf("NextData: %v", err)
		}
		out = append(out, view...)
		types = append(types, dataType)
		ch.Consume(len(view))
	}
}

func TestNextDataByteIdentity(t *testing.T) {
	// the canonical frame stream: the concatenated marshalled frames are the
	// reference; the read path must recover the payloads byte for byte
	frames := [][]byte{
		dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, "hello world"),
		dataFrameBytes(ssh3.SSH_EXTENDED_DATA_STDERR, "an error happened"),
		dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, string(bytes.Repeat([]byte{0xAB}, 4096))),
		dataFrameBytes(ssh3.SSH_EXTENDED_DATA_STDERR, ""),
		dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, "tail"),
	}
	var stream []byte
	for _, f := range frames {
		stream = append(stream, f...)
	}
	wantPayload := []string{"hello world", "an error happened", string(bytes.Repeat([]byte{0xAB}, 4096)), "", "tail"}
	wantTypes := []ssh3.SSHDataType{
		ssh3.SSH_EXTENDED_DATA_NONE, ssh3.SSH_EXTENDED_DATA_STDERR,
		ssh3.SSH_EXTENDED_DATA_NONE, ssh3.SSH_EXTENDED_DATA_STDERR,
		ssh3.SSH_EXTENDED_DATA_NONE,
	}
	for _, chunk := range []int{1, 2, 3, 5, 64, 4096} {
		src := &chunkSource{data: stream, chunk: chunk}
		ch := newReadChannel(src, 0)
		var got []byte
		var gotTypes []ssh3.SSHDataType
		i := 0
		for {
			dataType, view, err := ch.NextData()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("chunk %d: NextData: %v", chunk, err)
			}
			if i >= len(wantPayload) {
				t.Fatalf("chunk %d: more frames than expected", chunk)
			}
			if string(view) != wantPayload[i] {
				t.Fatalf("chunk %d: frame %d payload mismatch: got %d bytes %q, want %q",
					chunk, i, len(view), view[:min(len(view), 32)], wantPayload[i][:min(len(wantPayload[i]), 32)])
			}
			if dataType != wantTypes[i] {
				t.Fatalf("chunk %d: frame %d dataType = %d, want %d", chunk, i, dataType, wantTypes[i])
			}
			got = append(got, view...)
			gotTypes = append(gotTypes, dataType)
			ch.Consume(len(view))
			i++
		}
		if i != len(wantPayload) {
			t.Fatalf("chunk %d: got %d frames, want %d", chunk, i, len(wantPayload))
		}
		// byte identity over the whole stream: the concatenation of the
		// recovered payloads must equal the payload halves of the canonical
		// frames
		if !bytes.Equal(got, payloadStream(frames)) {
			t.Fatalf("chunk %d: payload stream mismatch", chunk)
		}
		if len(gotTypes) != len(wantTypes) {
			t.Fatalf("chunk %d: %d frames, want %d", chunk, len(gotTypes), len(wantTypes))
		}
	}
}

// payloadStream extracts the payload bytes of the canonical frames by
// re-parsing the framing: the varint length follows the type (and dataType).
func payloadStream(frames [][]byte) []byte {
	var out []byte
	for _, f := range frames {
		r := util.NewReader(bytes.NewReader(f))
		typeID, _ := util.ReadVarInt(r)
		if typeID == ssh3.SSH_MSG_CHANNEL_EXTENDED_DATA {
			_, _ = util.ReadVarInt(r) // dataType
		}
		length, _ := util.ReadVarInt(r)
		payload := make([]byte, length)
		_, _ = io.ReadFull(r, payload)
		out = append(out, payload...)
	}
	return out
}

func TestNextDataZeroAllocs(t *testing.T) {
	// 512 canned frames; the measured window consumes from the middle of the
	// stream, so the source never resets inside it
	var stream []byte
	for i := 0; i < 512; i++ {
		payload := bytes.Repeat([]byte{byte(i % 251)}, 200)
		stream = append(stream, dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, string(payload))...)
	}
	src := &chunkSource{data: stream, chunk: 8192}
	ch := newReadChannel(src, 0)
	// warmup: the ring buffer, the frame queue and the parse path reach
	// steady state
	for i := 0; i < 8; i++ {
		_, view, err := ch.NextData()
		if err != nil {
			t.Fatalf("warmup NextData: %v", err)
		}
		ch.Consume(len(view))
	}
	bad := false
	allocs := testing.AllocsPerRun(200, func() {
		_, view, err := ch.NextData()
		if err != nil {
			bad = true
			return
		}
		ch.Consume(len(view))
	})
	if bad {
		t.Fatalf("NextData failed during the measured runs")
	}
	if allocs > 0 {
		t.Fatalf("NextData+Consume allocates %.1f objects per frame, want 0", allocs)
	}
}

func TestReadWriteZeroAllocs(t *testing.T) {
	var stream []byte
	for i := 0; i < 512; i++ {
		payload := bytes.Repeat([]byte{byte(i % 251)}, 200)
		stream = append(stream, dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, string(payload))...)
	}
	src := &chunkSource{data: stream, chunk: 8192}
	ch := newReadChannel(src, 0)
	rwc := NewChannelReadWriteCloser(ch)
	p := make([]byte, 256)
	// warmup
	if _, err := io.ReadFull(rwc, p); err != nil {
		t.Fatalf("warmup read: %v", err)
	}
	bad := false
	allocs := testing.AllocsPerRun(200, func() {
		if _, err := rwc.Read(p); err != nil {
			bad = true
		}
	})
	if bad {
		t.Fatalf("Read failed during the measured runs")
	}
	if allocs > 0 {
		t.Fatalf("ChannelReadWriteCloser.Read allocates %.1f objects per call, want 0", allocs)
	}
}

func TestNextDataViewsLiveUntilConsume(t *testing.T) {
	stream := append(
		dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, "first"),
		dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, "second")...)
	ch := newReadChannel(&chunkSource{data: stream, chunk: 4}, 256)

	t1, v1, err := ch.NextData()
	if err != nil {
		t.Fatalf("NextData 1: %v", err)
	}
	t2, v2, err := ch.NextData()
	if err != nil {
		t.Fatalf("NextData 2: %v", err)
	}
	if t1 != ssh3.SSH_EXTENDED_DATA_NONE || t2 != ssh3.SSH_EXTENDED_DATA_NONE {
		t.Fatalf("dataTypes: %d, %d", t1, t2)
	}
	// both views carry live bytes before any Consume
	if string(v1) != "first" || string(v2) != "second" {
		t.Fatalf("views drifted before Consume: %q, %q", v1, v2)
	}
	ch.Consume(len(v1))
	if string(v2) != "second" {
		t.Fatalf("second view died after consuming the first: %q", v2)
	}
	ch.Consume(len(v2))
	if _, _, err := ch.NextData(); err != io.EOF {
		t.Fatalf("expected io.EOF after the stream drained, got %v", err)
	}
}

func TestNextMessageOrderViaRing(t *testing.T) {
	// parse order: data frame, open confirmation (consumed internally),
	// exit-status request, data frame; NextMessage must return the data
	// frames in order with the request between them
	stream := append(
		dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, "a"),
		confirmFrameBytes(30000)...)
	stream = append(stream, exitStatusFrameBytes(7)...)
	stream = append(stream, dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, "b")...)

	ch := newReadChannel(&chunkSource{data: stream, chunk: 3}, 256)

	msg1, err := ch.NextMessage()
	if err != nil {
		t.Fatalf("NextMessage 1: %v", err)
	}
	data1, ok := msg1.(*ssh3.DataOrExtendedDataMessage)
	if !ok || data1.Data != "a" {
		t.Fatalf("first message: %#v, want data \"a\"", msg1)
	}
	// the open confirmation is consumed internally by the legacy contract
	msg2, err := ch.NextMessage()
	if err != nil {
		t.Fatalf("NextMessage 2: %v", err)
	}
	req, ok := msg2.(*ssh3.ChannelRequestMessage)
	if !ok {
		t.Fatalf("second message: %T, want ChannelRequestMessage", msg2)
	}
	exit, ok := req.ChannelRequest.(*ssh3.ExitStatusRequest)
	if !ok || exit.ExitStatus != 7 {
		t.Fatalf("request: %#v, want exit-status 7", req.ChannelRequest)
	}
	msg3, err := ch.NextMessage()
	if err != nil {
		t.Fatalf("NextMessage 3: %v", err)
	}
	data3, ok := msg3.(*ssh3.DataOrExtendedDataMessage)
	if !ok || data3.Data != "b" {
		t.Fatalf("third message: %#v, want data \"b\"", msg3)
	}
}

func TestRWCSkipsControlFrames(t *testing.T) {
	// the legacy Read loop skipped non-data frames: the RWC over the ring
	// must keep that behaviour
	stream := append(
		dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, "a"),
		confirmFrameBytes(30000)...)
	stream = append(stream, exitStatusFrameBytes(7)...)
	stream = append(stream, dataFrameBytes(ssh3.SSH_EXTENDED_DATA_STDERR, "err")...)

	ch := newReadChannel(&chunkSource{data: stream, chunk: 2}, 256)
	rwc := NewChannelReadWriteCloser(ch)
	out, err := io.ReadAll(rwc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(out) != "aerr" {
		t.Fatalf("RWC stream: %q, want %q", out, "aerr")
	}
	if _, err := rwc.Read(make([]byte, 4)); err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestNextDataWrapBothPaths(t *testing.T) {
	// A frame crossing the physical end of the ring: without held views the
	// ring compacts; with a held view pinning the ring front the frame rides
	// the scratch buffer — both must yield the same bytes. The layout: frame
	// A (4 bytes on the wire) consumed, frame B0 (4 bytes) held as a view,
	// frame B1 (25 bytes) straddling the physical end of a 32-byte ring.
	big := string(bytes.Repeat([]byte{0x5A}, 22))
	var stream []byte
	stream = append(stream, dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, "x")...)
	stream = append(stream, dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, "y")...)
	stream = append(stream, dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, big)...)
	const ringCap = 32

	// compact path: every frame is consumed before the next is fetched
	ch := newReadChannel(&chunkSource{data: stream, chunk: 1}, ringCap)
	got, _ := readAll(t, ch)
	if string(got) != "xy"+big {
		t.Fatalf("compact path payload: %q", got)
	}

	// scratch path: B0 stays handed (unconsumed), so the ring cannot compact
	ch = newReadChannel(&chunkSource{data: stream, chunk: 1}, ringCap)
	_, v0, err := ch.NextData() // frame A
	if err != nil {
		t.Fatalf("NextData A: %v", err)
	}
	ch.Consume(len(v0))
	_, v1, err := ch.NextData() // frame B0, held
	if err != nil {
		t.Fatalf("NextData B0: %v", err)
	}
	if string(v1) != "y" {
		t.Fatalf("held view B0: %q", v1)
	}
	_, v2, err := ch.NextData() // frame B1 straddles the ring end
	if err != nil {
		t.Fatalf("NextData B1 (scratch): %v", err)
	}
	if string(v2) != big {
		t.Fatalf("scratch path payload mismatch")
	}
	// the held view stays alive and the scratch view survives the consume of
	// the frame before it
	ch.Consume(len(v1))
	if string(v2) != big {
		t.Fatalf("scratch view died after consuming the held frame")
	}
	ch.Consume(len(v2))
	if _, _, err := ch.NextData(); err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestRingBackpressure(t *testing.T) {
	// the ring is bounded: with a consumer holding every view the source
	// reads stop at the capacity, and consuming resumes the progress
	payload := string(bytes.Repeat([]byte{0x33}, 200))
	var stream []byte
	for i := 0; i < 400; i++ {
		// 400 frames of ~207 bytes: the stream (82 KB) exceeds the ring
		// (60 KB), so a consumer holding every view must hit the bound
		stream = append(stream, dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, payload)...)
	}
	src := &chunkSource{data: stream, chunk: 8192}
	ch := newReadChannel(src, 0) // 60000: about 270 frames of 207 bytes

	views := 0
	var lastErr error
	for {
		_, view, err := ch.NextData()
		if err != nil {
			lastErr = err
			break
		}
		_ = view // held: the consumer keeps every view until the ring is full
		views++
		if views > 1000 {
			t.Fatalf("ring grew past any bound: %d live frames", views)
		}
	}
	if views <= 1 {
		t.Fatalf("ring accepted only %d frames", views)
	}
	readsAtFull := src.reads
	if lastErr == nil {
		t.Fatalf("expected an error once the ring is full of held views")
	}
	// retire every held view at once: the ring front advances past them
	ch.Consume(views * len(payload))
	// consuming resumes: the source serves the remaining frames
	for {
		_, view, err := ch.NextData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextData after consume: %v", err)
		}
		if len(view) != len(payload) {
			t.Fatalf("payload len %d, want %d", len(view), len(payload))
		}
		ch.Consume(len(view))
	}
	if src.reads == readsAtFull {
		t.Fatalf("source was not read again after Consume")
	}
}

func TestNextDataEOFAndTruncated(t *testing.T) {
	frame := dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, "whole")
	// a clean EOF after whole frames
	ch := newReadChannel(&chunkSource{data: frame, chunk: 3}, 256)
	_, view, err := ch.NextData()
	if err != nil || string(view) != "whole" {
		t.Fatalf("NextData: %q, %v", view, err)
	}
	ch.Consume(len(view))
	if _, _, err := ch.NextData(); err != io.EOF {
		t.Fatalf("clean EOF: got %v", err)
	}

	// a truncated frame: EOF in the middle of the payload
	ch = newReadChannel(&chunkSource{data: frame[:len(frame)-2], chunk: 3}, 256)
	if _, _, err := ch.NextData(); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated frame: got %v, want io.ErrUnexpectedEOF", err)
	}

	// a truncated header: EOF inside the first varint surfaces as the clean
	// io.EOF the legacy ParseMessage path produced
	ch = newReadChannel(&chunkSource{data: frame[:1], chunk: 3}, 256)
	if _, _, err := ch.NextData(); err != io.EOF {
		t.Fatalf("truncated header: got %v, want io.EOF", err)
	}

	// a declared length beyond the protocol bound is refused without any
	// allocation attempt
	huge := append([]byte{0x40, 0x5E}, bytes.Repeat([]byte{0xFF}, 8)...) // DATA + varint 2^62-1
	ch = newReadChannel(&chunkSource{data: huge, chunk: 5}, 256)
	if _, _, err := ch.NextData(); err == nil {
		t.Fatalf("oversized length accepted")
	}
}

func TestChannelReadWriteCloserWriteTo(t *testing.T) {
	payloads := []string{"part-one|", "part-two|", "part-three"}
	var stream []byte
	for _, p := range payloads {
		stream = append(stream, dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, p)...)
	}
	ch := newReadChannel(&chunkSource{data: stream, chunk: 7}, 256)
	rwc := NewChannelReadWriteCloser(ch)
	var _ io.WriterTo = rwc

	var sink bytes.Buffer
	n, err := rwc.WriteTo(&sink)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	want := "part-one|part-two|part-three"
	if sink.String() != want {
		t.Fatalf("WriteTo stream: %q, want %q", sink.String(), want)
	}
	if n != int64(len(want)) {
		t.Fatalf("WriteTo count: %d, want %d", n, len(want))
	}
	// a clean EOF must come out as a clean end (io.Copy relies on it)
	if _, err := rwc.WriteTo(&sink); err != nil {
		t.Fatalf("WriteTo after EOF: %v", err)
	}
}

func TestWriteToSinksThroughCopy(t *testing.T) {
	// io.Copy prefers WriterTo: one copy into the destination's Write, no
	// intermediate buffer — the observable contract of the view-aware path
	var stream []byte
	payload := bytes.Repeat([]byte{0x71}, 5000)
	stream = append(stream, dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, string(payload))...)
	ch := newReadChannel(&chunkSource{data: stream, chunk: 997}, 16384)
	rwc := NewChannelReadWriteCloser(ch)
	var sink bytes.Buffer
	if _, err := io.Copy(&sink, rwc); err != nil {
		t.Fatalf("io.Copy: %v", err)
	}
	if !bytes.Equal(sink.Bytes(), payload) {
		t.Fatalf("io.Copy payload mismatch: %d bytes", sink.Len())
	}
}

// referenceRead replicates the pre-optimization read path: ParseMessage over
// the stream (make+string inside ParseSSHString) plus the []byte conversion
// of the RWC. The benchmark pair anchors the before/after numbers.
func referenceRead(stream []byte) int {
	total := 0
	r := bytes.NewReader(stream)
	reader := util.NewReader(r)
	for {
		msg, err := ssh3.ParseMessage(reader)
		if err != nil {
			return total
		}
		if data, ok := msg.(*ssh3.DataOrExtendedDataMessage); ok {
			total += len([]byte(data.Data))
		}
	}
}

func BenchmarkNextData(b *testing.B) {
	var stream []byte
	for i := 0; i < 4096; i++ {
		payload := bytes.Repeat([]byte{byte(i % 251)}, 1024)
		stream = append(stream, dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, string(payload))...)
	}
	src := &chunkSource{data: stream, chunk: 1 << 20}
	ch := &channelImpl{ChannelInfo: ChannelInfo{MaxPacketSize: 30000}, confirmSent: true, confirmReceived: true}
	ch.ring = newChannelRecvRing(src, 2*30000)
	// warmup
	for i := 0; i < 16; i++ {
		_, view, err := ch.NextData()
		if err != nil {
			b.Fatal(err)
		}
		ch.Consume(len(view))
	}
	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, view, err := ch.NextData()
		if err == io.EOF {
			// the canned stream ran out: rewind it with a fresh ring (the
			// reset cost amortizes over 4096 frames)
			src.off = 0
			ch.ring = newChannelRecvRing(src, 2*30000)
			_, view, err = ch.NextData()
		}
		if err != nil {
			b.Fatal(err)
		}
		ch.Consume(len(view))
	}
}

func BenchmarkReferenceRead(b *testing.B) {
	var stream []byte
	for i := 0; i < 4096; i++ {
		payload := bytes.Repeat([]byte{byte(i % 251)}, 1024)
		stream = append(stream, dataFrameBytes(ssh3.SSH_EXTENDED_DATA_NONE, string(payload))...)
	}
	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		referenceRead(stream)
	}
}
