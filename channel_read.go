// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package ssh3

// The receive side of a channel as a bounded ring buffer (ROADMAP.local.md
// §R9, wave 4): the QUIC stream bytes land in the ring, data-frame headers
// are parsed in place and NextData hands the payload out as a view into the
// ring. The full legacy read path copied every payload three extra times
// (ParseSSHString make+string, then the []byte conversion of the RWC); here
// the single copy from the QUIC stream into the ring stays the only one
// before the consumer's own buffer.
//
// The contract for the consumer:
//
//   - NextData returns the payloads of the data frames in wire order with
//     their SSH data type. The view stays valid until a Consume retires its
//     bytes — several views may be held at once, bounded by the ring
//     capacity (two maximum data frames). Views must be consumed in order.
//   - Consume(n) retires n payload bytes of the handed views (partial
//     consumption inside a view is allowed, the io.Reader pattern).
//   - Non-data frames (channel requests, confirmations) parsed on the way
//     are served by NextMessage in the same wire order; NextData skips the
//     control frames ahead of the next data frame — the legacy Read loop
//     dropped them the same way.
//
// When the consumer does not consume, the ring fills up and the source
// stops being read: the QUIC flow control carries the backpressure to the
// peer. A consumer that keeps calling NextData while holding every view
// gets an error instead of unbounded growth.

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/francoismichel/ssh3/compress"
	ssh3 "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
)

// recvRingCap sizes the receive ring of a channel: two maximum data frames —
// one live frame plus the pipelined next one. Advertisements beyond the
// scratch fallback bound do not buy a bigger ring: a frame that no longer
// fits the compacted ring rides a scratch buffer (one extra copy, rare).
func recvRingCap(maxPacketSize uint64) int {
	const maxRecvRingCap = 1 << 23 // 8 MiB, far above every negotiated packet size
	size := 2 * maxPacketSize
	if size > maxRecvRingCap {
		size = maxRecvRingCap
	}
	if size < 2*minPeerMaxPacketSize {
		size = 2 * minPeerMaxPacketSize
	}
	return int(size)
}

// recvFrame is one parsed data frame living in the ring: the view points
// into the ring storage or into a scratch buffer when the payload crossed
// the physical end of the ring while other views pinned it.
type recvFrame struct {
	dataType ssh3.SSHDataType
	view     []byte
	off      int     // consumed offset within the view
	start    uint64  // logical position of the frame's first header byte
	ringLen  uint64  // payload bytes the frame occupies in the ring (the compressed size for compressed frames)
	seq      uint64  // parse order
	handed   bool    // NextData already returned this view
	scratch  *[]byte // the pooled scratch buffer holding the view, when not a ring slice
}

type pendingRecvMsg struct {
	msg ssh3.Message
	seq uint64
}

// channelRecvRing owns the receive stream of a channel: every read of data
// frames and control messages goes through it, so the wire order is kept.
type channelRecvRing struct {
	src      io.Reader
	buf      []byte // the ring storage, allocated on the first fill
	capacity int

	// parse and fill positions are absolute logical offsets; the physical
	// position inside buf is offset % capacity. The front of the live data
	// is the start of the oldest unconsumed frame, or the parse position
	// when no frame is held back.
	s int // parsed so far
	f int // filled so far

	frames []recvFrame // parsed, not fully consumed data frames (parse order)
	fh     int         // queue front index
	msgs   []pendingRecvMsg
	mh     int

	seq uint64 // parse order counter

	eof bool // the source returned a permanent EOF
}

// scratchBufs recycles the glue buffers of frames straddling the physical
// ring end while other views pin the wrapped bytes. The path is rare — a
// well-behaved consumer retires its views — and each buffer serves exactly
// one frame, so the views never alias a reallocation.
var scratchBufs = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096)
		return &b
	},
}

// errRecvRingFull is returned when the consumer holds every view the ring
// can hold and demands the next one: the alternative would be unbounded
// growth or a silent hang.
type errRecvRingFull struct{ capacity int }

func (e errRecvRingFull) Error() string {
	return fmt.Sprintf("receive ring is full (%d bytes): consume the handed views before the next NextData", e.capacity)
}

func newChannelRecvRing(src io.Reader, capacity int) *channelRecvRing {
	return &channelRecvRing{src: src, capacity: capacity}
}

func (r *channelRecvRing) queueEmpty() bool { return r.fh == len(r.frames) }

// front is the logical position of the oldest live byte: the start of the
// oldest unconsumed frame, or the parse position when no frame is held
// back. Control messages parsed ahead of it are already fully materialized
// (their strings copied), so their bytes count as dead.
func (r *channelRecvRing) front() uint64 {
	if !r.queueEmpty() {
		return r.frames[r.fh].start
	}
	return uint64(r.s)
}

func (r *channelRecvRing) free() int {
	return r.capacity - (r.f - int(r.front()))
}

// varintAt decodes the QUIC varint at the logical position; complete=false
// when the buffered bytes ran out inside the varint (call fill and retry).
func (r *channelRecvRing) varintAt(pos int) (v uint64, n int, complete bool) {
	if pos >= r.f {
		return 0, 0, false
	}
	b := r.buf[pos%r.capacity]
	n = 1 << (b >> 6)
	v = uint64(b & 0x3f)
	if pos+n > r.f {
		return 0, 0, false
	}
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(r.buf[(pos+i)%r.capacity])
	}
	return v, n, true
}

// needMore reports the outcome of an incomplete header decode: more bytes
// are on their way, or the source is done — mid-varint EOF surfaces as the
// clean io.EOF the legacy stream reader produced.
func (r *channelRecvRing) needMore() (bool, error) {
	if r.eof {
		return false, io.EOF
	}
	return false, nil
}

// fill pulls one contiguous run of bytes from the source into the ring: one
// blocking Read per call — the parse loop re-checks after every pull, so a
// frame is dispatched as soon as its last byte arrives. When the ring is
// full nothing is read: the QUIC flow control carries the backpressure.
func (r *channelRecvRing) fill() error {
	if r.eof {
		return io.EOF
	}
	if r.free() == 0 {
		return nil
	}
	if r.buf == nil {
		r.buf = make([]byte, r.capacity)
	}
	t := r.f % r.capacity
	run := r.capacity - t
	if fr := r.free(); fr < run {
		run = fr
	}
	n, err := r.src.Read(r.buf[t : t+run])
	r.f += n
	if err != nil {
		if err == io.EOF {
			// sticky EOF: the bytes that landed are parsed first, the parse
			// loop classifies the outcome (clean EOF or unexpected EOF)
			r.eof = true
			return nil
		}
		return err
	}
	if n == 0 {
		// a source returning (0, nil) would spin the parse loop; the QUIC
		// stream and every test source never do
		return io.ErrNoProgress
	}
	return nil
}

// compactToFront moves the buffered bytes to the front of the ring storage,
// shifting the logical offsets. Every view handed out before it is dead
// (the frame queue is empty), so no live slice breaks.
func (r *channelRecvRing) compactToFront() {
	m := int(r.front()) // == r.s when the queue is empty
	head := r.s % r.capacity
	buffered := r.f - r.s
	l1 := r.capacity - head
	if l1 > buffered {
		l1 = buffered
	}
	l2 := buffered - l1
	if l2 > 0 {
		// the wrapped prefix moves behind the suffix first: the copy is a
		// memmove, so the overlapping region reads as the original bytes
		copy(r.buf[l1:l1+l2], r.buf[0:l2])
	}
	if l1 > 0 {
		copy(r.buf[0:l1], r.buf[head:head+l1])
	}
	r.s -= m
	r.f -= m
}

// frameView returns the payload bytes of a frame spanning
// [payloadStart, payloadStart+length) — a slice of the ring when
// contiguous, a pooled scratch buffer when the payload crosses the physical
// end while held views pin the wrapped bytes (or when a capped ring
// capacity cannot grow around the frame).
func (r *channelRecvRing) frameView(payloadStart int, length int) ([]byte, *[]byte) {
	p0 := payloadStart % r.capacity
	if p0+length <= r.capacity {
		return r.buf[p0 : p0+length], nil
	}
	bp := scratchBufs.Get().(*[]byte)
	if cap(*bp) < length {
		*bp = make([]byte, length)
	}
	view := (*bp)[:length]
	n := copy(view, r.buf[p0:r.capacity])
	copy(view[n:], r.buf[0:length-n])
	return view, bp
}

// parseDataHeader decodes the data/extended-data frame header at s: it
// returns the SSH data type, the payload length and the header end. ok=false
// means the buffered bytes ran out inside the header (fill and retry).
func (r *channelRecvRing) parseDataHeader(typeID uint64, tn int) (dataType ssh3.SSHDataType, length uint64, hdrEnd int, ok bool, err error) {
	pos := r.s + tn
	if typeID == uint64(ssh3.SSH_MSG_CHANNEL_EXTENDED_DATA) {
		dt, n, complete := r.varintAt(pos)
		if !complete {
			b, e := r.needMore()
			return 0, 0, 0, b, e
		}
		dataType = ssh3.SSHDataType(dt)
		pos += n
	}
	length, n, complete := r.varintAt(pos)
	if !complete {
		b, e := r.needMore()
		return 0, 0, 0, b, e
	}
	pos += n
	if length > util.MaxSSHStringLen {
		return 0, 0, 0, false, fmt.Errorf("data frame length %d exceeds %d", length, util.MaxSSHStringLen)
	}
	return dataType, length, pos, true, nil
}

// parseOne parses one frame or control message at the parse position.
// done=false means more bytes are needed (call fill and retry); errors are
// protocol or stream errors.
func (r *channelRecvRing) parseOne() (bool, error) {
	if r.s >= r.f {
		if r.eof {
			return false, io.EOF
		}
		return false, nil
	}
	typeID, tn, complete := r.varintAt(r.s)
	if !complete {
		return r.needMore()
	}
	switch typeID {
	case uint64(ssh3.SSH_MSG_CHANNEL_DATA), uint64(ssh3.SSH_MSG_CHANNEL_EXTENDED_DATA):
		dataType, length, payloadStart, ok, err := r.parseDataHeader(typeID, tn)
		if err != nil || !ok {
			return ok, err
		}
		end := payloadStart + int(length)
		if end > r.f {
			if r.eof {
				return false, io.ErrUnexpectedEOF
			}
			return false, nil
		}
		// the whole frame is buffered: place the payload. A payload crossing
		// the physical end compacts the ring when no view pins the wrapped
		// bytes, and rides the scratch buffer otherwise.
		if payloadStart%r.capacity+int(length) > r.capacity && r.queueEmpty() {
			m := int(r.front())
			r.compactToFront()
			payloadStart -= m
			end -= m
		}
		view, scratch := r.frameView(payloadStart, int(length))
		r.appendFrame(recvFrame{
			dataType: dataType,
			view:     view,
			start:    uint64(r.s),
			ringLen:  length,
			seq:      r.seq,
			scratch:  scratch,
		})
		r.seq++
		r.s = end
		return true, nil

	case uint64(ssh3.SSH_MSG_CHANNEL_DATA_COMPRESSED):
		// the compressed frame: type varint, algorithm varint, compressed
		// length varint, compressed payload. The payload leaves the ring as
		// the decompressed plain buffer — the decompressor allocates it, so
		// this frame kind never rides the zero-copy view (compressed
		// channels are opt-in; the plain frames are the hot path).
		pos := r.s + tn
		algorithm, n, complete := r.varintAt(pos)
		if !complete {
			return r.needMore()
		}
		pos += n
		length, n, complete := r.varintAt(pos)
		if !complete {
			return r.needMore()
		}
		pos += n
		if length > util.MaxSSHStringLen {
			return false, fmt.Errorf("compressed data frame length %d exceeds %d", length, util.MaxSSHStringLen)
		}
		end := pos + int(length)
		if end > r.f {
			if r.eof {
				return false, io.ErrUnexpectedEOF
			}
			return false, nil
		}
		if pos%r.capacity+int(length) > r.capacity && r.queueEmpty() {
			m := int(r.front())
			r.compactToFront()
			pos -= m
			end -= m
		}
		compressed, scratch := r.frameView(pos, int(length))
		if scratch != nil {
			// the compressed bytes are dead after the decompression; the
			// buffer goes back to the pool right away
			defer func() {
				*scratch = (*scratch)[:0]
				scratchBufs.Put(scratch)
			}()
		}
		plain, err := compress.Decompress(algorithm, compressed)
		if err != nil {
			return false, err
		}
		r.appendFrame(recvFrame{
			dataType: ssh3.SSH_EXTENDED_DATA_NONE,
			view:     plain,
			start:    uint64(r.s),
			ringLen:  length,
			seq:      r.seq,
		})
		r.seq++
		r.s = end
		return true, nil

	default:
		// control frame: the message parsers work off a reader over the
		// buffered bytes; hitting the buffered end means retry after the
		// next fill (the parsers are pure reads, the restart is safe)
		rr := &ringReader{ring: r, pos: r.s}
		msg, err := ssh3.ParseMessage(rr)
		if err != nil {
			return r.incompleteOrErr(err, rr)
		}
		r.appendMsg(pendingRecvMsg{msg: msg, seq: r.seq})
		r.seq++
		r.s = int(rr.pos)
		return true, nil
	}
}

// incompleteOrErr classifies a parse error of the reader-based (control)
// path: an end-of-input error before the source is done means more data is
// needed (the parsers are pure reads, the restart from the parse position
// is safe); once the source is done the error surfaces as the legacy parser
// produced it. Anything else is a protocol error.
func (r *channelRecvRing) incompleteOrErr(err error, rr *ringReader) (bool, error) {
	if r.eof {
		return false, err
	}
	if isEOFish(err, rr) {
		return false, nil // retry after the next fill
	}
	return false, err
}

// isEOFish reports whether a parser error means "the buffered bytes ran
// out" — the bare io errors of the varint, ReadFull and binary.Read paths,
// the InvalidSSHString wrapper around them, or any other error raised at
// the exact end of the buffered bytes (the truncated-string short read).
// An unknown message type is always final: the legacy ParseMessage surfaced
// it without waiting for more bytes.
func isEOFish(err error, rr *ringReader) bool {
	var unknown ssh3.UnknownMessageType
	if errors.As(err, &unknown) {
		return false
	}
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return true
	}
	var invalid util.InvalidSSHString
	if errors.As(err, &invalid) {
		if invalid.Reason == io.EOF || invalid.Reason == io.ErrUnexpectedEOF {
			return true
		}
	}
	return rr.pos == rr.ring.f
}

func (r *channelRecvRing) appendFrame(fr recvFrame) {
	if r.fh > 0 {
		n := copy(r.frames, r.frames[r.fh:])
		r.frames = r.frames[:n]
		r.fh = 0
	}
	r.frames = append(r.frames, fr)
}

func (r *channelRecvRing) appendMsg(pm pendingRecvMsg) {
	if r.mh > 0 {
		n := copy(r.msgs, r.msgs[r.mh:])
		r.msgs = r.msgs[:n]
		r.mh = 0
	}
	r.msgs = append(r.msgs, pm)
}

func (r *channelRecvRing) popFrame() {
	if fr := r.frames[r.fh]; fr.scratch != nil {
		*fr.scratch = (*fr.scratch)[:0]
		scratchBufs.Put(fr.scratch)
	}
	r.fh++
	if r.fh == len(r.frames) {
		r.frames = r.frames[:0]
		r.fh = 0
	}
}

func (r *channelRecvRing) popMsg() {
	r.mh++
	if r.mh == len(r.msgs) {
		r.msgs = r.msgs[:0]
		r.mh = 0
	}
}

// consume retires n payload bytes of the handed frames, in parse order;
// frames fully consumed along the way leave the ring. Zero-length frames
// survive until NextData handed them out — a raw consumer must see them
// (the data type may matter), while the stream adapters skip them.
// Consuming past the handed bytes is a programming error and simply stops
// at the queue end.
func (r *channelRecvRing) consume(n int) {
	for r.fh < len(r.frames) {
		fr := &r.frames[r.fh]
		if fr.handed && fr.off == len(fr.view) {
			r.popFrame()
			continue
		}
		if n == 0 {
			return
		}
		m := len(fr.view) - fr.off
		if m > n {
			m = n
		}
		fr.off += m
		n -= m
		if fr.off == len(fr.view) {
			// fully consumed before (or while) being handed out: nothing is
			// left for a later NextData to return
			fr.handed = true
		}
	}
}

// unhandedFrame returns the first frame in parse order no view was handed
// out for yet.
func (r *channelRecvRing) unhandedFrame() *recvFrame {
	for i := r.fh; i < len(r.frames); i++ {
		if !r.frames[i].handed {
			return &r.frames[i]
		}
	}
	return nil
}

func (r *channelRecvRing) frontMsg() *pendingRecvMsg {
	if r.mh < len(r.msgs) {
		return &r.msgs[r.mh]
	}
	return nil
}

// ringReader adapts the buffered ring bytes to util.Reader for the control
// message parsers; it hits io.EOF at the end of the buffered bytes, which
// the parse loop translates into a retry after the next fill.
type ringReader struct {
	ring *channelRecvRing
	pos  int
}

var _ util.Reader = (*ringReader)(nil)

func (rr *ringReader) Read(p []byte) (int, error) {
	n := rr.ring.f - rr.pos
	if n == 0 {
		return 0, io.EOF
	}
	if len(p) < n {
		n = len(p)
	}
	p0 := rr.pos % rr.ring.capacity
	run := rr.ring.capacity - p0
	if run > n {
		run = n
	}
	copied := copy(p, rr.ring.buf[p0:p0+run])
	copied += copy(p[copied:], rr.ring.buf[0:n-run])
	rr.pos += copied
	return copied, nil
}

func (rr *ringReader) ReadByte() (byte, error) {
	if rr.pos >= rr.ring.f {
		return 0, io.EOF
	}
	b := rr.ring.buf[rr.pos%rr.ring.capacity]
	rr.pos++
	return b, nil
}

// recvRing lazily builds the receive ring of the channel over its QUIC
// stream; channels that never carry data never pay for the buffer.
func (c *channelImpl) recvRing() *channelRecvRing {
	if c.ring == nil {
		c.ring = newChannelRecvRing(c.recv, recvRingCap(c.ChannelInfo.MaxPacketSize))
	}
	return c.ring
}

// NextData returns the next data frame payload as a view into the receive
// ring with its SSH data type. The view stays valid until the next Consume
// retires it; several views may be held at once, in wire order, bounded by
// the ring capacity. Control frames ahead of the next data frame are
// dropped here — the legacy Read loop skipped them the same way.
func (c *channelImpl) NextData() (ssh3.SSHDataType, []byte, error) {
	ring := c.recvRing()
	for {
		ring.consume(0) // flush frames fully consumed by earlier Consume calls
		if fr := ring.unhandedFrame(); fr != nil {
			// control messages parsed earlier in the wire order are dropped;
			// NextMessage serves them when it is the consumer
			for pm := ring.frontMsg(); pm != nil && pm.seq < fr.seq; pm = ring.frontMsg() {
				ring.popMsg()
			}
			fr.handed = true
			return fr.dataType, fr.view[fr.off:], nil
		}
		if pm := ring.frontMsg(); pm != nil {
			ring.popMsg()
			continue
		}
		done, err := ring.parseOne()
		if err != nil {
			return 0, nil, err
		}
		if !done {
			if ring.free() == 0 {
				return 0, nil, errRecvRingFull{capacity: ring.capacity}
			}
			if err := ring.fill(); err != nil {
				return 0, nil, err
			}
		}
	}
}

// Consume retires n payload bytes of the views NextData handed out, in wire
// order; partial consumption inside a view is the io.Reader pattern.
func (c *channelImpl) Consume(n int) {
	c.recvRing().consume(n)
}
