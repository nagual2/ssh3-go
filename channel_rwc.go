// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package ssh3

import (
	"io"

	ssh3Messages "github.com/francoismichel/ssh3/message"
)

// ChannelReadWriteCloser adapts an ssh3 Channel to io.ReadWriteCloser so
// stream-oriented protocols (e.g. an SFTP subsystem) can run over it. Reads
// yield only the payloads of data messages: the adapter must be the sole
// consumer of the channel's receive side, since it pulls raw messages.
//
// The read side rides the channel's receive ring (channel_read.go): the
// payload of a data frame is handed out as a view and copied straight into
// the caller's buffer — one copy, the io.Reader contract itself. WriteTo
// feeds the views straight into the destination, so io.Copy reaches the
// view-aware path (one copy into the destination's own Write).
type ChannelReadWriteCloser struct {
	channel Channel
	view    []byte // the remainder of the current data frame view
}

func NewChannelReadWriteCloser(channel Channel) *ChannelReadWriteCloser {
	return &ChannelReadWriteCloser{channel: channel}
}

func (c *ChannelReadWriteCloser) Read(p []byte) (int, error) {
	if len(p) == 0 {
		// the legacy adapter fetched a message even for an empty read;
		// returning early is safe (no caller relies on the side effect)
		return 0, nil
	}
	for len(c.view) == 0 {
		_, view, err := c.channel.NextData()
		if err != nil {
			// io.EOF propagates so protocol stacks treat it as a clean end
			return 0, err
		}
		if len(view) == 0 {
			// an empty data frame retires at once (the legacy loop skipped
			// empty payloads the same way)
			c.channel.Consume(0)
			continue
		}
		c.view = view
	}
	n := copy(p, c.view)
	c.view = c.view[n:]
	c.channel.Consume(n)
	return n, nil
}

// WriteTo hands the data frame views straight to w: a view-aware consumer
// pays one copy inside its own Write instead of the copy into an
// intermediate buffer. A clean end of the channel returns a nil error —
// io.Copy relies on it (the Read path converts io.EOF the same way).
func (c *ChannelReadWriteCloser) WriteTo(w io.Writer) (int64, error) {
	var total int64
	// the remainder of a partially consumed view from an earlier Read goes
	// out first
	for len(c.view) > 0 {
		n, err := w.Write(c.view)
		c.channel.Consume(n)
		total += int64(n)
		c.view = c.view[n:]
		if err != nil {
			return total, err
		}
	}
	for {
		_, view, err := c.channel.NextData()
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
		for len(view) > 0 {
			n, werr := w.Write(view)
			view = view[n:]
			c.channel.Consume(n)
			total += int64(n)
			if werr != nil {
				// keep the rest for a later Read or WriteTo retry
				c.view = view
				return total, werr
			}
		}
		// an empty data frame retires on the next NextData call (the ring
		// flushes fully consumed frames off the queue front)
	}
}

func (c *ChannelReadWriteCloser) Write(p []byte) (int, error) {
	return c.channel.WriteData(p, ssh3Messages.SSH_EXTENDED_DATA_NONE)
}

func (c *ChannelReadWriteCloser) Close() error {
	c.channel.Close()
	return nil
}

// Compile-time interface checks.
var (
	_ io.ReadWriteCloser = (*ChannelReadWriteCloser)(nil)
	_ io.WriterTo        = (*ChannelReadWriteCloser)(nil)
)
