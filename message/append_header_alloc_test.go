package message

import (
	"testing"
)

// The header append runs once per WriteData chunk (ROADMAP.local.md §R9):
// the three varints must ride the caller's stack array, zero heap
// allocations per call.
func TestAppendHeaderNoAllocs(t *testing.T) {
	for _, m := range []*DataOrExtendedDataMessage{
		{DataType: SSH_EXTENDED_DATA_NONE},
		{DataType: SSH_EXTENDED_DATA_STDERR},
	} {
		name := "data"
		if m.DataType != SSH_EXTENDED_DATA_NONE {
			name = "extended-data"
		}
		var buf [16]byte
		bad := false
		allocs := testing.AllocsPerRun(100, func() {
			if len(m.AppendHeader(buf[:0], 30000)) == 0 {
				bad = true
			}
		})
		if bad {
			t.Fatalf("AppendHeader(%s) produced an empty header", name)
		}
		if allocs > 0 {
			t.Fatalf("AppendHeader(%s) allocates %.1f objects per call, want 0", name, allocs)
		}
	}
}

// the appended header plus the payload must stay byte-identical to Write of
// the same message — the property the zero-copy sender relies on
func TestAppendHeaderByteIdentity(t *testing.T) {
	for _, m := range []*DataOrExtendedDataMessage{
		{DataType: SSH_EXTENDED_DATA_NONE, Data: "payload-bytes"},
		{DataType: SSH_EXTENDED_DATA_STDERR, Data: "stderr-bytes"},
	} {
		ref := make([]byte, m.Length())
		if _, err := m.Write(ref); err != nil {
			t.Fatalf("reference marshal: %v", err)
		}
		var buf [16]byte
		hdr := m.AppendHeader(buf[:0], uint64(len(m.Data)))
		out := append([]byte{}, hdr...)
		out = append(out, m.Data...)
		if string(out) != string(ref) {
			t.Fatalf("header+payload mismatch (dataType=%d): got %x, want %x", m.DataType, out, ref)
		}
	}
}
