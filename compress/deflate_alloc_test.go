package compress

import (
	"bytes"
	"testing"
)

// The deflate codec is the one-shot path of a compressed data frame: the
// writer and its output buffer ride a pool, the only allocation left is the
// returned slice (ROADMAP.local.md §R9 wave 3).
func TestCompressDeflateAllocs(t *testing.T) {
	data := bytes.Repeat([]byte("compressible payload "), 200)
	packed, ok := Compress(AlgorithmDeflate, data)
	if !ok {
		t.Fatalf("the deflate codec refused the payload")
	}
	if len(packed) == 0 {
		t.Fatalf("empty deflate output")
	}
	bad := false
	allocs := testing.AllocsPerRun(100, func() {
		p, ok := Compress(AlgorithmDeflate, data)
		if !ok || len(p) == 0 {
			bad = true
		}
	})
	if bad {
		t.Fatalf("Compress(deflate) failed during the measured runs")
	}
	if allocs > 1 {
		t.Fatalf("Compress(deflate) allocates %.1f objects per call, want <= 1 (the output slice)", allocs)
	}
}
