// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package ssh3

import (
	"strings"
	"testing"

	"github.com/francoismichel/ssh3/compress"
)

// The -C of the CLI shapes the "compress=" field of the client's
// version string (the announce-side control of the compression, the
// ssh3-c canon): the auto keeps the build's codec list, the off keeps
// the field out of the version string, a codec name pins the list to
// it.  The server never carries the override, so its announce stays
// the build's list.

func TestVersionStringCompressAuto(t *testing.T) {
	versionString := ThisVersion().GetVersionString()
	want := "compress=" + compress.Available()
	if !strings.Contains(versionString, want) {
		t.Fatalf("the auto version string %q does not announce %q", versionString, want)
	}
}

func TestVersionStringCompressOff(t *testing.T) {
	versionString := ThisVersion().WithCompressAnnounce("").GetVersionString()
	if strings.Contains(versionString, "compress=") {
		t.Fatalf("the off version string %q still announces a compression", versionString)
	}
}

func TestVersionStringCompressPin(t *testing.T) {
	versionString := ThisVersion().WithCompressAnnounce("zstd").GetVersionString()
	if !strings.HasSuffix(versionString, " compress=zstd") {
		t.Fatalf("the pinned version string %q does not end with compress=zstd", versionString)
	}
	if strings.Contains(versionString, "deflate") || strings.Contains(versionString, "lz4") {
		t.Fatalf("the pinned version string %q announces more than the pinned codec", versionString)
	}
}

// The pinned announce rides the negotiation: the peer parses the
// version string the same way, so the codec it derives is the pinned
// one (and a peer without the codec falls back to the plain frames).
func TestCompressPinNegotiates(t *testing.T) {
	versionString := ThisVersion().WithCompressAnnounce("zstd").GetVersionString()
	peerVersion, err := ParseVersionString(versionString)
	if err != nil {
		t.Fatalf("the pinned version string does not parse: %s", err)
	}
	if peerVersion.GetCompressAlgorithms() != compress.MaskZstd {
		t.Fatalf("the pinned announce carries the mask %d, want %d", peerVersion.GetCompressAlgorithms(), compress.MaskZstd)
	}
	if compress.Choose(peerVersion.GetCompressAlgorithms()) != compress.AlgorithmZstd {
		t.Fatalf("the peer does not derive the pinned codec")
	}
}

// The off announce rides the negotiation the same way: the peer gets
// the empty mask and sends the plain frames.
func TestCompressOffNegotiatesPlain(t *testing.T) {
	versionString := ThisVersion().WithCompressAnnounce("").GetVersionString()
	peerVersion, err := ParseVersionString(versionString)
	if err != nil {
		t.Fatalf("the off version string does not parse: %s", err)
	}
	if peerVersion.GetCompressAlgorithms() != 0 {
		t.Fatalf("the off announce carries the mask %d, want 0", peerVersion.GetCompressAlgorithms())
	}
	if compress.Choose(peerVersion.GetCompressAlgorithms()) != compress.AlgorithmNone {
		t.Fatalf("the peer does not fall back to the plain frames")
	}
}

// The override copies the version: the package list (the one the
// conversation iterates and compares against the peer) keeps its own
// announce.
func TestWithCompressAnnounceDoesNotMutate(t *testing.T) {
	before := ThisVersion().GetVersionString()
	_ = ThisVersion().WithCompressAnnounce("")
	if after := ThisVersion().GetVersionString(); after != before {
		t.Fatalf("the package version mutated: %q -> %q", before, after)
	}
}

// ResolveCompressAnnounce is the validation of the -C value: the
// auto, the off (case-insensitive), the pinned codec
// (case-insensitive), the refusal of everything else (the refusal
// names the known ones).
func TestResolveCompressAnnounce(t *testing.T) {
	tests := []struct {
		value   string
		want    string
		wantErr bool
	}{
		{value: "", want: compress.Available()},
		{value: "none", want: ""},
		{value: "None", want: ""},
		{value: "NONE", want: ""},
		{value: "zstd", want: "zstd"},
		{value: "ZSTD", want: "zstd"},
		{value: "deflate", want: "deflate"},
		{value: "Deflate", want: "deflate"},
		{value: "lz4", want: "lz4"},
		{value: "LZ4", want: "lz4"},
		{value: "zstdd", wantErr: true},
		{value: "garbage", wantErr: true},
		{value: "none,zstd", wantErr: true},
		{value: "=none", wantErr: true},
		{value: " ", wantErr: true},
	}
	for _, test := range tests {
		got, err := ResolveCompressAnnounce(test.value)
		if test.wantErr {
			if err == nil {
				t.Fatalf("the value %q resolved to %q, want a refusal", test.value, got)
			}
			if !strings.Contains(err.Error(), "known ones") {
				t.Fatalf("the refusal of %q does not name the known ones: %s", test.value, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("the value %q refused: %s", test.value, err)
		}
		if got != test.want {
			t.Fatalf("the value %q resolved to %q, want %q", test.value, got, test.want)
		}
	}
}

// The resolved pin is a valid capability value: the version string it
// feeds parses back into the pinned mask.
func TestResolveCompressAnnouncePinParses(t *testing.T) {
	announce, err := ResolveCompressAnnounce("ZSTD")
	if err != nil {
		t.Fatalf("the pin refused: %s", err)
	}
	peerVersion, err := ParseVersionString("SSH 3.0 francoismichel/ssh3 0.1.40 compress=" + announce)
	if err != nil {
		t.Fatalf("the resolved pin does not feed the version string: %s", err)
	}
	if peerVersion.GetCompressAlgorithms() != compress.MaskZstd {
		t.Fatalf("the resolved pin carries the mask %d, want %d", peerVersion.GetCompressAlgorithms(), compress.MaskZstd)
	}
}
