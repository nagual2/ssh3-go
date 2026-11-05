// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"slices"
	"strings"
	"testing"
)

// compressFlagLookupStub is the flag registry of the walk: -i, -o, -s
// and -C take a value, -v, -N and -4 do not, everything else is
// undefined.
func compressFlagLookupStub(name string) (takesValue bool, defined bool) {
	switch name {
	case "i", "o", "s", "C":
		return true, true
	case "v", "N", "4":
		return false, true
	default:
		return false, false
	}
}

// The -C forms of the ssh3-c canon normalize into the "=" form the Go
// flag package parses, and the walk only touches the option region:
// the first operand ends it, so the command words keep their bytes.
func TestNormalizeCompressFlagArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    []string
		wantErr string
	}{
		{
			name: "the attached off moves to the = form",
			args: []string{"ssh3", "-Cnone", "URL"},
			want: []string{"ssh3", "-C=none", "URL"},
		},
		{
			name: "the attached pin moves to the = form",
			args: []string{"ssh3", "-Czstd", "URL"},
			want: []string{"ssh3", "-C=zstd", "URL"},
		},
		{
			name: "the = form rides untouched",
			args: []string{"ssh3", "-C=zstd", "URL"},
			want: []string{"ssh3", "-C=zstd", "URL"},
		},
		{
			name: "the separated pin eats its word",
			args: []string{"ssh3", "-C", "zstd", "URL"},
			want: []string{"ssh3", "-C=zstd", "URL"},
		},
		{
			name: "the separated off eats its word",
			args: []string{"ssh3", "-C", "none", "URL"},
			want: []string{"ssh3", "-C=none", "URL"},
		},
		{
			name: "the separated pin is case-insensitive",
			args: []string{"ssh3", "-C", "ZSTD", "URL"},
			want: []string{"ssh3", "-C=ZSTD", "URL"},
		},
		{
			name: "the destination after the bare -C escapes to the auto",
			args: []string{"ssh3", "-C", "example.org:443/path"},
			want: []string{"ssh3", "-C=", "example.org:443/path"},
		},
		{
			name:    "a word that is neither a codec nor a destination refuses",
			args:    []string{"ssh3", "-C", "zstdd", "URL"},
			wantErr: "unknown compression codec: zstdd",
		},
		{
			name: "the bare -C with no word is the auto",
			args: []string{"ssh3", "-C"},
			want: []string{"ssh3", "-C="},
		},
		{
			name: "the bare -C in front of a flag is the auto",
			args: []string{"ssh3", "-C", "-i", "key.pem", "URL"},
			want: []string{"ssh3", "-C=", "-i", "key.pem", "URL"},
		},
		{
			name: "the walk skips the value of another flag",
			args: []string{"ssh3", "-i", "key.pem", "-Cnone", "URL"},
			want: []string{"ssh3", "-i", "key.pem", "-C=none", "URL"},
		},
		{
			name: "the walk skips the inline value of another flag",
			args: []string{"ssh3", "-i=key.pem", "-Czstd", "URL"},
			want: []string{"ssh3", "-i=key.pem", "-C=zstd", "URL"},
		},
		{
			name: "the walk skips the separated value of a bool flag chain",
			args: []string{"ssh3", "-v", "-N", "-Czstd", "URL"},
			want: []string{"ssh3", "-v", "-N", "-C=zstd", "URL"},
		},
		{
			name: "the operand region keeps its bytes",
			args: []string{"ssh3", "host", "vim", "-Cfoo"},
			want: []string{"ssh3", "host", "vim", "-Cfoo"},
		},
		{
			name: "the operand region keeps a -C of its own",
			args: []string{"ssh3", "-v", "host", "cmd", "-Cnone"},
			want: []string{"ssh3", "-v", "host", "cmd", "-Cnone"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeCompressFlagArgs(test.args, compressFlagLookupStub)
			if test.wantErr != "" {
				if err == nil {
					t.Fatalf("the args %v normalized to %v, want the refusal %q", test.args, got, test.wantErr)
				}
				if !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("the refusal %q does not carry %q", err.Error(), test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("the args %v refused: %s", test.args, err)
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("the args %v normalized to %v, want %v", test.args, got, test.want)
			}
		})
	}
}

// The normalization rides twice (the control master re-executes the
// binary with the argv it was started with): the second pass is a
// fixed point.
func TestNormalizeCompressFlagArgsIdempotent(t *testing.T) {
	start := []string{"ssh3", "-Cnone", "-i", "key.pem", "-C", "zstd", "URL"}
	once, err := normalizeCompressFlagArgs(start, compressFlagLookupStub)
	if err != nil {
		t.Fatalf("the first pass refused: %s", err)
	}
	twice, err := normalizeCompressFlagArgs(once, compressFlagLookupStub)
	if err != nil {
		t.Fatalf("the second pass refused: %s", err)
	}
	if !slices.Equal(once, twice) {
		t.Fatalf("the normalization is not idempotent: %v -> %v", once, twice)
	}
}
