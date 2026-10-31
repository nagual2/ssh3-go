// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"
	"testing"
)

// R11: the positional --sftp canon mirrored from the ssh3-c client (906d73f):
// the remote operand rides the leading colon (the session host implied), the
// direction derives from which side carries it, exactly one remote operand —
// otherwise a clean refusal.

func TestParseSftpPositional(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		dst     string
		local   string
		remote  string
		upload  bool
		wantErr string
	}{
		{"positional put", "./file", ":/remote/path", "./file", "/remote/path", true, ""},
		{"positional get", ":/remote/path", "./file", "./file", "/remote/path", false, ""},
		{"both remote refuses", ":/a", ":/b", "", "", false, "exactly one remote operand"},
		{"both local refuses", "./a", "./b", "", "", false, "exactly one remote operand"},
		{"empty local refuses", "", ":/b", "", "", false, "both paths non-empty"},
		{"empty remote refuses", ":", "./b", "", "", false, "both paths non-empty"},
		{"empty dst with remote src refuses", ":/a", "", "", "", false, "both paths non-empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			local, remote, upload, err := parseSftpPositional(test.src, test.dst)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("parseSftpPositional(%q, %q) error = %v, want containing %q", test.src, test.dst, err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSftpPositional(%q, %q): %s", test.src, test.dst, err)
			}
			if local != test.local || remote != test.remote || upload != test.upload {
				t.Fatalf("parseSftpPositional(%q, %q) = (%q, %q, %v), want (%q, %q, %v)",
					test.src, test.dst, local, remote, upload, test.local, test.remote, test.upload)
			}
		})
	}
}

// the put|get:local:remote shapes stay the explicit aliases of the positional
// form; a colon right behind the drive letter rides the path (the Windows
// local side), the next one ends the local side

func TestParseSftpSpecAlias(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		local   string
		remote  string
		upload  bool
		wantErr string
	}{
		{"put alias", "put:./file:/remote/path", "./file", "/remote/path", true, ""},
		{"get alias", "get:./file:/remote/path", "./file", "/remote/path", false, ""},
		{"drive letter local rides", "put:C:/dir:/remote", "C:/dir", "/remote", true, ""},
		{"drive letter no second colon refuses", "put:C:/dir", "", "", false, "put|get:local:remote"},
		{"no head refuses", "./file:/remote/path", "", "", false, "put|get:local:remote"},
		{"empty local refuses", "put::/remote", "", "", false, "put|get:local:remote"},
		{"empty remote refuses", "put:./file:", "", "", false, "put|get:local:remote"},
		{"no separator refuses", "put:./file", "", "", false, "put|get:local:remote"},
		{"bare head refuses", "put:", "", "", false, "put|get:local:remote"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			local, remote, upload, err := parseSftpSpecAlias(test.spec)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("parseSftpSpecAlias(%q) error = %v, want containing %q", test.spec, err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSftpSpecAlias(%q): %s", test.spec, err)
			}
			if local != test.local || remote != test.remote || upload != test.upload {
				t.Fatalf("parseSftpSpecAlias(%q) = (%q, %q, %v), want (%q, %q, %v)",
					test.spec, local, remote, upload, test.local, test.remote, test.upload)
			}
		})
	}
}

// the connection operand of the --sftp form: user@host[:port][/url_path], the
// remote path never rides it (it lives in the colon-led operand)

func TestParseSftpURL(t *testing.T) {
	tests := []struct {
		name      string
		spec      string
		username  string
		hostname  string
		port      int
		urlPath   string
		wantPort  int
		wantPath  string
		wantError bool
	}{
		{"bare host", "max@host", "max", "host", 443, "/ssh3-term", 443, "/ssh3-term", false},
		{"host with port", "max@host:8443", "max", "host", 8443, "/ssh3-term", 8443, "/ssh3-term", false},
		{"host port url path", "max@host:8443/ssh3-x", "max", "host", 8443, "/ssh3-x", 8443, "/ssh3-x", false},
		{"no user refuses", "host:8443", "", "", 0, "", 0, "", true},
		{"empty user refuses", "@host", "", "", 0, "", 0, "", true},
		{"bracketed ipv6 refuses", "max@[::1]:443", "", "", 0, "", 0, "", true},
	}
	defaultPort, defaultURLPath := 443, "/ssh3-term"
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := parseSftpURL(test.spec, defaultPort, defaultURLPath)
			if test.wantError {
				if err == nil {
					t.Fatalf("parseSftpURL(%q) = %+v, want an error", test.spec, target)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSftpURL(%q): %s", test.spec, err)
			}
			if target.username != test.username || target.hostname != test.hostname ||
				target.port != test.wantPort || target.urlPath != test.wantPath {
				t.Fatalf("parseSftpURL(%q) = {user %q host %q port %d path %q}, want {user %q host %q port %d path %q}",
					test.spec, target.username, target.hostname, target.port, target.urlPath,
					test.username, test.hostname, test.wantPort, test.wantPath)
			}
		})
	}
}

// the --sftp operand wiring: the URL rides the last operand, the transfer spec
// rides the ones before it (one alias operand or two positional operands)

func TestResolveSftpOperands(t *testing.T) {
	tests := []struct {
		name     string
		operands []string
		local    string
		remote   string
		upload   bool
		wantErr  string
	}{
		{"positional put", []string{"./file", ":/remote/path"}, "./file", "/remote/path", true, ""},
		{"positional get", []string{":/remote/path", "./file"}, "./file", "/remote/path", false, ""},
		{"alias put", []string{"put:./file:/remote/path"}, "./file", "/remote/path", true, ""},
		{"alias get", []string{"get:./file:/remote/path"}, "./file", "/remote/path", false, ""},
		{"no spec refuses", []string{}, "", "", false, "the transfer spec"},
		{"three operands refuse", []string{"./a", ":/b", "./c"}, "", "", false, "alias operand or two positional"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			local, remote, upload, err := resolveSftpOperands(test.operands)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("resolveSftpOperands(%q) error = %v, want containing %q", test.operands, err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveSftpOperands(%q): %s", test.operands, err)
			}
			if local != test.local || remote != test.remote || upload != test.upload {
				t.Fatalf("resolveSftpOperands(%q) = (%q, %q, %v), want (%q, %q, %v)",
					test.operands, local, remote, upload, test.local, test.remote, test.upload)
			}
		})
	}
}
