// SPDX-License-Identifier: Apache-2.0 (fork changes: nagual2, 2026)
module github.com/francoismichel/ssh3

require (
	github.com/caddyserver/certmagic v0.20.0
	github.com/coreos/go-oidc/v3 v3.7.0
	github.com/creack/pty v1.1.18
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/kevinburke/ssh_config v1.2.0
	github.com/klauspost/compress v1.17.4
	github.com/onsi/ginkgo/v2 v2.13.0
	github.com/onsi/gomega v1.29.0
	github.com/pierrec/lz4/v4 v4.1.21
	github.com/pkg/sftp v1.13.7
	github.com/quic-go/quic-go v0.63.0
	github.com/rs/zerolog v1.31.0
	go.uber.org/zap v1.24.0
	golang.org/x/crypto v0.57.0
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842
	golang.org/x/oauth2 v0.37.0
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.46.0
)

require (
	github.com/go-jose/go-jose/v3 v3.0.5 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/libdns/libdns v0.2.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mholt/acmez v1.2.0 // indirect
	github.com/miekg/dns v1.1.55 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

go 1.26.0

// The io_uring send-path experiments live in the nagual2/quic-go fork
// (branch feat/io-uring-send, upstream v0.63.0 + patch behind
// QUIC_GO_IO_URING_SEND, benches verdict: parity with upstream).
// Release builds use upstream quic-go; to run the experiments locally,
// re-add: replace github.com/quic-go/quic-go => ../quic-go
