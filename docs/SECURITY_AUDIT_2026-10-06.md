# Security Audit — ssh3-go (Go implementation)

**Audit date (UTC):** 2026-10-06
**Audited revision:** `00c2f4697307c0b201e5d416bb0dfbe382998c78` (`origin/main`, tag `v0.1.26`)
**Auditor:** engineering agent (report-only engagement; no code was changed)
**Scope:** the Go implementation (`cmd/`, `client/`, `client_auth.go`, `server.go`, `conversation.go`, `channel.go`, `server_auth/`, `auth/`, `message/`, `util/`, forwarding, config parsing, host-key verification, logging) plus a review of the Rust workspace (`crates/`) and the dependency graph at the same revision.
**Method:** manual source review, reachability/call-graph analysis, `git grep` sweeps for panic/unsafe/unwrap surfaces, Go/Rust dependency advisory lookups (OSV), and local read-only dynamic probes where tooling allowed. No dynamic exploitation of any live system; no third-party system was contacted.
**Out of scope:** fixing anything (recommendations only), the C17 rewrite under `ssh3-c`, and the internals of the deliberate `vendor/h3` patch (reviewed only where it meets the Go/Rust boundary).

> This audit was time-boxed. Sections reflect exactly what was covered; see **Coverage** and **Limitations** before treating any absence of findings as a clean bill of health.

## Executive summary

- **The Go tree has no `recover()` anywhere, and the QUIC channel-accept loop runs in a goroutine that no `recover()` protects.** Every panic that is reachable from peer-controlled bytes is therefore a full process kill (`ssh3-server` dies; `ssh3` client dies). Two such panics are confirmed reachable — an unbounded allocation fed by a peer-controlled length field (`util.ParseSSHString`) and a `panic("not implemented")` on unknown message-type ids (`message.ParseMessage`).
- **Highest-impact finding: `util.ParseSSHString` allocates `make([]byte, length)` from an unvalidated, peer-controlled varint (`util/wire.go:209`).** On the server it is reached from a client-opened channel stream header; on the client from any server-opened channel stream. A hostile or merely buggy peer can choose a length above Go's `maxAlloc` (instant `makeslice` panic → process death) or a huge-but-allocatable length (OOM kill). Impact: remote, repeatable denial of service by any peer that has a channel accepted — i.e. by **any authenticated user on the server**, and by **any server against the client**.
- **`message.ParseMessage` panics on an unknown message-type id** (`message/message.go:231`) and is called directly on the peer's QUIC stream (`channel.go:273`). Any peer that can write on an accepted channel can kill the process with a 2-byte message. The codebase itself documents this hazard twice and works around it for new features instead of removing the panic.
- **The Stage 4.1 unauthenticated-conversation cap leaks a slot per successful authentication** (`server_auth/auth.go:96-100` is the only release path, and it is skipped once `authenticated == true`). At the default cap of 100 the server answers **503 to every new CONNECT until it is restarted**; one user with a valid identity can brick the server with 100 ordinary logins, and a long-running server bricks itself.
- **The SFTP "jail" is lexical only and does not resolve symlinks**, while the server is expected to run as root to setuid per user. An authenticated user can point a symlink inside their own home outside the jail and make the server read/write the target **as root** (`cmd/sftp_subsystem.go:90-151`).
- **Two dependencies carry published advisories reachable from the audited paths** — `golang-jwt/jwt/v5 v5.0.0` (CVE-2025-30204, reached pre-auth on an attacker-supplied bearer token) and `rustls 0.23.37` in the Rust workspace (RUSTSEC-2026-0285). Both are a version bump away. `golang.org/x/crypto v0.54.0` is also flagged, but the affected SSH transport/channel code is not exercised by ssh3.
- **The three Stage-1 bugs named in the delegation brief (T2 negative exit status, T3 silent truncation, T4 nil-key SIGSEGV) are all fixed at `v0.1.26`** — evidence in [Verified clean](#verified-clean). The `VarIntLen` panic itself (`util/wire.go:198`) is still present but its known trigger is guarded.

## Findings table

| ID | Severity | Component | Evidence (at `00c2f46`) | Impact |
|----|----------|-----------|-------------------------|--------|
| F-01 | **High** | `util/wire.go` + channel header parsing | `util/wire.go:204-218` (alloc at `:209`), sink `channel.go:167-168`, entry `server.go:140-146`, `conversation.go:284` | Peer-controlled length → `makeslice` panic (process kill) or OOM; remote DoS by any authenticated user (server) or any server (client) |
| F-02 | **High** | `message/message.go` + channel read path | `message/message.go:230-231`, caller `channel.go:273`; no `recover()` in tree | 2-byte unknown message-type id from a peer on an accepted channel kills the process |
| F-03 | **High** | `server_auth/auth.go` (DoS guard) | `server_auth/auth.go:89-100`, `server_auth/dos_guard.go:45-67` (release has no other caller) | One authenticated user (100 logins) permanently 503s the whole server; gradual self-DoS for legitimate use |
| F-04 | **High** | SFTP subsystem jail | `cmd/sftp_subsystem.go:90-107`, `:123-151`, `:217-230`; root server `util/unix_util/user.go:43-51` | Jail escape via symlink → arbitrary file read/write **as root** for any authenticated user |
| F-05 | Medium | Server-side TCP/UDP/dynamic forwarding | `cmd/ssh3-server.go:759-762`, `:771-774` (explicit TODOs) | Authenticated user turns the server into an SSRF/pivot/port-scanner with no target policy (no `PermitOpen` analog) |
| F-06 | Medium | `server_auth/auth.go` ordering | `server_auth/auth.go:61`, `:79` before the cap at `:89`; CHANGELOG claims the opposite | Cap does not bound pre-auth work (conversation allocation, two identity-file opens + parse per request) |
| F-07 | Medium | Dependency: `golang-jwt/jwt/v5 v5.0.0` | `go.mod:8`, use at `auth/plugins/pubkey_authentication/server/server_plugin.go:29` | CVE-2025-30204: memory amplification while parsing an **attacker-supplied** bearer token, pre-auth |
| F-08 | Low | `server_auth/auth.go:29` | `r.UserAgent()[:100]` on a short, unparseable UA | `slice bounds out of range` panic; recovered by quic-go (`vendor/.../http3/server_conn.go:225`) so only that stream aborts + 64 KiB stack trace logged → cheap log flooding |
| F-09 | Low | `util/wire.go:198` (`VarIntLen`) | panic on >2^62-1; current callers bounded | Latent landmine: any future arithmetic-derived `uint64` passed to `VarIntLen`/`AppendVarInt` kills the server; also `AppendVarIntWithLen` panics |
| F-10 | Low | Dependency: `rustls 0.23.37` (Rust workspace) | `Cargo.lock` via `ssh3-quinn` | RUSTSEC-2026-0285 / GHSA-2mjx-qc3c-rqvc: TLS 1.3 handshake messages accepted across encryption-level boundaries |
| F-11 | Low | Dependencies: `go-jose/v3 v3.0.1`, `golang.org/x/oauth2 v0.13.0`, `golang.org/x/crypto v0.54.0` | `go.mod:20-38` | Published advisories present in the module graph; reachability in the audited paths is low (details below) |
| F-12 | Low | Client config `Match exec` | `client/config/matchcfg/matchcfg.go:605`, `:757-759` | `sh -c` / `cmd /c` executed while parsing `~/.ssh/config` (`Include`/`-F` widen the input); OpenSSH parity but a design risk worth documenting |
| F-13 | Info | Host-key pin comparison | `known_hosts.go:51-66` (`bytes.Equal` on the DER cert) | Not constant-time, but the compared value is a public certificate, not a secret — no timing exposure; correctness (mismatch ⇒ refusal) verified |

## Detailed findings

### F-01 — High — Unbounded allocation from a peer-controlled SSH-string length (`util.ParseSSHString`)

**Evidence**

- `util/wire.go:204-218`:
  ```go
  func ParseSSHString(buf Reader) (string, error) {
          length, err := ReadVarInt(buf)      // <- up to 2^62-1, fully peer-controlled
          ...
          out := make([]byte, length)         // :209  <- no cap, no LimitReader
  ```
- Server sink: `server.go:140-146` calls `parseHeader(uint64(stream.StreamID()), &StreamByteReader{stream})`; `channel.go:163-172` reads `conversationControlStreamID` (varint), then `util.ParseSSHString(r)` for `channelType` (`channel.go:167-168`). The reader is the raw QUIC stream (`conversation.go:361-385`), so the length is the attacker's next bytes.
- Client sink: the mirror image, `conversation.go:284` (server-initiated channel streams).
- Same allocation shape is reachable from every message parse path, all of which read from the peer's stream: `channel.go:273` (`ParseMessage(util.NewReader(c.recv))` where `recv` is the peer's `*quic.Stream`), and through it `message/message.go:92,97,146,202` and `message/channel_request.go:70,112,132,290,318,405,479,484` (`cmd`, `subsystem`, `signal`, `exit-signal`, `pty-req` strings).

**Exploit conditions (direction of the protocol matters)**

- *Server side (post-auth):* `parseHeader` is only reached after `getConversationsManager`/`waitForConversationsManager` finds the conversation, and the conversation is registered only inside the authenticated HTTP handler (`server.go:255-260`, reached from `server_auth/auth.go:109/121/127`); `conversationRegistrationTimeout` is 2 s (`server.go:25`). So the attacker must first authenticate — any valid identity on that server suffices. Confidence: **high**.
- *Client side:* the client parses channel streams and channel messages coming from the connected server (`conversation.go:284`, `client/client.go:102,166`, `client/session_pump.go:145,212`). The peer controlling those bytes is the *server*, so a hostile/compromised server (or one the user reached by mistake, with TOFU accepting the first certificate) can kill the client process. Confidence: **high**.

**Impact**

`make([]byte, 2^62-1)` converts to a negative `int` → `panic: runtime error: makeslice: len out of range`. Nothing in the Go tree recovers (`git grep 'recover()' -- '*.go' ':!vendor'` → no hits), and the channel-accept loop runs in an unprotected goroutine (`server.go:91-110` spawned from `cmd/ssh3-server.go:1369`, itself in a bare `go func()` with no recover). Result: **the whole `ssh3-server` (or `ssh3` client) process exits**. Either way a remote, repeatable DoS (authenticated on the server, server-driven against the client); it is also a reliable crash primitive that masks other bugs.

**Locally confirmed (read-only probe, `go1.26.0`, no network):** a 12-line program calling the real `util.ParseSSHString` on a `bytes.Reader` carrying only the 8-byte varint was run against the audited tree:
- length `2^62-1` (max varint) → `PANIC: runtime error: makeslice: len out of range` — raised **inside `ParseSSHString`**, on the `make` at `util/wire.go:209`, with zero input bytes supplied by the peer beyond the varint itself.
- length `2^40` (1 TiB, comfortably below Go's `maxAlloc`) → `fatal error: runtime: out of memory` from `runtime.sysMapOS`/`mheap.grow`. A **fatal** runtime error is not catchable by `recover()` — the process dies even with a panic handler installed. This is the more dangerous variant, and 8 bytes of attacker input reach it.

So the finding is not theoretical: 8 bytes on a channel stream → server or client process death.

**Recommendation**

1. Bound the length before allocating: reject `length > maxSSHStringLen` (a small constant, e.g. 64 KiB, or the negotiated `MaxPacketSize`) and return `InvalidSSHString` instead of allocating.
2. Read through `io.LimitReader(buf, maxSSHStringLen+1)` and use `io.ReadAll`, so the allocation can never exceed the bound even if the cap check is refactored away.
3. Add `defer func(){ if r := recover(); r != nil { log...; cancel the stream } }()` at the top of `handleChannelStream`/`handleIncomingChannelStream` and around per-channel message loops — panics must not be able to take the process down.
4. Add a `go test -fuzz` target over `ParseSSHString`/`ParseRequestMessage` (there is currently no fuzz target for the message parser, despite CTO_TASK Stage 1 bug 2 asking for one) and a regression test for the oversized-length case.

### F-02 — High — `message.ParseMessage` panics on unknown message-type ids

**Evidence**

- `message/message.go:212-233`, terminal branch:
  ```go
  switch typeId {
  case SSH_MSG_CHANNEL_REQUEST: ...
  ...
  default:
          panic("not implemented")     // :231
  }
  ```
- Reachable directly from peer bytes: `channel.go:273` `func (c *channelImpl) nextMessage() { return ssh3.ParseMessage(util.NewReader(c.recv)) }`, called by `NextMessage()` (`channel.go:278`) and by every session/forwarding loop (`cmd/ssh3-server.go:210,833,1218`, `cmd/*_server.go`, `client/client.go:102,166`, `client/session_pump.go:145,212`, `cmd/dynamic_forward.go:578`).
- The project already knows: `cmd/dynamic_forward.go:575` and `message/reverse_forward.go:27` document that `ParseMessage` panics on unknown ids and therefore route new features through channel data instead. The panic itself was never removed.

**Exploit conditions.** Any peer with an accepted channel: on the server, an authenticated user (channels are consumed in the authenticated session loop, `cmd/ssh3-server.go:1195+`); on the client, the connected server. The trigger is two bytes (varint type id, e.g. `0x01`).

**Impact.** Unrecovered panic → process death (same reasoning as F-01). In addition, the panic means "unknown extension id" is fatal rather than ignored, which is a forward-compatibility and interop hazard: a newer peer sending a legitimate new message type kills an older peer.

**Recommendation.** Return a typed error and let callers skip/ignore unknown message types (as OpenSSH does for unrecognised channel messages); keep a `recover()` in the channel read loop as defence in depth; extend the message-parser fuzz target to cover arbitrary type ids.

### F-03 — High — The unauthenticated-conversation cap leaks a slot per successful authentication (permanent server-wide 503)

**Evidence**

- `server_auth/auth.go:86-100`:
  ```go
  if !TryAcquireUnauthenticatedConversation() { ... 503 ... }
  authenticated := false
  defer func() { if !authenticated { ReleaseUnauthenticatedConversation() } }()
  ```
- `ReleaseUnauthenticatedConversation` has exactly one caller in the whole tree — that `defer` (verified by `git grep`). The counter is therefore monotonically non-decreasing across authenticated conversations.
- `server_auth/dos_guard.go:45-67`: `unauthenticatedCount++` on acquire, decrement only via the release path; default `MaxUnauthenticatedConversations = 100` (`dos_guard.go:30`).

**Exploit conditions.** Any party that can authenticate once (i.e. any legitimate user, or anyone who has stolen one identity) can issue 100 CONNECTs; after that `TryAcquire` always fails and **every** new conversation — authenticated or not — is refused with 503 until the process restarts. No privilege escalation is needed; this is a pure availability attack from the weakest credentialed position. A busy legitimate server reaches the same state on its own after 100 successful connections.

**Impact.** Complete denial of service of the SSH3 endpoint, persisting until restart. Confidence: **high** (static; the arithmetic is unambiguous and the release path is single-caller).

**Recommendation.** Release the slot when the conversation goes authenticated→closed, not "on refusal only". The cleanest form: acquire the slot in the CONNECT handler, and `conv.Context().Done()` (already used for reverse-forward cleanup, `cmd/reverse_forward_server.go:321`) releases it; or count only conversations currently *in* the unauthenticated phase with an explicit `defer Release()` plus a success-path transfer of ownership to the conversation lifecycle. Add a regression test that authenticates `MaxUnauthenticatedConversations+1` times and asserts the last one is still served.

### F-04 — High — SFTP jail escape via symlinks (root-level file access for any authenticated user)

**Evidence**

- The jail is a pure lexical prefix check with no symlink resolution: `cmd/sftp_subsystem.go:90-107` (`resolveJailed` uses `filepath.Clean` + `strings.HasPrefix`, no `EvalSymlinks`, no `O_NOFOLLOW`, no `openat2`/`RESOLVE_BENEATH`).
- Data paths follow symlinks in the kernel: `Fileread` → `os.Open(name)` (`:123-129`), `Filewrite` → `os.OpenFile(...)` with create/trunc (`:131-151`) and `chownToUser` afterwards, `Filelist`'s `Stat`/`List` (`:239-266`), `mkdir` (`:174-184`).
- The server is designed to run as root: it must be root to drop to the user for command execution (`util/unix_util/user.go:40-51`, `cmd/ssh3-server.go` session path), and the CHANGELOG/CTO_TASK present root operation as the normal deployment.
- `Symlink` requests are supported (`:217-230`) but restricted to in-jail *targets*; the escape does not need them — any symlink the user can place in their home by other means (their own unsandboxed login shell through the same product, an existing symlinked layout, a `~/.ssh3` symlink, a mounted home…) is enough.

**Exploit conditions.** Authenticated user; server running as root (the documented multi-user setup). Example: `ln -s /etc ~/etc` in a session, then SFTP `get /etc/shadow` → `resolveJailed` maps it to `<home>/etc/shadow` (passes the prefix check) → `os.Open` follows the symlink and the server reads `/etc/shadow` **as root** and ships it to the client. Writes behave the same way (`put` to the symlinked path truncates the root-owned target) and newly created files are `chown`ed to the user.

**Impact.** Privilege escalation from "authenticated user" to root-level arbitrary file read/write on the host — the strongest finding in this report on the post-auth path. Confidence: **high** for the code path; exploitation additionally requires the symlink (trivially reachable by the same user).

**Recommendation.** Resolve and re-verify: `real, err := filepath.EvalSymlinks(path)` then re-check containment against `EvalSymlinks(root)`, and reject any path whose components include a symlink pointing outside; open the final component with `O_NOFOLLOW`; prefer `openat2(RESOLVE_BENEATH)` on Linux. Alternatively drop privileges to the session user before opening and accept that the jail then only bounds the user's own reach (defence in depth: the current design makes the jail a security boundary *because* the process is root). Add tests for symlinked components, `..` after a symlink, and symlink-to-outside for read/write/stat/rename.

### F-05 — Medium — Server-side forwarding has no target policy (SSRF / pivot / port scan)

**Evidence.** `cmd/ssh3-server.go:759-762` (`handleUDPForwardingChannel`) and `:771-774` (`handleTCPForwardingChannel`) carry the explicit TODO: *"currently, the rights for socket creation are not checked. The socket is opened with the process's uid and gid"* — the dial target is exactly what the client asked for (`channel.RemoteAddr`), with no allow/deny list and no per-user cap. The dynamic SOCKS path dials a client-supplied, server-resolved name (`cmd/dynamic_forward_server.go`), and reverse forwarding's *outbound* target is client-side by design.

**Exploit conditions.** Any authenticated user, post-auth. Targets include the server's loopback services and link-local metadata endpoints (`169.254.169.254`), i.e. a direct path from "SSH access" to "cloud credentials / admin interfaces".

**Impact.** Network pivot and port scanning attributed to the server; requests to internal services arrive from the server (bypassing network policy that trusts the server's position). OpenSSH has the same default exposure but ships `PermitOpen`/`PermitListen` to bound it; ssh3 has no equivalent.

**Recommendation.** Add an allowlist policy (`PermitOpen`/`PermitListen` analog) with a per-user connection/bandwidth cap; document that the server dials with its own privileges; consider refusing loopback and link-local by default on the dynamic-forward path while the policy is absent.

### F-06 — Medium — The DoS cap is acquired after the pre-auth work it is documented to prevent

**Evidence.** `server_auth/auth.go`: `NewServerConversation` at `:61`, `unix_util.GetUser` at `:74`, `GetAuthorizedIdentities(user)` (two file opens + parse, `server_auth/authorized_identities.go:146-164`) at `:79`, and only then `TryAcquireUnauthenticatedConversation()` at `:89`. The CHANGELOG entry for v0.1.26 states the opposite: *"refused with 503 before any identity file reading or crypto verification happens"*.

**Impact.** The cap bounds concurrent *slot holders*, not the per-request pre-auth cost, so an attacker who knows valid usernames can still force unbounded identity-file reads/parses and conversation allocations (the JWT/identity verifiers run after the cap in `:103-130`, so crypto work is bounded). Medium: real deployment cost is disk/CPU pressure rather than memory exhaustion.

**Recommendation.** Move the acquire before `GetAuthorizedIdentities` (and ideally before conversation creation), or fix the documentation. Align the CHANGELOG claim with the code — an inaccurate hardening claim is a security-documentation defect on its own.

### F-07 — Medium — `golang-jwt/jwt/v5 v5.0.0` — CVE-2025-30204 reachable pre-auth

**Evidence.** `go.mod:8` pins `github.com/golang-jwt/jwt/v5 v5.0.0`. OSV reports GHSA-mh63-6h87-95cp / GO-2025-3553 / **CVE-2025-30204** ("excessive memory allocation during header parsing") for that version. The code path is `auth/plugins/pubkey_authentication/server/server_plugin.go:29` (`jwt.Parse(jwtToken, keyfunc, …)`) reached from `server_auth/handlers.go:66-81` (`VerifyJWT`) on the **attacker-supplied** `Authorization: Bearer …` value, before any verification outcome.

**Impact.** Bounded memory amplification per pre-auth request (the token length is limited by the HTTP/3 header-field limit). Low single-request impact, but this is the only crypto-parsing work an *unauthenticated* request can drive, and it is trivially fixed. Confidence: **high** that the vulnerable function is reached; **medium** on the practical amplification factor, which depends on the H3 header-size limits in effect.

**Recommendation.** Bump to `golang-jwt/jwt/v5 >= 5.2.2` (`go get` + `go mod tidy` + `go mod vendor`; note the CTO_TASK trap that `go mod vendor` deletes the Go tree's synced vendor directory semantics — re-verify). Add a request-level bound on the `Authorization` header length as defence in depth.

### F-08 — Low — `r.UserAgent()[:100]` slice panic on a short, unparseable User-Agent

**Evidence.** `server_auth/auth.go:24-31`: `ParseVersionString` fails → the error branch formats `r.UserAgent()[:100]`. A UA shorter than 100 bytes (e.g. `curl`) panics with `slice bounds out of range`. Reachable **pre-auth**: `HandleAuths` wraps the whole handler, so the attacker only needs to send a CONNECT with a bogus short UA.

**Impact.** Recovered by quic-go's per-request recover (`vendor/github.com/quic-go/quic-go/http3/server_conn.go:225-247`; the connection survives, the stream is cancelled with `ErrCodeInternalError`). So: one aborted request plus a ~64 KiB stack trace written to the log per attempt — log amplification/flooding rather than a crash. Confidence: **high** (vendored code inspected; a panic outside `handler.ServeHTTP` would *not* be recovered, but this one is inside it).

**Recommendation.** Truncate on a rune/byte boundary instead of slicing blindly (`u := r.UserAgent(); if len(u) > 100 { u = u[:100] }`), and prefer not to echo attacker input into the error at all.

### F-09 — Low — `VarIntLen`/`AppendVarIntWithLen` panics are still latent landmines

**Evidence.** `util/wire.go:198-202` (panic above 2^62-1), `util/wire.go:156-165` (`AppendVarIntWithLen` panics on an invalid length or when the value does not fit). Task-hint verification: the Stage-1 bug-2 crash was `VarIntLen` ← `message.ExitStatusRequest.Length()` (`message/channel_request.go:442-444`) ← `cmd/ssh3-server.go:411`. At HEAD the server feeds only guarded values: the exit status comes from `safeExitStatus(exitError.ExitCode())` (`cmd/ssh3-server.go:458`, helper `cmd/exit_status.go:15-20` maps negative codes to 255) and parsed exit statuses come from `ReadVarInt` (`message/channel_request.go:432-440`), which cannot exceed 2^62-1. So the reported trigger is fixed; the unsafe helper remains. The nearest other risk is arithmetic on peer values, e.g. `c.ChannelInfo.MaxPacketSize - uint64(emptyMsgLen)` (`channel.go:316`) — currently safe only because the result is consumed by `MinUint64`.

**Recommendation.** Make the panic an error or clamp with a documented sentinel; keep the exit-status regression test; add a `VarIntLen` edge-value unit test plus the parser fuzz target (both were asked for by Stage 1 bug 2 and are still absent at HEAD — `util/wire_test.go` covers round-trips only).

### F-10 — Low — Rust workspace: `rustls 0.23.37` advisory

**Evidence.** `Cargo.lock` pins `rustls 0.23.37` (used through `ssh3-quinn`/`quinn 0.11.9`; `h3 0.0.8` is the deliberate vendored shim). OSV reports GHSA-2mjx-qc3c-rqvc / RUSTSEC-2026-0285 — *"TLS 1.3 handshake messages incorrectly accepted across encryption level boundaries"* — for that version. `quinn`, `h3`, `ring`, `ed25519-dalek`, `tokio`, `hyper` returned no advisories at the pinned versions.

**Impact.** The Rust implementation's TLS layer is a boundary against a network attacker; accepting handshake messages at the wrong encryption level ranges from a spec violation to a state-confusion primitive. Practical exploitability was not assessed (no dynamic testing); treated as Low-to-Medium pending an upgrade. Confidence: **medium** (advisory match verified; exploitability not verified).

**Recommendation.** Bump `rustls` to the fixed release (verify with `cargo audit`/OSV at upgrade time), re-run `cargo build --workspace` and the Rust↔Go interop suite; record the interop result in the PR.

### F-11 — Low — Other dependency advisories present in the graph

| Package | Pinned | Advisory | Audited reachability |
|---|---|---|---|
| `github.com/golang-jwt/jwt/v5` | 5.0.0 | CVE-2025-30204 (see F-07) | **Reached pre-auth** |
| `golang.org/x/crypto` | 0.54.0 | GO-2026-6303 (fixed 0.55.0), GO-2026-6354/6355 (fixed 0.56.0), openpgp unmaintained (GO-2026-5932) | Affected package is `golang.org/x/crypto/ssh`. ssh3 imports only `ssh` (key parsing: `server_plugin.go:13`, `pubkey_auth.go`, `privkey_auth.go`, `client_auth.go`) and `ssh/agent`; the SSHv2 transport/channel machinery the advisories concern is not run. `openpgp` is not imported. |
| `github.com/go-jose/go-jose/v3` | 3.0.1 (indirect, via `go-oidc`) | GHSA-c6gw-w398-hv78 (DoS in parsing), GHSA-78h2-9frx-2jm8 (JWE panic) | Only under the OIDC path; the issuer/JWKS is operator-configured, so an attacker must control the identity provider. |
| `golang.org/x/oauth2` | 0.13.0 | GO-2025-3488 (token-parsing memory) | Client-side OIDC only. |
| `golang.org/x/net` | 0.56.0 (indirect) | GO-2026-4918, html-parser DoS | `net/html` unused; HTTP/2 transport not on the ssh3 data path (H3 over QUIC). |

No advisories were returned for `quic-go v0.63.0`, `pkg/sftp v1.13.7`, `certmagic v0.20.0`, `coreos/go-oidc/v3 v3.7.0`, `kevinburke/ssh_config v1.2.0`, `rs/zerolog v1.31.0`, `creack/pty v1.1.18`.

### F-12 — Low — `Match exec` in `~/.ssh/config` executes a shell command during client start-up

**Evidence.** `client/config/matchcfg/matchcfg.go:605` (the `exec` criterion) and `:757-759` (`exec.Command("sh", "-c", command)` / `cmd /c`). The `Match` pre-parser processes the main config, `Include`d files (v0.1.24 feature) and `-F <path>`.

**Assessment.** This is deliberate OpenSSH parity — OpenSSH also runs `Match exec` — and the input is local configuration the user already trusts, so it is not a vulnerability. It is listed because (a) writing to a config file becomes code execution on every subsequent client start, including files pulled in by `Include` globs from directories with weaker permissions, and (b) the exec'd command's environment contains the resolved host/user values, so a future caller that lets a *remote* value reach the criteria would turn it into injection. No remote input reaches the criteria today.

**Recommendation.** Document it in the threat-model/README; keep the criteria values strictly local; consider a debug log line naming the command before execution.

### F-13 — Informational — Host-key pin comparison is byte comparison, not constant-time

**Evidence.** `known_hosts.go:51-66` (`CheckCertificate`: `bytes.Equal(pinned.Raw, cert.Raw)`; mismatch ⇒ `HostCertificateChanged` ⇒ refusal, with both SHA256 fingerprints reported by `cmd/ssh3.go:169-191,246-294`).

**Assessment.** Not constant-time, but the compared data is the peer's public certificate, not a secret — no exploitable timing channel. Comparison is exact (DER bytes, i.e. the same certificate), so a re-issued certificate for the same host is correctly treated as a change. Default policy is `ask` (`cmd/ssh3.go:560`), `yes` refuses unpinned hosts, `no` warns and connects. `-insecure` and `StrictHostKeyChecking=no` are explicitly logged as dangerous.

## Verified clean

Each item was checked specifically; "clean" means the code holds up for the stated reason, not that it was exhaustively fuzzed.

1. **Stage-1 bug 2 (negative/overflowing exit status ⇒ `VarIntLen` panic).** Fixed. `cmd/ssh3-server.go:458` routes the process status through `safeExitStatus` (`cmd/exit_status.go:15-20`, negative ⇒ 255); parsed exit statuses come from a varint and cannot exceed the encoder's limit. `VarIntLen` itself still panics (F-09), but no call site feeds it an out-of-range value today — every caller was enumerated (`git grep VarIntLen(`) and each argument trace is either a constant, a parsed varint, a `len()`, or a parsed `uint64` field.
2. **Stage-1 bug 3 (silent truncation reported as success).** Fixed. `client/session_pump.go:60-80` tracks the stdin pump and a truncation verdict, `:166-182` bounds the wait with `truncationGrace` and returns 255 with *"remote command exited before all input was sent; the transfer was truncated"*; `:212-227` handles a later status; regression tests `TestPumpPtyExitDrainIsBounded`/`TestPumpPtyExitHalfClosesChannel` and the truncation test at `client/session_pump_test.go:136`.
3. **Stage-1 bug 4 (nil signing key ⇒ SIGSEGV in `BuildJWTBearerToken`).** Fixed. `auth/plugins/pubkey_authentication/client/privkey_auth.go:178-183` returns the key-load error before `BuildJWTBearerToken` is reached.
4. **Privilege separation for executed commands.** `util/unix_util/user.go:40-51` sets `syscall.Credential{Uid,Gid}` when the target differs from the server's own ids, and sets `cmd.Dir` to the user's home; no `sudo`/shell interpolation of the user name. Command strings are passed to the login shell — that is the product's purpose (equivalent to `sshd` `ForceCommand`-free exec), not an escalation.
5. **Pre-auth surface is small.** The only work an unauthenticated peer can drive is the CONNECT handler: version-string parsing, `unix_util.GetUser`, identity-file read+parse for *existing* users (`server_auth/auth.go:70-84`), the JWT verifier (F-07), and the DoS guard. Channel headers/messages are *not* parsed until the conversation is registered, which happens only after a successful verdict (`server.go:255-260`) — this is what downgraded F-01 from a pre-auth to a post-auth finding, and it is worth preserving deliberately.
6. **0-RTT cannot carry authentication.** `server_auth/auth.go:49-54` rejects the request with 425 until the TLS handshake completes, so early-data replay cannot authenticate.
7. **Reverse forwarding policies are enforced where it matters.** `cmd/reverse_forward_server.go:187` applies the GatewayPorts policy before any bind (both TCP `:235` and UDP `:256`); the per-user budget is acquired *before* the bind (`:204`) and released on every failure path (`:216,230,237,251,258,270`) and on conversation end (`:321-325`); the bound port is the only thing returned, so the policy rewrite is not client-visible. Targets must be IP literals (`:213-221`), so the server never resolves a client-supplied name on this path. No bypass found for `no` (an unparseable or non-loopback bind is forced to `127.0.0.1`, `:71-97`).
8. **Password backend hardening.** `server_auth/handlers.go:86-111` checks the lockout *before* touching the backend, books failures only for real users (the username was already resolved by `unix_util.GetUser`), refuses with 429 while locked, and clears on success. `dos_guard.go` is mutex-protected. Lockout state is per user and cannot be poisoned by an unauthenticated attacker (i.e. no user-enumeration-driven lockout of arbitrary accounts, since the username must exist).
9. **No secret material in logs.** Grep over all non-vendor Go sources for `Authorization`/`Bearer`/`password` on logging lines found only the useful messages (`server_auth/handlers.go:94`, `client/client.go:357-362`); tokens, bearer strings and passwords are never formatted into log output. Server logs are JSON under systemd (journald-friendly, which also neutralises log forging).
10. **No telemetry, no git-sourced dependencies.** `go.mod`/`go.sum` are registry-only; `Cargo.lock` resolves to crates.io; the CTO_TASK ground rule holds at this revision.
11. **`vendor/h3` boundary.** The Rust patch is confined to the h3 extended-CONNECT shim; the Go tree does not depend on it and the vendored Go `vendor/` tree matches `modules.txt` (it compiled with `-mod=vendor`).

## Dependency / CVE notes

- Method: OSV `POST /v1/query` per `(ecosystem, module, version)`, plus manual reading of `go.mod`, `go.sum`, `Cargo.lock`. `govulncheck`/`cargo-audit` were not available offline in this environment; the OSV query is the same advisory database but without call-graph filtering, so *presence* of an advisory for a module does not mean the affected function is reachable. Reachability was assessed by hand and is recorded per finding (F-07, F-10, F-11).
- Go modules flagged: `golang-jwt/jwt/v5 v5.0.0` (**reached**, F-07), `golang.org/x/crypto v0.54.0` (affected package not exercised), `go-jose/v3 v3.0.1` + `golang.org/x/oauth2 v0.13.0` (OIDC-only), `golang.org/x/net v0.56.0` (affected packages unused).
- Rust crates flagged: `rustls 0.23.37` (F-10). No advisories for `quinn 0.11.9`, `h3 0.0.8`, `ring 0.17.14`, `ed25519-dalek 2.2.0`, `tokio 1.50.0`, `hyper 1.9.0`.
- All flagged Go/Rust versions are upgrades *within* the existing majors, which keeps them compatible with the CTO_TASK ground rule (no new dependencies, registry-only sources).

## Limitations

- **Report-only, no dynamic exploitation.** Nothing was run against a live server; no network peer was ever attacked. Findings F-01…F-06, F-08 are static-analysis conclusions.
- **Dynamic probing was only partially possible.** The image ships no Go toolchain; a `go1.26.0` toolchain was recovered from the module cache and used for read-only local probes of parser behaviour. The probe of `util.ParseSSHString` (see F-01) was executed and reproduced both the `makeslice` panic and an unrecoverable `fatal error: runtime: out of memory`. Everything else marked "static" was *not* executed end-to-end: no server was started, no fuzzing campaign was run (the message parser has no fuzz target in-tree).
- **No `recover()`-reachability proof by execution.** The "panic ⇒ process death" reasoning is Go language semantics plus a verified absence of `recover()` in the Go tree and in the `ServeQUICConn` goroutine (`cmd/ssh3-server.go:1355-1372`), not a live crash demonstration.
- **Rust workspace not triaged line by line.** 16 `unsafe` sites and ~874 `.unwrap()` calls exist in `crates/*/src`; the highest-density files are `crates/ssh3-client/src/lib.rs` (~502), `crates/ssh3-server/src/lib.rs` (~135), `crates/ssh3-h3/src/lib.rs` (~88), `crates/ssh3-quinn/src/channel.rs` (~61), `crates/ssh3-auth/src/lib.rs` (~30). The `unsafe` blocks cluster around TTY/ioctl handling (`ssh3-client/src/lib.rs:147,563-601`), process signalling (`:2393-2491`), and the shadow/`crypt(3)` FFI password backend (`ssh3-server/src/lib.rs:312-383`) — that last one parses a shadow entry with `CStr::from_ptr` and is the one I would fuzz next, since it feeds attacker-supplied password bytes into `crypt`. **Treat the Rust side as only partially covered.**
- **No Windows-path review.** `cmd/window_change_windows.go`, `client/signals_windows.go`, `util/unix_util` Windows files, and the Windows build path were not audited.
- **No review of** `internal/interop` harnesses (test-only), `bench/`, the C17 rewrite, packaging/goreleaser scripts, or the `.github` workflows.
- Coverage gaps are stated rather than padded: absence of a finding in an unreviewed area means nothing.

## Coverage

**Reviewed in detail (finding or "clean" statement attached)**

- Wire/varint and SSH-string codec: `util/wire.go`, `util/types.go`, `util/util.go` (length handling, `VarIntLen`/`AppendVarInt*`, `ParseSSHString`/`WriteSSHString`), including a full enumeration of `ReadVarInt`/`ParseSSHString`/`VarIntLen`/`AppendVarInt` call sites.
- Message parsing: `message/message.go` (all parse functions and `ParseMessage`), `message/channel_request.go` (all request parsers, `Length()`/`Write()` pairs, exit-status/exit-signal), `message/dynamic_forward.go`, `message/reverse_forward.go`.
- Channel/conversation plumbing: `channel.go` (`parseHeader`, header build, framing, `MaxPacketSize` arithmetic), `conversation.go` (stream classification, channel accept queue, datagram dispatch), `server.go` (`ServeQUICConn` accept loops, conversation registration, datagram loop), `channel_rwc.go`.
- Auth: `server_auth/auth.go`, `server_auth/handlers.go` (Basic/JWT/Bearer), `server_auth/authorized_identities.go` (identity file location + parsing), `server_auth/dos_guard.go` (cap and lockout), `auth/plugins/pubkey_authentication/{server,client}/*` (JWT verification: alg allowlist, exp/iss/sub/client_id/jti binding, keyfunc), `auth/oidc/openid_connect.go` (nonce/conversation binding), `util/unix_util/{user,linux_user,non_password_auth_user,cmd,agent}.go` (user lookup, credential switching, shadow path).
- Server session handling: `cmd/ssh3-server.go` (exec/PTY/exit status/signal paths, forwarding handlers, authentication loop, connection accept goroutine, shutdown/drain).
- Forwarding: `cmd/reverse_forward_server.go` (GatewayPorts policy, budget, bind/dial), the reverse-forward wire messages, `cmd/dynamic_forward{,_server}.go` (SOCKS5 reader bounds, per-conversation channel cap), `client/reverse_forward.go`.
- SFTP: `cmd/sftp_subsystem.go` (jail resolution, all `Filecmd`/`Filelist`/read/write handlers, symlink handling) and the v0.1.22 "server-absolute paths honored" change (it widened the accepted namespace to any path textually under the home directory — the escape in F-04 does not depend on it, but the change is what makes `/home/user/...` spellings pass the lexical check).
- Client side: `client/client.go`, `client/session_pump.go`, `client/session.go`, `client/escape.go`, `client/config/matchcfg/matchcfg.go` (`Match`/`Include` pre-parser, `exec`), `client_auth.go`, `known_hosts.go`, `strict_host_key.go`, `sshfp.go`, `cmd/ssh3.go` (host-key policy resolution and TOFU writes).
- Client master/slave control channel: `client/cm/*` (versioned framing codec, strict decoders), `client/{master,slave,control}.go` (UDS socket permissions 0600, control operations).
- Cross-cutting: `git grep 'panic('`, `'recover()'`, `'unsafe'`, `unwrap()/expect()`, `os/exec`, `Setuid`, `Authorization`-logging sweeps.

**Not reviewed** — Rust line-by-line triage of `unwrap()`/`unsafe` (statistics only, see Limitations); Windows-specific files; `internal/interop`; packaging and CI; C17 rewrite; `vendor/h3` internals.

## Appendix — how to reproduce the key checks

```bash
git clone --depth 50 https://github.com/nagual2/ssh3-go.git && cd ssh3-go
git rev-parse HEAD                     # expect 00c2f4697307c0b201e5d416bb0dfbe382998c78

# 1. no panic handler anywhere in the Go tree
git grep -n 'recover()' -- '*.go' ':!vendor'          # -> no hits

# 2. the unprotected goroutine that runs the channel accept loop
sed -n '1352,1372p' cmd/ssh3-server.go                 # go func() { ... ServeQUICConn ... }

# 3. unbounded allocation from a peer-controlled length
sed -n '204,218p' util/wire.go                         # make([]byte, length)
sed -n '163,172p' channel.go                           # ParseSSHString on the peer stream

# 4. unknown message id panics
sed -n '228,233p' message/message.go                   # default: panic("not implemented")

# 5. the DoS-guard slot leak
sed -n '86,101p' server_auth/auth.go
git grep -n 'ReleaseUnauthenticatedConversation' -- '*.go'   # single caller

# 6. the SFTP jail is lexical
sed -n '84,107p' cmd/sftp_subsystem.go

# 7. dependency advisories (same database govulncheck uses)
curl -s -X POST https://api.osv.dev/v1/query \
  -d '{"package":{"ecosystem":"Go","name":"github.com/golang-jwt/jwt/v5"},"version":"5.0.0"}'
```

*End of report.*
