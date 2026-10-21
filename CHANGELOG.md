# Changelog

All notable changes to the **nagual2 fork** of SSH3, starting from the first fork release. Changes that predate the fork — the upstream [`francoismichel/ssh3`](https://github.com/francoismichel/ssh3) project and the Rust-rewrite lineage this repository was built on — are **not** covered here; see the respective upstream sources for those.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); each section maps to a release tag, newest first.

## [Unreleased]

## [0.1.37] - 2026-10-18

### Added
- **The Debian packaging wave**: the RFS-grade Debian source package (`packaging/debian`, quilt 3.0, debhelper 13, lintian 0E/0W in the sid CI): the binary package `ssh3-go` ships both the `ssh3` client and the `ssh3-server` daemon with fresh mdoc man pages, and Conflicts/Replaces the sibling C17 `ssh3-server` package in both directions — the drop-in replacement of the P8 wave. The offline build pins `-mod=vendor` + `GOTOOLCHAIN=local` against the vendored tree.

### Changed
- **The client startup is quiet by default**: the init-time plugin registration logs ("plugin … successfully registered") are removed, the absent-SSH-agent notice drops from warning to debug, and both mains clamp the global log level to warnings-and-errors before the real level is resolved from `-v`/`-q`/`SSH3_LOG_LEVEL` — the pre-configure plugin/CLI-arg chatter no longer reaches the terminal (diagnostics stay available under `-v`). The session banner reads `ssh3-go session:` now (server-side; visible once servers are redeployed). A stray `%!s(<nil>)` in the connection-failure message is gone.

## [0.1.36] - 2026-10-18

### Added
- **`-f` goes to background (the ssh2 canon)**: after the row-1 retirement the maintainer chose to implement the background form. The Go runtime cannot fork an established connection, so `-f` re-execs a detached child (the ControlMaster daemon mechanics: no terminal, own process group on unix, `SSH3_F_DAEMON=1` marker) that runs the full startup itself; the parent validates and returns 0 immediately. The detached child cannot prompt, so every configuration needing an interactive answer is refused up front: password auth, the OIDC browser flow, the control master combination (it already backgrounds via `-control-persist`), and an unpinned host under the default ask policy — a key or the agent is required, exactly the ssh2 background usage. `-f` implies `-n` (the child's stdin is the null device); Windows runs in the foreground with a warning (no session detach yet, the control-master stance). `cmd/background.go` (TDD validator), the trilingual README parity tables updated.
- **CLI parity with OpenSSH (ssh2 canon)** (CTO_TASK §7c, maintainer decision 2026-10-17: where the functionality matches, the launch keys follow ssh(1)/sshd(8); the fork's own forms stay as deprecated aliases): client `-i` (identity file, alias of `-privkey`), `-V` (version, client and server, alias of `-version`), `-A` (agent forwarding, alias of `-forward-agent`), `-J DEST[,DEST...]` (proxy jump with the ssh(1) comma-chain; the hops are tunneled UDP hop by hop; alias of `-proxy-jump`), `-L [bind:]port:host:hostport` (repeatable local forwards in the ssh(1) shape; a `udp://` prefix is the documented UDP extension; the fork's `-forward-tcp/-forward-udp local/remote@port` shapes remain as aliases and a parse error there now aborts instead of continuing with nil addresses), `-M`/`-S path` (control master mode/socket, aliases of `-control-master yes`/`-control-path`), `-q` (quiet: diagnostics suppressed, errors kept), `-4`/`-6` (force the address family for the QUIC dial), `-p port` (remote port, also in transfer mode; the transfer-mode `-P` stays as a deprecated alias); `-o` keywords `Port`, `User`, `IdentityFile`, `LocalForward`, `RemoteForward`, `DynamicForward` (now repeatable, like `-D`), `ProxyJump`, `ControlMaster`, `ControlPath`, `ControlPersist` — precedence CLI flag > `-o` > `~/.ssh/config`. Server: `-h KEY` (host key, alias of `-key`), `-c CERT` (host certificate, alias of `-cert`), `-p PORT` (listen port overriding the `-bind` port; the bind address stays project-specific — QUIC needs it). Behavioral timeouts follow the sshd canon: `-max-idle-timeout` default 30 s → 24 h (`ClientAliveInterval=0` shape, raised on the client too since QUIC negotiates the smaller value) and `-handshake-idle-timeout` default 5 s → 120 s (`LoginGraceTime` scale). Root refuses password authentication unconditionally (the `PermitRootLogin prohibit-password` analog; `server_auth.PasswordLoginRefused`, refused before the password backend is consulted). The retired `-f` transfer form fails loudly with a pointer to the new `-transfer` long form — ssh2 reserves `-f` for backgrounding, and a silent other behavior would break ssh2-shaped scripts; the ssh(1) background mode itself is a future increment. README en/ru/de document the ssh2 forms as primary; deviation matrix against the sibling C implementation: `the sibling ssh3-c docs`.

## [0.1.34] - 2026-10-12

### Changed
- **Password authentication is enabled by default on the amd64 release server** (`cmd/ssh3-server.go`): the `enablePasswordLogin` default flips from off to on — the admin turns it off explicitly with `SSH3_ENABLE_PASSWORD_LOGIN=0` in `/etc/ssh3/ssh3-server.env` or `-enable-password-login=false`. Brute force stays bounded by the per-account lockout (`SSH3_MAX_PASSWORD_FAILURES` / `SSH3_PASSWORD_LOCKOUT_SECONDS`) and the unauthenticated conversation cap. arm server builds remain key-only (no CGO shadow backend), and the release client builds still ship without the password prompt — a password-capable client requires a custom build. Packaging comments (`packaging/ssh3-server.env`, `packaging/ssh3-server.service`) and the trilingual README updated to match.

## [0.1.33] - 2026-10-11

### Fixed
- **A malformed datagram no longer ends the conversation's datagram reception, on either side** (F-19, `conversation.go`, `server.go`, `util/types.go`; pass-6 audit, `docs/SECURITY_AUDIT_PASS6_2026-10-11.md`): after the F-14 fix the only peer-triggerable way to kill a datagram receive loop left was a datagram whose varints do not parse — one truncated datagram (on the client, sent by a hostile server; on the server, self-inflicted) silently disabled datagram delivery for the whole conversation while streams stayed up. An unparseable datagram is now classified as `util.DatagramMalformed` and dropped with a warning by both loops — the conversation-id parse failure, the channel-id parse failure inside `AddDatagram` and any other malformed payload all take the same drop-and-continue path; everything else (context cancellation, transport errors) stays terminal. The classification is pinned by a test; the Rust client keeps the same residual (`is_benign_datagram_dispatch_error`) and is noted for a follow-up port.

### Security
- **Rust password authentication can no longer be taken down by a poisoned lock** (F-21, `ssh3-server/src/lib.rs` in `nagual2/ssh3-rust`; pass-6 audit): the process-wide `crypt_lock()` was acquired with `lock().unwrap()`, so a single panic while holding it would poison the mutex and make every subsequent password authentication panic — a process-wide auth outage. The lock is now recovered with `unwrap_or_else(|poisoned| poisoned.into_inner())`, the same idiom the Rust client already uses; the critical section holds no invariant to repair (crypt(3) works on a static buffer).

## [0.1.32] - 2026-10-10

### Fixed
- **A single stale datagram no longer kills the client conversation's whole datagram loop** (F-14, `conversation.go`; pass-5 audit, `docs/SECURITY_AUDIT_PASS5_2026-10-10.md`): the client datagram receive loop treated any `AddDatagram` error as terminal, and since the P4-02 prune a datagram in flight while its channel closes comes back as `ChannelNotFound` — one such datagram silently silenced every channel's datagram delivery on the conversation for its remaining lifetime (the server loop has warned and continued on the same condition all along). The client loop now mirrors the server: `ChannelNotFound` is dropped with a warning, anything else stays terminal.
- **The dangling-datagram-queue cap is no longer fail-closed** (F-15, `resources_manager.go`): at the 256-queue cap a brand-new ID was refused, so junk IDs could pin every slot for the conversation's lifetime and silently drop every legitimate pre-registration datagram afterwards. The cap now evicts the oldest dangling queue (FIFO, tracked in a small order slice; a registered channel's queue leaves the eviction set when it is handed over), so a fresh ID is always accepted while the bound — and its worst-case memory — stays unchanged.

## [0.1.31] - 2026-10-10

### Security
- **Closed channels are pruned from the conversation's channel manager** (P4-02, `channel.go`; pass-4 audit, `docs/SECURITY_AUDIT_PASS4_2026-10-10.md`): the close listener was wired into every channel at construction but nothing ever invoked it, so the manager kept every channel ever accepted or opened — including ones the channel budget refused right after `AcceptChannel` registered them — for the conversation's whole lifetime. `Close` now notifies the listener, which removes the channel (and, with it, the last reference to its datagram queue) from the map; the removal is idempotent and skipped safely when no listener is set.
- **Dangling datagram queues are bounded per conversation** (P4-01, `resources_manager.go`): a datagram naming a channel that never registers pins a dangling queue (64 slots plus its buffered datagrams) until the conversation dies, and nothing capped their number — an authenticated peer holding one conversation open could grow the map without bound by cycling channel IDs. Brand-new dangling queues are now capped at 256 per conversation (far above any legitimate concurrent-channel count, whose datagrams race the registration by microseconds); beyond the cap, datagrams for unregistered channels are dropped with a warning. Queues already created still extend, and delivery on a late registration is unchanged (`resources_manager_test.go`).
- **The P3-01 session-prune fix is pinned by a regression test** (P4-03, `cmd/ssh3-server.go`, `cmd/session_admission_test.go`): the insert-before-admission / undo-on-refusal pairing lived inline in the accept loop and was verified only by reading the code. It is extracted into `admitSessionChannel`, and the tests pin both the refusal path (the entry is pruned, the session goroutine never starts) and the admission path (the entry is visible to the spawner, as the request handlers require).
- **The local `maxPacketSize` advertisement is floored at construction** (P4-04, `channel.go`): the P3-02 floor bounded the peer value only, leaving the `MaxPacketSize > emptyMsgLen` invariant an unwritten property of the call sites (every opener passes the same 30000 constant). `NewChannel` now floors the local value where the header and the `ChannelInfo` are built — a no-op for inbound channels, which arrive with the already-floored peer value — and `WriteData` fails fast on a `MaxPacketSize` at or below the empty-frame header length instead of spinning in a zero-progress loop.

## [0.1.30] - 2026-10-10

### Changed
- **`--continue` skips by size+mtime, not by size alone** (R7, `cmd/sftp_client.go`, `cmd/sftp_subsystem.go`): the resume decision trusted the file size only, so a source rewritten in place (same size, new content) was silently skipped as "already fully uploaded" — the message asserted a fact the code never checked. Every transfer path (single-file and tree, upload and download) now stamps the peer with the source mtime after a successful transfer — the server's sftp subsystem learned the timestamp form of SETSTAT for that (`setstat`, jail-resolved like every other path) — and skips only when both size and mtime match; a size match with a differing mtime re-transfers, so a stale copy can no longer hide behind an equal length. Transition cost: the first `--continue` over a tree uploaded by an older client re-transfers it once (the stamped mtime is missing there), later runs skip again. The skip/re-transfer messages now state what was actually compared.

## [0.1.29] - 2026-10-09

### Security
- **A budget-refused session channel no longer leaks its `runningSessions` entry** (P3-01, `cmd/ssh3-server.go`; pass-3 audit, `docs/SECURITY_AUDIT_PASS3_2026-10-09.md`): the v0.1.28 channel budget refused an over-cap channel before the handler goroutine started, but the session entry was inserted before that admission check and only the goroutine's teardown ever deleted it — every refused session channel kept one map entry (and the channel object it references) for the process lifetime. An authenticated peer holding the per-conversation budget exhausted (64 long-lived channels by default) could grow the map without bound by churn-opening session channels. `spawnChannel` now reports the refusal and the session branch prunes the entry it just inserted.
- **The `maxPacketSize` clamp gained a floor** (P3-02, `channel.go`): the S2-01 clamp was a ceiling only, so a peer advertising `maxPacketSize` of 0 or 1 passed it verbatim — the outbound chunk size in `WriteData` (`MaxPacketSize - emptyMsgLen`, an unsigned subtraction with an empty-frame length of 2) wrapped to ~2^64 and sent the whole caller buffer as one oversized frame, while the per-channel read buffers were allocated 0/1 bytes. Peer values below 4096 (`minPeerMaxPacketSize`) are now floored; the channel-open confirmation announces the floored value, so the peer sees what the endpoint actually accepts. Self-inflicted exposure (the peer chose its own value), so this is hardening rather than a remote fix.
- **The channel role table is an allow-list, not a negative list** (P3-03, `server.go`, `conversation.go`, `channel.go`): the S2-03 fix refused the four known cross-role names (`forwarded-tcp`/`forwarded-udp` from a client, `direct-tcp`/`direct-udp` from a server) but any other unknown type string still fell through to the session branch and occupied a real session slot. Both inbound paths now gate on allow-lists covering exactly the types each side dispatches (`session`, `sftp`, `direct-tcp`, `direct-udp`, `reverse-forward`, `dynamic-forward`, `dynamic-forward-tcp` on the server; `forwarded-tcp`, `forwarded-udp`, `agent-connection` on the client); anything else is cancelled with a stream error before any channel allocation. `channel_types_test.go` pins the table.
- **`-max-sftp-sessions-per-user` is enforced in the in-process sftp mode too** (P3-04, `cmd/sftp_subsystem.go`): the per-user budget was acquired only on the chroot-child path, so on an unprivileged server (which serves sftp in-process) or in explicit `lexical` mode the documented cap silently did nothing. The budget is now acquired before the jail-mode branch, in both modes; while a session runs it holds the slot and releases it on exit (`cmd/sftp_budget_test.go`).

The pass-3 fix-verification audit itself (`docs/SECURITY_AUDIT_PASS3_2026-10-09.md`) verifies the v0.1.28 remediation series (S2-01..S2-07) against `8725d65` and reports the findings above.

## [0.1.28] - 2026-10-05

### Security
- **A peer no longer picks the size of the endpoint's per-channel read buffers** (S2-01, `server.go`, `conversation.go`, `channel.go`): an incoming channel kept the peer's advertised `maxPacketSize`, and the read loops allocated `make([]byte, channel.MaxPacketSize())` per channel — one authenticated connection could pin ~100 streams x up to 16 MiB of heap with ~30 bytes of input per channel (the v0.1.27 cap only bounded the value at 16 MiB). Both inbound paths (the server's channel accept and the client's counterpart) now clamp the peer value by the locally advertised one; the channel-open confirmation already announces the local value, so lowering is protocol-consistent.
- **Channels, sftp children and the session map are bounded** (S2-02, `cmd/ssh3-server.go`, `cmd/channel_budget.go`, `cmd/sftp_subsystem.go`): the conversation accept loop used to admit channels without any cap, the process-global `runningSessions` map was written once per session channel and never pruned, and the default sftp mode re-execed a child process per sftp channel. A per-conversation channel budget (`-max-channels-per-conversation` / `SSH3_MAX_CHANNELS_PER_CONVERSATION`, default 64, 0 = unlimited) now refuses over-cap channels with a stream error, the session entry is deleted when the session ends, and concurrent sftp children are capped per authenticated user (`-max-sftp-sessions-per-user` / `SSH3_MAX_SFTP_SESSIONS_PER_USER`, default 16, 0 = unlimited). An unprivileged server serves sftp in-process instead of forking a pointless child per channel.
- **The in-process sftp handler carries a panic guard** (S2-05, `cmd/sftp_subsystem.go`): `pkg/sftp` parses peer-controlled requests, and a panic in the lexical/in-process mode killed the whole server (the chroot mode only loses a child). The handler now recovers with a logged stack trace and closes the channel.
- **The channel role table is enforced on both inbound paths** (S2-03, `server.go`, `conversation.go`): the server accepted client-opened `forwarded-tcp`/`forwarded-udp` channels (the server-to-client reverse-forward types), which fell through to the session branch and occupied a dead session slot; the client symmetrically accepted any server-opened type. The server now refuses the `forwarded-*` names on its inbound path and the client refuses `direct-*` on its, with a stream error.
- **Reverse-forward binds are policy-gated** (S2-04, `cmd/forward_policy.go`, `cmd/reverse_forward_server.go`, `cmd/ssh3-server.go`): `-permit-open` bounded the dials, but the `-R` listeners still bound any client-chosen port subject only to GatewayPorts. The same parser now backs `-permit-listen` / `SSH3_PERMIT_LISTEN` (the PermitListen analog; empty keeps the unrestricted default), consulted on the post-GatewayPorts bind address before the per-user budget.
- **The QUIC resource posture is explicit and configurable** (S2-06, `cmd/ssh3-server.go`): the quic.Config now sets `MaxIdleTimeout`/`HandshakeIdleTimeout`/`MaxIncomingStreams`/`MaxIncomingUniStreams` explicitly (defaults equal to the quic-go defaults: 30 s, 5 s, 100, 100) with the operator knobs `-max-idle-timeout`, `-handshake-idle-timeout`, `-max-incoming-streams`, `-max-incoming-uni-streams` (env `SSH3_*`), and concurrent connections can be capped with `-max-connections` / `SSH3_MAX_CONNECTIONS` (default 0 = unlimited).
- **The varint encoder panic contract is pinned by tests** (S2-07/F-09, `util/wire_test.go`): the edge-value and the >2^62-1 panic paths of `VarIntLen` were already covered; `AppendVarIntWithLen`'s two panic paths (an impossible length, a value too wide for the requested length) are now pinned as well, so a future error-return refactor notices the contract.

### Added
- **Recursive `-f` transfers pipeline files instead of round-tripping them** (`cmd/sftp_client.go`, `cmd/sftp_client_test.go`): the tree walk used to push one file at a time and wait for every CLOSE, at ~5 SFTP round-trips per file — 78 files/s on a LAN. `uploadDir`/`downloadDir` now run a 16-worker pipeline over one channel: SFTP requests are id-multiplexed, the server's RequestServer worker pool processes them concurrently, and each CLOSE still waits only for its own file's writes, so per-file confirmations and failure accounting hold. The recursive fast path also drops the three per-file Stats the walk makes redundant (dir-target check, parent auto-mkdir check, post-upload size verify — CLOSE carries the final write status; `--checksum` and the big-file threshold still re-read), and the client enables `UseConcurrentWrites` for chunk pipelining inside big files. Measured on the 0.1.27 LAN stand: 2000 x 2 KiB files, upload 25.9 s -> 1.3 s (x20, ~1500 files/s), download 2.1 s, all byte-exact. Process-level sharding (`-f -r` per subtree in parallel) composes on top for very large trees.

## [0.1.27] - 2026-10-07

### Added
- **Kernel-enforced sftp jail, the sshd model, by default** (`cmd/sftp_subsystem.go`, `cmd/internal_sftp.go`, `cmd/ssh3-server.go`): in `-sftp-jail chroot` (the default) the network-facing server no longer touches user paths at all — per sftp session it re-execs itself as a short-lived child that chroots into the user's home, drops to the user's uid/gid (supplementary groups cleared) before the first path is opened, and serves over stdio while the parent pumps bytes. After the chroot, path confinement is the kernel's: absolute symlinks and `..` cannot reach outside, no lexical check is load-bearing. `-sftp-jail lexical` (`SSH3_SFTP_JAIL`) keeps the historical in-process jail for unprivileged single-user servers. A chroot request arriving at a child that is not root fails closed (exit 1) instead of serving unjailed, and a group/world-writable jail root is refused (the sshd rule, adapted).
- **`-permit-open` / `SSH3_PERMIT_OPEN` — the PermitOpen analog for server-side forwarding** (`cmd/forward_policy.go`, `cmd/ssh3-server.go`, `cmd/dynamic_forward_server.go`): TCP, UDP and dynamic (`-D`) dials now pass a single gate with sshd_config PermitOpen semantics — comma/space-separated `host:port` entries, `*` wildcards, `!` negation (empty keeps the historical unrestricted default, matching OpenSSH). The dynamic path matches the name as the SOCKS client spelled it, before resolution, so a DNS name cannot be resolved outside the policy.
- **OpenSSH-style escape sequences for interactive sessions** (`client/escape.go`, `client/session_pump.go`, `cmd/cli_flags.go`, `cmd/ssh3.go`): an escape character at the start of a line introduces `~.` (a clean client-side teardown, exit 255 like a closed connection), `~^Z` (unix: restore the terminal, SIGTSTP the client, re-enter raw mode on resume) and `~~` (one literal escape character); an unknown sequence forwards literally, and a sequence split across stdin reads still fires. `-o EscapeChar=` and the `~/.ssh/config` keyword pick the character (one ASCII printable, a `^X` control form or `none`), `~` is the OpenSSH default. The filter arms only for interactive pty sessions, so exec traffic stays byte-exact.
- **Terminal modes ride the pty request** (`util/ttymodes/`, `client/session.go`, `client/client.go`, `cmd/forced_pty.go`, `cmd/ssh3-server.go`): the client captures the local termios and encodes them into the pty request (RFC 4254 section 8); the server parses the payload and applies the modes onto the pty slave — flags (input 30-42, local 53-64, output 70-75, CS7/CS8/PARENB/PARODD), control characters (1-17, an argument of 255 means disabled) and the 192/193 speeds (a zero speed leaves the baud alone). Unknown opcodes are skipped like OpenSSH does, and a payload that cannot be parsed or applied is logged without killing the session. Windows clients keep sending no modes.
- **RequestTTY policy and `-T`** (`cmd/ssh3.go`, `client/client.go`): `-T` disables pty allocation even for an interactive shell, and `-o RequestTTY=auto|no|yes|force` plus the `~/.ssh/config` keyword select the OpenSSH policy — `auto` (the default) requests a pty for interactive shells over a TTY, `yes` also for exec over a TTY, `force` routes through the forced-pty path even without a local TTY, `no` never. `-t` and `-T` are mutually exclusive; the CLI flags are the absolutes, the option overrides the config keyword.

### Security
- **A peer-controlled SSH-string length no longer drives an allocation** (F-01) (`util/wire.go`, `channel.go`, `util/wire_test.go`, `util/fuzz_test.go`): `ParseSSHString` used to `make([]byte, length)` straight from a peer-controlled varint — 8 bytes on a channel stream sufficed for a `makeslice` panic or an unrecoverable out-of-memory, killing the whole process (any authenticated user against the server, any server against the client). Lengths above `util.MaxSSHStringLen` (16 MiB, above any legitimate use) are rejected without allocating, and a channel open advertising `MaxPacketSize` beyond the same bound is refused instead of becoming a second allocation knob. Fuzz targets now cover `ParseSSHString`/`ReadVarInt`/`ParseMessage`.
- **An unknown message-type id is an error, not a panic** (F-02) (`message/message.go`, `message/parse_message_test.go`): `ParseMessage` ended in `panic("not implemented")`, reachable with 2 bytes from any peer holding an accepted channel. It now returns a typed `UnknownMessageType` error that tears the channel down (an unknown message cannot be skipped on the framing stream — its length is type-specific — so teardown is the only safe option).
- **The unauthenticated-conversation slot can no longer leak** (F-03, F-06) (`server_auth/auth.go`): the slot used to be released only on refusals, so every successful authentication consumed one permanently — one valid identity bricked the whole server with 503s after 100 logins, and the cap was acquired only *after* the conversation allocation, user lookup and identity-file reads it was documented to prevent. The slot is now acquired before any of that work and released unconditionally when the auth phase ends, whatever the verdict.
- **Peer-facing goroutines carry panic guards** (`util/util.go` `PanicGuard`, defers across `server.go`, `conversation.go`, `cmd/*`, `client/*`): the QUIC accept/session/forwarding loops parse peer-controlled bytes; a panic in any of them now logs with a stack trace and takes down the offending stream or connection, never the process (31 call sites).
- **A short unparseable User-Agent no longer panics** (F-08) (`server_auth/auth.go`): the error branch sliced `r.UserAgent()[:100]` blindly — a pre-auth `CONNECT` with a bogus UA cost a recovered panic and a 64 KiB stack trace per attempt (log flooding). The truncation is bounds-checked, and the debug lines no longer dereference the parse result before the error check.
- **The MaxStartups analog: unauthenticated conversations are capped** (`server_auth/dos_guard.go`, `server_auth/auth.go`, `cmd/ssh3-server.go`): a conversation between the CONNECT and the auth verdict now holds one of `-max-unauth-conversations` / `SSH3_MAX_UNAUTH_CONVERSATIONS` slots (default 100); over the cap the request is refused with 503 before any identity file reading or crypto verification happens, so a connection flood cannot stack unbounded auth work.
- **Password brute-force lockout** (`server_auth/dos_guard.go`, `server_auth/handlers.go`): failed password authentications are booked per user; after `-max-password-failures` / `SSH3_MAX_PASSWORD_FAILURES` (default 10) the account is locked out of the password backend for `-password-lockout-seconds` / `SSH3_PASSWORD_LOCKOUT_SECONDS` (default 60), refused with 429 without touching the shadow backend; a successful authentication clears the record and the lockout is per user.
- **Token replay across conversations is proven refused** (`auth/plugins/pubkey_authentication/server/server_plugin_test.go`): the pubkey JWT verifier requires the jti claim to carry the base64-encoded conversation ID; a regression test mints a valid token for one conversation and verifies it is accepted there and refused when replayed against another (the OIDC path binds the conversation via the nonce check the same way).

### Fixed
- **The sftp jail could not be escaped through a symlink anymore** (F-04) (`cmd/sftp_subsystem.go`): the lexical prefix check followed symlinks while a root server did the file I/O, so `ln -s /etc ~/etc` inside a shell session made the sftp server read and write root-owned files outside the home as root. The default chroot jail removes the privileged file I/O entirely (see Added); the lexical mode remains only for servers without privileges worth abusing.
- **The Rust workspace builds again: `vendor/h3` restored** (`vendor/h3`, per CTO_TASK §2): the deliberate `[patch.crates-io]` h3 shim was lost at `v0.1.26` by the re-vendor (the exact `go mod vendor` deletion trap documented after the previous loss), leaving every `cargo build` failing with `can't find h3 at vendor/h3`. Restored verbatim from history.
- **A remote process dying by signal now reports an exit-signal request (RFC 4254 section 6.10) instead of a 255 exit status** (`cmd/ssh3-server.go`, `cmd/ssh3.go`, `cmd/exit_status.go`): the server maps the wait status onto the wire signal name (no SIG prefix) with the core-dump flag; the client exits with the conventional 128+signum (SEGV → 139, TERM → 143), unknown names fall back to 255. Old servers keep working — the client pump already treats exit-signal as a terminal event.
- **Windows console resizes are now forwarded as window-change requests** (`client/winsize/winsize_windows.go`, `client/signals_windows.go`, `cmd/window_change_windows.go`): the interactive and forced-pty sessions poll the console geometry (draining console input events for resize notifications would steal keystrokes from the stdin pump) and report a change to the server.

### Changed
- **Dependencies with published advisories bumped within their majors** (F-07, F-10, F-11): `golang-jwt/jwt/v5` 5.0.0 → 5.3.1 (CVE-2025-30204 — excessive memory allocation while parsing an attacker-supplied bearer token, reached pre-auth), `golang.org/x/crypto` 0.54.0 → 0.57.0, `golang.org/x/oauth2` 0.13.0 → 0.37.0, `go-jose/v3` 3.0.1 → 3.0.5, `golang.org/x/net` 0.56.0 → 0.58.0; Rust: `rustls` 0.23.37 → 0.23.45 (RUSTSEC-2026-0285) with `aws-lc-rs`/`aws-lc-sys` pulled along. The vendored Go tree is re-synced (`go mod vendor`); the `vendor/h3` shim is restored after it (see Fixed).
- **GatewayPorts policy for reverse forwarding (`-R`)** (`cmd/reverse_forward_server.go`, `cmd/ssh3-server.go`): wide binds used to be honored with a warning. The server now applies the sshd_config semantics via `-gateway-ports no|clientspecified|yes` / `SSH3_GATEWAY_PORTS`, default `no`: every client-requested non-loopback bind is silently forced back to the loopback exactly as OpenSSH does (an info line names the rewrite), `clientspecified` honors the bind address the client asked for, `yes` binds the wildcard address. The bind reply carries the bound port only, so the change is wire-compatible with old clients. The per-bind wide-bind warning now fires only when a wide bind is actually taken under `clientspecified`/`yes`.
- **Per-user reverse forward limits** (`cmd/reverse_forward_server.go`, `cmd/ssh3-server.go`): the server caps active `-R` listeners per authenticated user (`-max-reverse-forwards` / `SSH3_MAX_REVERSE_FORWARDS`, default 10) across their conversations, on top of the existing per-conversation forwarded-channel bound; a bind over the limit is refused with a readable error on the control channel and the budget slot is returned when the conversation ends.

### Fixed
- **Reverse UDP forwards silently truncated datagrams at the server socket** (`cmd/reverse_forward_server.go`): the `-R .../udp` listener read into a 1500-byte buffer, so larger datagrams were cut at the read and the send then failed with a generic error. Datagrams are now read whole; one that exceeds the QUIC datagram limit of the path is dropped with an explicit warning naming the size and the path limit — the datagram path is lossy by design, but no longer silently truncated.

## [0.1.26] - 2026-10-05

### Changed
- **The repository is renamed to [`nagual2/ssh3-go`](https://github.com/nagual2/ssh3-go)**: the fork is now a daily-driver Go client/server next to the C rewrite, and the name says so. GitHub redirects the old `nagual2/ssh3` URLs (web and git), and the Go module path stays `github.com/francoismichel/ssh3` — imports are unaffected.
- **Packages are renamed: the deb/ar archives and the deb package are now `ssh3-go`** (`.goreleaser.yaml` `project_name`/`package_name`); the `ssh3-go` deb declares Conflicts/Replaces on `ssh3`, so an existing install migrates in place by installing the new package (or `dpkg -i ssh3-go_*.deb` directly). Binaries (`ssh3`, `ssh3-server`), the `ssh3-server.service` unit and `/etc/ssh3` configuration keep their names — scripts and systemd overrides are unaffected.

## [0.1.25] - 2026-10-04

### Fixed
- **Dynamic SOCKS forwarding (`-D`) could not connect at all** (`cmd/dynamic_forward.go`): the SOCKS5 request reader computed one byte too many for every address form. The `+1` that is only correct for the domain form's length byte was applied to IPv4 and IPv6 as well (IPv4 computed as 11 bytes instead of 10, IPv6 as 23 instead of 22), and after reading the domain length byte the final read started over at that byte, re-reading it. A real client's request was therefore never complete: the reader stalled until the 30-second handshake deadline killed the connection, so every `CONNECT` through the proxy timed out. The exact request size is now computed per address form, and the domain payload is read past the already-consumed length byte. Caught by a live loopback smoke test, not by the unit suite: the reader had no test at all, and a regression test now drives real request bytes for all three address forms through `net.Pipe`.
- **`-D` allocated a huge datagram queue per connection** (`cmd/dynamic_forward.go`): the data channel was opened with the 10 MiB channel window constant passed as the *datagrams queue size*, which allocates a channel entry per queue slot (tens of megabytes per SOCKS connection) although the tunnel never carries datagrams. The queue size is now 0, as for the session and reverse-forward channels.

## [0.1.24] - 2026-10-04

### Added
- **`Match` inside `Include` files** (`~/.ssh/config`): `Include` is now expanded by the `Match`-aware pre-parser itself, recursively, before the ssh_config decoder sees the text. Until now any `Match` block reached through an `Include` aborted the decoder and the whole `~/.ssh/config` was thrown away; now the content of an included file goes through the same alias and `Match` filtering as the main file, so an included `Host` or `Match` block behaves exactly as if it had been written inline. Glob patterns in `Include` targets, nested includes, a cyclic-include guard, and a recursion depth limit of 16 are supported. A missing or unreadable include is skipped instead of invalidating the rest of the configuration, and a `Match` parse error now names the included file and the line it actually comes from instead of pointing at the main config.
- **SSHFP host verification (RFC 4255)** (`sshfp.go`, `strict_host_key.go`, `cmd/sshfp_resolver.go`): the type-44 DNS records published for a host are looked up and compared against the real fingerprint of the presented host key. The fingerprint is taken over the DER X.509 host certificate (`cert.Raw`) — ssh3 pins certificates, not raw SSH public keys — and the DNS wire format is built and parsed in-tree, so no third-party resolver is involved. The verification is wired into the client connection path and is reachable from the command line through `-o VerifyHostKeyDNS=...` or the same keyword in `~/.ssh/config`; it is off by default, as in OpenSSH. Accepted values are `no` (also `false`, `off`, empty), `ask`, `yes` (also `true`, `on`) and `yes:algo[,algo...]`, which restricts the lookup to the listed host key algorithms — the short and full public-key names (`rsa`, `ssh-rsa`, `dsa`, `ssh-dss`, `ssh-dsa`, `ecdsa`, `ecdsa-sha2-nistp256/384/521`, `sk-ecdsa-sha2-nistp256`, `ed25519`, `ssh-ed25519`) plus the `sha1` and `sha256` digests. An unknown value or algorithm is rejected up front like any other malformed `-o`. Only a **mismatch** between published records and the presented key can refuse a host: NXDOMAIN, an empty answer, a truncated datagram, a timeout, an unavailable resolver and network errors are all soft skips that leave the known_hosts decision untouched. `ask` does not prompt — a mismatch under `ask` is refused with a warning naming the option that could override it — and with `StrictHostKeyChecking=no` a mismatch only warns and the connection continues. The exchange is bounded by a 2 s deadline (`DefaultSSHFPTimeout`) and the configured servers are queried in order; the lookup runs right after the dial, on the same certificate the known_hosts check used, and `-insecure` skips it along with the rest of host verification. On Windows the resolver configuration lives in the registry rather than in `/etc/resolv.conf`, so the servers are read from the local adapters through `GetAdaptersAddresses`, and an enumeration failure is a soft skip rather than an error. Record algorithms RSA, DSA, ECDSA and Ed25519 are recognised, and both SHA-1 and SHA-256 digest types are computed; RSA, ECDSA and Ed25519 host keys are matched against them.
- **ControlMaster control operations `check` and `stop`** (`client/control.go`, `cmd/controlmaster.go`): both travel over one new control frame that carries the operation name, so the master can grow operations without touching the framing. `check` answers with a status snapshot — pid, uptime, number of active sessions and forwarded channels — which the CLI plumbing prints on stdout before exiting 0; with no master listening it fails with an explicit error and a non-zero exit code. `stop` shuts the master down and waits until the control socket has actually been released, so the path is free and no stale socket is left behind. An operation this build does not know is refused by the master with a readable error instead of hanging. `exit` deliberately stays on the historical `MsgExit` frame so that masters from v0.1.22/v0.1.23 still understand it, and the new operations against such an older master produce a clear "the control master does not support …" error rather than a hang. All three operations are dispatched from the command line, on both the `-control-path` fast path and the normal path, and a value outside the set is rejected up front with the list of supported operations, before any key or known_hosts file is read.
- **Dynamic SOCKS forwarding** (`message/dynamic_forward.go`, `cmd/dynamic_forward_server.go`, `cmd/dynamic_forward.go`, `cmd/cli_flags.go`): the protocol is two channel types. The client opens one `dynamic-forward` control channel carrying a `RequestDynamicForward` announcement, and every connection its SOCKS listener accepts is mirrored to the server as a client-initiated `dynamic-forward-tcp` channel carrying a `DynamicForwardTarget`; the server resolves the address, dials it itself and bridges the channel with the TCP connection. Unlike the `-R` targets, the address may be a hostname — a SOCKS client often only knows a name — and the server is the side that resolves it. Deliberately **no new message-type id** was introduced: `ParseMessage` panics on unknown ids, which would crash older peers, so every payload travels as channel data behind a versioned varint prefix (version 1 + message kind) that an old peer simply never sees. Per connection the server replies with the outcome of the dial, so a resolution or connection failure reaches the SOCKS client as a readable reason; at most 64 `dynamic-forward-tcp` channels may be bridged at once per conversation, and closing the control channel or the conversation tears down every live bridge. On the client side `-D [bind_address:]port` opens the local SOCKS5 listener, the OpenSSH `-D` equivalent: it speaks SOCKS5 *no authentication required* only (it binds a local listener and bridges the connection inside ssh3, so it never sees credentials), supports `CONNECT`, accepts IPv4, IPv6 and domain address types, binds loopback without an address and every interface for `*`, requires IPv6 literals to be bracketed so a bare `::1:1080` is rejected instead of misread, and treats port `0` as a request for an ephemeral bind whose result is logged. `-D` combines with a session or with `-N`, in which case the client starts the channel loop itself.
- **Forced pseudo-terminal (`-t`)**: when there is no local terminal — a pipe, a cron job, a detached start — no PTY is requested and remote full-screen programs refuse to start. `-t` requests one anyway, taking the terminal type from `$TERM` (`xterm` when unset) and the geometry from the local console with an **80x24** fallback when it cannot be queried, which is still better than a bare pipe. `SIGHUP`, `SIGINT`, `SIGQUIT` and `SIGTERM` are relayed into the remote PTY, and on unix `SIGWINCH` becomes a window-change request, so `ssh3 -t user@host top` stays resizable. Windows has no `SIGWINCH` — the console reports a resize as an event rather than a signal — so there the geometry sent with the PTY request holds for the whole session.
- **Subsystem requests (`-s`)**: `-s NAME` asks the server for a subsystem instead of a shell or a command, exactly as `ssh(1)` does. `sftp` is special-cased onto the interactive SFTP client that already lives in the client package, with the command set of `sftp(1)` reduced to what is useful interactively (`pwd`, `ls`, `cd`, `get`, `put`, `mkdir`, `rm`, `rmdir`, `help`, `quit`/`exit`); any other name is sent as a subsystem request on the session channel, and the bundled Go server answers that with *not implemented*, so a free name is only useful against a server that serves subsystems. With `-t` the PTY is requested before the subsystem. `-s` owns the session channel and is rejected at the command line together with `-f`, `-N`, `-forward-agent`, `-R` and a remote command.
- **Alternative configuration file (`-F`)**: `-F PATH` reads a user configuration file other than `~/.ssh/config`, whose path is used verbatim as in OpenSSH, so a relative path stays relative to the current directory. Everything resolved from the configuration — `Host`, `Match`, `Include` — is read from that file in exactly the same way. An unreadable path does not fail the connection: the read error goes to stderr and the configuration is ignored, and a missing file is silently skipped.

## [0.1.23] - 2026-10-04

### Added
- **Reverse forwarding (`-R`)**: `-R [bind:]port[/udp]:target:targetport` asks the server to bind a TCP or UDP listener (loopback by default, wide binds warn, ephemeral ports report the actual port); every accepted connection or datagram comes back over a server-initiated `forwarded-tcp`/`forwarded-udp` channel and is bridged to the client-local target. Targets are validated against the `-R` list, forwarded channels are capped per conversation. Older peers reject the extension gracefully — verified live against a v0.1.22 server and an old client against the new server.
- **`StrictHostKeyChecking`** (`ask|yes|accept-new|no`) with OpenSSH-style priority: CLI flag > `-o` > `~/.ssh/config` > `ask`. Known-host pins are compared on the server certificate after the dial; a changed fingerprint refuses the connection with both `SHA256:` fingerprints in the error; `accept-new` pins automatically; `no` explicitly allows cert changes with a warning.
- **`~/.ssh/config` `Match` support**: criteria `all`, `final`, `host`, `originalhost`, `user`, `localuser`, `exec` (with `!` negation and globs), resolved by a pre-parser that flattens applicable blocks before the vendored ssh_config decoder; configs without `Match` take the untouched fast path.
- `-o Key=Value` is now repeatable and validates known keys; `StrictHostKeyChecking` is accepted as a key.
- `bench/exec-latency.sh`: measures cold one-shot, control-master spawn and warm slave exec latency.

### Changed
- Exec latency: the server no longer sleeps 100 ms before tearing down a non-multiplexed conversation, and the client polls for a spawning control master every 2 ms instead of 100 ms. Cold one-shot exec median on loopback: ~140 ms → ~26 ms; master-spawn first call ~112 ms → ~31 ms; warm slave path unchanged (~9 ms).

### Fixed
- Control master recovers a stale unix socket left behind by a SIGKILLed master instead of failing with `EADDRINUSE` for the full wait deadline (slaves hung 10 s and exited 255).
- Server conversation handlers no longer hang in `AcceptChannel` forever when the QUIC connection dies; the conversation context now derives from the connection.
- The client close path now also closes the QUIC connection, so the server learns of the client's departure promptly.

## [0.1.22] - 2026-10-02

### Added
- `SSH3_ENABLE_PASSWORD_LOGIN` server environment variable as the default for `-enable-password-login`, so systemd `EnvironmentFile` installs can opt into password auth without editing the unit.
- Client flag `-N`: hold the connection open for the forwards without running a session or shell.
- Control master: pty slave sessions now relay terminal resizes (SIGWINCH) and out-of-band signals through the master onto the ssh3 channel; raw-mode input bytes keep flowing through the io stream.
- `~/.ssh/config` extensions: `ServerAliveInterval` tunes the QUIC keepalive (default 1s), `ForwardAgent yes` defaults the `-forward-agent` flag, `ProxyJump` is honored as an alias of the fork's `UDPProxyJump`; `Include` directives resolve via ssh_config v1.2.0.
- Server: graceful shutdown on SIGTERM/SIGINT — stop accepting, drain active connections up to `SSH3_SHUTDOWN_DRAIN` seconds (default 5, `0` closes immediately), exit 0. Under systemd, non-verbose logging emits plain JSON to stderr (journald-friendly, no ANSI colors).

### Changed
- The amd64 release server is now built with CGO and the shadow/crypt password backend compiled in; password auth stays disabled by default and is enabled with `-enable-password-login` or persistently via `SSH3_ENABLE_PASSWORD_LOGIN=1` in `/etc/ssh3/ssh3-server.env`. arm server builds remain key-only (`disable_password_auth`).
- `-control-master` combined with `-proxy-jump` (from the command line or `~/.ssh/config`) is now an explicit error instead of a silent bypass.

### Fixed
- `ssh3 -f` honors server-absolute remote paths (e.g. `/home/user/file`), which previously failed with "file does not exist"; missing remote parent directories are auto-created on single-file uploads.
- The logger mapped the `error` level to `WarnLevel`.

### Performance
- Control master: fast slave path when an explicit `-control-path` is given.

## [0.1.21] - 2026-10-01

### Added
- **Control master** (connection multiplexing): one authenticated QUIC connection shared by many client invocations through a Unix control socket.
  - New flags: `-control-master no|yes|auto`, `-control-path`, `-control-persist no|yes|<seconds>`, `-O exit`.
  - TCP forwarding (`-forward-tcp`), UDP forwarding, and agent forwarding are multiplexed through the master.
  - Master lifecycle: background persistence, idle timeout, clean shutdown via `-O exit`.
  - Median latency of 100 sequential execs drops from ~130 ms (one handshake each) to ~24 ms (a single handshake).
  - Limitations: window changes and signals are not forwarded through the master, `-proxy-jump` is incompatible, Windows is not supported.

### Fixed
- Client half-closes the channel on the truncated-transfer verdict.

### Performance
- Server pools exec stdout/stderr read buffers.

## [0.1.20] - 2026-09-30

### Added
- Key-controlled QUIC bulk-transfer tuning on client and server: `-initial-packet-size`, `-stream-rx-mb`, `-conn-rx-mb`.

### Fixed
- Bounded the post-exit-status PTY drain with FIN and a grace window (PTY Ctrl+D hang).

## [0.1.19] - 2026-09-30

### Changed
- quic-go upgraded from v0.49.0 to v0.63.0 and ported to the new `http3` raw-connection API; release builds use upstream quic-go v0.63.0.

### Fixed
- Dataplane: `WriteData` no longer counts frame-header bytes as stream data.

### Added
- Go wire reference dumper for browser-client test vectors.

## [0.1.18] - 2026-09-30

### Fixed
- The HTTP/3 datagram layer no longer steals ssh3 datagrams.
- The stream hijacker waits for conversation registration.

## [0.1.17] - 2026-09-29

### Changed
- quic-go upgraded from v0.40.1 to v0.59.1, ported to the new `http3` client API.

### Performance
- Zero-copy channel writes: `WriteData` marshals only the frame header.

## [0.1.16] - 2026-09-29

### Added
- Profiling groundwork and the SSH2-vs-SSH3 benchmark suite.

## [0.1.15] - 2026-09-29

### Changed
- Internal refactor: session setup and pumping extracted over arbitrary streams (`io.ReadWriteCloser`).

## [0.1.14] - 2026-09-28

### Added
- File-transfer operand form `user@host:port/url_path:remote_path`.

### Fixed
- The server never truncates command output at session teardown.
- The client keeps reading output after the exit status arrives.

## [0.1.13] - 2026-09-28

### Added
- **File transfer** (`ssh3 -f`) over a dedicated SFTP channel: recursive `-r`, `--continue` resume of interrupted transfers, and `--checksum` SHA-256 verification. The server serves SFTP jailed to the session user's home directory; created files belong to that user.

### Fixed
- The transfer client builds on non-Linux targets.

## [0.1.12] - 2026-09-28

### Added
- `SSH3_USER_HOME` environment override when resolving the session home directory.

### Fixed
- The client waits for the stdin pump before declaring a truncated transfer.

## [0.1.11] - 2026-09-28

### Fixed
- Exit-status delivery hardening for PTY sessions: the real exit status is reported even with pending stdin; the server flushes the exit status before channel teardown; a non-zero exit code is returned when the remote command stops consuming stdin early; signal-killed remote commands yield exit code 255 instead of a panic.
- A clean error is returned instead of a panic on an unreadable private key file.
- Restored the vendored Rust `h3` shim after a vendor sync.

## [0.1.10] - 2026-09-27

### Fixed
- The client half-closes the channel send side on stdin EOF so remote commands terminate.

## [0.1.9] - 2026-09-27

### Added
- Trilingual README (English, Russian, German) with fork documentation.
- CI: Windows client artifacts on every push to `main`; tests run on pushes to `main`.

### Changed
- The shipped systemd unit follows OpenSSH parity: no sandbox directives, `KillMode=process` (active sessions survive daemon restarts; `sudo` inside a session regains full root capabilities).
- Apache-2.0 SPDX headers added to fork-touched files.

## [0.1.8] - 2026-09-26

### Added
- First fork release.
- **Windows client as a first-class citizen:** the Go client compiles for Windows and supports interactive PTY sessions — VT input/output, UTF-8 console code page, real console size, `SIGINT`/`SIGTERM` forwarding, and an 80x24 PTY fallback when the console size cannot be queried.
- Login statistics banner (uptime, load, memory, disk) before the interactive shell prompt.
- Locale forwarding: the server passes `LANG`/`LC_*` from its environment to user shells.
- goreleaser v2 release pipeline: per-tag release archives and a key-only `.deb` package (password authentication compiled out with `-tags disable_password_auth`).
