# CTO Task: Bring SSH3 to OpenSSH (SSHv2) parity

> Task brief for an autonomous engineering agent working in this repository.
> Fork lineage: `nagual2/ssh3-go` (renamed from nagual2/ssh3, 2026-10-05) ← `MatiasHiltunen/ssh3` (+13 commits, Rust rewrite) ← upstream `francoismichel/ssh3` (dormant since 2024-09-04, HEAD `5b4b242`).

## 1. Mission

Turn this SSH3 implementation into a transport that can be used as a **daily driver on private infrastructure** and, eventually, as a credible alternative to OpenSSH. Work proceeds in stages; each stage is independently shippable. Do not start a later stage before the previous one is green.

## 2. Current state (verified 2026-09-24)

What already works (do not re-litigate, build on it):

- Go client/server (`cmd/ssh3`, `cmd/ssh3-server`): pubkey auth (ed25519/P-256/RSA), shell, exec, PTY, OIDC, agent forwarding, TCP/UDP forwarding CLI, proxy jump, Let's Encrypt automation.
- Rust workspace (`crates/`): protocol core, QUIC/H3 bootstrap, auth, client+server binaries, real-binary Rust↔Go interop test suite (`cargo test -p ssh3-client`).
- `vendor/h3` is a **deliberate** `[patch.crates-io]` shim for `:protocol=ssh3` extended CONNECT; verified byte-identical to hyperium/h3 v0.0.8 except the shim. Do not swap it for upstream h3 until datagram/extended-CONNECT support lands upstream.
- Security audit of the full delta vs upstream came back clean (static review of all `unsafe`/`exec`/network/file access points, supply-chain check of go.mod/go.sum/Cargo.lock — no git deps, all crates.io).
- LAN benchmark (512 MiB random, WSL client → Atom x5-Z8350 server, USB btrfs destination): SSH3 push ≈ 28.5 MB/s, pull ≈ 24 MB/s; scp baseline ≈ 42.5 MB/s. Single QUIC stream, userspace crypto on a CPU without AES-NI.

Build notes (reproduce before hacking):

```bash
# Go: vendor/ is a synced Go module tree since 2026-09-27 — plain
# `go build ./...` / `go test ./...` work; -mod=mod is no longer needed.
# TRAP: `go mod vendor` deletes vendor/h3 (see §2 shim note above).
# If nuked, restore with: git checkout dba4017 -- vendor/h3
CGO_ENABLED=0 go build -tags disable_password_auth -o bin/ssh3 ./cmd/ssh3
CGO_ENABLED=0 go build -tags disable_password_auth -o bin/ssh3-server ./cmd/ssh3-server
# Windows client (host build or cross): bin/ is gitignored, live-tested 2026-09-30
CGO_ENABLED=0 GOOS=windows go build -tags disable_password_auth -ldflags "-s -w" -o bin/ssh3.exe ./cmd/ssh3
# Server needs a writable log target: env SSH3_LOG_FILE=/tmp/ssh3.log (default /var/log/ssh3.log fails unprivileged)
```

## 3. Ground rules

1. Tests first (TDD). The Rust interop suite is the primary verification path; add a regression test for every bug fix below.
2. Small PRs, conventional commits, one concern per PR.
3. No new dependencies without justification in the PR description; Go deps must stay in go.mod/go.sum, Rust in Cargo.lock (registry sources only — no git dependencies).
4. No telemetry, no network calls outside the SSH3 protocol semantics.
5. Prefer file-backed secrets (`--password-file`, `--bearer-token-file`) over CLI args in new code.
6. Both implementations must keep building after every PR: Go with the flags above, Rust with `cargo build --workspace`.

## 4. Stage 1 — Reliability (P0, do first)

Four bugs reproduced in a real transfer session; bug 5 found 2026-09-30. Each: root cause → fix → regression test.

| # | Bug | Evidence / entry points | Acceptance |
|---|-----|------------------------|------------|
| 1 | Client never signals EOF to the server after local stdin is exhausted. Remote `cat > file` hangs forever; pipelines cannot terminate. | stdin pump goroutine in `client/client.go` (~line 676-692): on `os.Stdin.Read` EOF it just returns; no fin/half-close is sent on the channel | `cat bigfile \| ssh3-client URL "cat > out"` terminates by itself, sha256(out) == sha256(bigfile); interop test covers stdin EOF |
| 2 | Server panics when a client dies mid-transfer: `panic` in `util.VarIntLen` (`util/wire.go:198`) via `message.ExitStatusRequest.Length` (`message/channel_request.go:443`) from `execCmdInBackground` (`cmd/ssh3-server.go:411`). Negative exit status is not length-safe. | kill -9 the client during an active exec; server process dies | server survives abrupt client disconnects; negative/overflowing exit statuses are encoded safely; unit test for `VarIntLen`/`ExitStatusRequest` edge values; fuzz target for message length encoding |
| 3 | Client exits rc=0 even when the transfer was silently truncated (remote `head -c` exited early, channel closed, client reported success) | exec result handling in `client/client.go` and `cmd/ssh3.go` | if the remote side ends early or reports an error, client exits non-zero with a clear stderr message; test with a remote command that exits before consuming all input |
| 4 | Client SIGSEGVs (nil pointer in `jwt.NewWithClaims` ← `BuildJWTBearerToken`, `client_auth.go:331` ← `auth/plugins/pubkey_authentication/client/privkey_auth.go:181`) when the `--privkey` file does not exist | run client with a bogus `--privkey` path | clean error message, exit code 2; nil-key path covered by a unit test |
| 5 | **(2026-09-30, P0, fixed 2026-09-30)** Interactive PTY session: Ctrl+D (0x04 typed in a raw-mode console) makes the remote shell exit, but the client process never terminates. Client 0.1.18/0.1.19; verified NOT a server-build issue (hang reproduces against both release and HEAD servers on LAN latency; clean on loopback latency). **Full brief: `docs/BUG-PTY-CTRLD-HANG.md`.** | Post-ExitStatus drain loop `client/session_pump.go:141-155` waits for a server-side channel EOF the server only sends after the client's send half closes; raw console stdin never EOFs. PTY wiring: `client/client.go:600-648`. Fixed client-side: on ExitStatus a PTY session FINs its send half and bounds the drain with `ptyExitGrace` + `CancelRead` (`client/session_pump.go`) | `printf '\x04'` into a PTY session via `script -qc` terminates the client on its own against a LAN-latency server (see brief §6); exec-mode EOF/truncation semantics (bugs 1/3) unchanged; regression tests `TestPumpPtyExitDrainIsBounded`/`TestPumpPtyExitHalfClosesChannel` |

Definition of done for Stage 1: full `cargo test` + Go test suite green; the four scenarios above covered by automated tests; manual 512 MiB transfer stress (repeat 10×, including abrupt kills) leaves the server alive and all completed transfers bit-identical.

## 5. Stage 2 — Real file transfer (P1)

Today "copy" is a stdin-pipe trick. Implement a proper file transfer channel:

1. An SFTP-like subsystem multiplexed over an SSH3 channel (reuse the existing channel/request machinery; evaluate embedding a Go SFTP server implementation such as `github.com/pkg/sftp` over an `io.ReadWriteCloser` adapter to the channel — justify the dependency).
2. Client UX: `ssh3 -f <local> <user@host:path>` upload/download, directory recursion, resume (`--continue`), preserve mode/timestamps (best effort), progress output, `--checksum` verification mode.
3. Integrity by default: final hash comparison for transfers above a size threshold, mismatch → non-zero exit.
4. Optional: expose the same over the Rust client CLI once the channel protocol is settled (Rust first as a library consumer, CLI flags second).

Acceptance: copy a 1 GiB tree with subdirectories over a lossy link (simulate with `tc netem` 2% loss), resume works, checksums match, no server panics under interruption.

## 6. Stage 3 — Daily-driver features (P2)

Status 2026-10-02 (v0.1.22 release):

1. Host key verification story: TOFU mode writing QUIC/TLS certificates to `~/.ssh3/known_hosts` (format already parsed by the client — `ssh3.ParseKnownHosts`), `strict` and `--insecure` explicitly logged as dangerous. Pin by certificate fingerprint, support SSHFP-like DNS records as stretch goal. — **done 2026-10-04 except SSHFP** (`StrictHostKeyChecking` ask|yes|accept-new|no with OpenSSH-style source priority; pins compared on the server certificate, changed fingerprint refuses with both fingerprints; SSHFP DNS remains a stretch goal)
2. Rust CLI parity with Go: port forwarding flags (TCP/UDP direct + reverse), proxy jump, secret URL path. — **open (Rust track deferred beyond v0.1.22)**
3. `~/.ssh/config`: extend parsing to `ProxyJump`, `ForwardAgent`, `ServerAliveInterval`, `Include`, `Match` (currently only Hostname/User/Port/IdentityFile). — **done 2026-10-04** (ProxyJump honored as UDPProxyJump alias; Include resolves via ssh_config v1.2.0; Match resolved by the `client/config/matchcfg` pre-parser — all/final/host/originalhost/user/localuser/exec; `Match` inside `Include`d files is not resolved)
4. Keepalives and connection migration sanity: NAT rebinding should not kill a session (QUIC gives this for free only if transport config enables migration — verify and test). — **done 2026-10-02 by inspection** (quic-go v0.63 always enables active migration — the Config knob was removed; keepalive default 1s, overridable via ServerAliveInterval)
5. Server ops: graceful shutdown on SIGTERM (finish active channels, configurable drain), systemd hardening docs (unit example with `ProtectSystem`, `PrivateTmp`), log to journald-friendly output. — **done 2026-10-02** (SIGTERM drain via `SSH3_SHUTDOWN_DRAIN`, default 5s; JSON-to-journald under systemd; unit deliberately keeps OpenSSH parity without Protect* — see packaging/ssh3-server.service comment)

Additional v0.1.22 stage-3 items beyond this list:

- Password backend compiled into the amd64 release server (off by default; `-enable-password-login` / `SSH3_ENABLE_PASSWORD_LOGIN=1`) — release packaging item, pairs with Stage 4.2 below.
- `-N` (no-session forwarding-only mode).
- Control master: window-change and signal relay for pty slaves (new WINDOW_CHANGE/SIGNAL control frames).
- Control master + proxy-jump is now an explicit client error (was a silent bypass).
- Transfer bug 6 fixed: server-absolute remote paths honored by the sftp jail; missing remote parents auto-created.

Reverse forwarding (`-R`) — **done 2026-10-04**, with one deviation from the sketch below: the request travels as versioned channel data on a dedicated `reverse-forward` channel instead of a new conversation-level message type, because `message.ParseMessage` panics on unknown type IDs while unknown channel data is rejected cleanly by old peers (verified live against a v0.1.22 server and an old client against the new server). The server binds TCP/UDP (loopback default, wide binds warn) and opens `forwarded-tcp`/`forwarded-udp` channels carrying the target in the additional bytes; the client validates targets against the `-R` list and bridges to local endpoints. Two reliability blockers were fixed on the way: server conversation context now derives from the QUIC connection (was `context.Background()` — handlers hung in `AcceptChannel` forever), and `Client.Close()` closes the QUIC connection. Deferred remainder — **done 2026-10-05**: GatewayPorts policy (`-gateway-ports no|clientspecified|yes` / `SSH3_GATEWAY_PORTS`, default `no` forces client-requested non-loopback binds back to the loopback, sshd_config semantics), per-user bind limits (`-max-reverse-forwards` / `SSH3_MAX_REVERSE_FORWARDS`, default 10, refused with a readable error), and the UDP truncation fix (datagrams read whole; over the QUIC datagram limit of the path they are dropped with an explicit warning instead of being silently cut at a 1500-byte read). Unit tests `TestParseGatewayPorts*`/`TestResolveReverseForwardBind`/`TestReverseForwardBindLimit`. Original sketch kept for reference: (1) new conversation-level control message `REQUEST_REVERSE_FORWARD {bind_addr, bind_port, target_addr, proto: tcp|udp}` sent by the client on the control stream; (2) server binds and, per accepted conn/datagram, opens a `forwarded-tcp`/`forwarded-udp` channel whose additional bytes carry the client-side target; (3) client channel manager learns to accept these types and bridges to local targets; (4) additive wire change, old clients reject unknown channel types gracefully — verify before shipping.

## 6a. Stage 1.5 — Data-path performance — P1, pilot-prioritized 2026-09-29

Close the loopback bulk-transfer gap exposed by the R3 benchmark
(docs/BENCH-2026-09-29.md): SSH3 130 MB/s vs OpenSSH 365–488 MB/s (×2.8–3.7).

Diagnosis constraints (verified 2026-09-29): AES-NI is already in use (Go
crypto/aes hardware path on the bench CPU) — the cost is the userspace QUIC
packet pipeline (per-packet syscalls, buffer copies, single connection loop),
not the AES math. kTLS/kernel crypto is impossible for QUIC by protocol design.
quic-go is pinned at v0.40.1 (2024-01); QUIC transport tuning is absent.

Increments (measurement-driven; re-run B1/B2 after each):

| # | Increment | Acceptance |
|---|-----------|------------|
| 1 | Profile harness: pprof hooks (opt-in flag) on client/server; quic-go-only microbench to separate transport ceiling from ssh3-layer overhead | hotspot profile committed to docs/ |
| 2 | Transport tuning: GSO verification/activation, datagram size, flow-control windows and buffer sizes for bulk | B1 loopback improvement, each knob measured separately |
| 3 | quic-go upgrade to current release, re-basing the deliberate vendor/h3 `:protocol=ssh3` shim | full Go + Rust interop suites green; B1/B2 re-measured |
| 4 | (conditional on profile) ssh3-layer copies/buffering fixes | B1 loopback ≥ 250 MB/s; LAN within 15% of scp |

Non-goal: kernel TLS / crypto offload (impossible for QUIC). For no-AES-NI
targets (Atom), evaluate ChaCha20-Poly1305 cipher agreement instead.

**maintainer decision 2026-10-03:** the ≥250 MB/s throughput target is no longer
chased — it is unreachable by small means against quic-go's userspace pipeline
and OpenSSH's kernel-adjacent path. Priorities are functionality, reliability
and minimal command latency (the fork is used as an MCP transport). The bulk
throughput gap is the reason `ssh3-c` (C17 rewrite) exists. Delivered
instead (2026-10-04): exec-latency pass — server teardown yield removed, master
wait poll tightened, cold one-shot exec median 140→26 ms on loopback
(`bench/exec-latency.sh`).

## 6b. Stage 3.5 — Connection multiplexing (ControlMaster) — P2, pilot-prioritized 2026-09-28

ssh2-style ControlMaster for the Go client: one authenticated QUIC connection shared by many
CLI invocations through a Unix-domain-socket control channel. Client-only; works against a
stock ssh3-server.

Design (verified against the code on 2026-09-28):

| # | Element | Decision |
|---|---------|----------|
| 1 | Master | First invocation with `ControlMaster=auto/yes` + `ControlPath` performs connect+auth, then serves a UDS socket instead of running one session; `ControlPersist` keeps it in the background with an idle timeout |
| 2 | Mux protocol | Own minimal versioned framing (not OpenSSH-wire compatible): `HELLO{v}`, `OPEN_SESSION{argv,env,pty,agent}`, `OPEN_FORWARD_TCP/UDP`, `EXIT`; UDS perms 0600, path `~/.ssh3/cm-<user>@<host>:<port>`; SO_PEERCRED uid check on Linux |
| 3 | Slave | Later invocations connect to the UDS, request a session; master opens a channel via `Client.OpenChannel("session", …)` on the live connection and bridges bytes both ways |
| 4 | Refactor | Extract `RunSession`'s stdio pumping into a variant over `io.ReadWriteCloser` so the master can serve slave sessions without owning process stdio |
| 5 | Keepalive | Master-owned keepalives against the QUIC idle timeout; connection migration is a free win |
| 6 | Portability | Windows AF_UNIX works but is a separate test track; Rust client adopts the same protocol later (parity, non-blocking) |

Increments (TDD, each independently shippable):

| # | Increment | Acceptance |
|---|-----------|------------|
| 1 | Session pump refactor over `io.ReadWriteCloser` (**done 2026-09-30**: `client/session.go` — `SessionSpec`/`PtySpec`, `OpenSession`, `PumpSession`; RunSession keeps console concerns; suites green, live exec/pty smoke byte-exact) | no behavior change; existing suites green |
| 2 | Mux framing codec (**done 2026-10-01**: `client/cm` — versioned magic header, strict decoders; 15 unit tests: round-trips, version mismatch, garbage/truncation) | unit tests: round-trip, version mismatch, garbage input |
| 3 | Master + slave session bridging (**done 2026-10-01**: `client/master.go`/`slave.go` — UDS master serves HELLO/OPEN_SESSION/ATTACH/EXIT, pump relays io+stderr attachments, exit status returns on the control conn; integration test `TestControlMasterSlaveSessionIntegration` gated by `SSH3_CM_INTEGRATION=1`: exec output, exit codes, byte-exact stdin through one master) | integration test on loopback: slave session executes through master |
| 4 | `ControlPersist`, idle timeout, `-O exit` control ops (**done 2026-10-01**: `MasterOptions.IdleTimeout` — activity-aware watchdog, exits only with no running sessions; `ExitMaster` (-O exit); clean teardown removes the socket file; gated integration subtests) | master survives client exit; clean teardown |
| 5 | Forwards through master (**done 2026-10-01**: `OpenMasterForwardTCP/UDP` — master listens locally and relays through the shared connection, bound addr returned; agent forwarding now passes through, bridged to the master's `SSH_AUTH_SOCK` = the same socket for a same-user slave; integration subtests TCP+UDP echo round-trips) | local TCP/UDP forward via slave request works |
| 6 | Config plumbing (`-o ControlMaster/ControlPath/ControlPersist`) (**done 2026-10-01**: Go-flag style `-control-master no|yes|auto`, `-control-path` (default `~/.ssh3/cm-<user>@<host>:<port>`, 0600), `-control-persist no|yes|<seconds>`, `-O exit`; detached master = re-exec with `SSH3_CM_DAEMON=1`; slave console raw mode + pty pass-through; documented in README.md/ru/de) | flags documented in all READMEs |

**Stage 3.5 DoD: achieved 2026-10-01** — 100 sequential `ssh3 host true` with a master:
**1 handshake total**, per-exec median **24 ms = 17%** of the cold path (139 ms;
acceptance <=30%); without a master: 100 handshakes. Two server-side fixes were
required for multiplexed conversations (both wire-compatible): CONNECT `mux=1`
marker marks the conversation (`Conversation.SetMultiplexed`) so the per-session
`DrainAndClose` teardown is skipped, and the 100 ms packer-yield sleep before the
session channel close is gated on `!IsMultiplexed` (it added a flat 100 ms to
every slave session).

Definition of done: 100 sequential `ssh3 host true` — with a master: 1 handshake total and
per-exec time ≤ 30% of the cold path; without: 100 handshakes. No new dependencies.

## 7. Stage 4 — Hardening & ecosystem (P3)

1. External security review checklist — **done 2026-10-05, except the external review itself (that is ROADMAP R2, on the frozen code)**:
   - **MaxStartups analog**: conversations between the CONNECT and the auth verdict hold one of `-max-unauth-conversations` / `SSH3_MAX_UNAUTH_CONVERSATIONS` slots (default 100); over the cap the request is refused with 503 before any identity work (`server_auth/dos_guard.go`, TDD).
   - **Brute-force lockout**: failed password authentications book per user, `-max-password-failures` (default 10) locks the account out of the password backend for `-password-lockout-seconds` (default 60, refused with 429 without touching shadow), success clears, lockout is per user (`server_auth/dos_guard.go`, TDD).
   - **Token replay (jti binding) proven**: the pubkey verifier requires the jti claim to equal the base64 conversation ID; a regression test mints a valid ed25519 token for conversation A and verifies acceptance on A and refusal on B (and on a mismatching jti) (`server_plugin_test.go`). The OIDC path binds the conversation via the nonce check (`auth/oidc`).
   - **Header injection in CONNECT: verified, no vector** — the request-controlled values (URL user/query user, user-agent) never reach response headers: the Server header is a fixed version string, `http.Error` writes the body only, h3 field parsing rejects control characters on the wire, and a malformed username fails `unix_util.GetUser` before any path use. The residual log-forging risk is neutralized by the JSON journald logging.
   - **QUIC amplification: verified bounded** — quic-go enforces the RFC 9000 section 8.1 3× anti-amplification limit with no configuration knob to disable it, and the auth phase rejects 0-RTT data with 425 before identity work (`server_auth/auth.go`), so early-data replay cannot carry authentication.
2. PAM-based password auth (replace direct shadow reading; enables non-root servers and 2FA).
3. FIDO2/hardware keys (`ed25519-sk` semantics), SSH certificate authority model.
4. Packaging: distro packages (deb/rpm), release pipeline without third-party toolchain downloads (current upstream release CI pulls musl toolchain from musl.cc — replace with reproducible local builds).
5. Docs: deployment guide (self-signed + Let's Encrypt paths), threat model document.
6. Terminal parity (EncodedTerminalModes, RequestTTY, Windows resize, exit-signal, EscapeChar) — выделено в §7b, 2026-10-05.

## 7a. Кросс-имплементационная матрица с ssh3-c: Go-сторона — P2, добавлено 2026-10-05

Контекст. Матрица C-порта (`ssh3-c/interop/run-h3.sh`, 23 сценария) гоняет
Go-сторону через харнес `s3interop` — модуль `ssh3-c/interop/quic-go/`
(отдельный go.mod `module s3interop`, только quic-go, сам форк он не импортирует).
В харнесе два пробела: нет UDP-форвардинга и нет pty/resize, поэтому направления
«Go-клиент → C-сервер» по этим фичам не покрыты. У форка собственный CLI умеет и то
и другое: `-forward-udp` (cmd/ssh3.go:387), `Client.ForwardUDP` (client/client.go:462),
forced-pty + SIGWINCH (cmd/forced_pty.go, cmd/window_change_unix.go); свои B10/B11 в
docs/FORWARDING-TESTPLAN.md — PASS, но только против Go-сервера. Пилот утвердил
пункты 7a.1–7a.2 (исполнение отдельной сессией); 7a.3 — записанная альтернатива, отклонена.

### 7a.1 `-fwd-udp` в харнесе + сценарий 24

- Файл: `ssh3-c/interop/quic-go/main.go`. Режим `-h3-forward-client` сегодня
  умеет только `-fwd-tcp localport/remoteip@remoteport`; добавить симметричный
  `-fwd-udp localport/remoteip@remoteport`: локальный UDP listener, датаграммы →
  датаграммы канала к C-серверу, обратно — эхо-сверка.
- Wire со стороны C-сервера: direct-udp (датаграммы с префиксом
  controlStreamID|channelID); эталон формата — C-клиент
  `ssh3-c/interop/interop_client.c` (режим `-F udp=@port`).
- Приёмка: сценарий 24 в `interop/run-h3.sh` («quic-go forward-client -fwd-udp →
  C server», 20 датаграмм с эхо-сверкой — как C-сценарий 13), полный прогон матрицы
  завершается `INTEROP-MATRIX OK`, счётчик сценариев 24.
  — **done 2026-10-05** (`s3UDPForwarder` в main.go: один direct-udp канал на
  локальный адрес-источник, семантика форка `ForwardUDP`; `s3DialAndConnect` получил
  флаг датаграмм; ран сам драйвит 20 датаграмм 1024 B с эхо-сверкой и вердиктом
  `INTEROP-GO-FWD-UDP-OK count=20`; сценарий 24 в run-h3.sh; матрица 25/25 PASS).

### 7a.2 pty/resize в харнесе + сценарий 25

- Зависимость: добавить `github.com/creack/pty` в go.mod харнеса (в форке пин v1.1.18 —
  версий не разводить).
- Режим: `-h3-session-client -pty` — программная аллокация pty-пары (без живого
  терминала), pty-реквест + exec на C-сервере, вывод через pty байт-сверяется; затем
  resize (новый размер пары → SIGWINCH-релей шлёт WindowChange) и проверка, что
  C-сервер применил новую геометрию (эхо-маркер после ресайза).
- Эталоны форка: cmd/forced_pty.go, cmd/window_change_unix.go, client/client.go:60
  (sendWindowChangeRequest).
- Приёмка: сценарий 25 в run-h3.sh («quic-go pty-client → C server, exec через pty +
  resize»), полный прогон матрицы OK, счётчик сценариев 25.
  — **done 2026-10-05** (`pty_unix.go`/`pty_other.go` с билд-тегами, creack/pty
  v1.1.18; пара 80x24 → pty-req + exec `stty size; sleep 1; stty size`, после первой
  геометрии `Setsize(40x100)` + SIGWINCH себе → релей шлёт window-change; вердикт
  `INTEROP-GO-PTY-OK resize=40x100` при порядке маркеров `24 80` → `40 100`;
  `s3SessionExecRead` переведён на callback `onConfirmed` — kill-логика переехала в
  вызывающего; сценарий 25 в run-h3.sh; матрица 25/25 PASS).

### 7a.3 Записанная альтернатива (отклонена)

Считать собственное покрытие форка достаточным (B10/B11 PASS против Go-сервера) и не
расширять кросс-матрицу. Отклонено Пилотом 2026-10-05: асимметрию матрицы C-порта
по UDP-форвардингу и pty закрывают пункты 7a.1–7a.2.

## 7b. Terminal parity — P2, добавлено 2026-10-05

TTY/терминальный паритет с OpenSSH. Базовый PTY (openpty, resize, сигналы) приехал
готовым из апстрима и в стадиях не планировался; пробелы выявлены ревизией паритета
2026-10-05. Порядок внутри стадии: 1 → 2 → 3 → 4, EscapeChar — последним.

| # | Пункт | Приёмка |
|---|-------|---------|
| 1 | Применять `EncodedTerminalModes` — **done 2026-10-05** (пакет `util/ttymodes`: парсер RFC 4254 §8 + termios-маппинг, TDD 8 тестов; клиент шлёт локальные termios в pty-реквесте, сервер применяет через TCSETS на слейв; неизвестные opcode пропускаются, кривой payload логируется без обрыва сессии). Живая проверка: `stty intr '^k'` под script-pty → удалённый `stty -a` показывает `intr = ^K` |
| 2 | `RequestTTY` — **done 2026-10-05** (`-T`, `-o RequestTTY=auto|no|yes|force`, ключ в `~/.ssh/config`, приоритет: CLI > -o > config > auto; `-t`+`-T` взаимно исключаются; RunSession получил параметр политики). Живая проверка: `-T` интерактивно → remote `tty` = not a tty; `-o RequestTTY=force` без локального tty → pty+exec отдаёт `/dev/pts/N` |
| 3 | Windows: форвард ресайза консоли — **код готов 2026-10-05** (поллер геометрии `client/winsize.PollChanges` вместо `ReadConsoleInput` — дренаж input-событий крал бы нажатия у stdin-насоса; `cmd/window_change_windows.go` и `client/signals_windows.go` больше не стабы; `sendForcedPtyWindowChange` вынесен в платформо-нейтральный `cmd/window_change.go`). Windows-клиент и unix-сборка зелёные; живая приёмка (Win11 VM): ресайз консоли в forced-pty сессии доходит до удалённого `stty size` — **ожидает VM** |
| 4 | exit-signal вместо 255 — **done 2026-10-05** (сервер: `signalExit` поверх WaitStatus → `98 exit-signal` с wire-именем и core-dump; клиент: `exitCodeForExitSignal` = 128+signum, неизвестное имя → 255). Живая проверка: `kill -SEGV $$` → rc 139, `kill -TERM $$` → rc 143, `true` → rc 0; совместимость с v0.1.25 не ломается — pump и на старых клиентах трактует exit-signal как терминальное событие |
| 5 | EscapeChar — **done 2026-10-05** (`client/escape.go` — конечный автомат фильтра stdin-насоса, TDD 11 тестов, устойчив к разрыву последовательности между чтениями; `~.` — чистый teardown с rc 255, `~^Z` — restore терминала + SIGTSTP + raw на resume (unix), `~~` — литеральный `~`, неизвестное — литерально; `-o EscapeChar=<символ|^X|none>` + ключ в `~/.ssh/config`, дефолт `~`; фильтр активен только в pty-сессиях — exec-трафик байт-точен). Живая проверка: `~.` → rc 255; текст с `~` не в начале строки проходит; `EscapeChar=none` отключает |

## 7c. CLI-parity with OpenSSH (ssh2) — P1, added 2026-10-17

Canon decision (the maintainer, 2026-10-17): **where the functionality matches, the launch keys follow ssh(1)/sshd(8)** — not the fork's own shapes. The full deviation matrix of both implementations (this fork and `ssh3-c`) against ssh(1)/sshd(8), including the hard conflicts, lives in `the ssh3-c docs` (mirrored as P8(1a)–(1c) of the ssh3-c plan). Rule of the wave: old fork forms stay as deprecated aliases — live installs and existing scripts keep working.

| # | Item (Go side) | From → to (ssh2 canon) | Acceptance |
|---|----------------|------------------------|------------|
| 1 | Hard conflict `-f` | ssh2 `-f` = background the process to the background; the transfer mode moves to a new home (a maintainer decision per key: subcommand or long form) | transfer keeps working through the new/aliased form; `ssh3 -f` either means background per ssh(1) or is removed, decided and documented |
| 2 | Identity flag | `-privkey` → add `-i` (sshd/ssh canon; `ssh3-c` already has `-i`) | `-i key` authenticates exactly like `-privkey key` |
| 3 | Version flag | `-version` → add `-V` (client; server too) | `-V` prints the version and exits 0 |
| 4 | Agent forwarding | `-forward-agent` → add `-A` (ssh(1); `-X` stays reserved for X11 semantics) | `-A` bridges the agent like the current `-forward-agent` |
| 5 | Proxy jump | `-proxy-jump URL` → add `-J destination` (ssh(1) chains via commas) | `-J user@host:port` equal to `-proxy-jump` |
| 6 | Local forwards | `-forward-tcp/-forward-udp localport/remoteip@remoteport` → add `-L [bind:]port:host:hostport` (ssh(1) shape; UDP — documented extension); verify `-R` against the ssh(1) shape | ssh2-shaped specs accepted end-to-end; old specs still parse |
| 7 | Control master shapes | `-control-master/-control-path/-control-persist` → add `-M`, `-S path`, `-o ControlMaster=…/ControlPath=…/ControlPersist=…` | ssh2-shaped mux invocation works end to end |
| 8 | Missing ssh2 keys | add `-q`, `-4/-6`; extend `-o` (Port, User, IdentityFile, LocalForward, RemoteForward, DynamicForward, ProxyJump — EscapeChar is done §7b) | each key unit-tested; precedence CLI > `-o` > `~/.ssh/config` |
| 9 | Server host key/cert | `-key` → add `-h` (sshd canon), `-cert` → add `-c` (coincides with sshd `-c` host certificate) | `-h priv.key -c cert.pem` starts the daemon |
| 10 | Server port | `-bind [::]:443` → add `-p port` (sshd canon; the bind address stays project-specific — QUIC needs it) | `-p 8443` serves on :8443 |
| 11 | Behavioral timeouts | idle: `-max-idle-timeout` default 30 s → the ssh2 canon "do not kill the idle" (sshd `ClientAliveInterval=0`): a large default (day scale) **or** ClientAliveInterval-style keepalive probes (an interval + a count, the drop after CountMax missed probes); handshake: 5 s (the quic-go default) → the `LoginGraceTime` scale (120 s); client setup: 5 s → `ConnectTimeout`-unset semantics. quic-go does not accept a zero `MaxIdleTimeout` (0 → its 30 s default) — a large value or probe-keepalive is the only path; the ssh3-c values (60 s idle, 30 s handshake/setup) align in the same wave (the ssh3-c plan P8(1d)) | an idle interactive session survives ≥24 h like an ssh2 session; if the probe form is chosen — the drop happens only after CountMax missed probes |
| 12 | Reverse-forward cap | `-max-reverse-forwards` default 10 per user vs ssh3-c `0` (no cap; a per-conversation budget of 10) — a maintainer decision which default is canonical, then both align (no sshd equivalent: PermitListen only filters binds) | the default matches the decision; the interop matrix covers both values |
| 13 | Password default — the sshd canon | the maintainer's decision 2026-10-17 ("as in ssh2"): keep `enablePasswordLogin := true` on builds with the backend (already the case — the `PasswordAuthentication yes` analog); add the sshd pair `PermitRootLogin prohibit-password`: root via password is always refused, root via a key is allowed (no root gate exists today); the deb env-template is already correct in the repo — the stale deployed copy on the target host was corrected 2026-10-17; the brute-force barrier stays (`-max-password-failures` 10 / `-password-lockout-seconds` 60) | a fresh install accepts the user's system password like sshd does; root+password is refused, root+key works; the deployed env file matches the code |

DoD: every ssh2-shaped invocation of the table works against the fork binaries; every old invocation keeps working through the alias layer (regression-tested); `go test ./...` green; README en/ru/de documents the ssh2 forms as primary, the fork forms as aliases.

Status 2026-10-17 (implementation session, Go side): rows 1–11 and 13 **done**, row 12 **open** (maintainer decision pending).

- Row 1 — **done 2026-10-17**: the transfer mode moved to the long form `-transfer`; `-f` is retired with a loud error pointing at `-transfer` (the "removed, decided and documented" variant — the ssh2 background semantics stays a separate future increment, since real `-f` needs auth-before-background). Documented in README en/ru/de.
- Row 2 — **done**: `-i` routes through the privkey plugin's `IdentityFile` option.
- Row 3 — **done**: `-V` on the client and the server (alias of `-version`).
- Row 4 — **done**: `-A` (alias of `-forward-agent`).
- Row 5 — **done**: `-J destination[,destination...]` — comma chains are real multi-hop: each hop tunnels UDP towards the next, the last towards the destination; `-proxy-jump` stays as the single-hop alias. `-p`/`-o Port`/`-o User` deliberately do not apply to hops (each `-J` destination carries its own user@host).
- Row 6 — **done**: `-L [bind_address:]port:host:hostport`, repeatable, with the `udp://` prefix as the documented UDP extension; the deprecated `-forward-tcp/-forward-udp` shapes map onto the same forward list (and a parse error there now aborts instead of continuing with nil addresses); `-R` already parsed the ssh(1) TCP shape — pinned by `TestReverseForwardAcceptsSSH2Shape`.
- Row 7 — **done**: `-M`, `-S path`, `-o ControlMaster=/ControlPath=/ControlPersist=`; precedence CLI flag > `-o` > config.
- Row 8 — **done**: `-q`, `-4`/`-6` (family-checked against the resolved peer address), `-o Port/User/IdentityFile/LocalForward/RemoteForward/DynamicForward/ProxyJump`; precedence CLI > `-o` > `~/.ssh/config`.
- Row 9 — **done**: `-h priv.key` / `-c cert.pem`; giving both forms of the same knob is an error, not a silent last-one-wins.
- Row 10 — **done**: `-p port` merges into `-bind` (bracketed IPv6 handled; a bare unbracketed IPv6 `-bind` is refused as ambiguous rather than guessed).
- Row 11 — **done, the large-default variant**: idle 30 s → 24 h on **both** endpoints (QUIC negotiates the smaller of the two, so the client raises its side too; quic-go maps 0 to its 30 s default, so "unset" is expressed as a large value) and handshake 5 s → 120 s (the `LoginGraceTime` scale), client setup included. The probe form was not needed: the client already sends 1 s QUIC keepalives (`ServerAliveInterval`-tunable).
- Row 12 — **open**: Go keeps the default cap of 10 per user (the conservative side) until the maintainer picks the canonical default for both implementations; no code change in this wave.
- Row 13 — **done**: the root gate (`server_auth.PasswordLoginRefused`) refuses root password auth in both Basic-auth handlers before the backend is consulted; the password-on default was already the sshd canon, and the deployed env file was corrected on the target host on 2026-10-17.

DoD verification: `go test ./...` green (WSL, full uncached pass, 13 packages); new tests `cmd/ssh2_parity_test.go` (ssh2 shapes for -L/-J/-o/-p/-mergeBindPort/aliases) and `server_auth/root_gate_test.go`; README en/ru/de rewritten where the old forms were primary; CHANGELOG `Unreleased` entry.

## 8. Non-goals

- Do not chase X11 forwarding or interactive agent features before Stage 3 is done.
- Do not attempt WireGuard/Tailscale-style VPN features.
- Do not break the wire protocol without bumping and documenting a protocol version — interop with the Go implementation must be maintained at every commit.

## 9. Reporting

Every PR states: which stage/task it belongs to, what tests prove it, and any deviations from this brief with rationale. If a task turns out to be infeasible as specified, stop and document why instead of silently shipping something weaker.
