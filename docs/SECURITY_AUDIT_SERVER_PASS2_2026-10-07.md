# Security Audit — ssh3 Go server, deep-dive (pass 2)

**Audit date (UTC):** 2026-10-07
**Audited revision:** `ff5ef776dec9ca40a04d90be79c1b3b9c898f915` (`origin/main`, tag `v0.1.27`)
**Auditor:** engineering agent (report-only engagement; no code was changed)
**Predecessor:** `docs/SECURITY_AUDIT_2026-10-06.md` (pass 1, PR #2), audited `00c2f46` / `v0.1.26`.
**Scope:** the ssh3 **Go server** end to end — `cmd/ssh3-server.go` (accept loop, conversation lifecycle, session exec/PTY/signals, drain/shutdown, logging), `server.go` / `channel.go` / `conversation.go` (channel + request handling, ordering, ID validation, per-conversation limits), `server_auth/` and the auth plugins (pubkey, OIDC/JWT bearer, password backend, unauthenticated cap), `util/unix_util`, `cmd/sftp_subsystem.go` + the new `cmd/internal_sftp.go`, server-side forwarding (`cmd/forward_policy.go`, `cmd/dynamic_forward_server.go`, `cmd/reverse_forward_server.go`), server-side message/util parsing, and the timeout/resource-exhaustion posture.
**Method:** line-by-line source review at the revision above; `git grep` sweeps (panic/recover/dial/chroot/exec/channel types); a diff-level review of the v0.1.26→v0.1.27 remediation series; cheap local dynamic probes with a recovered `go1.26.0` toolchain (read-only, no live attacks, no third-party system contacted).
**Out of scope:** fixing anything (recommendations only); Windows-specific files; packaging/release scripts and CI; `internal/interop` harnesses; the C17 (`ssh3-c`) tree; the internals of the deliberate `vendor/h3` patch (reviewed only where it meets the server boundary); Rust `crates/` beyond the dependency-version check noted below.

> Report-only: **no code was changed anywhere**. Every recommendation below is a proposal.

## Executive summary

- **The pass-1 server findings were all remediated between `v0.1.26` and `v0.1.27`** (commits `9cfd185` F-01, `8dc90cc` F-02, `e61aca0` F-03/F-06/F-08, `8872616` F-04, `9a61107` F-05, `634cd64` panic guards, `8807b43` dependency bumps). Pass 2 re-verified each one against the *fix*, line by line: **F-01, F-02, F-03, F-06, F-07, F-08, F-10, F-11 are genuinely fixed**; **F-04 is fixed for the default mode** (with a documented weaker opt-in mode left in the tree); **F-05 is only partially fixed** (a policy *mechanism* now exists, but it is off by default and does not cover reverse-forward binds); **F-09 (varint encoder panics) and F-12/F-13 remain** as before.
- **The server no longer has a remotely reachable `panic()`.** `util.ParseSSHString` bounds the allocation before `make`, `message.ParseMessage` returns a typed error for unknown type ids, and every peer-facing goroutine that handles channel data now carries a `util.PanicGuard`. The only remaining `panic()` sites reachable in the *server* are the varint encoders (`util/wire.go:148-165`, `:195-203`), which no current call site feeds an out-of-range value. The two remaining `panic("not implemented")` and the OIDC `panic(err)` are client-side paths (`client_auth.go:170`, `auth/plugins/pubkey_authentication/client/pubkey_auth.go:97`, `auth/oidc/openid_connect.go:41`).
- **The strongest new finding (S2-01, Medium) is an allocation knob the F-01 fix left open.** A peer still chooses the `maxPacketSize` its channel advertises, and the server sizes its per-channel read buffers with it (`make([]byte, channel.MaxPacketSize())`), while only clamping it to the new 16 MiB `MaxSSHStringLen`. With quic-go's default of 100 concurrent incoming streams per connection and no application-level cap, one authenticated peer can pin on the order of 100 × 16 MiB of server heap per connection with a few dozen bytes of input per channel — the same class of bug as F-01, one level up.
- **S2-02 (Medium): nothing bounds channels or subsystems per conversation, and the default SFTP mode now forks a process per `sftp` channel.** `cmd/ssh3-server.go:1194-1240` accepts channels in an unbounded loop, `runningSessions` is written at `:1238` and **never pruned anywhere in the tree**, and `cmd/sftp_subsystem.go:110-160` re-execs a (root, then chroot+drop) child for every SFTP channel. One authenticated user can therefore spawn process/fd/memory load proportional to the channels they open; the only backstop is quic-go's stream default.
- **S2-03 (Low): channel-type role inversion.** The server accepts client-opened channels named `forwarded-tcp` / `forwarded-udp` and treats them as a request to dial the target in the header, although those names are declared the *server→client* reverse-forward types (`message/reverse_forward.go:20-21`), and it does *not* recognise the `direct-tcp` / `direct-udp` names its own library emits to request the same thing (`conversation.go:409`, `:424`). The dial is permit-open-gated either way, so this is a role/policy-clarity defect rather than a bypass — but any future policy keyed on channel type would be unsound.
- **S2-04 (Low): `-permit-open` has no `PermitListen` counterpart.** Reverse forwarding still binds client-chosen ports on the server with only the GatewayPorts rewrite and the per-user budget in the way (`cmd/reverse_forward_server.go:187-270`). The pass-1 "verified clean" note on GatewayPorts still holds; the *gap* (no allowlist for binds) is new.
- **Positive results worth keeping:** the auth-gating *order* is now correct and provably so (§ "Auth path, line by line"), the conversation-control-stream ID is validated (`conversation.go:295-301`), the `PanicGuard` placement composes correctly with the conversation-teardown defers (`server.go:306-311`), and the F-04 chroot design really does move confinement into the kernel for the default configuration.

## Pass-1 findings — re-verification at `ff5ef77` (v0.1.27)

Status values: **FIXED** (the reported mechanism is gone), **FIXED-SHALLOW** (the reported symptom is gone but the class survives), **STILL PRESENT**, **CONFIRMED** (pass 1 was right), **CORRECTED** (pass 1 was wrong).

| Pass-1 ID | Pass-1 claim | Status at `ff5ef77` | Evidence |
|---|---|---|---|
| F-01 | `ParseSSHString` allocates from an unbounded peer length | **FIXED** for the reported sink — see S2-01 for the surviving class | `util/wire.go:204-222`: `MaxSSHStringLen = 1<<24` (`:211`) checked *before* `make` (`:216`); `channel.go:176-181` also refuses a peer `maxPacketSize` above the cap. Regression `util/wire_test.go:42-70`, fuzz target `util/fuzz_test.go:12-33`. |
| F-02 | `ParseMessage` panics on an unknown type id | **FIXED** | `message/message.go:213-225` defines `UnknownMessageType`; `:246` returns it instead of `panic("not implemented")`. Tests `message/parse_message_test.go`; fuzz `message/fuzz_test.go:11-29`. |
| F-03 | DoS slot leaks on every successful auth → permanent server-wide 503 | **FIXED** (the arithmetic of the old bug is gone, not just hidden) | `server_auth/auth.go:68-74`: `TryAcquire` now runs *before* conversation allocation and a plain `defer ReleaseUnauthenticatedConversation()` always runs when the handler returns. Crucially, the handler *does* return at the verdict: `handlerFunc` → `server.go:244-320` registers the conversation and spawns goroutines, then returns, so the slot is not held for the session's lifetime. |
| F-04 | SFTP jail is lexical; symlink escape read/write **as root** | **FIXED** in the default mode (`-sftp-jail chroot`); the old behaviour survives as an explicit opt-in (`lexical`) — see S2-05 | `cmd/internal_sftp.go:96-116` (`Chdir` → `Chroot` → `Chdir("/")` → `Setgroups([])` → `Setgid` → `Setuid`), `:126-137` (root required, fail-closed), `:60-78` (jail root must not be group/world-writable). Default chosen in `cmd/ssh3-server.go:983-1000`; `cmd/sftp_subsystem.go:74-110` spawns the child and never opens a user path itself. |
| F-05 | No target policy for server-side forwarding (SSRF/pivot) | **FIXED-SHALLOW** — mechanism added, default still unrestricted, binds uncovered | `cmd/forward_policy.go:1-123` (new); wired at `cmd/ssh3-server.go:764-771` (UDP), `:779-786` (TCP), `cmd/dynamic_forward_server.go:270-275` (dynamic/SOCKS). Default empty spec ⇒ `permitOpen == nil` ⇒ allow everything (`forward_policy.go:34-36,133-137`), matching OpenSSH. Reverse-forward *binds* have no analog (S2-04). |
| F-06 | DoS cap acquired after the pre-auth work it protects | **FIXED** | `server_auth/auth.go:68` precedes `unix_util.GetUser` (`:95`) and `GetAuthorizedIdentities` (`:100`); the CHANGELOG claim is now true of the code. |
| F-07 | `golang-jwt/jwt/v5 v5.0.0` — CVE-2025-30204 reachable pre-auth | **FIXED** | `go.mod:8` → `v5.3.1` (commit `8807b43`). |
| F-08 | `r.UserAgent()[:100]` slice panic (pre-auth, log amplification) | **FIXED** | `server_auth/auth.go:24-35`: length-checked truncation, and the log lines moved after the check. |
| F-09 | `VarIntLen`/`AppendVarIntWithLen` panics are latent landmines | **STILL PRESENT** (unchanged; still latent) | `util/wire.go:148-165`, `:195-203`. Callers re-enumerated at HEAD: constants, `len()`, parsed varints, `safeExitStatus` output (`cmd/exit_status.go:15-20`) — none can exceed 2^62-1. |
| F-10 | Rust workspace `rustls 0.23.37` advisory | **FIXED** | `Cargo.lock` → `rustls 0.23.45`. |
| F-11 | Other dependency advisories | **FIXED** (bumps) | `golang.org/x/crypto 0.57.0`, `go-jose/v3 3.0.5`, `golang.org/x/oauth2 0.37.0` (`go.mod:25-34`). |
| F-12 | Client `Match exec` runs a shell command while parsing `~/.ssh/config` | **STILL PRESENT** (client-side, by design) | unchanged at this revision |
| F-13 | Host-key pin comparison is `bytes.Equal`, not constant-time | **CONFIRMED** | unchanged; the compared value is a public certificate, so no secret leaks by timing. |

## New findings

| ID | Severity | Component | Evidence (at `ff5ef77`) | Impact |
|----|----------|-----------|-------------------------|--------|
| S2-01 | **Medium** | Peer-chosen `maxPacketSize` still sizes server buffers | `conversation.go:302-310`, `channel.go:407-409`, `cmd/ssh3-server.go:357`, `:830`, `cmd/dynamic_forward_server.go:388`; cap only at `channel.go:176-181` | Authenticated memory amplification: ~100 channels × up to 16 MiB per QUIC connection, from ~30 bytes of peer input per channel |
| S2-02 | **Medium** | Unbounded channels/subsystems per conversation; `runningSessions` never pruned; one process per SFTP channel | `cmd/ssh3-server.go:1194-1240`, `:1238` (no `Delete` anywhere), `:1212`, `cmd/sftp_subsystem.go:110-160` | One authenticated user drives process/fd/heap growth; the process-global session map grows for the server's lifetime |
| S2-03 | Low | Channel-type role inversion (`forwarded-*` accepted from the client) | `conversation.go:312-334`, `cmd/ssh3-server.go:1200-1206`, `message/reverse_forward.go:20-21`, `conversation.go:409,424` | No policy bypass today (the dial is permit-open-gated); unsound invariant for any future type-based policy |
| S2-04 | Low | No `PermitListen` analog for reverse-forward binds | `cmd/reverse_forward_server.go:187-270` | An authenticated user binds arbitrary ports on the server (subject to GatewayPorts policy + per-user budget) |
| S2-05 | Low | `lexical` SFTP mode keeps exactly the F-04 exposure; in-process `pkg/sftp` runs unguarded | `cmd/sftp_subsystem.go:96-110`, `:170-190`, `cmd/ssh3-server.go:1212` | Operator-opted-in config: symlink escape as the server's uid; a `pkg/sftp` panic in that mode kills the whole server |
| S2-06 | Info | No explicit QUIC timeouts / connection cap / idle policy | `cmd/ssh3-server.go:1164-1176` (no `MaxIdleTimeout`, `MaxIncomingStreams`, `HandshakeIdleTimeout`), no connection counter | Slow-loris style holds are bounded only by quic-go defaults; the operator cannot tighten them |
| S2-07 | Info | Varint encoder panics (F-09) still latent | `util/wire.go:148-165`, `:195-203` | Landmine for future arithmetic-derived call sites, not reachable today |

### S2-01 — Medium — A peer still picks the size of the server's read buffers (`maxPacketSize`)

**Evidence**

- An incoming client channel keeps the **peer's advertised** `maxPacketSize`: `conversation.go:287` (`parseHeader`) → `:302-308` (`MaxPacketSize: maxPacketSize`) → `:310` (`NewChannel(..., channelInfo.MaxPacketSize, ...)`), and `channel.go:407-409` returns exactly that value from `MaxPacketSize()`.
- The v0.1.27 cap is the *only* bound: `channel.go:176-181` rejects values above `util.MaxSSHStringLen` (16 MiB, `util/wire.go:211`) — anything up to and including 16 MiB is accepted verbatim.
- The server allocates that many bytes eagerly, once per channel read loop, on **peer-opened** channels:
  - `cmd/ssh3-server.go:357` — the session channel's stdin pump (`b := make([]byte, channel.MaxPacketSize())`), i.e. every `ssh3 … exec`/shell channel the client opens;
  - `cmd/ssh3-server.go:830` — the forwarded-agent-socket channel loop;
  - `cmd/dynamic_forward_server.go:388` — every `dynamic-forward-tcp` channel.
- The server's *own* advertised value (30000, `cmd/ssh3-server.go:1189`) is sent back in the confirmation (`channel.go:350-356`, `c.confirmChannel(c.maxPacketSize)` in `conversation.go:468`) but is **never used to clamp the inbound value, and is not enforced on inbound data messages** — the only inbound message-size bound is the 16 MiB `ParseSSHString` cap.
- Concurrency: `quic.Config` (`cmd/ssh3-server.go:1164-1176`) does not set `MaxIncomingStreams`, so quic-go's default (100 concurrent peer-initiated streams per connection) applies. 100 channels × 16 MiB ≈ 1.6 GiB of server heap for one connection; connections are not capped either (S2-06), so several connections multiply it.

**Exploit conditions.** Post-auth: any account that can complete a CONNECT. The peer needs ~30 bytes per channel (stream header with `maxPacketSize = 16777216`) and never has to send a data byte — the allocation happens at the top of the loop. Pre-auth: **no** — channels are only processed after the conversation is registered by the authenticated handler (`server.go:255-260`, reached only from the verdict at `server_auth/auth.go:111-131`), and the pre-auth HTTP path never allocates from peer lengths. Confidence: **high** for the code path; the practical effect (RSS growth vs. kernel overcommit) depends on the host, and Go's `make` for a 16 MiB slice does touch pages via `sysAlloc`/zeroing, so RSS growth is expected.

**Impact.** A single authenticated user can exhaust the server's memory (or drive the host into the OOM killer) with a small amount of input, and can repeat it after the connection dies. It is the same failure class as F-01, just one level up the stack: F-01 bounded *one string*; nothing bounds *strings × channels × connections*.

**Recommendation.**

1. Clamp on ingress: in `parseHeader` (or right after `conversation.go:307`), reject — or silently lower to the server's configured default — any peer `maxPacketSize` above the server's own `defaultMaxPacketSize` (30000 today). The confirmation already tells the peer the server's value, so lowering is protocol-consistent.
2. Enforce the advertised value on inbound data messages (a peer sending a message longer than the value the server advertised should be a stream error), so the cap and the buffer size cannot diverge.
3. Give the read loops a fixed, server-configured buffer (`defaultMaxPacketSize`) rather than the peer's number; a channel that needs more can be grown on demand up to the cap.
4. Add a per-conversation and per-user cap on concurrent channels (see S2-02) so the multiplication is bounded even if a single value is inflated.

### S2-02 — Medium — Unbounded channel/subsystem count, a never-pruned global session map, and one process per SFTP channel

**Evidence**

- The conversation loop accepts channels in a bare `for` loop with **no counter, no per-conversation limit, and no admission control** (`cmd/ssh3-server.go:1194-1240`); each accepted channel becomes a goroutine (`:1212` sftp, `:1220` reverse-forward, `:1227` dynamic-forward, `:1234` dynamic-forward-tcp, `:1244` session).
- `runningSessions.Insert(channel, …)` at `cmd/ssh3-server.go:1238` is the only write; `git grep runningSessions` finds no `Delete`/`Remove` call anywhere in the tree — the map is process-global (`:124`), so it accumulates one entry per session channel ever accepted, for the server's whole lifetime. (Channels are never re-used as keys within a connection either, so this is monotonic growth, not a bounded working set.)
- The default SFTP mode (`-sftp-jail chroot`, `cmd/ssh3-server.go:983-1000`) re-execs the server binary per SFTP channel: `cmd/sftp_subsystem.go:110-160` (`exec.Command(exe, "-sftp-server-internal", …)`, two pipes, two pump goroutines, `cmd.Wait()`). The child is root until `applyChrootAndDrop` finishes. Nothing caps how many children one account may hold.
- The only backstop is quic-go's default `MaxIncomingStreams` (100 per connection, not configured at `cmd/ssh3-server.go:1164-1176`); connections are not counted at all, and a `?mux=1` control-master conversation deliberately keeps one connection alive for many sessions (`server.go:261-263`, `conversation.go:508-513`).

**Exploit conditions.** Post-auth. Confidence: **high** (static; the loop and the missing `Delete` are unambiguous).

**Impact.** Resource exhaustion from the weakest credentialed position — process table (`ps` filled with `ssh3-server -sftp-server-internal` children, each holding a QUIC connection's worth of fds), goroutines, memory, and a monotonically growing map. Slow-ish (it needs the attacker to open and close channels), but it is the kind of thing that turns into "the server was killed by one user" during an incident. A long-running multi-user server also accumulates the map entries benignly, which is a real (if small) leak.

**Recommendation.**

1. Count channels per conversation (and per authenticated user/connection) and refuse over the cap with a channel-open failure; make the cap a flag with a conservative default.
2. Cap concurrent `-sftp-server-internal` children per user, and prefer the in-process handler when the server is already unprivileged (the child only buys confinement, which is only needed when there are privileges to contain).
3. Prune `runningSessions` when a session channel ends (the session goroutine's deferred block at `:1257-1264` is the natural place), and assert the map size in a test.
4. Set `MaxIncomingStreams` (and `MaxIncomingUniStreams`) explicitly in the `quic.Config` so the effective bound is a documented choice rather than a library default.

### S2-03 — Low — Client-opened `forwarded-tcp` / `forwarded-udp` channels are honoured as server-side dial requests

**Evidence**

- Inbound classification keys on the channel-type string: `conversation.go:312-334` turns `"forwarded-tcp"` into a `TCPForwardingChannelImpl` and `"forwarded-udp"` into a `UDPForwardingChannelImpl`, parsing the target address from the channel's extra header bytes.
- The server's session loop then dials that target: `cmd/ssh3-server.go:1204-1206` → `handleTCPForwardingChannel` → `net.DialTCP` at `:786` (UDP at `:771`/`handleUDPForwardingChannel`). Both are gated by `checkForwardTarget` (`:764-771`, `:779-786`).
- Those same two names are declared the *server→client* reverse-forward types: `message/reverse_forward.go:20-21` (`ChannelTypeForwardedTCP`, `ChannelTypeForwardedUDP`) and `cmd/reverse_forward_server.go:329-348` opens exactly them toward the client.
- Meanwhile the library's own "please dial this for me" helper is named differently: `conversation.go:409` (`"direct-udp"`) and `:424` (`"direct-tcp"`), and the server's inbound switch has no case for either — such a channel falls through to the session `default:` branch (`cmd/ssh3-server.go:1237-1243`).

**Assessment.** The dial is permit-open-gated regardless of which name the client uses, so there is no bypass of S2-01…F-05's control. What is wrong is the invariant: the server cannot tell "the peer is answering my reverse-forward request" from "the peer wants me to dial", because the roles are encoded only in the direction of travel, and the naming used by the two directions does not line up (`forwarded-*` accepted from the client; `direct-*` not recognised). Confidence: **high** on the code facts. **Unverified:** which type string the CLI `-L` path actually emits — I could not find the client-side helper that opens a server-side forwarding channel within the server-focus budget (see Coverage); that does not affect the finding, but it is the one loose end.

**Impact.** No privilege change today. It matters because (a) a deployment that hardens by allow-listing channel types would be unsound, (b) it makes the reverse-forward `forwarded-*` namespace available to a malicious client, and (c) the ASCII-protocol spec should say who may open what.

**Recommendation.** On the server's inbound path, accept only the client-role names (`direct-tcp`/`direct-udp` + the ssh3 session/subsystem types) and cancel `forwarded-tcp`/`forwarded-udp` with a stream error; symmetrically, make the client refuse server-role-only types it does not expect. Document the role table (direction → permitted types) in the spec/README.

### S2-04 — Low — `-permit-open` has no `PermitListen` counterpart (reverse-forward binds stay unrestricted)

**Evidence.** `cmd/forward_policy.go` is consulted only on dial paths (`cmd/ssh3-server.go:764-771`, `:779-786`, `cmd/dynamic_forward_server.go:270-275`; the full `net.Dial*` inventory in `cmd/` is exactly those three sites, while `cmd/ssh3-server.go:888`/`cmd/ssh3.go:*` are not server dial paths). Reverse forwarding binds through `cmd/reverse_forward_server.go:229-257` (`net.ListenTCP` / `net.ListenUDP`) with only the GatewayPorts policy (`:71-97`, applied at `:187`) and the per-user budget (`:204`) in front of it.

**Impact.** An authenticated user can still occupy arbitrary server ports (subject to the bind policy and budget), which is the inbound mirror of F-05 — a pivot/footgun that the new policy mechanism invites operators to believe is covered.

**Recommendation.** Add `-permit-listen` with the same parser (the `forwardPolicy` type is directly reusable) and gate `ListenTCP`/`ListenUDP` with it; default to the current behaviour only if the operator explicitly opts in, and document that `-permit-open` governs *dials*, not *binds*.

### S2-05 — Low — The `lexical` SFTP mode keeps F-04, and in-process `pkg/sftp` runs without a panic guard

**Evidence.** `serveSFTPSubsystem` (`cmd/sftp_subsystem.go:74-110`) selects `serveSFTPInProcess` when `-sftp-jail lexical` is set *or* when the server is unprivileged **and** the user has no home directory; `serveSFTPInProcess` (`:96-110`, `:170-190`) uses the unchanged lexical `resolveJailed` (`:196-230`) and calls `pkg/sftp`'s `server.Serve()` in the goroutine started at `cmd/ssh3-server.go:1212`, which carries **no** `PanicGuard`. In the default chroot mode the equivalent code runs in a separate process (`cmd/internal_sftp.go:60-78`), so a `pkg/sftp` panic kills only that child — a genuine robustness improvement that the lexical mode does not get.

**Impact.** Operator-selected configuration: the F-04 symlink escape class applies with the server's own privileges (as documented in the mode's own comment, `cmd/sftp_subsystem.go:81-88`), and a malformed SFTP request that panics in `pkg/sftp` takes down the whole server instead of one child. Both are avoidable: the jail mode is an explicit choice, and the child model is strictly safer.

**Recommendation.** Deprecate `lexical` (or require an explicit "I accept root-file access" flag), and wrap `serveSFTPInProcess` (and the `go serveSFTPSubsystem(...)` call site) in `util.PanicGuard` regardless of mode, so the in-process path cannot kill the server.

### S2-06 — Info — No explicit QUIC idle/handshake timeouts, stream limits or connection cap

**Evidence.** The `quic.Config` at `cmd/ssh3-server.go:1164-1176` sets `Allow0RTT`, datagrams, and the receive windows — no `MaxIdleTimeout`, `HandshakeIdleTimeout`, `MaxIncomingStreams`, `MaxIncomingUniStreams`. The `http3.Server` at `:1180-1186` has no connection-count hook. Accepted connections are counted only for the shutdown drain (`conns` at `:1402`, `:1427`), not limited. Server reads on QUIC streams (`util.ReadVarInt`, `io.ReadFull` in `channel.go`/`message/`) have no per-read deadline, so a peer that trickles bytes keeps its goroutine and its accepted channel alive as long as the QUIC connection lives.

**Assessment.** With quic-go's defaults (30 s idle timeout, 5 s handshake) this is *not* an open door: an idle pre-auth peer is dropped, and the pre-auth path does no length-driven allocation (F-01's fix plus the S2-01 analysis show the pre-auth cost is a UA parse, a passwd lookup, one identity-file read and a JWT parse, each bounded). The concern is that the operator has no knob to tighten it and no bound on *how many* authenticated connections/channels one user may hold — which is what makes S2-01/S2-02 reachable at scale.

**Recommendation.** Make `MaxIdleTimeout`/`HandshakeIdleTimeout`/`MaxIncomingStreams`/`MaxIncomingUniStreams` explicit flags; add a global and a per-user concurrent-connection cap; document the effective defaults in the deployment README.

### S2-07 — Info — Varint encoder panics remain (F-09 confirmed, still latent)

**Evidence.** `util/wire.go:148-165` (`AppendVarIntWithLen`: `panic("invalid varint length")` / `panic(fmt.Sprintf("cannot encode %d in %d bytes", …))`), `:195-203` (`VarIntLen` panics above 2^62-1 via a self-formatting struct). Callers at HEAD: `message/channel_request.go` exit-status encoders fed by `safeExitStatus` (`cmd/exit_status.go:15-20`) or parsed varints; frame builders fed by `len()`/constants; `message/message.go:69-76` (channel-open confirmation, server's own constant 30000). None is peer-derived beyond the 62-bit varint domain.

**Recommendation.** Return errors (or clamp with a documented sentinel) instead of panicking; add the `VarIntLen` edge-value test the Stage-1 brief asked for (the new `util/wire_test.go` covers round-trips and the `ParseSSHString` cap, not the >2^62-1 panic path).

## Auth path, line by line (F-03/F-06/F-08 re-proof)

The brief asked for the auth-gating *order* to be re-proved from the source, because pass 1 claimed channel/message parsing happens only post-auth and the cap ordering was wrong. At `ff5ef77`:

1. `server_auth/auth.go:23-41` — `Server` header, UA parse (bounds-checked at `:30-32`), protocol-version check. No peer-length allocation. Refusals return before the slot is taken, so a bogus UA costs nothing but a response.
2. `:44` — `defer w.(http.Flusher).Flush()`.
3. `:48-53` — QUIC connection from the request context; `:55-60` — **0-RTT (early data) is refused with 425 until `HandshakeComplete`**, so a replayed 0-RTT CONNECT cannot authenticate.
4. `:68-74` — `TryAcquireUnauthenticatedConversation()` **first**, then `defer ReleaseUnauthenticatedConversation()`. `dos_guard.go:45-66` is mutex-protected and the release is unconditional, so the F-03 leak (release only on refusal) is structurally gone. Both the acquire and the release are inside the handler frame, so the slot's lifetime is exactly the authentication attempt — no more, no less.
5. `:76-87` — `HTTPStream()` and `NewServerConversation` (conversation allocation, now *behind* the cap → F-06).
6. `:91-105` — username resolution (`URL.User` then `?user=`) and `unix_util.GetUser` (passwd/NSS lookup; failure ⇒ 401), then `GetAuthorizedIdentities` (identity-file reads). Both behind the cap, both bounded.
7. `:107-132` — verification: plugin verifiers (`WrappedPluginVerifier.Verify`), `Basic` password (`CheckBasicAuth`, which checks the lockout *before* the backend, `server_auth/handlers.go:86-111`), or `Bearer` JWT (`VerifyJWT`).
8. `:113/124/129` — `handlerFunc(username, conv, w, r)` only on a successful verdict. That handler is `server.go:244-320`, which *registers the conversation* (`:255-260`, `conversationsManager.addConversation`) and then spawns the two conversation goroutines; it **returns immediately**. Channel streams are only ever attributed to a conversation through that registry (`conversation.go:265-301` looks the conversation up; `server.go:140-146`'s parse path is reached from the per-connection accept loop *after* lookup, and the lookup fails for an unregistered conversation), and the registration timeout is 2 s (`server.go:25`). So:

**Confirmed: parsing of channel headers and channel messages happens only post-auth on the server, as pass 1 stated.** F-03's fix did not break that property; if anything it strengthened it, because the slot (and therefore the conversation allocation) now precedes the identity work rather than following it.

Two notes on the new arrangement, both minor:

- The 503 path logs `r.URL.User.Username()` (`auth.go:70`), which may be empty when the username comes from `?user=` — a cosmetic logging defect, not a security one.
- Because the slot is now released at the verdict, there is **no** cap on authenticated conversations (there never was one that functioned — the old behaviour was an accidental permanent cap). That is the right semantics for a `MaxStartups` analog, but it means the only remaining bound on post-auth work is quic-go's stream limit; that is the gap S2-02/S2-06 recommend closing explicitly.

## Verified clean (server side, at `ff5ef77`)

Checked specifically; "clean" means the code holds up for the stated reason.

1. **Conversation-control-stream ID validation.** `conversation.go:295-301` compares the header's `controlStreamID` with the conversation's control stream and cancels the stream on mismatch; channel IDs are QUIC stream IDs (`:305`), so a peer cannot forge or reuse an identifier. (Pass 1 did not state this; it is now explicitly verified.)
2. **Panic-guard composition.** In `server.go:306-311` the `PanicGuard` defer is registered *before* the teardown defers (`newConv.Close()`, `removeConversation`, `removeConnection`), so LIFO order runs the teardown first and the recovery last: a panic in the conversation handler still releases the conversation, its reverse-forward binds and the connection registration. Same shape in `conversation.go:100/114/208`, `cmd/ssh3-server.go:1356`, `server.go:272`. The guard logs a stack trace (`util/util.go:358-368`) rather than dying — appropriate for peer-facing goroutines.
3. **`-sftp-server-internal` fail-closed behaviour.** A chroot request without root exits 1 (`cmd/internal_sftp.go:126-131`) instead of serving unjailed; a missing/invalid jail root, a non-directory root, or a group/world-writable root all exit before serving (`:118-137`); the child receives an empty environment (`cmd/sftp_subsystem.go:135`) and stdio pipes only; after `Chroot` the served root is `/` and the lexical mapping becomes a no-op, so confinement is the kernel's (`withinRoot` at `cmd/sftp_subsystem.go:180-186`, tested at `cmd/internal_sftp_test.go:20-40`).
4. **SFTP child lifetime.** The parent pumps channel↔child, waits for the child, closes the channel, and bounds the drain at 2 s (`cmd/sftp_subsystem.go:143-160`) so a peer that holds the channel open cannot wedge the teardown; the child ends on stdin EOF, so an abrupt parent death (`kill -9`) does not leave a serving child behind (its pipe closes).
5. **Reverse-forward policy and budget (pass 1's clean item re-verified).** GatewayPorts is applied before any bind (`cmd/reverse_forward_server.go:187`), the per-user budget is acquired before the bind (`:204`) and released on every failure path and on conversation end (`:321-325`); targets must be IP literals (`:213-221`), so no client-supplied name is resolved on that path. The *missing* piece is a listen allowlist (S2-04), not a bypass.
6. **Password backend ordering.** `server_auth/handlers.go:86-111`: lockout checked before the backend, failures booked only for users that already resolved, 429 while locked, cleared on success; `dos_guard.go` state is mutex-protected and per-user, so an attacker cannot lock out accounts that do not exist. Bookkeeping for a real user with failures but no lockout persists as a small record — informational, bounded by the passwd database.
7. **No response-header injection on the pre-auth error path.** `http.Error(w, "Unsupported user-agent: …", 403)` writes attacker bytes into the *body* with a framework-set `Content-Length`; no header is built from peer input.
8. **Dependency posture.** `go.mod` is registry-only, no git-sourced modules; the four pass-1 advisories are patched by version bumps (`8807b43`); `vendor/` still matches `modules.txt` (`-mod=vendor` builds). The `vendor/h3` Rust shim is untouched by the server Go path.

## Coverage

**Reviewed in detail (with a finding or a clean statement attached)**

- **Auth**: `server_auth/auth.go` (whole handler, order re-proved line by line), `server_auth/handlers.go` (Basic/Bearer/`VerifyJWT` flow, lockout ordering), `server_auth/dos_guard.go` (both guards, mutex protection, release paths), `server_auth/authorized_identities.go` (read at the call site; the file-parse internals were re-read in pass 1 and are unchanged), `util/unix_util/{user,non_password_auth_user}.go` (lookup, uid/gid parsing, home resolution, the `SSH3_USER_HOME` deployment override, shell resolution), the plugin verifier entry points.
- **Conversation/channel plumbing**: `server.go` (CONNECT handler, registration, datagram loop, per-connection accept goroutine, teardown defers), `channel.go` (`parseHeader` + the new cap, channel construction, `confirmChannel`, `MaxPacketSize`, `nextMessage`/`NextMessage`), `conversation.go` (inbound stream classification and ID validation, accept queue, datagram dispatch, `AcceptChannel`, `OpenChannel`/forwarding openers, `SetMultiplexed`), `cmd/ssh3-server.go:1189-1460` (channel-type dispatch, session lifecycle, drain/shutdown) and the exec/PTY/signal/exit-status handlers.
- **SFTP**: `cmd/sftp_subsystem.go` (mode selection, child spawn, pumps, lexical mapping, `chownToUser*`), `cmd/internal_sftp.go` (chroot/drop, serve loop), `cmd/internal_sftp_test.go` and `cmd/forward_policy_test.go` (test intent).
- **Forwarding**: `cmd/forward_policy.go` (parser + matcher semantics, negation, wildcards, `*` port), the dial call sites (`cmd/ssh3-server.go:764-786`, `cmd/dynamic_forward_server.go:270-280`), the bind path and GatewayPorts logic (`cmd/reverse_forward_server.go:71-97,187-270,321-325`), `cmd/dynamic_forward_server.go` channel/state handling.
- **Parsing/panics**: complete `panic(` inventory over non-vendor, non-test Go; `util.PanicGuard` and all its call sites; `util/wire.go` (varint + SSH-string codecs, the new cap), `message/message.go` (`ParseMessage` + every parser, the new typed error), `message/channel_request.go` (parse/`Length()`/`Write()` pairs, exit status/signal), the new fuzz targets (`util/fuzz_test.go`, `message/fuzz_test.go`) and regression tests.
- **Dependencies**: `go.mod`/`Cargo.lock` versions at HEAD vs. the pass-1 advisories.

**Not reviewed** (stated rather than padded)

- **Windows-specific files** and the Windows build path; **packaging/goreleaser/CI**; `internal/interop` harnesses; `bench/`; the C17 `ssh3-c` tree; the internals of `vendor/h3` (only the server-boundary facts were checked).
- **Rust `crates/`**: only the `rustls` version was checked (F-10). The Rust server crate's own logic, its `unsafe` blocks and its `crypt(3)` FFI were *not* re-triaged in this pass — pass 1's statistics and its recommendation (fuzz the shadow parser) stand.
- **The client side** was touched only where the server's behaviour needs it (channel-type names, `-L` emission). I did **not** locate the client helper that opens a server-side forwarding channel, so S2-03's "which type does the CLI actually send for `-L`" is left unverified; the server-side facts in that finding stand on their own.
- **No fuzzing campaign and no end-to-end dynamic run.** The dynamic probes were limited to building the relevant packages with the recovered `go1.26.0` toolchain and running the repo's own `util`/`message` tests (including the `FuzzParseSSHString` target for a short window); see the appendix for exactly what was executed and its result. No server was started, no QUIC peer was faked, and no third-party system was contacted.
- **Logging review** was limited to the auth and SFTP paths (no credential material appears in either); a full logging sweep was pass 1's item and was not repeated.
- **Shutdown/drain**: reviewed statically (`cmd/ssh3-server.go:1427-1455`, `shutdownDrainPeriod`); not exercised.

## Limitations

- Report-only: **nothing was fixed**, no branch other than this one was touched, and no dynamic exploitation was attempted.
- Severity for S2-01/S2-02 is assigned from static reasoning about Go allocation and process behaviour, not from a measured memory curve; no live RSS measurement was taken.
- The `maxPacketSize` analysis assumes quic-go's default `MaxIncomingStreams` (100) because the server does not set it; if a deployment's quic-go version differs, the multiplication factor changes, but the missing application-level cap does not.
- Absence of a finding in the areas listed under "Not reviewed" means nothing was checked there.

## Appendix — how to reproduce the key checks

```bash
git clone https://github.com/nagual2/ssh3-go && cd ssh3-go
git rev-parse HEAD                    # expect ff5ef776dec9ca40a04d90be79c1b3b9c898f915

# F-01 fix: cap checked before the allocation
sed -n '204,222p' util/wire.go
sed -n '163,183p' channel.go          # parseHeader, incl. the new maxPacketSize cap
sed -n '210,247p' message/message.go  # UnknownMessageType instead of panic

# F-03/F-06: the slot is acquired before the per-request work and released unconditionally
sed -n '62,105p' server_auth/auth.go
git grep -n 'ReleaseUnauthenticatedConversation' -- '*.go'
sed -n '244,320p' server.go           # handlerFunc returns at the verdict (spawns goroutines)

# F-04: the chroot child
sed -n '96,140p' cmd/internal_sftp.go
sed -n '74,110p' cmd/sftp_subsystem.go

# S2-01: peer-chosen maxPacketSize sizes the server's buffers
sed -n '287,311p' conversation.go
sed -n '350,360p' channel.go          # confirmation carries the server's own value
sed -n '355,360p' cmd/ssh3-server.go  # make([]byte, channel.MaxPacketSize())
sed -n '828,832p' cmd/ssh3-server.go
sed -n '386,390p' cmd/dynamic_forward_server.go

# S2-02: no channel cap, and runningSessions is never pruned
sed -n '1194,1245p' cmd/ssh3-server.go
git grep -n 'runningSessions' -- '*.go'   # no Delete/Remove caller

# S2-03: client-opened forwarded-* is dialled
sed -n '312,335p' conversation.go
sed -n '1200,1207p' cmd/ssh3-server.go

# S2-04: binds are not policy-gated
git grep -n 'ListenTCP\|ListenUDP\|net.Listen(' -- 'cmd/*.go'

# Panic inventory: no peer-reachable panic() left in the server
git grep -n 'panic(' -- '*.go' ':!vendor' ':!*_test.go'
sed -n '355,372p' util/util.go        # PanicGuard

# Local probes (go1.26.0 recovered from the module cache, -mod=vendor)
go test ./util/ ./message/
go test ./util/ -run '^$' -fuzz FuzzParseSSHString -fuzztime 30s
```

**Local probe result (this pass, `go1.26.0` linux/amd64, vendored build, no network):** `go vet ./util/ ./message/` produced no diagnostics; `go test ./util/ ./message/` passed (`ok … /util 0.041s`, `ok … /message 0.429s`); the 30 s `FuzzParseSSHString` run completed **PASS** after 1,391,018 executions with 8 newly-interesting inputs and **no crash** — consistent with the F-01 cap being checked before the allocation. This is a smoke confirmation of the fix, not a fuzzing campaign: 30 s on one target is nowhere near coverage of the parse surface.

*End of report.*
