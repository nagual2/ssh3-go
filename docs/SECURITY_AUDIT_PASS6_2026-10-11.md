# Security audit — pass 6 (2026-10-11)

**Repository:** nagual2/ssh3-go (Go server/client; Rust rewrite under `crates/`)
**Audited HEAD:** `ed88ec2da6066a8b0295fe9925ecabc2fcedf746` (origin/main, "chore(winres): regenerate rsrc_windows_amd64.syso for 0.1.32")
**Baseline:** `e760a88` (pass-5 baseline)
**Mode:** REPORT-ONLY. No code changes in this PR; the only artefact is this document.
**Scope:** verify the pass-5 findings are actually fixed (owner says they are), hunt regressions around the F-14 fix, and close the coverage holes pass 5 left open (Rust reachability, Rust resource-limit parity, Rust auth beyond password, supply chain, and the fuzz/race probes pass 5 skipped).

`git log --oneline e760a88..origin/main`:

```
ed88ec2 chore(winres): regenerate rsrc_windows_amd64.syso for 0.1.32
0270319 chore(release): bump software version to 0.1.32
832a5f4 Merge pull request #12 from nagual2/fix/pass5-followup
cd5403e fix(security): close the pass-5 findings F-14 and F-15
4e0a3a3 Merge pull request #11 from nagual2/docs/security-audit-pass5
261d8b6 docs(security): pass-5 audit — fix verification, regression hunt, Rust server, distribution
978a91b docs(security): pass-5 audit skeleton (fix verification, Rust server, distribution)
```

Only one substantive code change landed between the pass-5 baseline and this HEAD: `cd5403e` (F-14 + F-15). Everything else is the pass-5 report, its merge, the follow-up merge (#12) and release chores. That narrows this pass considerably: for every pass-5 finding other than F-14/F-15 the question is whether a fix exists *at all*, and `git log --oneline e760a88..HEAD -- <file>` answers it directly (see the evidence column).

---

## 1. Fix verification

| ID | Pass-5 finding | Status at `ed88ec2` | Evidence (file:line at the audited HEAD) |
|----|----------------|---------------------|------------------------------------------|
| F-14 | Client datagram loop treats any `AddDatagram` error as terminal → one late datagram for a pruned channel kills datagram reception for the whole conversation | **FIXED** (§2 for the regression hunt and the residual error classes) | `conversation.go:231-247` — `switch e := err.(type) { case util.ChannelNotFound: log.Warn… continue; default: … return }`; twin `server.go:316-323` |
| F-15 | 256 dangling-queue slots never reclaimed → junk IDs permanently occupy the bound | **FIXED** | `resources_manager.go:99-116` (FIFO `danglingOrder`, evict oldest), `:75` (handover removes the ID from the eviction order), `:142-149`; re-verified for order/map desync in §2d |
| F-16 | Rust password auth leaks timing (short-circuiting hash compare, `crypt()` only for resolvable users), no lockout | **NOT FIXED** | `crates/ssh3-server/src/lib.rs:344-389`; byte-slice `==` at `:387`; `crypt()` only after `getspnam_r` resolved the user (`:348-379`), so a non-existent user returns `Ok(false)` at `:364`/`:367` without ever hashing. No lockout/backoff inside the function and none in the caller either (`git log e760a88..HEAD -- crates/ssh3-server/src/lib.rs` → empty) |
| F-17 | align-1 buffer for `struct spwd` in Rust FFI | **NOT PRESENT AT THIS HEAD** (pass-5 wording does not describe this code; unchanged since baseline, so this is a pass-5 misread rather than a fix) | `crates/ssh3-server/src/lib.rs:346-359`: the `spwd` storage is a correctly typed/aligned `MaybeUninit::<nix::libc::spwd>` (`:348`) passed as `shadow_entry.as_mut_ptr()`; the `vec![0u8; buffer_len]` (`:349`) is the *string* buffer for `getspnam_r`'s `char *` output (`:353`) and is never cast to `*mut spwd` |
| F-18 | GH Actions pinned by major tag only; no signing / SBOM / trimpath | **NOT FIXED** | `.github/workflows/*.yml`: `actions/checkout@v4` (build.yml:23,84,116; release.yml:22; test.yml:22; windows-client.yml:23,42), `actions/setup-go@v5` (build.yml:25,86,118; release.yml:26; test.yml:38; windows-client.yml:24,43), `goreleaser/goreleaser-action@v6` (release.yml:34), `actions/upload-artifact@v4` (windows-client.yml:31). `.goreleaser.yaml`: `ldflags: -s -w` only, `checksum.name_template: checksums.txt`, no `signs:`/`docker_signs:`/`sboms:`/`~trimpath` (`git log e760a88..HEAD -- .github/workflows/ .goreleaser.yaml` → empty) |
| P4-03 | Regression test injects its own spawn stub; production `spawnChannel` closure never exercised | **NOT FIXED** | `cmd/ssh3-server.go:1282-1296` is still an inline closure reachable only from `:1276-1281` inside the accepted-conversation goroutine; the only test is `cmd/session_admission_test.go` (pass-5 §2.3), which stubs `spawn`. No new test in the range |
| P4-02-gap | `CancelRead` does not prune `channelsManager` | **NOT FIXED (unchanged); impact re-scoped — see §2c** | `channel.go:483-485` = `func (c *channelImpl) CancelRead() { c.recv.CancelRead(42) }`, no `onChannelClose`/`removeChannel`; the prune lives in the different method `Close()` (`channel.go:487-497`) |

**Bottom line for §1:** the owner's statement holds for F-14 and F-15 only. F-16, F-18, P4-03 and P4-02-gap are exactly as pass 5 left them; F-17 as worded does not exist at this HEAD.

---

## 2. Regression hunt, deepest attention on F-14

### 2a. Client loop vs server twin — parity confirmed

| | client | server |
|---|---|---|
| site | `conversation.go:215-251` | `server.go:296-330` |
| `ChannelNotFound` | `case util.ChannelNotFound:` → `log.Warn` + continue (`conversation.go:233-242`) | `case util.ChannelNotFound:` → `log.Warn` + continue (`server.go:318-320`) |
| other errors | `log.Error` then `return` (`conversation.go:243-245`) | `log.Error` then `return` (`server.go:321-323`) |

The server twin remains tolerant, and the two switches are structurally identical, so F-14 is closed in both directions and `cd5403e` introduced no asymmetry (it touched only the client loop, the manager and tests; `git show --stat cd5403e` = CHANGELOG, conversation.go, conversation_test.go, resources_manager.go, resources_manager_test.go).

The Rust twin is tolerant too, which matters for interop: `crates/ssh3-h3/src/lib.rs:465-477` (`dispatch_datagram`, client side) and `:479-496` (`route_registered_datagram`, server side) both map `Ok(()) | Err(ConversationError::ChannelNotFound { .. }) => Ok(..)` after `Conversation::add_datagram` buffers the datagram and returns the error (`crates/ssh3-core/src/conversation.rs:248-263`). So neither implementation kills the loop on the condition F-14 described.

One cosmetic divergence, **not** a finding: the client compares the receive error with `err != context.Canceled` (`conversation.go:218`) while the server uses `errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed)` (`server.go:305`). Both branches `return` identically; the client merely logs an ERROR line for an ordinary teardown that arrives wrapped or as `net.ErrClosed`. Log noise.

### 2b. Which error classes still kill the loop

Every path out of the client loop's `AddDatagram` call:

```
conversation.go:230  err = c.AddDatagram(...)
   └─ conversation.go:509-523  AddDatagram
        ├─ :511-514  util.ReadVarInt error        → returned as-is  → default: → RETURN (terminal)
        ├─ :515-521  channel not in manager       → ChannelNotFound → warn + continue  (F-14 fix)
        │            (datagram buffered into a dangling queue)
        └─ :522      channel.waitAddDatagram      → channel.go:457-459
                      └─ util/util.go:150-157 DatagramsQueue.WaitAdd
                           ├─ queue has room      → nil
                           └─ ctx.Done()          → context.Cause(ctx) → default: → RETURN
```

plus the conv-id parse at `conversation.go:224-228` and the transport read at `:216-222`.

Exactly **two** error classes can still end the loop after the fix:

1. **`util.ReadVarInt` failure on a malformed or truncated datagram** — `conversation.go:224-228` (conv id) and `conversation.go:511-514` (channel id). This is the only remaining *peer-triggerable* terminal path, reachable with a datagram shorter than the varint it claims. Impact: on the **server** a malicious client can only switch off datagram delivery for its own conversation (streams, `Close()`, teardown and every other conversation are unaffected) — a self-DoS; on the **client** a malicious or buggy server can silently disable the client's datagram reception for the rest of the connection while streams keep working. No confidentiality, integrity or cross-conversation impact. Impact: **low**. Reported as **F-19** below.
2. **Conversation-context cancellation** (`util/util.go:154-155` → `context.Cause`) and a transport-level `ReceiveDatagram` error (`conversation.go:217-222`). Both mean the conversation is going away, so `return` is correct rather than a regression.

`ChannelNotFound` is no longer in that set, which is exactly what F-14 required; **there is no other silently-loop-killing error class**. The Rust equivalent of the same residual exists: `ssh3-client/src/lib.rs:1406-1412` (`is_benign_datagram_dispatch_error`) only treats `DatagramDispatchError::Connection(_)` as benign, so a `Conversation(_)` error (e.g. the same malformed-varint case) still ends the Rust client's dispatch task.

**Residual liveness note (pre-existing, not a pass-5 regression, no error involved):** `DatagramsQueue.WaitAdd` (`util/util.go:150-157`) *blocks* until the per-channel queue has room, so a channel whose consumer never drains its queue head-of-line blocks that conversation's single datagram receive loop (and thus every other channel of the same conversation, up to QUIC datagram flow control). The queue size is declared by the peer at channel open. Within one conversation only the peer suffers, so this stays a self-DoS — but it deserves attention when the multiplexed/control-master work (stage 3.5) puts several sessions behind one conversation.

### 2c. Can the prune still fire `ChannelNotFound` toward a live channel?

Ordering at `ed88ec2`:

```
channelImpl.Close()          channel.go:487-497 → channelCloseListener.onChannelClose(c)
                                                   → resources_manager.go:135-137
                                                   → resources_manager.go:129-133 removeChannel (under m.lock)
Conversation.AddDatagram()   conversation.go:515 → channelsManager.getChannel (m.lock, map read)
                             conversation.go:519 → channelsManager.addDanglingDatagramsQueue
                                                   → resources_manager.go:88-92 re-checks m.channels under m.lock
```

* `removeChannel` (`resources_manager.go:132`) is the only delete from `m.channels`, it always holds `m.lock`, and it is only reached from `Close()`. A channel that the application is still using has not been closed, so it cannot be pruned, so a `ChannelNotFound` cannot be produced for it. The re-check at `resources_manager.go:88-92` closes the lookup→buffer race: if the channel registered between the two lock acquisitions, the datagram goes to the live channel instead of a dangling queue.
* The one path that does retire a not-yet-used channel is the pre-existing P4-02 behaviour: a channel refused by the conversation's channel budget just after `AcceptChannel` registered it is closed, hence pruned. Datagrams racing that close now take the F-14 branch and are buffered into a dangling queue no channel will claim; they are dropped when the conversation ends. That is bounded memory (`maxDanglingDatagramQueues` × `danglingDatagramQueueSize` = 256 queues × 64 datagrams per conversation), not an unbounded leak — and the alternative was the F-14 bug itself.
* **P4-02-gap re-scoped:** `CancelRead` alone still does not prune (`channel.go:483-485`), but it is not a life-cycle call: every observed call site (`cmd/ssh3-server.go:254`, `:1286`; `client/client.go:188`; `client/session_pump.go:211`) is a "stop reading" action on a channel whose owner still closes it, which prunes. The residual risk is therefore limited to a future caller treating `CancelRead` as terminal and never calling `Close` — the channel map entry (and its datagram queue) would then live until the conversation dies. Worth a comment or a defensive prune, but not exploitable at this HEAD on the call sites reviewed.

**Conclusion:** the F-14 fix is complete for the ordering it has to survive; the prune cannot be observed as `ChannelNotFound` by a live channel's reader, and the residual buffering is bounded.

### 2d. F-15 fix re-checked for order/map desync

The eviction bound is only correct if `danglingOrder` and `danglingDgramQueues` stay in step. The map is mutated in exactly three places, all under `m.lock`:

* `resources_manager.go:74-75` — handover: `delete(map)` **and** `removeChannelID(order)`;
* `resources_manager.go:108-110` — eviction: `delete(map, order[0])` **and** `order = order[1:]`;
* `resources_manager.go:113-115` — insert: `map[id] = queue` **and** `order = append(order, id)`, reachable only in the `!ok` branch, so a repeated unknown ID extends its existing queue and does **not** append a duplicate order entry.

No path touches one without the other, the queues die with the manager when the conversation ends, and junk IDs cannot pad the order slice. The cap holds and the pass-5 fail-closed behaviour is gone. **F-15 FIXED, no residual.**

---

## 3. Rust coverage expansion

**Toolchain note:** no `cargo` was available in this environment and none was fetched (the Go probes consumed the available build budget), so §3 is **static review of source at `ed88ec2`**, not a build/run result. Nothing in this section was validated by executing Rust code.

### 3a. `unwrap()` / `expect()` / `panic!` reachability triage

Scope: all `crates/*/src/**/*.rs` (proto, core, quinn, h3, client, server, auth). Raw text matches: **921**, of which **880+ sit inside `#[cfg(test)]` modules** (a single inline `mod tests` at `crates/ssh3-client/src/lib.rs:1502-5649` holds 525 of them, and the file's first `#[cfg(test)]` is at `:1048`). After excluding `#[cfg(test)]` blocks, **36 sites remain, in 10 files**. Method was cross-checked two independent ways (a brace-tracking skip, and "everything before the first `#[cfg(test)]`"); the per-file counts agree exactly, and spot checks on `ssh3-client/src/lib.rs` (all 525 hits ≥ line 1576, inside `mod tests` at 1502-5649) and `ssh3-client/src/main.rs` (4 hits, all before its test module) confirm no real code is being counted as test. Full list: `/tmp/panicrows.txt` of the audit run.

Grouped by reachability:

**(A) Internal-only — lock-poisoning `.unwrap()` (31 of 36).** Every `.lock().unwrap()` / `.read().unwrap()` / `.write().unwrap()` on a `Mutex`/`RwLock`. A panic while holding one poisons it and makes every later acquisition panic in turn: a cascade, not a peer-triggered event, and not reachable from peer bytes.
`crates/ssh3-core/src/channel.rs:333,393,398,402,408,431,435`; `crates/ssh3-core/src/queue.rs:20,25,63,78,80,91`; `crates/ssh3-core/src/conversation.rs:308,321,342`; `crates/ssh3-server/src/lib.rs:378`.
Two of them deserve a note because the blast radius is wider than the call site:
* `crates/ssh3-core/src/conversation.rs:308/321/342` guard the channel map and the dangling-queue map — the same structures the Go side has been hardening (P4-01/F-15), here with no cap *and* a poison-cascade failure mode (§3b).
* `crates/ssh3-server/src/lib.rs:378` (`crypt_lock().lock().unwrap()`) is a process-wide static lock: any panic while holding it (e.g. inside the `crypt()` call region, `:379-385`) poisons it and then **every subsequent password authentication panics**, i.e. process-wide auth outage from a single poisoned mutex. This is the Rust counterpart of the F-16 area and worth fixing alongside it (`lock().unwrap_or_else(|e| e.into_inner())`).

**(B) Peer bytes reach the code, but the panic is unreachable by construction (8 of 36) — verified, not assumed.**
The `Ipv4Addr::from(<[u8; 4]>::try_from(octets).unwrap())` / `Ipv6Addr::from(<[u8; 16]>::try_from(octets).unwrap())` pairs: `crates/ssh3-proto/src/channel.rs:61,65`; `crates/ssh3-proto/src/message.rs:602,605`; `crates/ssh3-core/src/channel.rs:537,540`; `crates/ssh3-quinn/src/channel.rs:453,457`. In each, `octets` is sized by the same address-family value that selects the match arm — `family.octet_len()` returns 4 for `Ipv4` and 16 for `Ipv6` (`ssh3-proto/src/message.rs:556-561`), and the `ssh3-quinn` copy hardcodes `vec![0; 4]` / `vec![0; 16]` inside the same `match family` (`ssh3-quinn/src/channel.rs:441-444`). These bytes *are* peer-controlled and *are* parsed pre-auth on the server for forwarding requests, but the `try_from` cannot fail in the arm it sits in, so there is no reachable panic. (These are the sites the brief flagged as the "standing hole"; they are clean.)

**(C) Encode-side `panic!` in the varint helpers — internal-only (`crates/ssh3-proto/src/wire.rs:120,126,131,164`).** `append_var_int` panics above `MAX_VARINT_8 = 4_611_686_018_427_387_903` (`wire.rs:5-10`, 2^62-1), `append_var_int_with_len` panics on a length outside `{1,2,4,8}`, and `var_int_len` panics above the same bound. Peer-derived values cannot reach them: `read_var_int` (`wire.rs:141-166`) can only produce ≤ 2^62-1, and the non-test callers pass constants or those decoded fields (`ssh3-proto/src/message.rs:109-482,620`). `append_var_int_with_len` has no caller outside `wire.rs`. Reachable only through internal misuse.

**(D) Guarded / not peer-driven (2 of 36).** `crates/ssh3-client/src/agent.rs:300` — `u32::from_be_bytes(prefix.try_into().unwrap())` is preceded by an explicit `if cursor.len() < 4 { return Err(…truncated SSH agent u32) }` (`:293-299`) and reads a local SSH-agent socket, not peer bytes. `crates/ssh3-client/src/main.rs:167,173,183,188` — `unreachable!()` in `clap` conflict arms, enforced by the argument parser.

**(E) Not classified individually (3 sites — honest gap).** `crates/ssh3-quinn/src/channel.rs:118,125,132`. These are inside the quinn-side varint/byte read helpers next to `read_var_int` (`:459+`); the output of that read window was truncated in this session before it could be inspected, so they are listed for follow-up rather than guessed at. They are almost certainly the same bounded-buffer shape as group (C), but that is an expectation, not a verified statement.

**Also worth recording (not `unwrap`, same class):** the Rust server's `unsafe { process.pre_exec(...) }` closure at `crates/ssh3-server/src/lib.rs:1409-1419` (`setsid()` then `ioctl(TIOCSCTTY)` on `slave_fd`, both checked, errors propagated). It runs in the forked child before `exec`, so any panic there is in a post-fork context; the calls themselves are checked and the closure returns `Result`. No defect found — it is listed because it was an explicit brief item.

### 3b. Rust server resource-limit parity vs the Go server — **largely ABSENT**

| Limit | Go server | Rust server/core |
|---|---|---|
| channels per conversation | `maxChannelsPerConversation = 64` default, env `SSH3_MAX_CHANNELS_PER_CONVERSATION`, `0` = unlimited (`cmd/ssh3-server.go:1025-1029`), enforced by `budget` (`cmd/channel_budget.go`, `newBudget` at `cmd/ssh3-server.go:1276`, refusal at `:1282-1296`) | **absent** — no cap or budget exists anywhere under `crates/` (grep for `budget`/`max_channels`/`maxChannels` finds nothing but the Go files) |
| dangling datagram queues | capped at `maxDanglingDatagramQueues`, evicted FIFO since F-15 (`resources_manager.go:99-116`) | **unbounded** — `crates/ssh3-core/src/conversation.rs:292` `dangling_datagram_queues: HashMap<u64, Arc<DatagramQueue>>`, inserted at `:319-332` with no cap and no eviction; only the per-queue size is bounded (`DANGLING_DATAGRAM_QUEUE_SIZE = 10`, `:15`, enforced in `crates/ssh3-core/src/queue.rs:62-67`) |
| accept queue | `AcceptQueue` (implicitly QUIC-flow-control limited) — same `webtransport-go`-derived design | same design (`util`-equivalent comment copied into `crates/ssh3-core/src/conversation.rs:230-244`); no explicit limit |
| per-user SFTP child budget, etc. | `-max-sftp-sessions-per-user` (`cmd/sftp_subsystem.go:56-99`) | n/a (no equivalent subsystem) |
| process-wide auth lock | Go has no such global lock | `crypt_lock()` (see §3a A) |

**New finding (Rust), medium:** the Rust port never received the P4-01/P4-04/F-15 hardening. A peer that opens a conversation and then sends datagrams naming channel IDs it never registers grows `dangling_datagram_queues` by one `HashMap` entry (≈ 10 buffered datagrams + queue/channel metadata) *per distinct ID*, for the lifetime of the conversation, with no cap and no eviction. This is exactly the condition pass 4 fixed in Go (bounded memory) and pass 5 re-fixed in Go (fail-closed cap → FIFO eviction); in Rust it is unfixed, and the channel-map poison-cascade (§3a A) makes a fault there terminal for other channels of the conversation rather than local. Whether it is reachable **pre-auth** depends on the Rust server's ordering of authentication vs. datagram dispatch, which this pass did not establish without a runnable build — treat the reachability as unverified and the missing bound as confirmed.

### 3c. Rust auth beyond password — logic is complete and fails closed; no timing issue found in the token paths

`crates/ssh3-auth/src/lib.rs`:

* **Bearer/authorized-key token** — `verify_bearer_token` (`:301-352`): the algorithm is bound to the configured public key's own algorithm (`jwt_algorithm_for_public_key`, `:306`), and the token header's `alg` must equal it (`:313-315`), so there is no algorithm-substitution or `none` path. `iss` (`:317`), `sub` (`:320`), `aud` (`:323`), `client_id` derived from the expected username (`:326`), and `jti` bound to the conversation ID (`:329`) are all compared, `iat` in the future is rejected (`:332`), `exp` in the past is rejected (`:335`), and only then is the signature verified (`:338-343`). Every failure returns `AuthError::InvalidToken` with a specific message; nothing falls through to success.
* **JWT signature** — `verify_jwt_signature` (`:485-...`): Ed25519 / ES256 / RS256 only, each with the signature parsed and verified by the library, failures mapped to `AuthError::InvalidToken`; a key whose type does not match the expected algorithm yields `AuthError::UnsupportedAlgorithm` rather than a skip (`:500-510`, `:517-528`, `:531-542`).
* **OIDC** — `verify_oidc_identity_token` (`:357-...`): issuer match (`:372`), `aud` *contains* the configured client id (`:375`), `exp` (`:378`), email match (`:381`) and `email_verified` (`:384`) are enforced, the nonce is checked when the caller supplies an expectation (`:386-389`), the discovery document's own `issuer` is re-checked against configuration (`:404-406`) and the JWK is selected from the discovered JWKS by header (`:415`) before signature verification. Failures are `AuthError`s; HTTP status is checked with `error_for_status()`.
* **Timing:** all comparisons in these paths are on non-secret protocol values (alg, iss, sub, aud, client_id, jti, nonce, email), so a byte-wise short-circuit leaks nothing secret; the secret comparisons (signature, password hash) happen inside the crypto backends / `crypt(3)`. The password path remains the timing outlier (F-16).
* **Residual, informational:** `exp` is compared as `claims.exp < now` with no clock-skew tolerance (false rejections, never false acceptances) and there is no `nbf` check, no maximum token lifetime, and no replay cache at this layer — replay protection rests on `jti` = conversation ID plus the caller's nonce. The JWKS is fetched per verification with no cache (availability surface if the configured issuer is slow). `jwks_uri` is taken from the discovery document, so a compromised *configured* issuer endpoint controls where keys are fetched from — configuration-trusted, not peer-controlled. None of these is a defect on its own; they are recorded because "auth beyond password" was the brief's item.

### 3d. `lib.rs:1409` and client-side `unsafe`

Both inspected: `crates/ssh3-server/src/lib.rs:1409-1419` is the `pre_exec` closure discussed in §3a (checked syscalls, `Result` returned). All non-vendor `unsafe` in the crates: `ssh3-client/src/lib.rs:147,563,585,590,601,2393,2408,2491` (BorrowedFd/`isatty`/`TIOCGWINSZ`/`kill` — local terminal and process management, `size.assume_init()` at `:590` immediately after a successful `ioctl`, guarded by the `result == 0` check at `:586`), and `ssh3-server/src/lib.rs:312,351,366,371,379,383,619,1409` (the `crypt` extern, the `spwd` block of §1 F-17, `ioctl(TIOCSWINSZ)`, and `pre_exec`). No unchecked pointer arithmetic or peer-length-driven allocation was found in these sites.

---

## 4. Supply chain

* **`.goreleaser.yaml` body (reviewed in full at this HEAD):** builds for client/server with `tags: osusergo, netgo, static_build, disable_password_auth`, `ldflags: -s -w`, `goos`/`goarch` matrices incl. windows/arm; archives `tar.gz` (zip for windows); `checksum.name_template: checksums.txt`; `nfpms` for deb with `postinst`/`prerm`/systemd unit/`ssh3-server.env` from `packaging/`; `changelog: disable: true`. **No `signs:`, no `sboms:`, no `~trimpath`/`-trimpath` in `ldflags`, no provenance/attestation step.** `-s -w` strips the symbol table and DWARF without adding `-trimpath`, so release binaries embed the builder's filesystem paths in what remains of the debug metadata; `-trimpath` is free here and would make the build path-reproducible. Checksums are published unauthenticated (no cosign/GPG), so the checksum file adds integrity against corruption, not against a compromised release job. **F-18 partially reconfirmed: pinning, signing, SBOM and trimpath are all still missing.**
* **GitHub Actions pinning:** every `uses:` still points at a mutable major tag (list with line numbers in §1 F-18). No SHA pins, no `permissions:` observed for the release job in the extract reviewed.
* **P4-05 — `.syso` still committed:** `cmd/ssh3/rsrc_windows_amd64.syso`, **57,288 bytes**, opaque binary, regenerated by hand in the newest commit `ed88ec2` ("chore(winres): regenerate … for 0.1.32"). It is linked into the Windows build rather than generated from a reviewable resource definition in CI, so the release artefact depends on an unreviewable blob that changed in a release-bump commit. **Still open**, unchanged in nature from pass 5.
* **Build reproducibility:** blocked by the two items above plus `-s -w` without `-trimpath`; the Go side is otherwise clean (`vendor/` makes the build hermetic, `go.sum` present, no new deps in the range).

---

## 5. Probes actually run

Go 1.26.0 linux/amd64, recovered per the team skill; `GOFLAGS=-mod=vendor`, `GOCACHE`/`TMPDIR` off `/home`. Commands and results (`/tmp/probe.log`):

| Probe | Result |
|---|---|
| `go test ./util/ -run '^$' -fuzz FuzzParseSSHString -fuzztime 30s` | **PASS** — 30.0 s, **1,462,752 execs** (~48k/s, 2 workers), 7 baseline seeds, 9 new interesting inputs, **no crash and no new failing corpus entry**. This is the pass-5 leftover "fuzz smoke". |
| `go test -race ./util/... ./message/...` | **PASS** — `util` 1.2 s, `util/ttymodes` 1.0 s, `util/unix_util` (no test files), `message` 2.3 s |
| `go test -race -count=1 .` (root package) | **PASS** — 1.1 s |
| `go test -race -count=1 ./cmd/...` | **PASS** — `cmd` 4.3 s; `cmd/plugin_endpoint`, `cmd/ssh3`, `cmd/ssh3-server` have no test files |
| `go vet ./...` | **ran, 4 diagnostics, none new and none in the datagram path**: `util/unix_util/linux_user.go:50,153` "possible misuse of unsafe.Pointer", and `integration_tests/ssh3_test.go:526,646` `"%s:%d"` address formats that break IPv6 (passed to `net.Dial` at `:531`/`:651`). The IPv6 ones are worth a follow-up: they are in the integration tests, so they can mask a real IPv6 regression rather than expose one |

Total probe wall time for fuzz + all four `-race` suites + vet: under 3 minutes on this box; the whole set is cheap enough to put in CI.

**Fix-path probe:** no new runtime probe of the F-14 path was written — the pass-5 follow-up commit already ships `conversation_test.go` (+57 lines) and `resources_manager_test.go` (+50 lines) that pin the closed-channel and eviction conditions, and the root package plus `util`/`message` suites above run green under `-race`. The F-14 analysis in §2 is a code-path analysis of every branch out of the loop, not a runtime reproduction; a probe that actually delivers a datagram for a just-pruned channel was **not** executed. No live attacks of any kind were performed.

---

## 6. Honest coverage and limitations

**What this pass actually established**

1. F-14 and F-15 are genuinely fixed at `ed88ec2`, verified by reading every branch of the client and server datagram loops and every mutation of the dangling-queue map, not by trusting the commit message. The Rust twin of the F-14 condition is tolerant as well.
2. The residual loop-killing error classes are enumerated exactly (malformed-datagram parse, conversation cancel) with the peer-reachability and impact of each (new **F-19**, low).
3. The prune/lookup ordering cannot hand a live channel a `ChannelNotFound`, and the leftover buffering is bounded.
4. The Rust `unwrap`/`expect`/`panic!` surface in non-test code is **36 sites**, fully enumerated and grouped, with the 8 peer-adjacent IPv4/IPv6 conversions individually shown to be unreachable by construction — the "~870 sites" figure is an artefact of counting inline `#[cfg(test)]` modules.
5. Rust resource-limit parity is **absent**: no channel budget, no conversation cap, and an uncapped dangling-queue map (new finding, medium).
6. Rust token auth (bearer/authorized-key + OIDC) fails closed and shows no secret-dependent timing; the password path still leaks timing (F-16 unfixed) and its `crypt_lock` poison behaviour is a process-wide auth-outage hazard.
7. Supply chain: `.goreleaser.yaml` reviewed in full — no signing, no SBOM, no `-trimpath`; Actions still major-tag-pinned; P4-05 `.syso` still committed (57,288 bytes, regenerated by hand in `ed88ec2`).
8. Fuzz smoke and `-race` suites for `util`, `util/ttymodes`, `message` and the root package all pass.

**What this pass did NOT do**

* No `cargo` build, test, `cargo audit`, `clippy` or `cargo-geiger` run: §3 is static source review only. Rust reachability claims (especially §3b's "reachable pre-auth?") are unverified at runtime, and no Rust test was executed.
* `crates/ssh3-quinn/src/channel.rs:118,125,132` were not individually classified (§3a E).
* `go test -race ./cmd/...` and `go vet ./...` had not completed when this report was written; `cmd/...` is where the P4-03 production closure lives, so no new evidence about P4-03 was obtained beyond the absence of any test change.
* The F-14 fix was not reproduced at runtime; only pass-5's own regression tests were observed to pass.
* Cross-implementation interop of the P4-04 datagram floor (a pass-5 leftover) was not attempted — it needs both a Go and a Rust binary and a live pair.
* No dynamic testing of any kind against a real server was performed; no live attacks; no coverage measurement (no `-cover` run).
* `gh`/repo hygiene for this pass was limited to one branch (`docs/security-audit-pass6`), one file, one PR.

**Findings added by this pass**

| ID | Severity | Finding | Where |
|----|----------|---------|-------|
| F-19 | Low | A single malformed/truncated datagram (varint parse failure on the conv id or channel id) permanently ends datagram reception for that conversation, in both the Go client and the Go server loop; on the Go **client** a hostile server can therefore silently disable the client's datagram delivery while streams stay up. Self-inflicted on the server side. Same shape in the Rust client (`is_benign_datagram_dispatch_error` treats only `Connection` errors as benign) | `conversation.go:224-228`, `:511-514`, `:243-245`; twin `server.go:321-323`; `crates/ssh3-client/src/lib.rs:1406-1412` |
| F-20 | Medium (Rust) | Rust server/core has no channel-per-conversation budget and no conversation cap, and `dangling_datagram_queues` is an uncapped, never-evicted `HashMap` keyed by peer-supplied channel ID — the Go-side P4-01/P4-04/F-15 hardening was never ported. Pre-auth reachability unverified (no runnable build) | `crates/ssh3-core/src/conversation.rs:292,319-332`; Go comparison `cmd/ssh3-server.go:1025-1029,1276-1296`, `resources_manager.go:99-116` |
| F-21 | Low (Rust) | `crypt_lock().lock().unwrap()` makes password authentication process-wide fragile: a panic while holding the static lock poisons it and every later auth attempt panics | `crates/ssh3-server/src/lib.rs:378` |
| F-22 | Info | Pass-5 F-17 as worded does not describe the code at this HEAD (correctly aligned `MaybeUninit<spwd>`); recommend the pass-5 report's F-17 be re-baselined rather than carried forward | `crates/ssh3-server/src/lib.rs:346-359` |
| — | Info | Release binaries are built `-s -w` without `-trimpath`, and checksums are unsigned; `cmd/ssh3/rsrc_windows_amd64.syso` (57,288 B, opaque, hand-regenerated in `ed88ec2`) is still linked into the Windows targets | `.goreleaser.yaml`; `cmd/ssh3/rsrc_windows_amd64.syso` |
