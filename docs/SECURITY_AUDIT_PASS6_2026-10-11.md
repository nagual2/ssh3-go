# Security audit — pass 6 (2026-10-11)

**Repository:** nagual2/ssh3-go (Go server/client; Rust rewrite under `crates/`)
**Audited HEAD:** `ed88ec2da6066a8b0295fe9925ecabc2fcedf746` (origin/main, "chore(winres): regenerate rsrc_windows_amd64.syso for 0.1.32")
**Baseline:** `e760a88` (pass-5 baseline)
**Mode:** REPORT-ONLY. No code changes in this PR; the only artefact is this document.
**Scope of this pass:** verify the pass-5 findings are actually fixed (owner says they are), hunt regressions around the F-14 fix, and close the coverage holes pass 5 left open (Rust reachability, Rust resource-limit parity, Rust auth beyond password, supply chain, and the fuzz/race probes).

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

Only one substantive code change landed between the pass-5 baseline and this HEAD: `cd5403e` (F-14 + F-15). Everything else in the range is the pass-5 report itself (#11), its merge, a follow-up merge (#12), and release chores. That materially narrows this pass: the fix-verification questions for F-16..F-18, P4-03 and P4-02-gap are questions about *whether a fix exists at all* at this HEAD, since no commit in the range claims them.

---

## 1. Fix verification

| ID | Pass-5 finding | Status at `ed88ec2` | Evidence (file:line at audited HEAD) |
|----|----------------|---------------------|--------------------------------------|
| F-14 | Client datagram loop treats any `AddDatagram` error as terminal → one late datagram for a pruned channel kills datagram reception for the whole conversation | **FIXED** (see §2 for the regression hunt and the residual error classes) | `conversation.go:231-247` — `switch e := err.(type) { case util.ChannelNotFound: log.Warn… continue; default: … return }` |
| F-15 | 256 dangling-queue slots never reclaimed → junk IDs permanently occupy the bound | **FIXED** | `resources_manager.go:99-116` (FIFO `danglingOrder`, evict oldest), `resources_manager.go:75` (handover removes the ID from the eviction order), `resources_manager.go:142-149` |
| F-16 | Rust `crypt(3)` verify: username/hash comparison timing, no lockout inside the function | **TBD** | §3c |
| F-17 | align-1 buffer for `struct spwd` in Rust FFI | **TBD** | §3c |
| F-18 | GH Actions pinned by major tag only; no signing / SBOM / trimpath | **TBD** | §4 |
| P4-03 | Regression test injects its own spawn stub; production `spawnChannel` closure never exercised | **TBD** | §1 note below |
| P4-02-gap | `CancelRead` does not prune `channelsManager` | **TBD** | §1 note below |

*(table completed in the sections below; this is the committed skeleton)*

### P4-02-gap — one-line status

`channel.go:483-485` at this HEAD is still `func (c *channelImpl) CancelRead() { c.recv.CancelRead(42) }` — no `onChannelClose`/`removeChannel`. The prune added by the P4-02 fix lives in `Close()` (`channel.go:487-497`), which is a *different* method. Whether `CancelRead`-without-`Close` leaves a channel registered is analysed in §2.

---

## 2. Regression hunt, deepest attention on F-14

### 2a. Client loop vs server twin — parity confirmed

| | client | server |
|---|---|---|
| site | `conversation.go:215-251` | `server.go:296-330` |
| `ChannelNotFound` handling | `case util.ChannelNotFound:` → `log.Warn` and continue (`conversation.go:233-242`) | `case util.ChannelNotFound:` → `log.Warn` and continue (`server.go:318-320`) |
| other errors | `log.Error` then `return` (`conversation.go:243-245`) | `log.Error` then `return` (`server.go:321-323`) |
| log text | "dropping datagram for unknown channel %d on conversation %d" | "could not find channel %d, queue datagram in the meantime" |

The server-side twin remains tolerant at this HEAD. The two switches are structurally identical, so F-14 is genuinely closed in both directions and no new asymmetry was introduced by `cd5403e` (the commit edited only the client loop, `conversation.go`, and the manager).

One cosmetic divergence, **not** a security finding: the client compares the receive error with `err != context.Canceled` (`conversation.go:218`) while the server uses `errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed)` (`server.go:305`). Both branches `return` regardless, so behaviour is the same; the client simply logs an `ERROR`-level line ("could not receive message from conn: …") on an ordinary teardown where a wrapped cancel or `net.ErrClosed` arrives. Log noise, not a functional regression.

### 2b. Which error classes still kill the loop

Every path out of the client loop's `AddDatagram` call:

```
conversation.go:230  err = c.AddDatagram(...)
   └─ conversation.go:509-523  AddDatagram
        ├─ :511-514  util.ReadVarInt error            → returned as-is  → default: → RETURN (terminal)
        ├─ :515-521  channel not in manager           → ChannelNotFound → warn + continue  (F-14 fix)
        │            (and buffers into a dangling queue)
        └─ :522      channel.waitAddDatagram          → channel.go:457-459
                      └─ util/util.go:150-157 DatagramsQueue.WaitAdd
                           ├─ queue has room            → nil
                           └─ ctx.Done()                → context.Cause(ctx) → default: → RETURN
```

and before that, the conv-id parse at `conversation.go:224-228`.

So after the F-14 fix exactly two error classes can still end the loop:

1. **`util.ReadVarInt` failure on a malformed/truncated datagram** (`conversation.go:224-228` for the conv ID, `conversation.go:511-514` for the channel ID). This is the only remaining *peer-triggerable* terminal path. Reaching it needs a datagram shorter than a varint for the conv ID / channel ID — trivially constructible. Consequences: on the **server**, a malicious client can only switch off datagram delivery for its own conversation (self-DoS — streams keep working, `Close()`/teardown unaffected); on the **client**, a malicious or buggy server can silently disable the client's datagram reception for the rest of the connection while streams stay alive. No confidentiality or integrity impact, no cross-conversation impact (the loop is per-conversation), but it is silent degradation of a transport feature in an authenticated session. Impact: low. Finding **F-19**.
2. **Conversation context cancellation** (`util/util.go:154-155` → `context.Cause`) and the transport-level `ReceiveDatagram` error (`conversation.go:217-222`). Both mean the conversation is going away, so returning is correct, not a regression.

`ChannelNotFound` is no longer in that set, which is exactly what F-14 asked for. No *other* error class silently kills the loop; there are only these.

**Residual liveness note (not new, not a pass-5 regression, no error involved):** `DatagramsQueue.WaitAdd` (`util/util.go:150-157`) *blocks* until the per-channel queue has room. A channel whose consumer never reads its datagrams therefore head-of-line blocks the conversation's single datagram receive loop, i.e. datagrams for that conversation's other channels (up to the QUIC datagram flow-control window). Within one conversation the peer is the only party affected, and the queue size is peer-declared/bounded, so this stays a self-DoS inside one conversation. Worth noting for the multiplexed/control-master work (stage 3.5) where “that conversation” may be shared by several sessions.

### 2c. Can the prune still fire `ChannelNotFound` toward a live channel?

The prune and the lookup order as they stand at `ed88ec2`:

```
channelImpl.Close()            channel.go:487-497   → channelCloseListener.onChannelClose(c)
                                                       → resources_manager.go:135-137 onChannelClose
                                                       → resources_manager.go:129-133 removeChannel (under lock)
Conversation.AddDatagram()     conversation.go:515   → channelsManager.getChannel (lock, map read)
                               conversation.go:519   → channelsManager.addDanglingDatagramsQueue
                                                       → resources_manager.go:88-92 re-checks m.channels under the
                                                         same lock before buffering
```

* The map is only ever mutated under `m.lock`, and `removeChannel` is the sole delete from `m.channels` (`resources_manager.go:132`). A channel leaves the map **only** after `Close()` has been called on it, so a channel that is still live (not closed) cannot be pruned — a `ChannelNotFound` cannot be produced for a channel the application is still using. The re-check at `resources_manager.go:88-92` closes the lookup→buffer race: if the channel registered between the two lock acquisitions, the datagram is handed to the live channel instead of being buffered.
* The one path that does remove a channel that has not yet been used by the application is the pre-existing P4-02 behaviour: a channel refused by the conversation's channel budget right after `AcceptChannel` registered it gets `Close()`d, hence pruned. Datagrams racing that close now take the F-14 `ChannelNotFound` branch and are buffered into a *dangling* queue which no channel will ever claim, so they are dropped when the conversation ends. That is bounded memory (`maxDanglingDatagramQueues` × `danglingDatagramQueueSize`, i.e. 256 × 64 datagrams per conversation), not an unbounded leak — and the alternative (killing the loop) was the actual F-14 bug.
* Conclusion: **the F-14 fix is complete for the ordering it has to survive**; the prune cannot be observed as `ChannelNotFound` by a live channel's reader, and the residual buffering is bounded.

### 2d. F-15 fix re-checked for desync

The eviction order is only a correct bound if `danglingOrder` and `danglingDgramQueues` stay in step; if an entry were removed from the map without the slice (or vice versa), eviction would silently stop deleting real entries and the map could grow past the cap. At this HEAD the map is mutated in exactly three places, all under `m.lock`:

* `resources_manager.go:74-75` — handover in `addChannel`: `delete(map)` **and** `removeChannelID(order)`;
* `resources_manager.go:110` + `:109` — eviction: `delete(map, order[0])` **and** `order = order[1:]`;
* `resources_manager.go:114-115` — insert: `map[id] = queue` **and** `order = append(order, id)`, reachable only when `!ok` (a repeated unknown ID extends its existing queue and does **not** append a duplicate order entry).

No path touches one without the other, the queues die with the manager when the conversation ends, and a repeated unknown ID cannot pad the order slice. The cap holds and the pass-5 fail-closed behaviour is genuinely gone: the N+1-th junk ID now evicts the oldest junk queue rather than being refused. **F-15 FIXED, no residual.**

---

## 3. Rust coverage expansion

*(pending — see committed skeleton)*

## 4. Supply chain

*(pending — see committed skeleton)*

## 5. Probes

*(pending — see committed skeleton)*

## 6. Honest coverage and limitations

*(pending — see committed skeleton)*
