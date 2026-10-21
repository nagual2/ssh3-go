# Agent kickoff prompt

Copy the block below into the agent (cto.new). It is intentionally short — the authoritative brief is `CTO_TASK.md` in the repo root.

---

You are a senior systems engineer working autonomously in this repository (`nagual2/ssh3-go`, a fork of francoismichel/ssh3). The Rust rewrite that used to live here was extracted into its own repository, `nagual2/ssh3-rust`, on 2026-10-21.

**First action:** read `CTO_TASK.md` in the repository root. It is the authoritative task brief: current state, ground rules, staged roadmap, concrete bug entry points (files and line numbers), and acceptance criteria. Follow it exactly.

**Your scope for this run: Stage 1 — Reliability (P0) only.** That is the four reproduced bugs listed in Section 4 of `CTO_TASK.md`:

1. Client never signals EOF after stdin exhaustion (remote `cat` hangs) — `client/client.go` stdin pump.
2. Server panic on abrupt client disconnect (`util.VarIntLen` ← `ExitStatusRequest.Length`, negative exit status) — `util/wire.go`, `message/channel_request.go`, `cmd/ssh3-server.go`.
3. Client exits rc=0 on silently truncated transfers — exec result handling.
4. Client SIGSEGV on missing `--privkey` file — `privkey_auth.go` → `client_auth.go:331`.

Work one task per PR, in order 1→4. For each: root-cause analysis first, then a failing regression test (red), then the fix (green), then a short PR description stating which task number it closes and what tests prove it.

**Ground rules (Section 3 of `CTO_TASK.md` apply in full):** tests first; small PRs, conventional commits; no new dependencies without written justification; no telemetry; the Go implementation must keep building (`CGO_ENABLED=0 go build -mod=mod -tags disable_password_auth ...`). The Rust workspace, its `cargo build --workspace` gate and the deliberate `vendor/h3` patch moved to `nagual2/ssh3-rust` — that patch is still off-limits, but it is maintained there, not here.

**Definition of done:** full `cargo test` (run in the `ssh3-rust` checkout) and the Go test suite green; all four scenarios covered by automated tests; a manual 512 MiB transfer stress run (10 iterations including abrupt client kills) leaves the server alive with bit-identical completed transfers. Do not start Stage 2 (file transfer) — that is a separate run.

If a task proves infeasible as specified, stop that task and document why in the PR instead of shipping something weaker silently.
