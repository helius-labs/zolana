# 2026-07-25 23:35 UTC | the audit tail, `E03` and `K10`, and one routing call | `program-libs/event/`, `sdk-libs/keypair/`

- Baseline: HEAD `1b10b87c`; sources [row-updates/quality-and-completeness-audit.md](../row-updates/quality-and-completeness-audit.md), [row-updates/keypair-error-redaction.md](../row-updates/keypair-error-redaction.md), [row-updates/open-threads-2026-07-25.md](../row-updates/open-threads-2026-07-25.md)
- Worker: Opus 5 reconciliation subagent, finishing the fold the earlier commit `34b50199` left partway
- Explanation: Three items, none of which moves a verdict. Two record evidence that arrived from a second direction, and one answers a routing question the coordinator raised rather than a parity question.
- Evidence: For `E03`, the audit's scan of each `export` in the `src` trees against references elsewhere in the workspace. For `K10`, the four control edits in the redaction review, each applied and the intended assertion observed to fail. For `W02`, the coordinator's own note plus the row's history.

## `E03`, confirmed unreachable, still undecided

- Verdict: `NOT_APPLICABLE` for `E03`, unchanged

The row said `OutputUtxo` was unreachable and recorded that as a disposition nobody had confirmed. The audit reached the same conclusion independently by scanning exports against references across the workspace, tests included, and found it among eight symbols with no consumer. So the fact is settled by two workers on different routes, and the row still cannot close, because what to do about it is a separate call: delete the type, or move it behind whatever eventually decodes `GeneralEvent`. A confirming reviewer should know which half is done.

## `K10`, closing evidence rebuilt rather than restated

- Verdict: `PARITY` for `K10`, unchanged

The redaction review found the test behind this row's data-exposure claim weaker than it read: each key in its fixture sat outside `KeypairErrorDetails`, so it demonstrated that unknown keys are dropped without touching the one shape that can carry a secret, a value under a known key. Four control edits confirm the replacements fail when they should. The fourth is the one worth remembering, because it is the failure mode this queue keeps meeting: making `safeCause` keep `cause.cause` fails the new test while the pre-existing test passes, so a change reconnecting the client to the underlying dependency error would have landed green.

The direction against Rust runs opposite to the usual finding, so the row now says it plainly. TypeScript carries more structured detail, since Rust's error derives `Copy` and holds three integers at most, and TypeScript strips more, since `safeCause` rebuilds the cause and drops the link to the dependency error while Rust's `#[from]` keeps the keypair error reachable through `source()`. Both are deliberate.

One residual is recorded by a test rather than argued away: the allowlist bounds which keys survive, not what they hold, so the guarantee rests on the call sites and a source scan now enforces that. Capping allowlisted string values in the low forties would turn that discipline into a runtime invariant.

## `W02` is unowned, not blocked

- Verdict: `STALE` for `W02`, unchanged

The coordinator asked for a routing call rather than a verdict, so this is one. Nothing blocks the row: its finding was re-reviewed to parity and the fixture regeneration has landed. It stayed open because it sits in `wallet/src/deposit.ts`, outside the packages the last wallet worker held, and that worker would not record a verdict it had not measured. `STALE` is right for the state it is in, because the deposit tag ruling moved its canonical Rust after the review, and a reader should not take it for blocked. It goes to the next wallet-package batch, and the work is one test rewired to derive from the recipient address instead of from the expected hash.

- Gap and smallest fix: `E03`, an owner call between deleting the type and placing it behind a `GeneralEvent` decoder. `K10`, cap the allowlisted string values. `W02`, drive `deposit-vector.test.ts` through `createDeposit`
- Row transitions: none. Evidence recorded on `E03` and `K10`, ownership recorded on `W02`
- Progress: `74/145`, unchanged
- Exact next file: none outstanding; the baseline block and the README status are next
- Full SDK parity claim: unsupported
