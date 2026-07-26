# 2026-07-26 01:20 UTC | reconciliation: the deposit-tag residue is confirmed and the transport rewrite is reviewed | `I07`, `I19`, `I26`, `A01`

- Baseline: HEAD `767dc271`, the `ts-sdk-port` tip, merged into `port/reconcile3`
- Worker: reconciler, fourth holder of the role
- Explanation: four rows were each held open by one named condition rather than by an open question. Both conditions are met at this HEAD, and both were checked here rather than taken from a worker's report
- Evidence: `npm ci && npm run build` on a fresh worktree, then `test:unit` (1941 passed, 1 skipped), `test:vectors`, `test:property`, `test:cross` and `test:prover`, each passing; one control edit per closure, applied through `tools/control-edit.mjs` and observed to fail

## The deposit discovery tag, `I07`, `I19` and `I26`

The three rows named one residue between them: nobody had confirmed that the
regenerated wallet deposit fixtures write the tag the owner ruled for. They do.

`xtask/src/ts_fixtures_wallet.rs:316` derives the fixture's tag through
`recipient.shielded_address()?.confidential_view_tag()?` and writes it out at
`:366`, so the recorded bytes come from the ruled derivation in Rust rather than
from a TypeScript expectation. `wallet/test/vectors/deposit-vector.test.ts:126`
asserts the fixture's `viewTagBytes` equals `recipient.confidentialViewTag()`
computed from that same fixture's recipient, and `:127` asserts it is not the
viewing public key's x-coordinate, which is the value the pre-ruling derivation
produced. A regeneration from the old derivation therefore fails the row rather
than moving the expectation with it.

Control edit, run here: pointing `createDeposit` at
`params.recipient.viewingPublicKey.x()` instead of `confidentialViewTag()` fails
two cases, "derives the recipient owner hash and view tag through createDeposit"
and "tags a deposit with the recipient signing pubkey".

`sdk-libs/wallet/src` has not moved since `BASELINE_SHA`, so the deposit fixture
is current against the generator that wrote it. The three drifted paths reported
by `fixtures:check` at this HEAD are elsewhere and are recorded in the baseline
block.

Neither language derives, validates or interprets the tag inside the interface
package: `DepositIxData::view_tag: [u8; 32]` is copied through, and so is
`writer.bytes(value.viewTag, 32, "viewTag")`. Nothing else in these three rows
depended on the confirmation, and their codec, builder and payload halves were
already evidenced by the interface parity batch.

## The transport rewrite, `A01`

The row kept `PARITY` and left `done` so that `quoteUnsafeIntegers` would be read
by someone other than its author, and asked that the reading wait for the
per-field reconciliation. That reconciliation is merged and verified in the tree,
so the row is eligible and this is the reading.

The scanner is sound on the two cases Light Protocol's regex gets wrong, and the
report that ported it said so; both are now pinned. It skips string literals with
escape handling, so a digit run inside a base64 payload is left alone, and it is
position-agnostic, so an oversized array element is quoted where Light's
key-and-colon pattern misses it. `isUnsafeIntegerLiteral` requires
`/^-?[0-9]+$/`, so a float, an exponent and `1e999` are consumed whole and left
alone rather than half-quoted.

Four executed cases in `api/test/transport.test.ts` hold it, and two of them are
controls: a safe integer and a negative block time decode as they were sent, and
a twenty-digit run inside a string payload survives. A third is the seam,
`refuses an oversized value on a field the tree height caps, quoted or not`,
which pins that quoting cannot smuggle a value past a per-field cap.

What the row already claimed is untouched: `api/test/vectors.test.ts` replays the
Rust-generated `fixtures/api/transport-v1.json` over the five methods, both
nullifier start-sequence paths, request bytes, decoded responses, limits and
shared errors.

One thing recorded rather than fixed, because it belongs to a different row. The
combined stack still refuses an oversized value on a capped field where Rust's
`serde` reads it into the declared `u64`. That refusal is raised by
`indexer-api/src/codec.ts`, which `X01` owns and `C04` records, and both stay
adverse on it.

- Verdict: `PARITY` for `I07`, `I19` and `I26`, closed on the confirmed deposit tag
- Verdict: `PARITY` for `A01`, unchanged, and the row returns to `done`
- Row transitions: four rows to `done`
- Progress: `102/145`
- Exact next file: `K11`, first at `needs_re_review` in queue order
- Full SDK parity claim: unsupported
