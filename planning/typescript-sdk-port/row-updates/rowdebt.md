# Row debt: I01, W07, and W01/W03/W05 siblings

Worktree `zolana-ts-rowdebt`, branch `port/rowdebt`. Independent check of the
two spot-check findings in
[`certification-evidence.md`](../certification-evidence.md) §5, plus the three
Class-1 wallet siblings that also skipped the post-audit oracle reopen.

## Sync-delegate viewing key (the question that matters)

**Yes: Rust and TypeScript agree on all four cases.**

Oracle: `xtask/src/bin/program-libs-parity.rs` →
`sdk-libs/ts/vectors/program-libs-parity-v1.json` →
`userRegistry.senderViewingKeyRule`, replayed by
`sdk-libs/ts/wallet/test/vectors/program-libs-registry.test.ts`.

| Case | Record | Rust `sender_viewing_pubkey` | TypeScript `senderViewingPublicKey` |
| --- | --- | --- | --- |
| no-delegate | `minimal` | owner key | owner key |
| active-with-entries | `full` | latest `entries` key | latest `entries` key |
| active-empty-entries | `delegate-without-entries` | owner fallback | owner fallback |
| revoked-with-entries | `revoked-with-entries` (new) | owner key (leftover entries ignored) | owner key |

No divergence. The encrypt-to path
(`resolvedAddressFromRecord` → `senderViewingPublicKey`) uses the same rule.

## I01 - error code / name / message parity

**Spot-check confirmed.** The test named `matches every Rust error code and
message` compared only `{ code }`. Oracle and TypeScript both define **29**
codes, not 26. Codes and names already matched.

**Disposition: fixed in substance.**

- Added `ShieldedPoolErrorMessages` with the static Rust `Display` strings
  (none interpolate; literal comparison is valid).
- `decodeShieldedPoolError` now returns `message` on known codes.
- Oracle test compares `{ code, message }` and asserts length 29.
- Count corrected in `row-updates/interface-parity.md` (checklist left alone).

Evidence for the reconciler: `sdk-libs/ts/interface/src/errors.ts`,
`sdk-libs/ts/interface/test/vectors/rust-oracle.test.ts`, oracle
`sdk-libs/ts/interface/test/rust-oracle.json` (unchanged generator; already
emitted messages).

## W07 - sync-delegate viewing key

**Spot-check mostly confirmed, with one correction.**

Confirmed gaps:

- Checklist citations pointed at `registry.test.ts` (TS-only delegated case) and
  stale line ranges - pre-audit evidence shape for a fund-losing rule.
- No revocation vector in the Rust-generated oracle (active delegate with
  leftover `entries` after `sync_delegate` cleared).
- W07 skipped the post-audit oracle reopen cycle.

Correction to the spot-check: the empty-`entries` + active `syncDelegate`
fallback **was** already covered by `program-libs-registry.test.ts` against
`delegate-without-entries` in `program-libs-parity-v1.json`. The review looked
at W07's cited cell (registry.test.ts), not that oracle suite. Still not enough
for W07: revocation was missing, and the row did not name the regenerable
oracle.

**Disposition: fixed.**

- Extended `program-libs-parity` with `revoked-with-entries` and an explicit
  `senderViewingKeyRule` of the four cases above.
- TypeScript replays every case against Rust `expected` bytes.
- Regenerated `sdk-libs/ts/vectors/program-libs-parity-v1.json`.

What the reconciler should write into W07: PARITY on
`program-libs-parity` / `senderViewingKeyRule` +
`program-libs-registry.test.ts` `sender viewing key rule (W07)`, not on the
old `registry.test.ts:189-204` line range alone.

## Sibling check: W01, W03, W05

Checked whether each cell's cited evidence actually supports PARITY. Did not
rebuild rows that already clear the bar.

### W01 - adequately supported

Cited: Rust-generated `fixtures/wallet/create_associated_token_account.json`
(via `ts-fixtures` / `ts_fixtures_wallet.rs`) and
`wallet.test.ts` pinning derived address + compiled message bytes.

Verified: the fixture carries the P00 schema fields and is produced by the
wallet fixture generator; the test compares `result.address` and signed
`messageBytes` to the oracle. That is regenerable cross-language evidence for
the ATA action. **No rebuild.**

### W03 - supported for the oracle-backed path; residual on untested arms

Cited: `fixtures/wallet/submit.json` (CU limit `1400000`, `MergeDisabled`,
`MergeTreeMismatch`) and `submit.test.ts` covering those two rejections;
re-review line-reads for `treeCheckedIndexer` and the three key-mismatch codes.

Verified:

- Fixture and tests do pin CU limit, merge-disabled, and tree mismatch.
- Cell itself admits: "Untested: the three key-mismatch codes have no test."
- No test exercises `treeCheckedIndexer` rejecting a wrong *indexer-returned*
  proof tree (the existing `WALLET_MERGE_TREE_MISMATCH` case hits the
  client-tree / submit-tree check).

Not as thin as W07 was (there is a regenerable fixture for the happy path and
two errors), but PARITY overclaims the three mismatch codes and the indexer
proof-tree guard. **Do not rebuild here** - assign: add oracle or unit cases
for `WALLET_MERGE_SIGNING_KEY_MISMATCH`,
`WALLET_MERGE_NULLIFIER_KEY_MISMATCH`,
`WALLET_MERGE_VIEWING_KEY_MISMATCH`, and an indexer proof whose
`state_tree` / `nullifier_tree` disagrees with the submit tree. Until then the
reconciler should narrow the cell (PARTIAL on those arms) or leave PARITY with
that residual explicit.

### W05 - adequately supported, with the residual the cell already names

Cited: `export-vector.test.ts` accounting for all thirty `actions/mod.rs`
re-exports; residual that `xtask` still writes a hand-typed nine-name
`mod.json` allowlist.

Verified:

- Counted thirty names in `actions/mod.rs:10-24` (four `_sync` adapters).
- Test pins exact TypeScript runtime key set and typechecks the erased names;
  dispositions exist for sync adapters / `MergeMaterial`.
- Unlike W06, this test does **not** parse `actions/mod.rs` at test time - the
  `names` map is hand-maintained. A Rust-added export fails nothing until that
  map is updated. The cell already records this as an xtask follow-up.

Surface evidence is enough for today's PARITY claim. Drift protection is
weaker than W06's source-parsed ledger. **No rebuild** unless the reconciler
wants the same parse-Rust treatment W06 has.

## Checklist edits for the reconciler

Do **not** applied here (`review-checklist.md` is reconciler-owned). Needed:

1. **I01** - notes: 29 codes/names/messages; test compares
   `ShieldedPoolError` + `ShieldedPoolErrorMessages` to oracle `{ code, message }`.
2. **W07** - replace stale `registry.test.ts` line cites with
   `program-libs-parity-v1.json` `senderViewingKeyRule` +
   `program-libs-registry.test.ts` W07 block; keep PARITY.
3. **W03** - either PARTIAL on the three untested mismatch codes + indexer
   proof-tree arm, or keep PARITY with that residual spelled as open debt.
4. **W01**, **W05** - no verdict change; optional note that sibling audit
   confirmed evidence still holds.

## Commands run

```bash
cargo run -q -p xtask --bin program-libs-parity
npm run build
npx vitest run sdk-libs/ts/interface/test/vectors/rust-oracle.test.ts \
  sdk-libs/ts/interface/test/interface.test.ts \
  sdk-libs/ts/interface/test/exports.test.ts \
  sdk-libs/ts/wallet/test/vectors/program-libs-registry.test.ts \
  sdk-libs/ts/client/test/solana-rpc.test.ts
cargo fmt --all
npm run check:static   # green
```
