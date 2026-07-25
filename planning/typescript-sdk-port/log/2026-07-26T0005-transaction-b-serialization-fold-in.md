# 2026-07-26 00:05 UTC | transaction batch B, the error and serialization rows | `sdk-libs/transaction/src/serialization/`, `error.rs`

- Baseline: HEAD `aef149ef`; source [row-updates/transaction-b.md](../row-updates/transaction-b.md); oracle `sdk-libs/ts/transaction/test/oracles/transaction-parity-v1.json`
- Worker: Opus 5 reconciliation subagent
- Explanation: Six rows close. The batch's evidence is the generated oracle the first transaction batch built, extended from 72 replayed tests to 210, and I checked its currency rather than taking it: `cargo test -p zolana-transaction --test ts_oracle` passes both `the_typescript_oracle_matches_current_rust` and `every_variant_has_a_sample` at this HEAD, and the TypeScript replay passes 210 of 210. A stale oracle is the one way this evidence class fails quietly, so it is worth the three minutes to compile.
- Evidence: `sdk-libs/transaction/tests/ts_oracle.rs` runs the production Rust path and writes the committed fixture; `sdk-libs/ts/transaction/test/vectors/rust-oracle.test.ts` replays the same inputs through TypeScript.

## A rule about three test classes, written down rather than applied silently

Three of these rows were held open for "browser and export evidence", and one of them, `T09`, the batch closed while `T08` beside it stayed open on the identical wording. That is a sign the class was doing no work where it sat. The transaction package has neither an `exports.test.ts` nor a browser test, so the class is real and missing; what it is not is a property of any one behaviour row. It needs a build-and-pack harness, and the aggregate export rows `T10`, `T17`, `T26`, `T30`, and `T31` already ask for exactly that, six allowlist classes each.

So the rule is now in the Vocabulary section: a behaviour row closes on an executed comparison of its behaviour, and the export-allowlist, browser-runtime, and packed-artifact classes are held once per package on the aggregate rows and the gate blocks. The distinction that keeps this from being a loosening is that an export's *existence* is pinned by the oracle replay, which imports the symbol and fails if it goes. What the aggregate rows hold is the allowlist that catches an unintended *addition*, which no behavioural test can see.

Applying it uniformly closes `T08`, which the batch declined, on the same grounds the batch closed `T09`.

## Rows closed

- Verdicts: `PARITY` for `T01`, `T04`, `T05`, `T07`, `T08`, `T09`

`T01` is the one worth reading twice. It had the exhaustive Rust-to-TypeScript error map since the first batch, and it stayed open because a map is not a producer: five declared codes were raised by nothing. Each now has a named replayed case, so deleting a producer fails the suite.

`T05` closed on work that landed after the batch wrote its report, `c69d0a97`, which is why the file says the row was not reached. The oracle now perturbs a body the rail itself produced and compares which category each language sorts it into, seventeen cases across the two rails. That is the right shape for this row, because a published slot is attacker-chosen bytes and the rejection category is protocol surface rather than a convenience. Before the fix a key failure escaped as a `KeypairError` no transaction caller catches. The row's own wording asked for Rust `Decrypt` categories that do not exist, and the text now says what the categories actually are.

`T07`'s remaining half was an authority question, and the protocol owner has since ruled: amend the spec to define the memo record rather than delete it. That inverts the smallest fix the row carried, which is worth stating plainly in the row so nobody implements the old one.

- Gap and smallest fix: none outstanding on these six. The package-surface harness belongs to `T10`, `T17`, `T26`, `T30`, and `T31`
- Row transitions: `PARTIAL -> PARITY` for `T01`, `T05`, `T08`, `T09`; `DIVERGENT -> PARITY` for `T04` and `T07`; each `needs_fix -> done`
- Progress: `80/145` after this entry
- Exact next file: the rest of [row-updates/transaction-b.md](../row-updates/transaction-b.md), the builder and type rows
- Full SDK parity claim: unsupported
