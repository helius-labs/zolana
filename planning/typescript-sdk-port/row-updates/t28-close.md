# T28: the zone data hash normalization, and the clause that was not taken

Worker on branch `port/t28-close` from `d0e86036`. Scope held to `sdk-libs/`
(both languages) and this planning directory. Nothing in `programs/`,
`program-libs/`, `prover/`, `xtask/`, or `docs/spec.md` was touched.

## The ruling this implements

The owner's answer to question 10 is `data_hash_only`. The earlier answer,
recorded the same day, was to normalize an explicitly-passed zero rather than
refuse it; writing it down showed that one sentence was being applied to two
clauses that cost differently, so the owner split it.
[`authority-rulings.md`](../authority-rulings.md#q10-an-explicitly-passed-zero-at-a-zone-binding-t28)
carries the reasoning. The short form:

- **Zone data hash: normalize.** `Some([0u8; 32])` and `None` already reached the
  commitment as the same field, so the prepared value was the only thing keeping
  them apart. Closing that gap moves nothing.
- **Zone address: leave alone.** `Some([0u8; 32])` there commits to `pk_field(0)`,
  a non-zero field the circuit reads as zone-bound. Normalizing it would make the
  same UTXO unbound, which is a change to what the commitment says. No refusal
  either: such a UTXO cannot settle on chain, so a guard would tighten a
  constructor past Rust for a case no caller reaches.

## What changed, and who changed it

Both languages needed it. Neither normalized before, so this was not TypeScript
catching up to Rust; the two agreed, and the agreement was the defect.

**Rust moved twice and ends up here.** `994574a0`, on `port/rulings-impl`,
landed `normalized_zone_data_hash` in `sdk-libs/transaction/src/utxo.rs` and
applied it at `SppProofInputUtxo::with_zone_data_hash`,
`SppProofOutputUtxo::with_zone_data`, and
`SppProofOutputUtxo::with_zone_data_hash`, under the interim authorization that
released the data-hash half before the owner confirmed the split. This branch
had written the same change independently and yielded to theirs on first merge.
That worker then reverted their own commit in `5cae755c`, on the reasoning that
two normalizers cannot share three call sites and T28 was dispatched here; the
revert reached this branch on the second merge and took the input-side call site
and its two tests with it, while leaving the output side and the helper standing.
So the wording of the helper and the output sites is theirs, the input site and
its tests are restored here, and the three call sites travel together again.
`MergeZone::new` needs no change either way, because its `Some` arm routes
through `with_zone_data_hash`.

**TypeScript is this branch's**, in `sdk-libs/ts/transaction/src/utxo.ts`:

- `normalizeZoneDataHash`, the mirror of the Rust helper.
- The `ProofInputUtxo` constructor applies it before the canonicity check. A
  zeroed `Uint8Array` is truthy, so the old `if (input.zoneDataHash)` took the
  present branch.
- `createProofOutput` applies it once, and `withZoneData` and `withZoneDataHash`
  inherit it because they re-enter the factory.

## Two things deliberately left where they were

`ExternalData::with_zone_hashes` and its TypeScript counterpart. That `Option` is
presence-tagged in the instruction bytes rather than folded through
`unwrap_or_default`, so collapsing it would move what is submitted rather than
only what is prepared. It also sets `data_hash` and `zone_data_hash` as a guarded
pair, and normalizing one of the two would break that symmetry.

The dummy-canonicity rule. A zero-owner input whose `zone_data_hash` field is
assigned directly is still rejected with field `zone_data_hash`, in both
languages. That rule was the counterargument the ruling declined to follow, and
it is untouched; what changes is that the builder no longer produces the value
for it to catch.

## What pins it

The data-hash half is covered by
`an_explicit_zero_zone_data_hash_is_stored_as_absence` and
`a_non_zero_zone_data_hash_is_kept`, one pair in
`sdk-libs/transaction/src/instructions/types.rs` and one in
`.../instructions/transact/types.rs`. Both pairs are worded as `994574a0` wrote
them; the input pair came back with the call site the revert removed. What was
missing is the other half of the split, so nothing in the suite objected if a
later worker extended the normalization to the zone address. This branch adds:

- `the_zero_zone_address_stays_bound_rather_than_normalizing`, beside each pair,
  asserting that the zero zone address still resolves to `pk_field(0)` and that
  the resulting commitment differs from the unbound one.
- `the_zone_data_builder_normalizes_the_explicit_zero_too`, because the existing
  output test exercised `with_zone_data_hash` and left `with_zone_data`
  uncovered.
- `normalizes an explicit zero at the zone data hash and not at the zone address`
  in `sdk-libs/ts/transaction/test/core.test.ts`, which asserts both halves in
  one case, TypeScript having had neither.

Watched failing under two control edits rather than merely passing. Dropping the
normalization fails the data-hash assertions; normalizing the zone address, in
Rust at `program_id_field` and in TypeScript at `commitmentFields`, fails the
address assertions.

Suites run green afterwards, at the third merge of `ts-sdk-port`:
`cargo test -p zolana-transaction`,
`cargo clippy -p zolana-transaction --all-targets`, `npm run typecheck`,
`npm run lint`, `npm run format:check`, and the unit run at 1983 passing after
`npm run build`. The `ts_oracle` comparison is included and passes; it was red
between the first two merges because the other worker regenerated the committed
oracle for the same normalization in `1e6dab57`.

## What the row should now say

`T28` stays `needs_fix` / `PARTIAL`. Two of its three clauses are settled and one
of those settled by ruling rather than by code:

- Clause one, refusing the zero zone address: **ruled not to be taken.** The row
  should stop carrying it as owed work. It is not deferred and it is not open.
- Clause two, the explicit zero zone data hash: **done**, both languages.
- Clause three, refusing a zone data hash at or above the BN254 modulus:
  **untouched and still owed.** It refuses nothing that succeeds today, relabels
  a `TRANSACTION_KEYPAIR` raised at hashing time into a named error raised at the
  supplying call, and may land in either language first. It is the only thing
  left between this row and `PARITY`.
