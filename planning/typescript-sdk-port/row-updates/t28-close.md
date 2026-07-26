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

## What changed

Both languages moved. Neither normalized before, so this is not TypeScript
catching up to Rust; the two were in agreement and the agreement was the defect.

Rust, `sdk-libs/transaction/src/`:

- `utxo.rs` gains `normalize_zone_data_hash`, beside the existing zone helpers.
- `instructions/types.rs`, `SppProofInputUtxo::with_zone_data_hash` applies it.
- `instructions/transact/types.rs`, `SppProofOutputUtxo::with_zone_data` and
  `with_zone_data_hash` apply it.
- `MergeZone::new` needed no change: its `Some` arm routes through
  `with_zone_data_hash`, so an explicit zero now lands where the `None` arm
  already did.

TypeScript, `sdk-libs/ts/transaction/src/utxo.ts`:

- `normalizeZoneDataHash`, the mirror of the Rust helper.
- The `ProofInputUtxo` constructor applies it before the canonicity check.
- `createProofOutput` applies it once and both `withZoneData` and
  `withZoneDataHash` inherit it, since they re-enter the factory.

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

One test per construction site, each asserting both halves of the split so the
address clause is enforced by the suite rather than by memory:

- `an_explicit_zero_normalizes_at_the_zone_data_hash_and_not_at_the_zone_address`
  in `sdk-libs/transaction/src/instructions/types.rs` (input builder) and in
  `.../instructions/transact/types.rs` (both output builders).
- `normalizes an explicit zero at the zone data hash and not at the zone address`
  in `sdk-libs/ts/transaction/test/core.test.ts`.

Watched failing under two control edits rather than merely passing. Dropping the
normalization fails the first half of all three; normalizing the zone address,
in Rust at `program_id_field` and in TypeScript at `commitmentFields`, fails the
second half of all three.

Suites run green afterwards: `cargo test -p zolana-transaction -p zolana-wallet`,
`cargo clippy -p zolana-transaction --all-targets`, and the TypeScript unit run
at 1942 passing after `npm run build`.

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
