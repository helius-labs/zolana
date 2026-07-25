# Rust residuals: the zone-hash commitment test and the zone-authority public leg

Two Rust-side loose ends from the TypeScript port, closed in `af5d95c0` and
`5f5ae90a`. SDK crates only; nothing under `programs/`, `program-libs/`,
`prover/`, or `docs/spec.md` was touched.

## 1. `input_commitments_include_data_and_zone_hashes` failed on the committed tree

Root cause: commit `6882ca25`, "fix(transaction): enforce canonical asset and
zone pairs". It added the rule that a proof input carrying a nonzero
`zone_data_hash` must name a zone program, in `ProofInputUtxo::with_zone`
(`bc55a9b9` later re-checked it in `hash()` because the fields are public). The
wallet test builds its input through `p256_input`, which sets
`zone_program_id: None`, and then sets `spend.zone_data_hash = Some([12u8; 32])`.
That pair was legal when the test was written in #134 and became invalid with
`6882ca25`.

The failure was in the test's own expected-hash computation
(`sdk-libs/wallet/tests/transaction.rs:769`, `Utxo::hash` returning
`MissingZoneProgramId`), not in the SDK path under test, which is why it read as
unexplained: the panic points at a line that only prepares the assertion.

Neither candidate raised as a likely cause is involved. `1ff51a4c` (deposit tag
to the recipient signing pubkey) touches `actions/deposit.rs`, `wallet_data.rs`,
and a validator test; `b416a64f` reverts interface transact instruction data.
Neither reaches the UTXO commitment.

Disposition: the expectation is real and unchanged. The input commitment must
bind both the data hash and the zone hash, and the assertions on `utxo_hash` and
`nullifier` still fail if either is dropped. Only the fixture was stale, so the
input now carries a zone program and the test asserts exactly what it did
before. The rule itself is `JUSTIFIED` against the circuit per
`rejection-validation.md:66`, so the code was the right side to keep.

## 2. `ZoneAuthorityWithdrawalNotAllowed` removed

Per the "Zone-authority withdrawals" ruling in `authority-rulings.md`, the check
is gone rather than narrowed, matching the TypeScript removal in `f836288c`. The
error variant had no other producer and went with it.

One thing the removal exposed, worth recording because it is not visible from
the guard alone: the refusal was also what made `public_amounts:
PublicAmounts::default()` correct in `PreparedZoneAuthority::new`. Those amounts
are proof public inputs. `client/src/prover/zone_authority.rs:96-110` feeds them
straight into the proof inputs and the instruction data, so once a leg is
permitted, a hardcoded default would prove zero public amounts over a nonzero
external-data leg. `new` now derives them from the same `SppProofInputs` it already builds for
`check_shape()`. Derived and default agree when there is no leg, so the change
adds no behavior on the paths that previously passed.

The test `a_public_leg_is_rejected` encoded the old policy and was inverted to
`a_public_leg_is_accepted_in_either_direction` rather than deleted. It now
asserts that an incoming and an outgoing SOL leg both build and that their
amounts reach `public_amounts`, plus a token leg for the SPL side, which needs
token notes because the public SPL asset is read off the UTXOs.

Residual, unchanged by this work: `PreparedZoneAuthority`'s fields are public, so
a caller assembling it as a literal skips `new` entirely and supplies its own
`public_amounts` (`client/tests/zone_authority/steps.rs:157` does exactly that,
consistently). This is the Rust half of the branding residual already recorded
for TypeScript in `transaction-unblock.md`.

## Verification

- `cargo test -p zolana-transaction`: green, 51 unit tests plus the integration
  suites.
- `cargo test -p zolana-wallet`: green, 96 tests, including the previously
  failing one.
- `cargo check -p zolana-client --all-targets`: clean, so the literal
  `PreparedZoneAuthority` construction in the client's zone-authority test still
  compiles.
- `cargo clippy -p zolana-transaction -p zolana-wallet --all-targets` and
  `cargo fmt --check`: clean.
