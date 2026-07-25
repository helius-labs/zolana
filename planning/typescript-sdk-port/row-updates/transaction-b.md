# Transaction rows, second pass, `port/transaction-b`

Branch: `port/transaction-b`, eight commits on the integration tip.

| Commit | What it closed |
| --- | --- |
| `de3f9c94` | Transfer builder: zero amounts, padding position, dummy rails, field helpers |
| `fc489bfb` | Both merge rails and the prepared-value data re-check |
| `64437661` | Split builder plus `ownerViewTag` and `ConfidentialSplit.sign` |
| `f8ab836c` | `encodeConfidentialSlots` and both keypair `sign` rails |
| `07740230` | The four transaction types, the canonical dummy rule, the Poseidon error category |
| `ac7c260a` | The zone-authority shape check |
| `4d54a140` | The merge UTXO rebuild |
| `4e11c369` | The proofless note layout, reader and writer |

## What the evidence is

Every verdict below rests on the generated oracle the previous transaction batch
built, extended rather than replaced. `sdk-libs/transaction/tests/ts_oracle.rs`
runs the production Rust path over a case list and writes
`sdk-libs/ts/transaction/test/oracles/transaction-parity-v1.json`; its own test
fails if Rust drifts from the committed file, and
`sdk-libs/ts/transaction/test/vectors/rust-oracle.test.ts` replays the same
inputs through TypeScript. A divergence fails one side or the other. The file
now runs 193 tests, up from 72.

Regenerate with:

```bash
ZOLANA_WRITE_TS_ORACLES=1 cargo test -p zolana-transaction --test ts_oracle
```

New sections: `transfer` (16 builder cases), `merge` (21 builder cases plus 7
prepared-value cases across both rails), `split` (16 cases), `fields` (9 signed
amounts, 3 assets), `utxo.canonicalDummy` (10 cases), `transactTypes` (7
private-transaction hash chains, 4 input UTXOs, 9 output builder sequences, 4
encrypted transactions), `zoneAuthority` (9 cases),
`fromUtxos.mergeIntoUtxos` (4 cases), and `serialization.proofless` (5 notes,
each read back as well as written).

## Divergences the evidence exposed

Nine, all fixed on the TypeScript side because Rust was the authority in each.

1. **`ConfidentialTransfer.send` and `.withdraw` rejected a zero amount.** Rust
   performs no such check; `zeroAmountRecipient` and `zeroAmountWithdrawal` are
   cases Rust accepts and TypeScript refused. This is the over-strict failure
   mode the brief warns about, and the fix was to delete the guards.
2. **`ConfidentialTransfer.prepare` padded inputs and outputs to the shape.**
   Rust pads in `finalize`. The consequence was not cosmetic: `prepare().outputs`
   is what a wallet hands its authority to encrypt, so TypeScript was asking an
   authority to encrypt dummy slots and reporting the shape's width as the real
   slot count. Padding moved to `finalizeTransfer`.
3. **Padded slots took the sender's rail.** Rust samples the rail from the
   transaction's real recipients (`dummy_rail`) precisely so a curve-membership
   test on a published view tag cannot single out a dummy. TypeScript always used
   `SigningKey.generate(senderRail)`, which on a mixed-rail transfer marks every
   dummy. Ported the sampling.
4. **The dummy ciphertext length was the constant 88.** Rust derives it by
   encoding a throwaway output through the real path, so a dummy slot keeps the
   same byte length as a real one when the encoding changes. Ported.
5. **`PreparedMerge.inputUtxoHashes` did not re-check the data policy.** Rust's
   `real_input_contexts` does, and the prepared value is publicly constructible,
   so TypeScript would hand a data-carrying input to merge assembly where Rust
   raises `MergeInputHasData`.
6. **`PreparedMergeZone.inputUtxoHashes` revalidated the zone binding.** Rust
   checks only the data policy there. The `zoneForeignZone` oracle case records
   Rust accepting an input TypeScript rejected, which is the proof that the check
   was over-strict rather than a useful extra. Relaxed to Rust's rule;
   `validateMergeZoneInputs` stays exported for callers that want it.
7. **Poseidon failures reported the wrong error category.** Rust routes both
   `KeypairError::Poseidon` and every `zolana_hasher::HasherError` into
   `TransactionError::Keypair`, so an out-of-field input reports
   `TRANSACTION_KEYPAIR`. TypeScript reported `TRANSACTION_HASH` from the same
   input. The `addressHashOutOfField` case fails if either side moves. This
   changes the code every hashing path raises, so it is the widest of the nine.
8. **`prepareZoneAuthority` accepted an unprovable shape.** Rust
   `PreparedZoneAuthority::new` resolves the shape through
   `SppProofInputs::check_shape` and rejects padded slot counts that name no
   proving system; TypeScript accepted them and exposed no shape at all. The
   `unsupportedShape` case (2 inputs by 5 outputs) fails without the fix. The
   lookup now has one implementation, `exactShape`, shared with
   `SppProofInputs.checkShape`.
9. **The output data setters were absent.** Rust `SppProofOutputUtxo` replaces a
   record of the same kind rather than appending a second one, and re-sorts into
   the order `Data::validate` demands. TypeScript had no counterpart, so a caller
   attaching a memo after zone data had to sort by hand or build an invalid
   `Data`. Ported as `withZoneData`, `withZoneProgramId`, `withZoneDataHash`,
   `withUtxoData`, and `withMemo`; `memoThenZoneData` and `memoReplaced` are the
   cases that fail if the ordering or the replacement changes.

## Row dispositions

`PARITY` means a test in this branch executes both languages over the same
inputs and compares, so the row would fail on divergence.

| Row | Verdict | Basis |
| --- | --- | --- |
| T01 | `PARITY` | The row's residual was that six declared codes had no producer and that no fixture derived the code set from current Rust. Both are closed. The code set is derived in both directions by a compiler-enforced exhaustive Rust map over all 70 variants (`the Rust oracle and TypeScript agree on the error code set`), and `the declared error codes have producers` asserts that each of the five previously-unproduced codes is raised by a named replayed case: `TRANSACTION_INVALID_OUTPUT_POSITION` (anonymous-sender `solAtTheSplPosition`, plaintext `recipientPositionGap`), `TRANSACTION_OUTPUT_AMOUNT_MISMATCH` and `TRANSACTION_OUTPUT_BLINDING_MISMATCH` (split `amountMismatch`, `blindingOutOfOrder`), `TRANSACTION_OUTPUT_ASSET_MISMATCH` (plaintext `solInTheSplSlot`), `TRANSACTION_OUTPUT_OWNER_MISMATCH` (three families' `foreignOwner`). `TRANSACTION_UNKNOWN_ASSET_FIELD`, the sixth, was closed by the previous batch. A fourth assertion fails if the oracle ever expects a code TypeScript does not declare. Deleting a producer now fails the suite. |
| T04 | `PARITY` | The row's named fix was to export a `plaintextTransferFromUtxos` counterpart. It exists, is exported from the package root, and the oracle replays 10 cases through it: the full sender-plus-recipients shape, an empty set, recipients only, both asset-slot crossings, a foreign owner in the sender slot, a blinding off the seed, a recipient position gap, a zone mismatch, and an unregistered mint. Encodings are byte-identical and every rejection matches by code. On the stale `serialization-v1` fixture, the same reasoning the previous batch applied to T02 holds: the oracle supersedes it as evidence, and its staleness is the fixture-pipeline issue, not a behavioural gap. |
| T06 | `PARTIAL` | Advanced. `anonymousRecipientFromUtxos` and `anonymousSenderFromUtxos` both exist, are exported, and are replayed over 11 cases (single, memo-bearing, zone-bound, empty, two UTXOs, foreign owner; SPL-and-SOL, SOL only, empty, SOL at the SPL position, two SPL legs). Not `PARITY`: the row also asks for shared-tag state progression, which nothing in this branch exercises. |
| T07 | `PARITY` | Both halves are closed. `prooflessFromUtxos` is exported and replayed over four cases (single, every record kind, empty, foreign owner), and `decodeProofless`, which the row called private, is exported from `./serialization` and executed: `serialization.proofless` replays five notes covering all six optional fields absent, all present, the zone trio only, `u64::MAX`, and the empty-payload case Borsh distinguishes from absent. Both the writer and the reader are compared against Rust bytes field by field. The memo ruling half is settled elsewhere. |
| T08 | `PARTIAL` | Advanced. Both named residuals are closed: `SplitEncryptedUtxos` is exported from `./serialization` and `splitBundleFromUtxos` is the `Split::from_utxos` counterpart, replayed over six cases including all four mismatch categories. Not `PARITY`: the row also asks for browser and export evidence, which this pass did not produce. |
| T22 | `PARITY` | The row's sole residual was that `encode_confidential_slots` had no named TypeScript export, its logic living inside `LocalWalletAuthority.encryptConfidentialTransfer`. It is now `encodeConfidentialSlots` in `instructions/transact.ts`, exported from the root and from `./instructions`, and the authority calls it rather than duplicating it. It is executed by every transfer path in the suite, including the new `ConfidentialTransfer.sign`. `slotOrdinal` agreement over eight positions including `u32::MAX` was already pinned by the previous batch. |
| T24 | `PARITY` | Both named residuals are ported: `PreparedSplit.ownerViewTag` and `ConfidentialSplit.sign`, the keypair rail that derives the salt, the blinding seed, and the transaction viewing key instead of taking them from an authority, and signs in place on P256. The builder's decision set is pinned by 16 oracle cases: part counts 0, 1, 2, 8 and 9, a zero-value split, an amount mismatch, a product that overflows `u64` (Rust's `checked_mul` and TypeScript's bigint comparison agree on `SplitAmountMismatch`), a dummy input, a foreign owner, a foreign nullifier key, an asset mismatch, a zone-bound input, and both data forms. Accepted cases also compare all eight slot amounts, the first nullifier, the owner view tag, and the payer hash. |
| T25 | `PARITY` | All four residuals closed. The three behavioural ones are divergences 2, 3 and 4 above, each fixed and each covered: `declaredShapeWithRoomToPad` (shape `1x8`, three real outputs) fails if padding moves back into `prepare`, and `oneRecipient` (one input, shape `2x3`) fails if inputs are padded early. `SENDER_SLOT_COUNT` is exported and checked against the Rust constant. `ConfidentialTransfer.sign` is ported and asserted to reach the same shape and the same output hashes as the authority rail. `Recipient` and `Withdrawal` are Rust-internal shapes carried by `WithdrawalTarget` and the `send` parameters on the TypeScript side; nothing in the public surface needs them as named types. |
| T27 | `PARITY` | 21 oracle cases over the merge builders' accept and reject set, 14 on the plain rail and 7 on the zone rail: one and eight inputs, zero amounts, `u64::MAX`, nine inputs, an empty set, an overflowing total, a foreign owner, a foreign nullifier key, an asset mismatch, and each rail's zone and data policy on both sides. The validation order is identical, which the per-case codes prove. Accepted cases compare the merged asset and amount, the padded input count, the default expiry, and every real input's hash and nullifier. Seven further cases perturb a prepared value's first input and compare the re-check. `MERGE_INPUTS` is exported and asserted against the Rust constant. Not covered: `MergeInputRailMismatch`, which needs an ed25519 keypair the oracle does not build; both languages check the rail first and in the same place. |
| T18 | `PARITY` | The row's rule is that a zero-owner input carrying any nonzero field is rejected by naming that field, in a fixed order. `utxo.canonicalDummy` executes it: one accepted canonical dummy, one case per field (`asset`, `amount`, `data`, `zone_program_id`, `data_hash`, `zone_data_hash`, `nullifier_key`), and two multi-field cases that pin which name wins. Both languages report the same code and the same `field`. Note TypeScript enforces the rule in the `ProofInputUtxo` constructor while Rust enforces it in `try_from`, `message_hash`, and `input_utxo_hashes`; the failure is the same, TypeScript's is just earlier, and no Rust path accepts a noncanonical dummy end to end. |
| T19 | `PARITY` | All four named types are ported and executed. `createInputUtxo` carries the nullifier public key rather than the secret and is replayed over four hash cases (bare, data hash, zone-bound, both hashes). `privateTxHash` is replayed over seven chains, including the `address_hashes.len() != input_hashes.len()` rule with its `expected` and `actual` details and the out-of-field case from divergence 7. `createEncryptedTransaction` is replayed over the four dummy and real slot combinations, which is what pins the zero-hash rule that makes it agree with `SppProofInputs.messageHash`. `SppProofOutputUtxo` is `ProofOutputUtxo` under the TypeScript name; its nine builder sequences are divergence 9. `messageHash` now calls `privateTxHash` rather than repeating the chain. |
| T29 | `PARITY` | The rail's four rules are executed by nine cases: an unpinned zero zone, an input outside the zone and an unbound input, an output outside the zone and an unbound output, the dummy exemption (each case pads with a dummy input and a dummy output that carry no zone and must pass), and both public legs. The deposit half the row calls over-strict is settled: Rust accepts a leg in either direction and `depositLeg` and `withdrawalLeg` prove TypeScript does too, so the withdrawal ruling the row asks for is no longer blocking a verdict. Divergence 8 was found here. Accepted cases also compare the resolved shape, the payer hash, and every real input's hash and nullifier. |
| T09 | `PARITY` | The row's named residual, `mergeUtxo` raising `TRANSACTION_UNKNOWN_ASSET` where Rust returns `UnknownAssetField`, is closed and now executed. `fromUtxos.mergeIntoUtxos` replays `Merge::into_utxos` over four cases: SOL, an SPL mint, a zone-bound rebuild that must carry the zone onto the UTXO, and an unregistered asset field that both languages reject as `TRANSACTION_UNKNOWN_ASSET_FIELD`. The forward direction (`mergePlaintextFromUtxo`) was closed by the previous batch. The row's browser and proof-contribution classes are test infrastructure rather than parity questions. |
| T28 | `PARTIAL` | Advanced. The zone rail's accept and reject set is now executed: a zone-bound input, one carrying zone data and a zone data hash, one carrying a memo, one carrying UTXO data, one carrying an external data hash, one with no zone, and one with a foreign zone. Divergence 6 above was found here and fixed. Not `PARITY`: the row asks for canonical zone-hash validation at construction, which neither language performs, so closing it means adding a rule to Rust first. |
| T11 | `PARITY` | The field-helper residual is closed: `signedToField` and `assetField` are ported and exported, with `BN254_MODULUS_DEC` as the domain constant, and the oracle compares nine signed amounts (zero, `+/-1`, `+/-500`, both `i64` bounds, `i64::MIN + 1`, `u32::MAX`) and three assets. The row's second ask, that the zone rule not be reachable only through `with_zone`, is met: the struct fields are public, so `ProofInputUtxo::hash` re-checks it and every consumer hashes. The builder path is covered by `nonzero_zone_hash_requires_zone_program` in `sdk-libs/transaction/src/utxo.rs`, the hash path by `proofInputHashes/zoneDataWithoutZoneProgram`. |
| T12 | `PARTIAL`, unchanged | The `entries()` disposition is an API decision, not a parity question. The previous batch's proposal stands: keep it and record it as a TypeScript-only accessor. |
| T02, T03, T20 | unchanged | Closed or advanced by the previous batch; nothing here touches them. |
| T05, T10, T13-T17, T26, T30, T31 | unchanged | Not reached. See below. |

Count: `12` rows reach evidence-backed `PARITY` this pass (T01, T04, T07, T09,
T11, T18, T19, T22, T24, T25, T27, T29). `3` are advanced by new executed
evidence but remain adverse (T06, T08, T28). The rest were not reached.

## Rows that remain adverse, and why

- **T05** wants decryption failures mapped onto the Rust `Decrypt` categories.
  Current Rust has no `Decrypt` variant: `viewing_key.decrypt_verifiable`
  returns a `KeypairError`, so the category is `TransactionError::Keypair`. The
  row's wording predates that. Closing it means generating malformed-ciphertext
  vectors and pinning the keypair category on both sides, which is the same
  alignment divergence 7 made for hashing. Not reached.
- **T06 and T08** each have one named residual left that is not a `from_utxos`
  question: shared-tag progression and browser-plus-export evidence
  respectively.
- **T10, T17, T26, T30, T31** are aggregate export rows. They inherit the rows
  below them and ask for six allowlist classes each (declaration, runtime,
  tarball, browser, packed-consumer, aggregate-fixture). None of that is
  behavioural; it needs a build-and-pack harness rather than an oracle. The
  root and `./instructions` aggregates gained `SENDER_SLOT_COUNT`,
  `BN254_MODULUS_DEC`, `signedToField`, `assetField`,
  `encodeConfidentialSlots`, `createInputUtxo`, `createEncryptedTransaction`,
  `createProofOutput`, `privateTxHash`, and the `InputUtxo`,
  `EncryptedTransaction`, `PrivateTxHashInput`, and `ProofOutputInit` types
  here, and `./serialization` gained `decodeProofless`. `./transact` carries the
  same four values and types, which closes part of T26's named omission list.
- **T13-T16** are the wallet rows: an authority-model change, the missing wallet
  state API, a tag-window scan with resumable counters, and a real worker. Each
  is a self-contained port of a size this pass could not absorb without rushing.
- **T28** needs a Rust rule before TypeScript can match it, as above.

## Rows that cannot reach parity from the SDK

- **T21** is blocked on `program-libs/interface`, which is off limits. The
  preimage `u16` question and the boundary vector both belong there. Unchanged.
- **T23** is blocked on a protocol-owner ruling that changes a deployed
  circuit's public input. Unchanged.

No row in this pass required a change under `programs/**`, `program-libs/**`,
`prover/**`, or `docs/spec.md`. Every fix is in `sdk-libs/ts/**` or in the Rust
crate's own test binary.

## Notes for the reconciler

`sdk-libs/transaction/tests/ts_oracle.rs` had a JSON key collision in the
transfer section, where the prepared input count overwrote the input spec list.
The counts are now `preparedInputs` and `preparedOutputs`. Anyone reading an
oracle file generated between those two states will see `inputs` as a number.

Divergence 7 changes the error code every TypeScript hashing path raises on an
out-of-field input, from `TRANSACTION_HASH` to `TRANSACTION_KEYPAIR`. Nothing in
the suite depended on the old code, and `TRANSACTION_HASH` stays declared
because Rust's `TransactionError::Hash(String)` maps onto it, but a downstream
caller matching on the old code would need updating.

Three row texts are now out of date in ways worth folding in rather than
copying: T05 names a Rust `Decrypt` variant that does not exist, T19 asks for
`SppProofOutputUtxo` which TypeScript calls `ProofOutputUtxo`, and T29's
withdrawal ruling is no longer blocking because Rust already accepts a public
leg in either direction.
