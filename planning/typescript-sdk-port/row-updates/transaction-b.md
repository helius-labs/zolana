# Transaction rows, second pass, `port/transaction-b`

Branch: `port/transaction-b`, four commits on the integration tip.

| Commit | What it closed |
| --- | --- |
| `de3f9c94` | Transfer builder: zero amounts, padding position, dummy rails, field helpers |
| `fc489bfb` | Both merge rails and the prepared-value data re-check |
| `64437661` | Split builder plus `ownerViewTag` and `ConfidentialSplit.sign` |
| `f8ab836c` | `encodeConfidentialSlots` and both keypair `sign` rails |

## What the evidence is

Every verdict below rests on the generated oracle the previous transaction batch
built, extended rather than replaced. `sdk-libs/transaction/tests/ts_oracle.rs`
runs the production Rust path over a case list and writes
`sdk-libs/ts/transaction/test/oracles/transaction-parity-v1.json`; its own test
fails if Rust drifts from the committed file, and
`sdk-libs/ts/transaction/test/vectors/rust-oracle.test.ts` replays the same
inputs through TypeScript. A divergence fails one side or the other. The file
now runs 139 tests, up from 72.

Regenerate with:

```bash
ZOLANA_WRITE_TS_ORACLES=1 cargo test -p zolana-transaction --test ts_oracle
```

Three new sections: `transfer` (16 builder cases), `merge` (21 builder cases
plus 7 prepared-value cases across both rails), `split` (16 cases), and
`fields` (9 signed amounts, 3 assets).

## Divergences the evidence exposed

Six, all fixed on the TypeScript side because Rust was the authority in each.

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

## Row dispositions

`PARITY` means a test in this branch executes both languages over the same
inputs and compares, so the row would fail on divergence.

| Row | Verdict | Basis |
| --- | --- | --- |
| T01 | `PARITY` | The row's residual was that six declared codes had no producer and that no fixture derived the code set from current Rust. Both are closed. The code set is derived in both directions by a compiler-enforced exhaustive Rust map over all 70 variants (`the Rust oracle and TypeScript agree on the error code set`), and `the declared error codes have producers` asserts that each of the five previously-unproduced codes is raised by a named replayed case: `TRANSACTION_INVALID_OUTPUT_POSITION` (anonymous-sender `solAtTheSplPosition`, plaintext `recipientPositionGap`), `TRANSACTION_OUTPUT_AMOUNT_MISMATCH` and `TRANSACTION_OUTPUT_BLINDING_MISMATCH` (split `amountMismatch`, `blindingOutOfOrder`), `TRANSACTION_OUTPUT_ASSET_MISMATCH` (plaintext `solInTheSplSlot`), `TRANSACTION_OUTPUT_OWNER_MISMATCH` (three families' `foreignOwner`). `TRANSACTION_UNKNOWN_ASSET_FIELD`, the sixth, was closed by the previous batch. A fourth assertion fails if the oracle ever expects a code TypeScript does not declare. Deleting a producer now fails the suite. |
| T04 | `PARITY` | The row's named fix was to export a `plaintextTransferFromUtxos` counterpart. It exists, is exported from the package root, and the oracle replays 10 cases through it: the full sender-plus-recipients shape, an empty set, recipients only, both asset-slot crossings, a foreign owner in the sender slot, a blinding off the seed, a recipient position gap, a zone mismatch, and an unregistered mint. Encodings are byte-identical and every rejection matches by code. On the stale `serialization-v1` fixture, the same reasoning the previous batch applied to T02 holds: the oracle supersedes it as evidence, and its staleness is the fixture-pipeline issue, not a behavioural gap. |
| T06 | `PARTIAL` | Advanced. `anonymousRecipientFromUtxos` and `anonymousSenderFromUtxos` both exist, are exported, and are replayed over 11 cases (single, memo-bearing, zone-bound, empty, two UTXOs, foreign owner; SPL-and-SOL, SOL only, empty, SOL at the SPL position, two SPL legs). Not `PARITY`: the row also asks for shared-tag state progression, which nothing in this branch exercises. |
| T07 | `PARTIAL` | Advanced. `prooflessFromUtxos` is exported and replayed over four cases (single, every record kind, empty, foreign owner). The memo ruling half is settled elsewhere. Not `PARITY`: `decodeProofless` is still private, which the row names. |
| T08 | `PARTIAL` | Advanced. Both named residuals are closed: `SplitEncryptedUtxos` is exported from `./serialization` and `splitBundleFromUtxos` is the `Split::from_utxos` counterpart, replayed over six cases including all four mismatch categories. Not `PARITY`: the row also asks for browser and export evidence, which this pass did not produce. |
| T22 | `PARITY` | The row's sole residual was that `encode_confidential_slots` had no named TypeScript export, its logic living inside `LocalWalletAuthority.encryptConfidentialTransfer`. It is now `encodeConfidentialSlots` in `instructions/transact.ts`, exported from the root and from `./instructions`, and the authority calls it rather than duplicating it. It is executed by every transfer path in the suite, including the new `ConfidentialTransfer.sign`. `slotOrdinal` agreement over eight positions including `u32::MAX` was already pinned by the previous batch. |
| T24 | `PARITY` | Both named residuals are ported: `PreparedSplit.ownerViewTag` and `ConfidentialSplit.sign`, the keypair rail that derives the salt, the blinding seed, and the transaction viewing key instead of taking them from an authority, and signs in place on P256. The builder's decision set is pinned by 16 oracle cases: part counts 0, 1, 2, 8 and 9, a zero-value split, an amount mismatch, a product that overflows `u64` (Rust's `checked_mul` and TypeScript's bigint comparison agree on `SplitAmountMismatch`), a dummy input, a foreign owner, a foreign nullifier key, an asset mismatch, a zone-bound input, and both data forms. Accepted cases also compare all eight slot amounts, the first nullifier, the owner view tag, and the payer hash. |
| T25 | `PARITY` | All four residuals closed. The three behavioural ones are divergences 2, 3 and 4 above, each fixed and each covered: `declaredShapeWithRoomToPad` (shape `1x8`, three real outputs) fails if padding moves back into `prepare`, and `oneRecipient` (one input, shape `2x3`) fails if inputs are padded early. `SENDER_SLOT_COUNT` is exported and checked against the Rust constant. `ConfidentialTransfer.sign` is ported and asserted to reach the same shape and the same output hashes as the authority rail. `Recipient` and `Withdrawal` are Rust-internal shapes carried by `WithdrawalTarget` and the `send` parameters on the TypeScript side; nothing in the public surface needs them as named types. |
| T27 | `PARITY` | 21 oracle cases over the merge builders' accept and reject set, 14 on the plain rail and 7 on the zone rail: one and eight inputs, zero amounts, `u64::MAX`, nine inputs, an empty set, an overflowing total, a foreign owner, a foreign nullifier key, an asset mismatch, and each rail's zone and data policy on both sides. The validation order is identical, which the per-case codes prove. Accepted cases compare the merged asset and amount, the padded input count, the default expiry, and every real input's hash and nullifier. Seven further cases perturb a prepared value's first input and compare the re-check. `MERGE_INPUTS` is exported and asserted against the Rust constant. Not covered: `MergeInputRailMismatch`, which needs an ed25519 keypair the oracle does not build; both languages check the rail first and in the same place. |
| T28 | `PARTIAL` | Advanced. The zone rail's accept and reject set is now executed: a zone-bound input, one carrying zone data and a zone data hash, one carrying a memo, one carrying UTXO data, one carrying an external data hash, one with no zone, and one with a foreign zone. Divergence 6 above was found here and fixed. Not `PARITY`: the row asks for canonical zone-hash validation at construction, which neither language performs, so closing it means adding a rule to Rust first. |
| T11 | `PARTIAL` | Advanced. The row's field-helper residual is partly closed: `signedToField` and `assetField` are ported and exported, with `BN254_MODULUS_DEC` as the domain constant, and the oracle compares nine signed amounts (zero, `+/-1`, `+/-500`, both `i64` bounds, `i64::MIN + 1`, `u32::MAX`) and three assets. Not `PARITY`: the row also asks that Rust route construction through a single validated path, which is a Rust change this pass did not make. |
| T12 | `PARTIAL`, unchanged | The `entries()` disposition is an API decision, not a parity question. The previous batch's proposal stands: keep it and record it as a TypeScript-only accessor. |
| T02, T03, T09, T20 | unchanged | Closed or advanced by the previous batch; nothing here touches them. |
| T05, T10, T13-T19, T26, T29-T31 | unchanged | Not reached. See below. |

Count: `6` rows reach evidence-backed `PARITY` this pass (T01, T04, T22, T24,
T25, T27). `5` are advanced by new executed evidence but remain adverse (T06,
T07, T08, T11, T28). The rest were not reached.

## Rows that remain adverse, and why

- **T05** wants decryption failures mapped onto the Rust `Decrypt` categories.
  That is a real port, not an alignment, and it needs malformed-input vectors
  the oracle does not yet generate.
- **T06, T07, T08** each have one named residual left that is not a `from_utxos`
  question: shared-tag progression, a private `decodeProofless`, and browser and
  export evidence respectively.
- **T10, T17, T26, T30, T31** are aggregate export rows. They inherit the rows
  below them and ask for six allowlist classes each (declaration, runtime,
  tarball, browser, packed-consumer, aggregate-fixture). None of that is
  behavioural; it needs a build-and-pack harness rather than an oracle. The
  root and `./instructions` aggregates gained `SENDER_SLOT_COUNT`,
  `BN254_MODULUS_DEC`, `signedToField`, `assetField`, and
  `encodeConfidentialSlots` here.
- **T13-T16** are the wallet rows: an authority-model change, the missing wallet
  state API, a tag-window scan with resumable counters, and a real worker. Each
  is a self-contained port of a size this pass could not absorb without rushing.
- **T18, T19** need `InputUtxo`, `EncryptedTransaction`, `PrivateTxHash`, and
  `SppProofOutputUtxo` ported with their owned copies and equality.
- **T28** needs a Rust rule before TypeScript can match it, as above.
- **T29** is the zone-authority row. Its deposit half is over-strict on both
  sides and its withdrawal half needs an owner ruling; the previous batch's
  correction to the row text stands, and nothing here changes it.

## Rows that cannot reach parity from the SDK

- **T21** is blocked on `program-libs/interface`, which is off limits. The
  preimage `u16` question and the boundary vector both belong there. Unchanged.
- **T23** is blocked on a protocol-owner ruling that changes a deployed
  circuit's public input. Unchanged.

No row in this pass required a change under `programs/**`, `program-libs/**`,
`prover/**`, or `docs/spec.md`. Every fix is in `sdk-libs/ts/**` or in the Rust
crate's own test binary.

## Note for the reconciler

`sdk-libs/transaction/tests/ts_oracle.rs` had a JSON key collision in the
transfer section, where the prepared input count overwrote the input spec list.
The counts are now `preparedInputs` and `preparedOutputs`. Anyone reading an
oracle file generated between those two states will see `inputs` as a number.
