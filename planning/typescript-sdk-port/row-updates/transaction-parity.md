# Transaction parity pass, `port/transaction`

Worker: transaction parity pass, `2026-07-25`, branch `port/transaction` forked
from `ts-sdk-port` at `c585faaf`. Commits: `6a7e1000`, `157ed768`, `d6e658e2`.

Scope: rows `T01`-`T31`. This entry records what the executed evidence supports
and nothing more. Rows that were not reached say so.

## What the evidence is

`sdk-libs/transaction/tests/ts_oracle.rs` builds the cases below from the
production Rust path and writes
`sdk-libs/ts/transaction/test/oracles/transaction-parity-v1.json`. Without
`ZOLANA_WRITE_TS_ORACLES=1` it verifies the committed file, so a Rust change
that moves any recorded value fails in the Rust suite.
`sdk-libs/ts/transaction/test/vectors/rust-oracle.test.ts` runs the TypeScript
path over the same inputs and compares. The comparison runs in both
languages under `cargo test -p zolana-transaction` and `npm run test:vectors`; neither side reads the other's source.

The error section is the load-bearing one. `ts_code` matches on
`TransactionError` exhaustively, so a variant added to Rust does not compile
until it is mapped to a TypeScript code. That is what makes the TypeScript code
set derived from current Rust rather than asserted to match it.

Case counts, passing: 70 error variants, 12 UTXO data records, 7 scheme
bytes plus 249 rejected bytes, 112 shape resolutions plus 70 canonical
selections, 16 asset-registry operations, 8 UTXO commitments plus 3 owner
commitments plus 5 blinding derivations, 8 slot ordinals, 6 plaintext encodings.

## Divergences the evidence exposed

1. **Two Rust variants had no TypeScript code.** The exhaustive map failed on
   `OutputSlotOverflow` and `ExcessOutputSlots`. Input that exposes it: any
   attempt to map the Rust enum onto `TRANSACTION_ERROR_CODES`; concretely, a
   `finalize` call with more output slots than the shape has outputs, which Rust
   rejects as `ExcessOutputSlots { got, outputs }` and TypeScript rejected as
   `TRANSACTION_TOO_MANY_OUTPUTS`. Fixed in `6a7e1000`: both codes exist, the
   finalize site reports `TRANSACTION_EXCESS_OUTPUT_SLOTS` with Rust's detail
   names, and the boundary itself is unchanged. Rust `slot_ordinal` is now
   public and mirrored by an exported `slotOrdinal`, which produces
   `TRANSACTION_OUTPUT_SLOT_OVERFLOW` on the same input Rust rejects.
2. **The merge asset field reported the wrong code.** Rust `Merge::into_utxos`
   returns `UnknownAssetField` when no registered mint hashes to the plaintext's
   asset field. `mergeUtxo` raised `TRANSACTION_UNKNOWN_ASSET`, the code the
   registry raises for an unknown asset *id*. Input exposing it: a merge
   plaintext whose `assetField` is `[4u8; 32]` against a registry holding only
   SOL. Fixed in `d6e658e2`; the rejection is unchanged, only its name.

No case was found where TypeScript rejects input Rust accepts. Both fixes rename
a rejection or add a code; neither narrows an accepted set. The `slotOrdinal`
guard is the same `u32` bound Rust already enforced, applied at the same place.

## Row dispositions

`PARITY` here means a test in this branch executes both languages over the same
inputs and compares. Three rows reach it.

| Row | Verdict | Basis |
| --- | --- | --- |
| T01 | `PARTIAL` | The code set is now derived from current Rust by a compiler-enforced exhaustive map, and each declared code with no Rust counterpart carries a recorded reason in `TYPESCRIPT_ONLY_CODES`. Residual, and the reason this is not `PARITY`: five declared codes still have no TypeScript producer (`TRANSACTION_INVALID_OUTPUT_POSITION`, `TRANSACTION_OUTPUT_AMOUNT_MISMATCH`, `TRANSACTION_OUTPUT_ASSET_MISMATCH`, `TRANSACTION_OUTPUT_BLINDING_MISMATCH`, `TRANSACTION_OUTPUT_OWNER_MISMATCH`). All five are raised by the Rust `from_utxos` conversions that T04, T06, and T08 still have no TypeScript counterpart for, so they should be produced by closing those rows, not deleted. `TRANSACTION_UNKNOWN_ASSET_FIELD`, the sixth, now has a producer. |
| T02 | `PARITY` | 12 data cases compared by execution: empty, each record alone, canonical order, a 300-byte memo across the `u8`/`u16` length boundary, an empty record body, duplicate memo, duplicate zone, and the three non-canonical orders. Encodings are byte-identical and the four rejections raise the same code in both languages. The memo record is implemented per the spec ruling in [spec-amendments.md](spec-amendments.md); both languages define tag `3`. The frozen `data-v1` fixture is still stale, but that is the fixture-pipeline issue G8-1, not a behavioral gap: this oracle supersedes it as evidence for `data.rs` against `data.ts`. |
| T03 | `PARITY` | `encryptedSchemeToByte` is the named counterpart of Rust `as_byte`, exported from the package root and from `./serialization`. The oracle test imports it from the root entry point, so the export is proven by execution rather than by an allowlist. The 7 scheme bytes round trip and the 249 unassigned bytes raise `TRANSACTION_BAD_DISCRIMINATOR` in both languages. |
| T04 | `DIVERGENT`, open | Not reached. No TypeScript counterpart for `PlaintextTransfer::from_utxos`; the conversion stays private inside `wallet/sync.ts`. Blocks two of T01's five unproduced codes. |
| T05 | `PARTIAL`, open | Advanced: the confidential output plaintext wire layout is now proven identical over four cases (bare, zone-bound, all three data records, zero amount), including decode. Untouched: decryption failures still do not map onto the Rust `Decrypt` categories, and there is no malformed-input or browser evidence. |
| T06 | `DIVERGENT`, open | Not reached. No counterpart for `AnonymousRecipient::from_utxos` or `AnonymousSenderBundle::from_utxos`; no shared-tag progression coverage. |
| T07 | `DIVERGENT`, open | Not reached beyond the memo ruling, which the T02 evidence covers for the `Data` layer. The proofless-specific residual stands. |
| T08 | `PARTIAL`, open | Not reached. `SplitEncryptedUtxos` is still unexported from `./serialization` and `Split::from_utxos` has no counterpart. |
| T09 | `PARTIAL` | Advanced: the merge plaintext wire layout is proven identical (zero and `u64::MAX` amounts), and the error-code residual named by the row is fixed, so `mergeUtxo` now raises `TRANSACTION_UNKNOWN_ASSET_FIELD` like Rust. Not `PARITY`: the row also asks for export, browser, and proof-contribution evidence, none of which this pass produced. |
| T10 | `DIVERGENT`, open | Not reached. `DecodeCx`, `OwnerCx`, and `UtxoSerialization` still have no TypeScript adaptation, and `SplitBundlePlaintext` still names two different types. |
| T11 | `PARTIAL` | Advanced substantially: 8 proof-input commitments are byte-identical, including the zone rule in both directions (a zone program without zone data is accepted; zone data without a zone program raises `TRANSACTION_MISSING_ZONE_PROGRAM_ID` on both sides), the canonical dummy, zero and `u64::MAX` amounts, plus 3 owner commitments and 5 blinding derivations. Not `PARITY`: Rust still routes the rule through `with_zone` and `hash` rather than one construction path, and the field-encoded proof-input helpers and domain constants are still absent from TypeScript. |
| T12 | `PARTIAL` | Advanced: 7 inserts (including the reserved `0` and `1`, a duplicate id, a duplicate mint, and the SOL mint under a new id), 5 resolutions, 4 mint lookups, and 3 asset-field lookups agree on both the value and the rejection code. Not `PARITY`: `entries()` still has no Rust counterpart. Proposed disposition, not applied here because it is an API decision: keep it and record it as a TypeScript-only accessor, since `clone()` is implemented on top of it and Rust reaches the same data through `HashMap` iteration that its `AssetRegistry` newtype does not expose. |
| T13 | `DIVERGENT`, open | Not reached. Four Rust authority changes plus three unported types; the largest row in the set and not attemptable inside this window without rushing an authority-model change. |
| T14 | `DIVERGENT`, open | Not reached. The missing wallet state API is a large, self-contained port. |
| T15 | `DIVERGENT`, open | Not reached. The tag-window scan with resumable counters is a rewrite of `syncWallet`, not an alignment. |
| T16 | `DIVERGENT`, open | Not reached. `decryptTransactionsWorkerEquivalent` is still a serial alias. |
| T17 | `DIVERGENT`, open | Not reached; inherits T13-T16. |
| T18 | `DIVERGENT`, needs re-review | Not this pass's row, but reinforced: the canonical-dummy commitment is now also pinned through the shared oracle (`canonicalDummy`, zero owner hash at blinding `[7u8; 31]`), and `TRANSACTION_NONCANONICAL_DUMMY_INPUT` is covered by the error map. |
| T19 | `DIVERGENT`, open | Not reached. `InputUtxo`, `EncryptedTransaction`, `PrivateTxHash`, and `SppProofOutputUtxo` are still absent. |
| T20 | `PARITY` | The exhaustive boundary and error evidence the row asked for now exists: 70 canonical selections over a 7x10 grid and 112 declared-shape resolutions over six declared shapes, two of them unsupported, agree on the selected shape and on all three rejection codes (`TRANSACTION_UNSUPPORTED_SHAPE`, `TRANSACTION_TOO_MANY_INPUTS`, `TRANSACTION_TOO_MANY_OUTPUTS_FOR_SHAPE`). This also gives `shape.rs` the direct Rust tests it lacked. |
| T21 | `BLOCKED` on the interface package, repointed | The row's TypeScript target was `transaction/src/instructions/transact.ts`; the behavior lives in `interface/src/external-data-hash.ts`. Repointed in the checklist. What the interface package needs is recorded below. |
| T22 | `PARTIAL` | Advanced: Rust `slot_ordinal` is public, TypeScript has the named `slotOrdinal` counterpart exported from the root, `./instructions`, and `./transact`, and the two agree on 8 positions including `u32::MAX` and `u32::MAX + 1` under the same code. Not `PARITY`: `encode_confidential_slots` still has no named TypeScript export; its logic lives inside `LocalWalletAuthority.encryptConfidentialTransfer`, which now routes its slot index through `slotOrdinal`. |
| T23 | `BLOCKED` | Unchanged and correctly blocked. The confidential-variant `solana_owner_pk_hashes[i]` question for a P256-owned input changes a deployed circuit's public input; it is the protocol owner's call, not an SDK one. |
| T24 | `PARTIAL`, open | Not reached. `ConfidentialSplit::sign` and `PreparedSplit::owner_view_tag` still have no counterpart. |
| T25 | `DIVERGENT`, open | Advanced: the excess-slot rejection now reports Rust's code and detail names, which closes one of the row's divergences. Untouched: TypeScript still pads in `prepare` where Rust pads in `finalize`, still derives dummy tags from the sender's own rail, and `SENDER_SLOT_COUNT`, `Recipient`, `Withdrawal`, and `ConfidentialTransfer::sign` are absent. |
| T26 | `PARTIAL`, open | Not reached; inherits T19-T25. |
| T27 | `PARTIAL` | Advanced: `MERGE_INPUTS` is now exported, which is the row's only named residual. Not marked `PARITY` because no executed comparison of the merge builder's accept and reject set ran in this pass; the constant's value is asserted in both languages but the builder behavior around it is not compared. |
| T28 | `PARTIAL`, open | Not reached. Canonical zone-hash and zone-address validation is still deferred rather than checked at construction. |
| T29 | `DIVERGENT`, open, with a correction | Not reached, but the row text is stale in a way that matters. It says `PreparedZoneAuthority::new` "rejects a public leg" and that TypeScript raises `TRANSACTION_ZONE_AUTHORITY_WITHDRAWAL_NOT_ALLOWED`. Neither language does that today, and neither should: both now permit the public leg deliberately, with the reasoning written into the code on both sides, and no such code exists in `TRANSACTION_ERROR_CODES`. The exhaustive error map confirms it: there is no Rust variant for it. The real remaining difference is that Rust `new` also resolves the shape and computes the payer hash while `prepareZoneAuthority` does neither, so TypeScript is the *looser* of the two. Do not close this row by adding the withdrawal guard. |
| T30 | `PARTIAL`, open | Not reached; inherits T18-T29. `slotOrdinal` and `MERGE_INPUTS` were added to the `./instructions` aggregate. |
| T31 | `PARTIAL`, open | Not reached. `encryptedSchemeToByte`, `slotOrdinal`, and `MERGE_INPUTS` were added to the root; the long list of omissions in the row stands. |

Count: `3` rows reach evidence-backed `PARITY` (T02, T03, T20). `7` rows are
advanced by new executed evidence or a landed fix but remain adverse (T01, T05,
T09, T11, T12, T22, T25, and T27 by its named residual). `2` stay `BLOCKED` for
reasons outside this package (T21, T23). The remaining rows were not reached.

## T21: what the interface package needs

`ExternalData::hash` in `sdk-libs/transaction` delegates to the interface
`ExternalDataHash`, and TypeScript `externalDataHash` in
`sdk-libs/ts/transaction/src/instructions/transact.ts` mirrors the interface
layout, so the SDK copies whatever the interface settles on. The row belongs to
`interface/src/external-data-hash.ts`.

Recorded for the interface owner, not acted on here:

- `program-libs/interface` replaced the truncating `u16` casts with a checked
  `length_prefix` returning `HasherError::IntegerOverflow` in `bc55a9b9`, and
  that hunk is awaiting a revert decision.
- TypeScript currently matches the checked form: `externalDataHash` raises
  `TRANSACTION_TOO_MANY_OUTPUTS` when `outputs.length` or `messages.length`
  exceeds `0xffff`. If the interface reverts to truncation, this guard must be
  removed in the same change, or the SDK will reject a transaction the deployed
  program accepts. It should not be removed before then, because that would
  restore the truncation on the TypeScript side alone.
- Whichever form is chosen, the preimage needs a cross-language vector at the
  boundary: `0xffff` outputs (accepted, hashed) and `0x10000` outputs (rejected,
  or truncated to zero if truncation stands). Neither language has one.

## Reproducing

```bash
cargo test -p zolana-transaction --test ts_oracle   # verifies the committed oracle
cd sdk-libs/ts/transaction && npm run test:vectors  # runs TypeScript over the same cases
```

Regenerate after an intended Rust change with
`ZOLANA_WRITE_TS_ORACLES=1 cargo test -p zolana-transaction --test ts_oracle`,
then rerun the TypeScript side; a real divergence shows up there rather than
being absorbed into the regenerated file.

Verified on this branch: `npm run build`, `npm run typecheck`,
`npm run test:unit` (827 passed, 1 skipped), `npm run test:vectors`,
`npm run test:cross`, `npm run test:exports`, and `cargo test -p
zolana-transaction` (all suites pass).
