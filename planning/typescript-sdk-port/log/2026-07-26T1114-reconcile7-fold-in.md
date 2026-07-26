# 2026-07-26 11:14 UTC | reconciler pass seven: twelve of thirteen adverse rows closed, S01 refused | queue-wide

- Baseline: HEAD `3d846008`, the `ts-sdk-port` tip, checked out as `port/reconcile6`
- Worker: reconciler, sole writer of `review-checklist.md`
- Scope: `planning/` only. No source under `sdk-libs/`, `programs/`, `program-libs/`, `prover/`, `services/` or `xtask/` was touched
- Folded: [row-updates/verify-b.md](../row-updates/verify-b.md),
  [row-updates/verify-a.md](../row-updates/verify-a.md),
  [row-updates/serialization-rows.md](../row-updates/serialization-rows.md),
  [row-updates/t25-a01.md](../row-updates/t25-a01.md),
  [row-updates/fixture-ci-and-c04.md](../row-updates/fixture-ci-and-c04.md),
  and [row-updates/owner-rulings-3.md](../row-updates/owner-rulings-3.md)
- Gates: `node sdk-libs/ts/config/review-checklist-check.mjs` and
  `node sdk-libs/ts/config/pkp-entry-gate.mjs` both run after this entry landed

- Verdict: `T06` reaches PARITY
- Verdict: `T10` reaches PARITY
- Verdict: `T16` reaches PARITY
- Verdict: `T17` reaches PARITY
- Verdict: `T21` reaches PARITY
- Verdict: `T23` reaches PARITY
- Verdict: `T25` reaches PARITY
- Verdict: `T26` reaches PARITY
- Verdict: `T30` reaches PARITY
- Verdict: `C04` reaches PARITY
- Verdict: `C06` reaches PARITY
- Verdict: `C21` reaches PARITY
- Verdict: `S01` stays DIVERGENT

Counted from the tables with `awk` over the Status and Verdict columns rather
than adjusted from the previous figure: **134 `done`/`PARITY`, 1 adverse**, 7
`done`/`NOT_APPLICABLE` and 3 `needs_re_review`/`NOT_APPLICABLE`, summing to 145.
The adverse denominator falls from 13 to 1, and that one is `S01`.

Twelve of the thirteen adverse rows pass six left open had landed reports. Every
claim credited was re-derived at this HEAD with a file and a line; none was
credited to the report that made it. `verify-a.md`'s six rows (`I37`, `K11`,
`K12`, `K13`, `K14`, `W04`) were already `done` / `PARITY` from pass six and were
not moved. `verify-b.md`'s `T12`, `T13`, `T29`, and `T31` were likewise already
closed.

## The one refusal

**`S01`.** [verify-b.md](../row-updates/verify-b.md) correctly refuses the earlier
cluster claim that T21's external-data work closed this package. Checked at HEAD:
on every input both languages accept, the bytes agree, and the export surface is
pinned. The adverse residual is still that TypeScript refuses inputs Rust accepts:
the 1232-byte instruction and payload limits (now through `TRANSACTION_SIZE_LIMIT`
at `smart-account-client/src/instructions.ts:1,33`), an empty signer set, a
threshold of zero or above the signer count, duplicate signers, and an inner
instruction whose data reaches `0x10000` (Rust truncates with `as u16`). Nothing
under `smart-account-client/` was changed by the T21 work. Closing it from
TypeScript alone would restore quiet truncation; closing it from Rust needs
fallible builders and stable codes. A parallel worker is on `port/s01`; this pass
does not wait for it and does not close the row.

## What closed, checked rather than credited

**`T06`.** The conversions exist and are compared; `oracle.anonymousProgression`
replays shared-tag state progression; the four category fixes
(asset-before-zone order, record-tag as `TRANSACTION_DESERIALIZE`, viewing-key
overflow as `TRANSACTION_SERIALIZE`, cipher failures through
`inTransactionCategory`) are present in `codecs.ts` and pinned. The `solMint`
parameter is an API widening Rust cannot express and does not reopen the row.

**`T10`.** `DecodeContext` / `OwnerContext` ship; `UtxoSerialization` is
dispositioned with a written reason and a capability contract; one
`SplitBundlePlaintext` declaration; built entry-point surface suite and
`config/pack-check.mjs` cover the allowlist halves.

**`T16`.** `CounterpartyCounters.#sorted` / `advance` walk pubkey-byte order
(`sync.ts:224-241`). Atomicity was already pinned. No oracle pins an order Rust
leaves undefined; the new viewing-key-history case pins the stated sorted walk
against discovery order.

**`T17`, `T26`, `T30`.** Omission clauses already discharged; packaging clause
covered by `module-surface.test.ts` built-entry checks plus `pack-check.mjs`.

**`T21`.** Rust `check_preimage_prefixes` at `external_data.rs:159-184`; TypeScript
guards at `transact.ts:252-280` and `interface` `external-data-hash.ts`; boundary
vectors in the transaction oracle and `interface.test.ts`.

**`T23`.** All four ruling clauses hold: `publicAmounts()` returns three field
encodings with Rust's two asset errors; `inputUtxoHashes()` returns
`InputUtxoContext[]` and `inputContexts()` is gone; the constructor does not call
`checkShape()`; `signP256` checks the keypair curve and `applyP256Signature` keeps
only the length check.

**`T25`.** Constructor stores and returns; empty / dummy / foreign-owned inputs
construct; empty-input `withdraw` names `TRANSACTION_WITHDRAWAL_ASSET_MISMATCH`
(`transfer.test.ts`).

**`C04`.** `quoteUnsafeIntegers` quotes only the five unbounded keys
(`api/src/index.ts:379-427`); unsafe `leaf_index` refuses end to end through
`ZolanaIndexer`; merkle-proof wait matches the async twin and Light (no
completeness poll).

**`C06`.** `checked_be` refuses at and above Fr; assembler uses it for merkle
witnesses; raw `be` stays for P256 limbs.

**`C21`.** Empty tags return `MissingOutput`; confirmation timeout returns
`ConfirmationTimeout`; neither is retryable through `retry_cause`.

## Source defects named, none made

Per the brief, only `planning/` was changed. The only remaining source gap this
pass names is `S01`: the smart-account builders still need an owner ruling or
fallible Rust builders with stable codes.
