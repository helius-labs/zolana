# Current interface dispositions

This file records the current-Rust dispositions added after the frozen
`public-exports.md` baseline. The Rust authority is the interface source at
`4a60db74`. Later local commits in this series do not change Rust interface
files.

## Public instruction and state surface

- `BatchUpdateNullifierTreeData`, `CompressedProof`, `CreateTreeData`,
  `UtxoData`, `ZoneDepositIxData`, `MergeTransactIxData`, `MergeZoneIxData`,
  `CreateZoneConfigData`, `UpdateZoneConfigOwnerData`, and
  `UpdateZoneConfigData` map to owned TypeScript types and strict codecs.
- Rust borrowed view types map to the same owned decoders. JavaScript does not
  expose separate zero-copy lifetimes.
- `P256Proof::LEN`, merge shape constants, `fetch_tag`, tree parameters, tree
  account size, state root offset, state discriminators, and
  `SplAssetCounter::FIRST_ASSET_ID` have named TypeScript exports.
- The create-tree builder accepts optional custom nullifier-tree parameters and
  uses the canonical Borsh codec.
- Transaction, zone, and merge builders reuse interface codecs and PDA helpers.
  They return malformed settlement combinations for the Solana program to
  reject, matching the Rust builder boundary.

## Event surface

- `InstructionTag`, `MessageData`, and `OutputUtxo` are represented in
  `@zolana/interface` because instruction data uses them directly.
- `GeneralEvent`, `Input`, `DepositWithdraw`, and `EventKind` remain owned by
  the Rust event crate and Photon schema. TypeScript clients consume Photon
  response types from `@zolana/indexer-api`; they do not construct event
  self-CPI instructions.
- Rust event encoders and `program-test` log extraction are not TypeScript
  interface exports. Output payload encoding remains in
  `@zolana/transaction/serialization`, where wallet behavior uses it.
- Generated verifying-key modules, compile-time macros, `PROGRAM_ID_PUBKEY`,
  and mutable account initialization methods are not applicable to the
  browser-safe TypeScript package.
- Raw PDA seed constants map to the typed functions in
  `@zolana/interface/pda`. Pubkey aliases map to the shared `Address` type.
- SPL account byte offsets and token instruction discriminators remain Rust
  program implementation constants. TypeScript instruction builders use the
  canonical token program addresses and do not parse SPL account storage.

## Merge prefix (closed)

Both languages now accept the non-canonical merge encrypted-UTXO prefix Rust
reads. The earlier TypeScript-only reject was removed with `I08`/`I09`/`I20`/
`I21` (`78039fe9`); see
[row-updates/merge-prefix.md](row-updates/merge-prefix.md).

## Spec conflicts that no longer block the port

Deposit tag semantics, zone-deposit builders, and protocol-config single-field
updates were ruled in
[row-updates/interface-spec-conflicts.md](row-updates/interface-spec-conflicts.md)
and closed at `I07`/`I10`/`I19`. Spec text may still lag Rust; the TypeScript
surface matches current Rust.

The runtime allowlists are pinned in
`sdk-libs/ts/interface/test/exports.test.ts`. The owned codec and state behavior
is pinned in `sdk-libs/ts/interface/test/interface.test.ts`.
