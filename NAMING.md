# Naming Conventions

Conventions extracted from `sdk-libs`, `program-libs`, and
`programs/shielded-pool`. New code (including `sdk-tests` and per-test
programs) follows these. Existing exported core identifiers are pinned; do not
rename them to satisfy this document.

## Actors

Established parties: `user`, `payer`, `owner`, `sender`, `recipient`,
`authority` (qualified: `protocol_authority`, `tree_creation_authority`,
`forester_authority`, `zone_creation_authority`), `relayer`.

- The transaction fee payer is `payer` (`builders/transact.rs`,
  `payer_pubkey_hash`). Do not call it `issuer`, `caller`, or `maker` — those
  imply an identity check; name an account after a check only if the program
  performs it.
- The order creator is `user` in RFQ (matching `user_token_account` /
  `user_sol_account`); the swap program uses `maker`.
- The counterparty is `market_maker` / `MarketMaker` in RFQ, spelled out (never
  `mm` or `Mm*`); the swap program uses `taker`. This applies to Rust fields, Go
  circuit fields, and witness JSON keys.
- A party keeps the same name across the Go circuit, the Rust prover, the
  program, and the tests.

## Field-element encodings

Three operations produce `[u8; 32]`; the name must say which one:

- Poseidon-compressed encodings use `hash_field` / `*_field`:
  `owner_pk_field` (`sdk-libs/keypair/src/pubkey.rs`), `asset_field`,
  `signed_to_field`, `p256_signing_pk_field`. Go mirrors with `OwnerPkField`,
  `SolanaPkField`. These exported names are pinned.
- SHA-256 digests use `sha256` / `sha256_be` / `*_hash`.
- Plain zero-padding uses `right_align` / `fe_right_align`.

For new identifiers, prefer a name that needs no encoding suffix and let the
raw sibling carry the qualifier: the field-encoded per-leg asset values are
`SourceAsset` / `DestinationAsset` (they fill UTXO asset slots, as core Go
does with `UtxoCircuitFields.Asset`), and the raw u64 ids are
`SourceAssetId` / `DestinationAssetId`. When a local must distinguish the
encoded form from the raw value, use the `_fe` suffix (`secret_fe`,
`blinding_fe` in `sdk-libs/keypair`; PascalCase `Fe` in Go:
`MarketMakerPkFe`). Do not introduce new `_field`-suffixed names.

## Groth16 and proof terminology

- "committed" and "commitment" refer to BSB22 exclusively: `OrderProof::Committed`,
  `commitment`, `commitment_pok`, `vk_commitment_g2`.
- A verifying key checked into the repo is the `program_vk` (or
  `checked_in_vk`), never the "committed vk".
- A verifying key produced by a fresh setup is the `generated_vk`, not the
  `runtime_vk`.
- The rail without a BSB22 commitment is "standard Groth16" or named by the
  absence: `has_no_commitment`, `is_standard_groth16`. The word "vanilla" is
  banned in identifiers and prose.

## UTXOs / notes

Canonical struct fields (`sdk-libs/transaction/src/utxo.rs`): `owner`,
`asset`, `amount`, `blinding`, `zone_program_id`, `data`.

- Consumed notes: `SppProofInputUtxo` (signing/proving layer) or `InputUtxo`
  (encrypted/instruction layer); local binding `spend`; collections `inputs`.
- Created notes: `OutputUtxo`; collections `outputs`. No `src_out` / `in_` /
  `out_` prefixes.
- The client-side proof-inputs struct is `SppProofInputs`; its UTXO
  collections are qualified as `input_utxos` / `output_utxos`, while
  `inputs` / `outputs` remain the pinned spellings for the processor and
  instruction layers. Its remaining fields are `public_amounts`,
  `external_data`, `payer_pubkey_hash`, `p256_signature`, and `shape`.
  `p256_signature` holds a `[u8; 64]` signature, not an owner — never
  `p256_owner`. Local bindings are `proof_inputs`, never `signed`.
- The high-level padded-transfer builder is `Transfer` / `PreparedTransfer`,
  never `TxBuilder`; local bindings are `transfer`, not `tx`. The operation
  struct that seals slots into `SppProofInputs` is `SlotTransact` with a
  consuming `sign`. The first-nullifier accessor is `first_nullifier`.
- The note commitment is `utxo_hash`, not "commitment". The spend marker is
  `nullifier` (note method), `nullifier_hash` (instruction field),
  `nullifier_pk` / `nullifier_pubkey` (the key).
- When several blindings coexist, qualify each by its note
  (`escrow_blinding`, `market_maker_in_blinding`); a bare `blinding` is only
  acceptable where exactly one exists in scope.

## Keys

- Verifying key: type `Groth16Verifyingkey`, local `verifying_key` or `vk`,
  constant `VERIFYINGKEY`, selectors `select_*_verifying_key`.
- Public key: method `pubkey()`; field suffix `_pubkey`
  (`nullifier_pubkey`, `viewing_pubkey`) or `_pk` (`nullifier_pk`,
  `tx_viewing_pk`); constants `*_PUBKEY`. `pk` never means "proving key" in
  Rust code — proving keys live in the Go prover and its file names
  (`pk.bin`).
- Key material types: `SigningKey`, `ViewingKey`, `NullifierKey`, aggregated
  as `ShieldedKeypair { signing_key, nullifier_key, viewing_key }`.
- Use the full word `keypair` (`solana_keypair`, `shielded_keypair`).
  The `_kp` suffix is banned.
- Secret key fields are `secret` (accessors `secret()` / `secret_bytes()`);
  HKDF input material is `ikm`; ephemeral pairs are `ephemeral_pubkey` /
  `ephemeral_secret_key`.

## Hashes

Reuse these exact spellings:
`public_input_hash`, `private_tx_hash`, `external_data_hash`,
`payer_pubkey_hash`, `data_hash`, `zone_data_hash`, `utxo_hash`,
`owner_hash`, `owner_utxo_hash`, `nullifier_hash`, `hash_chain`
(accumulator local `acc`). Hash primitives are named by algorithm:
`poseidon`, `poseidon2`, `sha256`, `sha256_be`, `hash_field`.

## Instruction data and processors

- Owned struct `<Name>IxData`, borrowed view `<Name>IxDataRef<'a>`.
- Processor signature `process_<name>_ix(accounts, data: &[u8])`; the parsed
  struct is bound as `ix` (`let ix = TransactIxDataRef::from_bytes(data)?`).
  Never shadow `data` with the parsed struct.
- Shared bodies are `process_<name>_core`.
- Builder locals accumulating instruction bytes are `instruction_data`,
  seeded with `vec![tag::<NAME>]`. `payload` and `buf` are banned for
  instruction bytes.

## Accounts and loaders

- Raw `AccountView` bindings: `<role>_account` (`config_account`,
  `authority_account`). Loaded state: the type's short name (`config`).
- Loaders are `load_<thing>` / `load_<thing>_mut` in `loader.rs`.
- Validated account bundles: `<Ix>Accounts` with `validate_and_parse`.
- Program accounts passed for CPI: `<program>_program_account`, not the bare
  protocol name.

## PDAs and seeds

- Seed constants: `SCREAMING_SNAKE` ending in `_PDA_SEED`
  (`SPP_PROTOCOL_CONFIG_PDA_SEED`).
- Deriving functions are named after the account with no suffix
  (`protocol_config()`, `zone_config(zone_program)`), with a `_with_bump`
  variant; bump locals are `bump`.
- Local variables holding a derived address take the `_pda` suffix
  (`config_pda`).
- Signer-seed locals: `seeds`, `first_seed` — not `s` / `s0`.

## Go circuits

- Exported circuit fields are `PascalCase` one-to-one mirrors of the Rust
  names: `Owner`, `Asset`, `Amount`, `Blinding`, `DataHash`,
  `ZoneDataHash`, `OwnerPkField`, `OwnerPkHash`, `P256SigningPkField`.
  Circuit-local mirrors are `camelCase` (`p256PkField`, `ownerKeyHash`).
- Renaming a circuit struct field renames its witness JSON key; the Go
  bindings, the Rust witness writers, and any fixtures move in one commit.
- Do not shadow imported packages with locals (a `witness` map next to the
  `witness` package).
- KDF domain-separation constants are named after the domain string they
  hold (`mergeKdfInfo` for `"TSPP/merge"`), mirroring Rust's `INFO_*`
  constants.

## Banned

- `vanilla` — say "standard Groth16" or `has_no_commitment`.
- `mm`, `maker` — say `market_maker` / `MarketMaker`.
- `src`, `dst` — say `source` / `destination` (`SourceAsset`,
  `destination_output_blinding`).
- `issuer` — say `user` (order creator) or `payer` (fee payer).
- `payload`, `envelope`, `binding` (for data structures) — name the concrete
  struct (`SharedInputs`, `instruction_data`, `ix_data`).
- `_kp` — say `keypair`.
- `note` in identifiers — a UTXO is a `utxo`: `market_maker_utxo_hash`,
  `marketMakerUtxo`, not `maker_note_hash` / `makerNote`.
- New `_field` suffixes — use role-based names or `_fe` locals.
- Generic locals where a real name fits: `data` (except the processor
  byte-slice parameter), `info`, `result`, `target`, `tmp`, `val`, single
  letters outside tight loops and domain-standard proof points (`a`, `b`,
  `c`).
- Names that state an intent the code does not check (an account named
  `maker` that is only signer-checked) or a type the value does not have
  (`tree_key` for an authority keypair, `config` for a PDA address).
