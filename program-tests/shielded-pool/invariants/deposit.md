# Deposit Invariants

Covers `Deposit` (tag 1) and `ZoneDeposit` (tag 15). Shared invariants (pause,
rollback, event self-CPI, lamports conservation) live in `cross-cutting.md`.

SPEC_DIVERGENCE (resolved 2026-07-23): the spec's `DepositIxData`/`ZoneDepositIxData`
previously carried an `Option<u64>` public-amount pair; `docs/spec.md` now matches the
code. The instruction data is batched: `assets: Vec<DepositAssetKind>` declares the
settlement groups (and their account layout) and `deposits: Vec<DepositEntry>` carries
the entries (`view_tag`/`owner`/`blinding`/`amount: u64`/`utxo_data: Option<UtxoData>`/`memo`),
each selecting its asset by `asset_index` into `assets`.

## Deposit

### Account Constraints

- [x] **INV-DEPOSIT-01: depositor must sign**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `mollusk_deposit_rejects_every_account_privilege_downgrade`
  - Kind: precondition
  - Statement: `deposit` returns Err whenever the second account (index 1, `depositor`) is not a signer; the signer check is `iter.next_signer("depositor")` inside `DepositAccounts::validate_and_parse`.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:69` (`fn validate_and_parse`)
  - Error: `ProgramError::MissingRequiredSignature`
  - Severity: Critical (authorizes `utxo_data` and funds)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-02: fewer than 3 accounts is rejected**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `mollusk_deposit_rejects_fewer_than_three_accounts_exactly`
  - Kind: precondition
  - Statement: `deposit` returns Err whenever fewer than 3 accounts are supplied; there is no explicit count comparison — the data-declared account layout is consumed through an iterator that fails with `NotEnoughAccountKeys`, so the real minimum is layout-driven (a 1-asset SOL deposit needs 5 accounts).
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:65-69` (`AccountIterator` in `fn validate_and_parse`)
  - Error: `ProgramError::NotEnoughAccountKeys`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-03: SOL rail pins the funder to the depositor**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `sol_deposit_rejects_a_readonly_depositor`
  - Kind: precondition
  - Statement: on the SOL rail the lamports can only leave the depositor signer: the depositor account is the transfer source by construction, and it must be writable (`validate_sol_settlement`).
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:94-98` (`SettlementAccountsSol { recipient: depositor }` in `fn validate_and_parse`), `settlement/validate.rs:60-74` (`fn validate_sol_settlement`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Critical (theft of third-party lamports)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-04: SOL rail requires system program, writable interface and depositor**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `sol_deposit_rejects_wrong_vault`, `sol_deposit_rejects_wrong_system_program_account`, `sol_deposit_rejects_readonly_sol_interface`, `sol_deposit_rejects_a_readonly_depositor`
  - Kind: precondition
  - Statement: on the SOL rail, the `system_program` account address must be the system program, and `sol_interface` and the depositor must both be writable, with `sol_interface` owned by the system program and equal to the canonical `[b"sol_interface", [0]]` PDA; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:158-168` (`fn validate_sol`), `settlement/validate.rs:60-74` (`fn validate_sol_settlement`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-05: SPL rail pins the user token account to the depositor**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_deposit_rejects_foreign_source`
  - Kind: precondition
  - Statement: on the SPL rail, the user token account's stored owner must equal the depositor signer's address; any other token-account owner returns Err.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:200-205` (`fn validate_spl`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Critical (theft of third-party tokens)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-06: SPL rail binds the mint through the asset registry**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_deposit_rejects_mismatched_mint_atomically`
  - Kind: precondition
  - Statement: on the SPL rail, the registry account must be program-owned with the `SPL_ASSET_REGISTRY` discriminator, and its stored mint must equal both the user token account's mint and the vault's mint; any mismatch returns Err.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:196-205, 210-226` (`fn validate_spl`, `fn read_asset_registry_mint`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Critical (unregistered/unbacked asset)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-07: SPL rail requires the canonical per-mint vault PDA owned by the CPI authority**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_deposit_rejects_noncanonical_vault`
  - Kind: precondition
  - Statement: on the SPL rail, the vault address must equal the `[b"spl_asset_vault", mint]` PDA and the vault's stored owner must equal `SHIELDED_POOL_CPI_AUTHORITY`; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:196-197` (`fn validate_spl`), `settlement/validate.rs:100-114` (`fn validate_spl_settlement`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Critical (liquidity split / theft)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-08: trailing program account must be the shielded-pool program**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `mollusk_deposit_rejects_wrong_program_account_exactly`
  - Kind: precondition
  - Statement: the account following the settlement accounts must have exactly the shielded-pool program id as its address; any other address returns Err.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:144-147` (`fn validate_and_parse`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-09: surplus accounts are rejected**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `sol_deposit_rejects_extra_settlement_account`
  - Kind: precondition
  - Statement: `deposit` returns Err whenever accounts remain after the trailing program account (the settlement layout is declared by `assets` in the instruction data, so any surplus account is by definition unexplained).
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:148-150` (`fn validate_and_parse`, `iterator_is_empty`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-20: the same asset may be declared only once**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `deposit_batch_rejects_declaring_the_same_mint_twice`
  - Kind: precondition
  - Statement: two declared asset groups resolving to the same asset (all-zero SOL identity or same registry mint) return Err; one asset's settlement can never be split across two transfers.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:133-141` (`fn validate_and_parse`)
  - Error: `ShieldedPoolError::DuplicateDepositAsset = 7031`
  - Severity: Critical (settlement split)
  - Suggested test: negative; harness: mollusk unit

- [ ] **INV-DEPOSIT-23: more than MAX_DEPOSIT_ASSETS declared assets is rejected**
  - No direct on-chain test (builder-side only: `program-libs/interface/src/instruction/builders/deposit.rs`).
  - Kind: precondition
  - Statement: an `assets` list longer than `MAX_DEPOSIT_ASSETS` (5) returns Err at account parsing; the `ArrayMap` insert guard is the second, defensive gate.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:58-63`, `deposit/processor.rs:133-139`
  - Error: `ShieldedPoolError::TooManyDepositAssets = 7034`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [ ] **INV-DEPOSIT-24: an empty asset declaration is rejected**
  - No dedicated test found.
  - Kind: precondition
  - Statement: a batch declaring zero asset groups returns Err before any settlement account is read.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:58-60` (`fn validate_and_parse`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

### Instruction Data Validation

- [x] **INV-DEPOSIT-10: malformed payload is rejected with 7000**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `mollusk_deposit_rejects_truncated_data_exactly`
  - Kind: precondition
  - Statement: every payload that `DepositIxData::deserialize` fails to parse exactly (truncated, trailing bytes, overlong length prefix) makes `deposit` return Err.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:37-38` (`fn process_deposit`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: fuzz + negative; harness: mollusk unit

- [x] **INV-DEPOSIT-11: zero amount is accepted and settles nothing**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `sol_deposit_accepts_zero_amount`, `spl_deposit_accepts_zero_amount`
  - Kind: postcondition
  - Statement: post-PR164, a zero-amount deposit entry is accepted: it appends an empty proofless output and moves no lamports/tokens (the old zero-amount gate was dropped with the batched deposit rewrite).
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:65-209` (`fn process_deposit_internal`)
  - Severity: Medium
  - Suggested test: positive (zero entry accepted, no settlement); harness: mollusk unit

- [x] **INV-DEPOSIT-18: an empty deposit batch is rejected**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `deposit_batch_rejects_an_empty_batch`
  - Kind: precondition
  - Statement: `deposit`/`zone_deposit` return Err whenever the `deposits` entry list is empty, before any account is parsed.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:70-73` (`fn process_deposit_internal`)
  - Error: `ShieldedPoolError::EmptyDepositBatch = 7029`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-19: entry asset_index must reference a declared asset group**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `deposit_batch_rejects_an_out_of_range_asset_index`
  - Kind: precondition
  - Statement: every entry whose `asset_index` has no corresponding declared asset group returns Err (checked per entry during hashing, and again defensively at settlement fan-out).
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:99-102, 168-174` (`fn process_deposit_internal`)
  - Error: `ShieldedPoolError::InvalidDepositAssetIndex = 7030`
  - Severity: High (settlement binding)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-21: per-asset amount sums are overflow-checked**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `deposit_batch_rejects_summed_amounts_that_overflow`
  - Kind: precondition
  - Statement: the running `checked_add` sum of entry amounts per `asset_index` returns Err on u64 overflow.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:127-131` (`fn process_deposit_internal`)
  - Error: `ShieldedPoolError::DepositAmountOverflow = 7032`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-22: every declared asset group must be funded by an entry**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `deposit_batch_rejects_a_declared_asset_no_entry_funds`
  - Kind: precondition
  - Statement: after the batch loop, if the number of funded asset indices differs from the number of validated settlement groups, the instruction returns Err (an unused group would otherwise pass validation without settling).
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:160-164` (`fn process_deposit_internal`)
  - Error: `ShieldedPoolError::UnreferencedDepositAsset = 7033`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Success Postconditions

- [x] **INV-DEPOSIT-12: the appended leaf commits the deposit exactly**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `sol_deposit_with_utxo_data_commits_the_data_hash`
  - Kind: postcondition
  - Statement: after a successful `deposit`, one leaf per batch entry is appended to the UTXO tree whose value is `Poseidon(field(UTXO_DOMAIN=3), pk_field(asset), field(amount), data_hash, zone_hash, Poseidon(owner, blinding))` with `asset = [0;32]` on the SOL rail and the registry mint on the SPL rail, `data_hash` from `utxo_data` or `[0;32]`, `zone_hash = Poseidon(zone_data_hash, pk_field(zone_program_id))` as the 5th element, and the 31-byte `blinding` left-padded with one zero byte. (The batch-level append/settlement postconditions are INV-DEPOSIT-25.)
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:104-124` (`fn process_deposit_internal`)
  - Severity: Critical (note integrity)
  - Suggested test: positive with recomputed hash; harness: mollusk unit + `cargo test -p` reference vector
  - Note: for the non-zone deposit both `zone_data_hash` and the zone id field are zero, so `zone_hash = Poseidon(0, 0)` per the spec rule "an absent zone_program_id is 0" (`docs/spec.md:491-495`).

- [x] **INV-DEPOSIT-13: UTXO tree next_index increases by exactly the entry count**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `bootstrap_deposits_keep_indexer_wallet_and_tree_in_sync`
  - Kind: postcondition
  - Statement: after a successful `deposit` batch of N entries, the UTXO tree's `next_index` is exactly its value before plus N, and the emitted `first_output_leaf_index` equals the pre-append `next_index` (the batch-of-N semantics are pinned by INV-DEPOSIT-25).
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:95, 155-157` (`fn process_deposit_internal`, `append_batch`)
  - Severity: High
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-DEPOSIT-14: SOL deposit moves exactly amount from depositor to sol_interface**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `sol_deposit_moves_lamports_emits_the_exact_output_and_updates_the_indexer`
  - Kind: postcondition
  - Statement: after a successful SOL `deposit` of `amount`, the `sol_interface` lamports are exactly the before-value plus `amount` and the depositor's lamports are exactly the before-value minus `amount` (minus transaction fees paid outside the program).
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:176-186` (`fn process_deposit_internal`), `settlement/sol.rs:18-24`
  - Severity: Critical
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-DEPOSIT-15: SPL deposit moves exactly amount from user token account to vault**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/functional.rs` `spl_deposit_moves_tokens_emits_the_exact_output_and_updates_the_indexer`
  - Kind: postcondition
  - Statement: after a successful SPL `deposit` of `amount`, the vault token balance is exactly the before-value plus `amount` and the user token account balance is exactly the before-value minus `amount`, transferred with the depositor as authority.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:187-196` (`fn process_deposit_internal`), `settlement/spl.rs:58-80` (`fn settle_spl_deposit`)
  - Severity: Critical
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-DEPOSIT-16: successful deposit emits exactly one Deposit GeneralEvent with a proofless output per entry**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `sol_deposit_moves_lamports_emits_the_exact_output_and_updates_the_indexer`, `sol_deposit_emits_one_general_event_with_the_exact_deposit_withdraw`
  - Kind: postcondition
  - Statement: after a successful `deposit` batch, exactly one self-CPI `EmitEvent` inner instruction is recorded whose `GeneralEvent` has zero inputs, one output per batch entry carrying `view_tag`, the computed `utxo_hash`, and a `ProoflessOutput` payload with the cleartext `owner`, `blinding`, `asset`, `amount`, optional `data_hash`/`utxo_data`/`memo`, and whose `spl_transfers` carries one `SplTransfer { is_deposit: true, amount, asset: None-for-SOL / Some(mint)-for-SPL }` per funded asset group (pushed even for a zero total).
  - Location: `programs/shielded-pool/src/instructions/deposit/event.rs:16-46, 55-67` (`fn proofless_output_utxo`, `fn emit_deposit_event`)
  - Severity: Medium (wallet discovery)
  - Suggested test: positive; harness: litesvm

- [x] **INV-DEPOSIT-25: batch postconditions — N leaves, one settlement per funded asset**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `sol_deposit_batch_settles_once_and_appends_three_distinct_leaves`, `multi_asset_deposit_batch_settles_each_asset_once_and_appends_three_distinct_leaves`
  - Kind: postcondition
  - Statement: after a successful batch of N entries, the UTXO tree `next_index` increases by exactly N via one `append_batch` (one root recomputation); each funded asset group settles exactly once for its summed total (zero totals skip the CPI but still emit a zero `SplTransfer`); the event carries one output per entry in order and one `SplTransfer` per funded group. (Supersedes the single-leaf wording of INV-DEPOSIT-12/13/16.)
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:153-208` (`fn process_deposit_internal`)
  - Severity: Critical
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

### Frame Conditions

- [x] **INV-DEPOSIT-17: deposit modifies no account other than tree and the settlement pair**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `sol_deposit_modifies_only_the_tree_and_the_settlement_pair`
  - Kind: frame
  - Statement: after a successful `deposit`, every account other than the tree account, and the pair (depositor, sol_interface) on the SOL rail or (user token account, vault) on the SPL rail, has unchanged data and unchanged lamports.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:65-209` (`fn process_deposit_internal`)
  - Severity: High
  - Suggested test: positive; harness: mollusk unit (account snapshot compare)

## ZoneDeposit

### Account Constraints

- [x] **INV-ZONE-DEPOSIT-01: depositor must sign**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `mollusk_zone_deposit_rejects_an_unsigned_depositor_exactly`
  - Kind: precondition
  - Statement: `zone_deposit` returns Err whenever the second account (index 1, `depositor`) is not a signer.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:69` (`iter.next_signer("depositor")` in `fn validate_and_parse`)
  - Error: `ProgramError::MissingRequiredSignature`
  - Severity: Critical
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-DEPOSIT-02: fewer than 4 accounts is rejected**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `mollusk_zone_deposit_rejects_fewer_than_four_accounts_exactly`
  - Kind: precondition
  - Statement: `zone_deposit` returns Err whenever fewer than 4 accounts are supplied; there is no explicit count comparison — the data-declared account layout is consumed through an iterator that fails with `NotEnoughAccountKeys`, so the real minimum is layout-driven (tree, depositor, zone_config, plus the settlement group and program accounts).
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:65-82` (`AccountIterator` in `fn validate_and_parse`)
  - Error: `ProgramError::NotEnoughAccountKeys`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-DEPOSIT-03: zone_config must sign**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `zone_deposit_rejects_an_unsigned_zone_config`
  - Kind: precondition
  - Statement: `zone_deposit` can only succeed when the `zone_config` account (third parsed account) is a signer.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:77` (`iter.next_signer("zone_config")` in `fn validate_and_parse`, `HAS_ZONE = true`)
  - Error: account-checks signer error
  - Severity: Critical (zone authorization)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-DEPOSIT-04: zone_config must be a valid SPP-owned ZoneConfig**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `zone_deposit_rejects_a_signer_that_is_not_the_zone_authority`
  - Kind: precondition
  - Statement: the `zone_config` account must be owned by the shielded-pool program, have `data_len` exactly 67, and discriminator byte exactly 4; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/zone_config/loader.rs:14-20` (`fn load_zone_config`)
  - Error: `ShieldedPoolError::InvalidZoneConfig = 7014`
  - Severity: Critical
  - Suggested test: negative; harness: mollusk unit

### Instruction Data Validation

- [x] **INV-ZONE-DEPOSIT-05: malformed payload is rejected with 7000**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `zone_deposit_rejects_malformed_payload_exactly`
  - Kind: precondition
  - Statement: every payload that `ZoneDepositIxData::deserialize` fails to parse exactly makes `zone_deposit` return Err.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:50-51` (`fn process_zone_deposit`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: fuzz + negative; harness: mollusk unit

### Success Postconditions

- [x] **INV-ZONE-DEPOSIT-06: the appended leaf commits the zone binding**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `zone_sol_deposit_settles_and_indexes_the_exact_output`
  - Kind: postcondition
  - Statement: after a successful `zone_deposit`, each appended leaf's `zone_hash` component is exactly `Poseidon(zone_data_hash, pk_field(zone_config.program_id))`, where `program_id` is read from the signing `zone_config` account and never from instruction data.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:111-115, 211-217` (`fn process_deposit_internal`, `fn hash_with_program_id`), `deposit/account.rs:76-82`
  - Severity: Critical (zone binding integrity)
  - Suggested test: positive with recomputed hash; harness: mollusk unit

- [x] **INV-ZONE-DEPOSIT-07: the emitted proofless output carries the zone fields**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `zone_sol_deposit_settles_and_indexes_the_exact_output`, `zone_deposit_event_carries_the_zone_data_preimage_verbatim`
  - Kind: postcondition
  - Statement: after a successful `zone_deposit`, each emitted `ProoflessOutput` payload carries exactly `zone_program_id = Some(zone_config.program_id)`, the entry's `zone_data_hash`, and the `zone_data` preimage.
  - Location: `programs/shielded-pool/src/instructions/deposit/event.rs:16-46` (`fn proofless_output_utxo`), `processor.rs:142-150`
  - Severity: Medium (indexer/zone discovery)
  - Suggested test: positive; harness: litesvm

- [x] **INV-ZONE-DEPOSIT-08: settlement and tree postconditions equal the plain deposit's**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `zone_sol_deposit_settles_and_indexes_the_exact_output`
  - Kind: postcondition
  - Statement: after a successful `zone_deposit`, the settlement transfer and the UTXO-tree `next_index` change are exactly those of INV-DEPOSIT-13/14/15 (the zone adds authorization and hash inputs, not settlement behavior).
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:65-209` (`fn process_deposit_internal`)
  - Severity: High
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-ZONE-DEPOSIT-09: zone batch binds per-entry zone data**
  - Partial coverage: `program-tests/shielded-pool/tests/deposit/functional.rs` `zone_deposit_event_carries_the_zone_data_preimage_verbatim` (single-entry zone batches only).
  - Kind: postcondition
  - Statement: on the zone rail every entry carries its own `zone_data_hash`/`zone_data`; each leaf's `zone_hash` is `Poseidon(entry.zone_data_hash, pk_field(zone_config.program_id))`, and INV-DEPOSIT-18..25 apply unchanged (shared `process_deposit_internal<true>`).
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:49-63, 111-115` (`fn process_zone_deposit`, `fn process_deposit_internal`)
  - Severity: High
  - Suggested test: positive (multi-entry zone batch with distinct zone data); harness: program-tests integration (`cargo test-sbf`)
