# Deposit Invariants

Covers `Deposit` (tag 1) and `ZoneDeposit` (tag 15). Shared invariants (pause,
rollback, event self-CPI, lamports conservation) live in `cross-cutting.md`.

SPEC_DIVERGENCE (resolved 2026-07-23): the spec's `DepositIxData`/`ZoneDepositIxData`
previously carried an `Option<u64>` public-amount pair; `docs/spec.md` now matches the
code (`view_tag`/`owner`/`blinding`/`amount: u64`/`utxo_data: Option<UtxoData>`/`memo`,
asset inferred from the settlement accounts).

## Deposit

### Account Constraints

- [x] **INV-DEPOSIT-01: depositor must sign**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `mollusk_deposit_rejects_every_account_privilege_downgrade`
  - Kind: precondition
  - Statement: `deposit` returns Err whenever the second account (index 1, `depositor`) is not a signer; the signer check runs in the processor before account parsing.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:43-46` (`fn process_deposit`)
  - Error: `ProgramError::MissingRequiredSignature`
  - Severity: Critical (authorizes `utxo_data` and funds)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-02: fewer than 3 accounts is rejected**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `mollusk_deposit_rejects_fewer_than_three_accounts_exactly`
  - Kind: precondition
  - Statement: `deposit` returns Err whenever fewer than 3 accounts are supplied.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:40-42` (`fn process_deposit`)
  - Error: `ProgramError::NotEnoughAccountKeys`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-03: SOL rail pins the funder to the depositor**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `sol_deposit_rejects_foreign_source`
  - Kind: precondition
  - Statement: on the SOL rail, the `user_sol` account address must equal the depositor signer's address; any other funder returns Err.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:142-145` (`fn validate_sol`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Critical (theft of third-party lamports)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-04: SOL rail requires system program, writable interface and funder**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `sol_deposit_rejects_wrong_vault`, `sol_deposit_rejects_wrong_system_program_account`, `sol_deposit_rejects_readonly_sol_interface`, `sol_deposit_rejects_readonly_user_sol`
  - Kind: precondition
  - Statement: on the SOL rail, the `system_program` account address must be the system program, and `sol_interface` and `user_sol` must both be writable, with `sol_interface` owned by the system program and equal to the canonical `[b"sol_interface", [0]]` PDA; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:128-148` (`fn validate_sol`), `settlement/validate.rs:15-28`
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-05: SPL rail pins the user token account to the depositor**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_deposit_rejects_foreign_source`
  - Kind: precondition
  - Statement: on the SPL rail, the user token account's stored owner must equal the depositor signer's address; any other token-account owner returns Err.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:188-191` (`fn validate_spl`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Critical (theft of third-party tokens)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-06: SPL rail binds the mint through the asset registry**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_deposit_rejects_mismatched_mint_atomically`
  - Kind: precondition
  - Statement: on the SPL rail, the registry account must be program-owned with the `SPL_ASSET_REGISTRY` discriminator, and its stored mint must equal both the user token account's mint and the vault's mint; any mismatch returns Err.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:169-179, 196-212` (`fn validate_spl`, `fn read_asset_registry_mint`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Critical (unregistered/unbacked asset)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-07: SPL rail requires the canonical per-mint vault PDA owned by the CPI authority**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_deposit_rejects_noncanonical_vault`
  - Kind: precondition
  - Statement: on the SPL rail, the vault address must equal the `[b"spl_asset_vault", mint]` PDA and the vault's stored owner must equal `SHIELDED_POOL_CPI_AUTHORITY`; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:172-186` (`fn validate_spl`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Critical (liquidity split / theft)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-08: trailing program account must be the shielded-pool program**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `mollusk_deposit_rejects_wrong_program_account_exactly`
  - Kind: precondition
  - Statement: the account following the settlement accounts must have exactly the shielded-pool program id as its address; any other address returns Err.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:108-111` (`fn validate_and_parse`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-DEPOSIT-09: surplus accounts are rejected**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `sol_deposit_rejects_extra_settlement_account`
  - Kind: precondition
  - Statement: `deposit` returns Err whenever accounts remain after the trailing program account (the SOL/SPL branch is chosen by remaining-count, so surplus accounts would otherwise mis-select the branch).
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:112-114` (`fn validate_and_parse`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

### Instruction Data Validation

- [x] **INV-DEPOSIT-10: malformed payload is rejected with 7000**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `mollusk_deposit_rejects_truncated_data_exactly`
  - Kind: precondition
  - Statement: every payload that `DepositIxData::deserialize` fails to parse exactly (truncated, trailing bytes, overlong length prefix) makes `deposit` return Err.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:38-39` (`fn process_deposit`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: fuzz + negative; harness: mollusk unit

- [x] **INV-DEPOSIT-11: zero amount is accepted and settles nothing**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `sol_deposit_accepts_zero_amount`, `spl_deposit_accepts_zero_amount`
  - Kind: postcondition
  - Statement: post-PR164, a zero-amount deposit entry is accepted: it appends an empty proofless output and moves no lamports/tokens (the old zero-amount gate was dropped with the batched deposit rewrite).
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs` (`fn process_deposit_internal`)
  - Severity: Medium
  - Suggested test: positive (zero entry accepted, no settlement); harness: mollusk unit

### Success Postconditions

- [x] **INV-DEPOSIT-12: the appended leaf commits the deposit exactly**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `sol_deposit_with_utxo_data_commits_the_data_hash`
  - Kind: postcondition
  - Statement: after a successful `deposit`, exactly one leaf is appended to the UTXO tree whose value is `Poseidon(field(UTXO_DOMAIN=1), pk_field(asset), field(amount), data_hash, Poseidon(data_hash=0-or-given, 0), Poseidon(owner, blinding))` with `asset = [0;32]` on the SOL rail and the registry mint on the SPL rail, `data_hash` from `utxo_data` or `[0;32]`, and the 31-byte `blinding` left-padded with one zero byte.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:101-126` (`fn process_deposit_internal`)
  - Severity: Critical (note integrity)
  - Suggested test: positive with recomputed hash; harness: mollusk unit + `cargo test -p` reference vector
  - Note: for the non-zone deposit both `zone_data_hash` and the zone id field are zero, so `zone_hash = Poseidon(0, 0)` per the spec rule "an absent zone_program_id is 0" (`docs/spec.md:491-495`).

- [x] **INV-DEPOSIT-13: UTXO tree next_index increases by exactly one**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `bootstrap_deposits_keep_indexer_wallet_and_tree_in_sync`
  - Kind: postcondition
  - Statement: after a successful `deposit`, the UTXO tree's `next_index` is exactly its value before plus 1, and the emitted `first_output_leaf_index` equals the pre-append `next_index`.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:128-137` (`fn process_deposit_internal`)
  - Severity: High
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-DEPOSIT-14: SOL deposit moves exactly amount from depositor to sol_interface**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `sol_deposit_moves_lamports_emits_the_exact_output_and_updates_the_indexer`
  - Kind: postcondition
  - Statement: after a successful SOL `deposit` of `amount`, the `sol_interface` lamports are exactly the before-value plus `amount` and the depositor's lamports are exactly the before-value minus `amount` (minus transaction fees paid outside the program).
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:139-141` (`fn process_deposit_internal`), `settlement/sol.rs:18-24`
  - Severity: Critical
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-DEPOSIT-15: SPL deposit moves exactly amount from user token account to vault**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/functional.rs` `spl_deposit_moves_tokens_emits_the_exact_output_and_updates_the_indexer`
  - Kind: postcondition
  - Statement: after a successful SPL `deposit` of `amount`, the vault token balance is exactly the before-value plus `amount` and the user token account balance is exactly the before-value minus `amount`, transferred with the depositor as authority.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:139-142` (`fn process_deposit_internal`), `settlement/spl.rs:66-73`
  - Severity: Critical
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-DEPOSIT-16: successful deposit emits exactly one Deposit GeneralEvent with a proofless output**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `sol_deposit_moves_lamports_emits_the_exact_output_and_updates_the_indexer`, `sol_deposit_emits_one_general_event_with_the_exact_deposit_withdraw`
  - Kind: postcondition
  - Statement: after a successful `deposit`, exactly one self-CPI `EmitEvent` inner instruction is recorded whose `GeneralEvent` has zero inputs, exactly one output carrying `view_tag`, the computed `utxo_hash`, and a `ProoflessOutput` payload with the cleartext `owner`, `blinding`, `asset`, `amount`, optional `data_hash`/`utxo_data`/`memo`, and whose `deposit_withdraw` is `Some { is_deposit: true, amount, asset: None-for-SOL / Some(mint)-for-SPL }`.
  - Location: `programs/shielded-pool/src/instructions/deposit/event.rs:20-61` (`fn emit_proofless_event`)
  - Severity: Medium (wallet discovery)
  - Suggested test: positive; harness: litesvm

### Frame Conditions

- [x] **INV-DEPOSIT-17: deposit modifies no account other than tree and the settlement pair**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `sol_deposit_modifies_only_the_tree_and_the_settlement_pair`
  - Kind: frame
  - Statement: after a successful `deposit`, every account other than the tree account, and the pair (depositor, sol_interface) on the SOL rail or (user token account, vault) on the SPL rail, has unchanged data and unchanged lamports.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:88-156` (`fn process_deposit_internal`)
  - Severity: High
  - Suggested test: positive; harness: mollusk unit (account snapshot compare)

## ZoneDeposit

### Account Constraints

- [x] **INV-ZONE-DEPOSIT-01: depositor must sign**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `mollusk_zone_deposit_rejects_an_unsigned_depositor_exactly`
  - Kind: precondition
  - Statement: `zone_deposit` returns Err whenever the second account (index 1, `depositor`) is not a signer.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:67-70` (`fn process_zone_deposit`)
  - Error: `ProgramError::MissingRequiredSignature`
  - Severity: Critical
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-DEPOSIT-02: fewer than 4 accounts is rejected**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `mollusk_zone_deposit_rejects_fewer_than_four_accounts_exactly`
  - Kind: precondition
  - Statement: `zone_deposit` returns Err whenever fewer than 4 accounts are supplied.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:64-66` (`fn process_zone_deposit`)
  - Error: `ProgramError::NotEnoughAccountKeys`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-DEPOSIT-03: zone_config must sign**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `zone_deposit_rejects_an_unsigned_zone_config`
  - Kind: precondition
  - Statement: `zone_deposit` can only succeed when the `zone_config` account (third parsed account) is a signer.
  - Location: `programs/shielded-pool/src/instructions/deposit/account.rs:49-51` (`fn validate_and_parse`, `HAS_ZONE = true`)
  - Error: account-checks signer error
  - Severity: Critical (zone authorization)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-DEPOSIT-04: zone_config must be a valid SPP-owned ZoneConfig**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `zone_deposit_rejects_a_signer_that_is_not_the_zone_authority`
  - Kind: precondition
  - Statement: the `zone_config` account must be owned by the shielded-pool program, have `data_len` exactly 67, and discriminator byte exactly 4; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/zone_config/loader.rs:13-28` (`fn load_zone_config`)
  - Error: `ShieldedPoolError::InvalidZoneConfig = 7014`
  - Severity: Critical
  - Suggested test: negative; harness: mollusk unit

### Instruction Data Validation

- [x] **INV-ZONE-DEPOSIT-05: malformed payload is rejected with 7000**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `zone_deposit_rejects_malformed_payload_exactly`
  - Kind: precondition
  - Statement: every payload that `ZoneDepositIxData::deserialize` fails to parse exactly makes `zone_deposit` return Err.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:62-63` (`fn process_zone_deposit`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: fuzz + negative; harness: mollusk unit

### Success Postconditions

- [x] **INV-ZONE-DEPOSIT-06: the appended leaf commits the zone binding**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `zone_sol_deposit_settles_and_indexes_the_exact_output`
  - Kind: postcondition
  - Statement: after a successful `zone_deposit`, the single appended leaf's `zone_hash` component is exactly `Poseidon(zone_data_hash, pk_field(zone_config.program_id))`, where `program_id` is read from the signing `zone_config` account and never from instruction data.
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:109-113, 158-164` (`fn process_deposit_internal`, `fn hash_with_program_id`), `deposit/account.rs:49-55`
  - Severity: Critical (zone binding integrity)
  - Suggested test: positive with recomputed hash; harness: mollusk unit

- [x] **INV-ZONE-DEPOSIT-07: the emitted proofless output carries the zone fields**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `zone_sol_deposit_settles_and_indexes_the_exact_output`, `zone_deposit_event_carries_the_zone_data_preimage_verbatim`
  - Kind: postcondition
  - Statement: after a successful `zone_deposit`, the emitted `ProoflessOutput` payload carries exactly `zone_program_id = Some(zone_config.program_id)`, the instruction's `zone_data_hash`, and the `zone_data` preimage.
  - Location: `programs/shielded-pool/src/instructions/deposit/event.rs:20-40` (`fn emit_proofless_event`), `processor.rs:76-85`
  - Severity: Medium (indexer/zone discovery)
  - Suggested test: positive; harness: litesvm

- [x] **INV-ZONE-DEPOSIT-08: settlement and tree postconditions equal the plain deposit's**
  - Covered by: `program-tests/shielded-pool/tests/deposit/functional.rs` `zone_sol_deposit_settles_and_indexes_the_exact_output`
  - Kind: postcondition
  - Statement: after a successful `zone_deposit`, the settlement transfer and the UTXO-tree `next_index` change are exactly those of INV-DEPOSIT-13/14/15 (the zone adds authorization and hash inputs, not settlement behavior).
  - Location: `programs/shielded-pool/src/instructions/deposit/processor.rs:88-156` (`fn process_deposit_internal`)
  - Severity: High
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)
