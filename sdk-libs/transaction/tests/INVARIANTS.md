# Transaction crate test invariants

Coverage specification for the public APIs of `zolana-transaction`, following the
[shielded-pool invariant checklist](../../../program-tests/shielded-pool/invariants/README.md).
This file is a manually maintained specification; Rust tests implement its claims.
Program acceptance of a manually assembled witness does not establish SDK builder
coverage. Tests belong in this directory, with no inline unit tests in `src/`.

## Reading and maintaining the checklist

IDs are stable: never renumber an existing invariant. Each statement is an
observable requirement, not a description of an internal loop. Source links below
identify the implementation; test references identify actual assertions. Counts of
tests or checkboxes do not measure line/branch coverage.

- `[x]` Covered: direct assertions exist and the relevant test target passes.
- `[ ]` Partial: some assertions exist; the missing cases are stated.
- `[ ]` Missing: no direct crate test identified; the statement is a test work item.
- `[ ]` Blocked: a relevant test exists but cannot compile/run; it does not count.

Kinds: **pre** = acceptance/rejection condition; **post** = result on success;
**frame** = what remains unchanged; **wire** = hash/encoding compatibility.
Severity: **C** = value/spend/authorization integrity, **H** = invalid commitments,
unrecoverable outputs or incompatible encodings, **M** = metadata/API correctness.
An unchecked row is not necessarily an implementation defect. Desired guarantees
that are not implemented are listed separately under open questions.

To update: read the production symbol and the test assertions, add exact negative
errors and boundary cases, run the target, then update the evidence. Golden values
must have provenance; do not replace them just because the implementation changed.
Prefer comparisons to independent expected balances/notes, fixed protocol vectors,
and before/after snapshots. Pure serialization round trips alone do not establish
commitment validity, ownership, or spendability.

## Construction and padding

Source: [constructor](../src/instructions/transact/mod.rs),
[input helpers](../src/instructions/transact/inputs.rs),
[outputs and balance](../src/instructions/transact/outputs.rs),
[shape selection](../src/instructions/transact/shape.rs).

| ID | Kind / severity | Invariant | Coverage / required assertions |
|---|---|---|---|
| <a id="build-01"></a>INV-TX-BUILD-01 | pre / H | `ConfidentialTransaction::new` rejects an empty input vector with `NoInputs` and a dummy in slot zero with `DummyInFirstInputSlot`. | [x] `construction.rs::constructor_rejects_missing_and_dummy_first_inputs`. |
| INV-TX-BUILD-02 | pre / C | Each real input's committed fields, nullifier public key, supplied data hashes and tree ID must reproduce its published commitment; a validly encoded mismatch returns `InputCommitmentMismatch { index }`. | [x] `construction.rs::constructor_binds_every_committed_input_field_at_each_position`. |
| INV-TX-BUILD-03 | pre / H | Real inputs carrying UTXO or ring preimages require their corresponding hashes; construction reports `MissingInputDataHash` or `MissingInputRingDataHash` at the offending index. | [x] `construction.rs::constructor_requires_preimage_hashes_but_accepts_hash_only_inputs`. |
| INV-TX-BUILD-04 | pre / H | Real inputs declare at most `MAX_INPUT_TREES`; every dummy must name one of those trees. Violations return `TooManyInputTrees` or `PaddingInUndeclaredTree`. | [x] `construction.rs::constructor_enforces_declared_contiguous_trees_and_preserves_input_order`. |
| INV-TX-BUILD-05 | pre / H | Each input tree occupies one contiguous run, including dummies; a return to a previous tree gives `InterleavedInputTrees { index, tree_id }`. | [x] `construction.rs::constructor_enforces_declared_contiguous_trees_and_preserves_input_order`, `construction.rs::shape_selection_boundaries_and_explicit_consolidation`. |
| INV-TX-BUILD-06 | post / H | Construction preserves caller input order, records distinct real tree IDs in first-use order, and takes `first_nullifier` from slot zero. | [x] `construction.rs::constructor_enforces_declared_contiguous_trees_and_preserves_input_order`, `construction.rs::generated_sol_and_spl_operations_conserve_each_mint_and_recover_every_output`. |
| INV-TX-BUILD-07 | pre / H | Automatic shape selection returns the first fitting entry in the supported shape order excluding `IN36_OUT2`, or `UnsupportedShape`; consolidation is explicit only. | [x] `construction.rs::shape_selection_boundaries_and_explicit_consolidation`, `construction.rs::builder_automatically_selects_every_supported_nonconsolidation_boundary`. |
| INV-TX-BUILD-08 | pre / H | Explicit shape resolution rejects unsupported shapes, too many inputs and too many outputs with their distinct errors; `check_shape` requires exact final dimensions. | [x] `construction.rs::shape_selection_boundaries_and_explicit_consolidation`, `construction.rs::failed_padding_is_atomic_and_repairable_without_losing_configuration`. |
| INV-TX-BUILD-09 | post / H | For valid ordered inputs, padding preserves existing input slots and appends dummies under the last declared real input tree until the requested input count is reached. | [x] `construction.rs::padding_extends_last_tree_without_touching_existing_inputs`. |
| INV-TX-BUILD-10 | pre / C | For each active mint, negative change is rejected with `InsufficientBalance`; positive change above `u64::MAX` is rejected with `SelectedBalanceOverflow`. | [x] `construction.rs::failed_padding_is_atomic_and_repairable_without_losing_configuration`, `construction.rs::explicit_output_fields_survive_padding_and_change_uses_asset_first_use_order`, `construction.rs::another_mints_surplus_cannot_fund_private_or_public_spl_deficits`. |
| INV-TX-BUILD-11 | pre / H | Padding rejects more than `N_PUBLIC_SLOTS` active `Mint` values with `TooManyAssets`; zero-amount private slots do not create active assets. | [x] `construction.rs::asset_limit_ignores_zero_private_slots_and_failure_retains_configurability`. |
| INV-TX-BUILD-12 | post / C | For canonical zero-amount dummies and a consistent mint-address/compact-ID mapping, successful padding satisfies `sum(real inputs) + deposits - withdrawals = sum(outputs)` independently for each mint. | [x] `construction.rs::generated_sol_and_spl_operations_conserve_each_mint_and_recover_every_output`, `construction.rs::another_mints_surplus_cannot_fund_private_or_public_spl_deficits`. |
| INV-TX-BUILD-13 | post / H | Explicit outputs retain their order and data; nonzero change is appended in asset first-use order (positive inputs, then positive explicit outputs, then settlement requests); remaining outputs are zero-amount SOL notes owned by the sender, not ownerless circuit dummies. | [x] `construction.rs::explicit_output_fields_survive_padding_and_change_uses_asset_first_use_order`, `construction.rs::generated_sol_and_spl_operations_conserve_each_mint_and_recover_every_output`. |
| INV-TX-BUILD-14 | frame / H | A failed `pad_utxos` leaves the configurable builder unchanged, so a later valid padding attempt can succeed with the original contents. | [x] `construction.rs::failed_padding_is_atomic_and_repairable_without_losing_configuration`, `construction.rs::asset_limit_ignores_zero_private_slots_and_failure_retains_configurability`, `construction.rs::another_mints_surplus_cannot_fund_private_or_public_spl_deficits`. |
| INV-TX-BUILD-15 | frame / H | After padding, repeat padding, output addition, settlement addition and output-tree changes reject with `OutputUtxosAlreadyPadded` when their arguments pass any earlier convenience-API validation. Borrowing mutation failures preserve the padded state. | [x] `construction.rs::padded_builder_rejects_every_mutator_and_remains_encryptable`. |

Shape/count cases must separate the layers: `canonical_shape` and `resolve_shape`
only select capacities (including requests with zero counts); `check_shape` checks
exact dimensions and tree-run order, not commitment validity, first-slot ownership,
or balance. Builder tests must go through `ConfidentialTransaction`, not just call
these helpers. For encryption comparisons, ignore fresh salt/ciphertext equality;
assert decoded fields, commitments, selected dimensions and preserved input slots.

## Encryption, ownership and rings

Source: [encryption](../src/instructions/transact/encryption.rs),
[ring selection](../src/instructions/transact/ring.rs),
[signer assembly](../src/instructions/transact/inputs.rs).

| ID | Kind / severity | Invariant | Coverage / required assertions |
|---|---|---|---|
| INV-TX-ENC-01 | post / C | `encrypt` completes omitted shape selection/change/padding and produces outputs whose published commitments and decryptable plaintexts describe the same amounts, owners, data, blindings and output tree. | [x] `construction.rs::generated_sol_and_spl_operations_conserve_each_mint_and_recover_every_output`, `construction.rs::encrypted_explicit_data_and_memo_survive_with_their_commitment_hashes`. |
| INV-TX-ENC-02 | post / H | Every output blinding uses the transaction's first nullifier, derived output seed, and final physical slot index. | [x] `construction.rs::generated_sol_and_spl_operations_conserve_each_mint_and_recover_every_output` verifies every recovered slot; `encrypted_explicit_data_and_memo_survive_with_their_commitment_hashes` checks replacement of caller blindings. Independent derivation vectors: `commitments.rs::derivation_domains_match_committed_cross_language_vectors_and_bind_each_parameter`. |
| INV-TX-ENC-03 | post / C | Sender outputs use `Account(0)` only when the Ed25519/PDA sender equals the payer; other owners use their inline tag. Published owner tags resolve to the owner whose viewing key encrypts the slot. | [x] `construction.rs::mixed_rings_and_relayed_owner_tags_match_recovered_owners`, `construction.rs::pda_sender_owner_tags_resolve_for_self_paid_and_relayed_transactions`. |
| INV-TX-ENC-04 | pre / H | A P256 sender requires a custom ring; transfer convenience APIs reject P256 recipients with `P256TransactUnsupported`. | [x] `construction.rs::p256_requires_custom_sender_ring_and_cannot_use_transfer_convenience_apis`. |
| INV-TX-ENC-05 | post / H | Normal transfers/change/padding inherit the builder's ring; `transfer_with_ring` overrides only its output. Custom-ring outputs are encoded as `RingConfidential`, default-ring outputs as `Confidential`. | [x] `construction.rs::mixed_rings_and_relayed_owner_tags_match_recovered_owners`, `construction.rs::generated_sol_and_spl_operations_conserve_each_mint_and_recover_every_output`. |
| INV-TX-ENC-06 | post / C | Owner signers exclude dummies, P256 owners and the payer, deduplicate owner identities, and preserve first occurrence. `signer_pk_hashes` is payer-first, zero-padded to width, and returns `UnsupportedShape` if the run does not fit. | [x] `commitments.rs::signers_are_payer_first_deduplicated_by_identity_and_exclude_dummies_and_p256`. |
| INV-TX-ENC-07 | pre / H | Empty transaction-key responses cause `IncompleteDerivation { got: 0, want: 1 }`; key-holder errors propagate from builder encryption. | [x] `construction.rs::key_holder_errors_and_empty_response_propagate_and_requests_use_first_input`. |
| INV-TX-ENC-08 | post / H | `requires_p256_owner` and `inputs_require_p256` report whether any real input uses P256, ignoring dummies. | [x] `construction.rs::p256_requires_custom_sender_ring_and_cannot_use_transfer_convenience_apis`. |
| INV-TX-ENC-09 | post / H | Builder encryption requests one transaction viewing key naming the returned sender viewing key and the stored first input nullifier, and publishes the returned key in its encryption context. | [x] `construction.rs::key_holder_errors_and_empty_response_propagate_and_requests_use_first_input`. |

## Settlement and external data

Source: [settlement](../src/instructions/transact/settlement.rs),
[external data](../src/instructions/transact/external_data.rs).

| ID | Kind / severity | Invariant | Coverage / required assertions |
|---|---|---|---|
| INV-TX-SETTLE-01 | pre / C | Zero transfer amounts fail with `ZeroInterfaceTransferAmount`; SOL/SPL target mismatches fail with `SettlementTargetMismatch`. Failed `settle` does not append a transfer. | [x] `settlement.rs::settlement_validation_is_atomic_for_both_directions_and_targets`. |
| INV-TX-SETTLE-02 | pre / H | Transfer count cannot exceed `MAX_INTERFACE_TRANSFERS`; the exact maximum is accepted and the next addition is rejected without changing a mutable builder. | [x] `settlement.rs::settlement_count_limit_is_enforced_at_each_public_boundary`. |
| INV-TX-SETTLE-03 | pre / H | SPL convenience methods reject `SOL_MINT` with `ExpectedSplMint`; SPL transfer/withdrawal require a mint present in a real input or return `UnknownMint`. | [x] `settlement.rs::spl_convenience_apis_require_spl_mints_and_existing_spends_but_deposits_can_introduce_assets`. |
| INV-TX-SETTLE-04 | post / C | Public slots aggregate each mint in first-use order, with positive deposits and negative withdrawals, and leave unused slots zero. | [x] `settlement.rs::public_slots_aggregate_by_mint_in_first_use_order_with_signed_amounts`. |
| INV-TX-SETTLE-05 | pre / C | Low-level public-slot derivation rejects a zero net asset, a running aggregate magnitude above `u64::MAX`, or more than `N_PUBLIC_SLOTS` public assets with `ZeroNetInterfaceTransferAmount`, `PublicTransferOverflow`, or `TooManyPublicAssets`, respectively. | [x] `settlement.rs::public_slots_reject_zero_net_intermediate_overflow_and_excess_assets`, `settlement.rs::zero_amount_and_spl_sol_alias_are_rejected_by_external_data_and_public_slots`. |
| INV-TX-SETTLE-06 | wire / H | Field amounts are zero for zero, `amount` for deposits and `p - amount` for withdrawals in 32-byte big-endian BN254 encoding; interleaving yields asset, amount pairs in slot order. | [x] `settlement.rs::signed_field_amounts_match_literal_bn254_boundaries_and_interleave_all_slots`. |
| INV-TX-SETTLE-07 | wire / C | External-data hashing binds discriminator, expiry, encryption context, ordered output/message payloads, optional hashes, ordered settlement accounts and resolved account-owner addresses under the canonical program encoding. | [x] `settlement.rs::external_hash_binds_every_context_payload_order_and_settlement_field`, `settlement.rs::external_hash_uses_canonical_bytes_and_only_resolves_account_owner_tags`. |
| INV-TX-SETTLE-08 | pre / H | `with_ring_hashes` refuses to overwrite either already-populated hash with `RingHashesAlreadySet`. | [x] `settlement.rs::ring_hashes_can_be_set_once_and_neither_existing_field_can_be_overwritten`. |
| INV-TX-SETTLE-09 | wire / C | SOL settlement account pairs contain `SOL_INTERFACE` then the user SOL account; SPL pairs contain mint then user token account. Instruction legs preserve direction/amount and derive the SPL interface bump from that mint. | [x] `settlement.rs::ordered_settlement_accounts_and_instruction_legs_survive_builder_encryption`. SPL bump is independently derived from the address primitive and literal protocol seed, not a hardcoded bump vector. |
| INV-TX-SETTLE-10 | wire / C | External-data owner resolution requires one resolved tag per output; only `Account` tags append the supplied resolved address to the hash preimage. Inline owner addresses are already encoded in the output. | [x] `settlement.rs::external_hash_uses_canonical_bytes_and_only_resolves_account_owner_tags`. |

## UTXOs and commitments

Source: [UTXO hashing](../src/utxo/note.rs), [output hashing](../src/utxo/output.rs),
[dummy inputs](../src/utxo/input.rs), [wallet conversion](../src/utxo/wallet.rs),
[transaction hashes](../src/instructions/transact/transaction.rs),
[ring authority](../src/instructions/ring_authority.rs).

| ID | Kind / severity | Invariant | Coverage / required assertions |
|---|---|---|---|
| INV-TX-HASH-01 | wire / C | Real commitments bind tree ID, mint address, amount, data/ring hashes, ring program and owner/nullifier-key/blinding identity; compact asset ID is not a commitment field. | [x] `commitments.rs::commitments_bind_each_spend_field_in_both_input_and_output_representations`, `commitments.rs::commitments_do_not_bind_compact_ids_viewing_keys_cached_tags_or_raw_preimages`. |
| INV-TX-HASH-02 | wire / C | Dummy input commitments use the dummy domain and assigned tree; their nullifiers derive from the zero nullifier secret and their own commitment/blinding. | [x] `commitments.rs::dummy_hash_has_fixed_domain_and_tree_bound_zero_secret_nullifier`. |
| INV-TX-HASH-03 | wire / C | `message_hash` zeroes circuit-dummy inputs and ownerless dummy outputs but includes the real commitment of a sender-owned zero-amount padding output. | [x] `commitments.rs::ownerless_outputs_and_dummy_inputs_contribute_zero_but_owned_zero_outputs_are_committed`. |
| INV-TX-HASH-04 | wire / C | `PrivateTxHash` folds input/output/address-nullifier chains, external hash and private blinding; absent address nullifiers mean a zero chain of input width. `message_hash` is SHA256 of that private hash. | [x] `commitments.rs::private_transaction_hash_binds_every_chain_order_external_hash_and_blinding`, `commitments.rs::ownerless_outputs_and_dummy_inputs_contribute_zero_but_owned_zero_outputs_are_committed`. |
| INV-TX-HASH-05 | wire / C | Output seed, per-slot output blinding, and private transaction blinding use their distinct domains; changing first nullifier, secret seed or slot changes the appropriate derived value. | [x] `commitments.rs::derivation_domains_match_committed_cross_language_vectors_and_bind_each_parameter`. |
| INV-TX-HASH-06 | post / H | Owned and borrowed `WalletUtxo` conversions preserve all proof-input fields exactly, including published commitment/nullifier and tree/leaf metadata, without recomputation. | [x] `commitments.rs::wallet_conversions_preserve_every_proof_field_without_recomputation`. |
| INV-TX-HASH-07 | post / H | Output data setters retain at most one record of each kind in RingData/UtxoData/Memo order; memo changes do not change commitments. | [x] `commitments.rs::data_setters_replace_one_record_per_kind_and_keep_canonical_order`. |
| INV-TX-HASH-08 | wire / H | Shared merge-input count, tree heights, instruction tags, view-tag width and input-tree limits match the committed constants vector. | [x] `constants_vectors.rs::constants_match_the_shared_vector`. |
| INV-TX-HASH-09 | wire / C | Absent program IDs encode as the zero field; present IDs encode as `hash_bytes(address)` and ring-program hashing uses the same mapping. Output absent data/ring-data hashes are equivalent to explicit zero hashes. | [ ] Partial: `commitments.rs::program_and_data_hash_defaults_distinguish_absence_from_a_present_zero_address` checks default/custom mapping against the hash primitive and data-hash defaults; independent custom-ring byte vectors remain. |

## Merge

Source: [merge constructor](../src/instructions/merge/mod.rs),
[validation](../src/instructions/merge/inputs.rs),
[encryption](../src/instructions/merge/encryption.rs),
[ring merge](../src/instructions/merge/ring.rs),
[derivations](../src/instructions/merge/blinding.rs).

| ID | Kind / severity | Invariant | Coverage / required assertions |
|---|---|---|---|
| INV-TX-MERGE-01 | pre / H | Both merge constructors reject empty input with `NoInputs` and counts above `MAX_MERGE_INPUTS` with `TooManyInputs { got, max }`; valid counts select the smallest supported count that fits. | [ ] Partial: `merge.rs::merge_count_boundaries_are_explicit` checks both constructor rejection limits and helper 0/1/7/8/9/35/36/37/usize::MAX; `both_merge_sizes_preserve_inputs_and_recover_the_exact_sum` checks default merge success. Ring success is exercised separately, but not at every count boundary. |
| INV-TX-MERGE-02 | pre / C | All merge inputs must have the same `Mint`; summing their amounts above `u64::MAX` fails with `SelectedBalanceOverflow`. | [x] `merge.rs::merge_requires_one_mint_and_checked_total` checks address/compact-ID mismatches, exact maximum and overflow. |
| INV-TX-MERGE-03 | pre / H | Default merge rejects ring-bound inputs with `MergeInputRingMismatch` and all attached data/hashes (including memos) with `MergeInputHasData`; ring merge requires the selected ring, rejects UTXO data/hash, and permits ring data/hash and memos. | [ ] Partial: `merge.rs::default_and_ring_merge_apply_distinct_data_rules` tests default/ring preimage and hash gates and accepted ring data/memo; later-index and all empty-record/wrong-ring permutations remain. |
| INV-TX-MERGE-04 | pre / C | Encryption rejects inputs with a different owner rail, signing owner, or nullifier public key from the sender, with `MergeInputRailMismatch`, `MergeInputOwnerMismatch`, or `MergeInputNullifierKeyMismatch` at the offending index. | [ ] Partial: `merge.rs::merge_rejects_foreign_owner_rail_and_nullifier_key` checks all three exact later-index errors through both entry points and Ed25519/P256 success; first-index and PDA cases remain. |
| INV-TX-MERGE-05 | post / C | Successful encryption returns one sender-owned output with exactly the summed amount and selected mint, ring, output tree and expiry; confidential plaintext preserves its representable fields. | [ ] Partial: `merge.rs::both_merge_sizes_preserve_inputs_and_recover_the_exact_sum`, `merge_requires_one_mint_and_checked_total`, `ring_merge_preserves_spl_and_explicit_output_context` and `default_and_ring_merge_apply_distinct_data_rules` check sums, schemes, recovered plaintext, SPL/ring context and commitments; zero totals and full ring-size/recipient-key matrix remain. |
| INV-TX-MERGE-06 | post / H | Existing merge inputs retain order and every proof-input field; padding reaches the chosen supported input count with zero-amount dummy notes. | [x] `merge.rs::both_merge_sizes_preserve_inputs_and_recover_the_exact_sum` compares every preserved proof-input field, exact lengths and zero-amount dummy ownership at 1/8/9/36 inputs. |
| INV-TX-MERGE-07 | wire / C | Merge dummy nullifiers bind secret, first real nullifier and physical slot; output/private blindings use their specified distinct derivations. | [ ] Partial: `merge.rs::merge_derivations_match_shared_vectors_and_bind_every_parameter` checks independent shared vectors, domains and key/nullifier/slot changes; `merge_accessors_filter_dummies_and_recheck_data` checks physical slots 2..7. Nonadjacent dummy assembly and slot 255 remain. |
| INV-TX-MERGE-08 | pre / H | Dummy-nullifier assembly rejects missing or dummy-first input with `NoInputs`; builder encryption rejects an empty blinding/key response with `IncompleteDerivation { got: 0, want: 1 }`. | [x] `merge.rs::merge_accessors_filter_dummies_and_recheck_data` and `merge_routes_key_requests_and_propagates_failures` assert both first-input errors, empty responses and exact propagated key-holder errors. |
| INV-TX-MERGE-09 | pre / H | `input_utxo_hashes` returns references to real inputs in their existing order, excludes dummies, and rejects disallowed data under the proof object's default/ring policy with `MergeInputHasData`. | [ ] Partial: `merge.rs::merge_accessors_filter_dummies_and_recheck_data` checks mixed inputs and post-construction default memo rejection; `default_and_ring_merge_apply_distinct_data_rules` checks ring-policy success. Full mutated data/hash matrix and filtered-index case remain. |
| INV-TX-MERGE-10 | post / C | Key-holder encryption requests output blinding and transaction viewing key using the stored first input nullifier; the transaction-key request names the sender's viewing key. Returned values feed the emitted output blinding and encryption context. | [ ] Partial: `merge.rs::merge_routes_key_requests_and_propagates_failures` records exact requests and output blinding; `ring_merge_preserves_spl_and_explicit_output_context` checks supplied key/blinding. Direct equivalence with the same fixture remains. |

Merge fixtures should start from independently valid wallet notes, compare sums with
an integer oracle, and verify decoded output fields and commitments. A successful
merge builder is not proof of circuit acceptance; ownership checks alone do not
validate commitments, tree layout, nullifier correctness or duplicate spends.

## Serialization and data

Source: [formats](../src/serialization/mod.rs), [schemes](../src/serialization/scheme.rs),
[data records](../src/data.rs), [key schemas](../src/lib.rs).

| ID | Kind / severity | Invariant | Coverage / required assertions |
|---|---|---|---|
| INV-TX-WIRE-01 | wire / H | Scheme bytes are Proofless=0, AnonymousRecipient=1, AnonymousSender=2, Confidential=3, RingConfidential=4, Merge=6, PlaintextTransfer=7, RingDeposit=8; every other byte returns `BadDiscriminator`. | [x] `formats.rs::scheme_discriminators_cover_the_entire_byte_space`, `encoders_publish_the_expected_envelope_and_scheme_with_decodable_bodies`, and `proofless_full_fields_use_exact_borsh_and_resolve_the_published_mint`; ring-confidential emission: `construction.rs::mixed_rings_and_relayed_owner_tags_match_recovered_owners`. |
| INV-TX-WIRE-02 | pre / H | `Data::validate` and the Wincode payload serialization/deserialization wrappers require records to be unique and ordered RingData then UtxoData then Memo, with exact duplicate/order errors. `Data::new` itself does not validate. | [x] `formats.rs::payload_wrappers_validate_all_record_kinds_on_write_and_read`. Direct permutations/duplicates are also checked in `behavior.rs::every_record_kind_rejects_duplicates` and `record_order_accepts_canonical_subsets_and_rejects_every_other_permutation`. |
| INV-TX-WIRE-03 | post / M | Memo-only data is accepted and accessible; proofless encode/decode preserves memo contents. | [x] `behavior.rs::memo_only_is_valid`, `memo_round_trips_and_is_readable`, `proofless.rs::memo_round_trips_through_proofless_serialization`. |
| INV-TX-WIRE-04 | pre / H | Wincode payload decoders reject truncation and trailing bytes; payloads with key schemas reject malformed keys, and payloads with `Data` validate canonical records. Plaintext-transfer decoding also rejects a wrong type prefix. | [ ] Partial: `formats.rs::exact_payload_decoders_reject_every_truncation_trailing_bytes_and_invalid_keys` checks all payload decoders for exact framing and representative owner/P256 schema failures; malformed-key mutations at every individual payload key field remain. |
| INV-TX-WIRE-05 | post / H | A confidential slot embeds the recipient viewing key and recovers identical plaintext via recipient and transaction viewing keys with the original context. | [x] `confidential.rs::embedded_viewing_pk_is_the_recipient_pk`, `recipient_and_tx_key_both_decrypt_the_slot`. |
| INV-TX-WIRE-06 | pre / H | Confidential body splitting rejects a body shorter than a compressed P256 key with `InvalidLength` when the required encryption context is supplied. | [x] `confidential.rs::short_body_fails_with_invalid_length` covers decrypt, embedded-key lookup and transaction-key decode. Missing-context behavior remains WIRE-07. |
| INV-TX-WIRE-07 | pre / H | Confidential and anonymous encrypted decode require transaction viewing key and salt (`MissingEncryptionContext`); ID-based reconstruction rejects unknown asset IDs, and confidential/sender/plaintext reconstruction rejects ring preimages without a ring program (`MissingRingProgramId`). Proofless reconstruction uses mint addresses and has different validation. | [x] `formats.rs::encrypted_formats_require_both_context_fields_and_reconstruction_checks_assets_and_rings`. |
| INV-TX-WIRE-08 | pre / H | Anonymous recipient reconstruction allows memos but rejects ring or UTXO preimages with `UnsupportedOutputData`. | [x] `anonymous.rs::memo_only_recipient_is_accepted`, `ring_or_utxo_data_recipient_is_rejected`. |
| INV-TX-WIRE-09 | pre / H | Anonymous sender and plaintext bundles require a first nullifier; change uses physical slots 0/1 and plaintext recipients use slots 2 onward. | [x] `formats.rs::sender_slots_remain_physical_when_change_is_absent_and_recipients_start_at_two`. |
| INV-TX-WIRE-10 | pre / H | Plaintext encoding rejects unmatched blindings, non-increasing positions and recipient gaps; reconstruction rejects recipient positions greater than or equal to `MAX_OUTPUTS`. | [x] `formats.rs::plaintext_encoder_rejects_unknown_duplicate_reordered_and_gapped_positions`. |
| INV-TX-WIRE-11 | pre / H | A sender bundle rejects data attached to an absent output with `DataWithoutOutput` (anonymous: zero amount; plaintext: absent option). | [x] `formats.rs::data_requires_a_present_sender_output_but_explicit_zero_plaintext_outputs_exist`. |
| INV-TX-WIRE-12 | post / H | A ring-deposit plaintext encrypted for a recipient decrypts to the complete original value and reconstructs RingData/UtxoData/Memo in canonical order with caller-supplied owner/mint/amount/ring. | [x] `formats.rs::ring_deposit_recovers_all_optional_records_and_reproduces_the_commitment`. |
| INV-TX-WIRE-13 | wire / H | Proofless uses exact Borsh decoding and preserves published owner hash, mint address, amount, blinding, optional hashes, ring ID and optional preimages/memo; reconstruction resolves the mint and takes the signing owner from `OwnerCx`. | [x] `formats.rs::proofless_full_fields_use_exact_borsh_and_resolve_the_published_mint`. |
| INV-TX-WIRE-14 | wire / H | Payload record tags are RingData=1, UtxoData=2, Memo=3, with u8 record counts and u16 byte lengths; anonymous viewing-key and plaintext recipient lists use u8 counts. | [x] `formats.rs::data_and_payload_lengths_match_literal_little_endian_layouts`. |
| INV-TX-WIRE-15 | post / H | Anonymous and plaintext sender reconstruction uses SPL slot 0 and SOL slot 1 even when one change is absent; plaintext recipient slot derivation always starts at 2. Ring-bearing anonymous sender/plaintext records use the caller's ring only when RingData exists. | [x] `formats.rs::sender_slots_remain_physical_when_change_is_absent_and_recipients_start_at_two`. |

## Decoding and spend verification

Source: [scan and verification](../src/decrypt.rs),
[indexed output helpers](../src/indexer_types.rs).

| ID | Kind / severity | Invariant | Coverage / required assertions |
|---|---|---|---|
| INV-TX-SCAN-01 | post / H | `decrypt` returns decoded candidates with published hash/tree/leaf, transaction signature/slot, physical slot index and derived nullifier; it does not claim commitment or spend verification. | [x] `decryption.rs::sparse_encrypted_slots_preserve_metadata_and_separate_candidates_from_verified_notes`. |
| INV-TX-SCAN-02 | pre / H | Missing/malformed output envelopes, unknown/unsupported schemes, foreign proofless owner, confidential viewing keys not held and absent encryption context produce no candidate. | [x] `decryption.rs::malformed_unsupported_foreign_and_contextless_slots_do_not_hide_valid_notes`. |
| INV-TX-SCAN-03 | pre / C | `verify_spendable` excludes foreign owner/nullifier-key notes, unresolved data hashes and validly hashable commitments inconsistent with note fields or tree ID. Hashing errors propagate instead of silently skipping the note. | [x] `decryption.rs::verification_filters_each_untrusted_field_without_losing_the_valid_control`. |
| INV-TX-SCAN-04 | pre / C | Verification re-derives nullifiers and removes notes spent anywhere in the supplied batch, regardless of transaction order; caller-supplied note nullifiers do not override derived values. | [x] `decryption.rs::batch_spends_apply_before_or_after_publication_and_cached_nullifiers_are_untrusted`. |
| INV-TX-SCAN-05 | post / C | Duplicate verified commitments contribute once to spendable results and balances. | [x] `decryption.rs::unique_notes_sort_by_metadata_and_separate_ring_and_data_from_balances`, `decryption.rs::shuffled_multi_asset_publications_recover_unique_balances_and_data_notes`. |
| INV-TX-SCAN-06 | post / C | Verified ring-bound or data/hash-bearing notes are separated into `utxos_with_data`; ordinary and memo-only default-ring notes contribute to balances. | [x] `decryption.rs::unique_notes_sort_by_metadata_and_separate_ring_and_data_from_balances`, `decryption.rs::shuffled_multi_asset_publications_recover_unique_balances_and_data_notes`. |
| INV-TX-SCAN-07 | post / M | Notes are ordered by slot, signature bytes, then physical slot; balances are ordered by asset ID. Nonoverflowing balances equal the sum of included unspent unique notes. | [x] `decryption.rs::unique_notes_sort_by_metadata_and_separate_ring_and_data_from_balances`, `decryption.rs::shuffled_multi_asset_publications_recover_unique_balances_and_data_notes`. |
| INV-TX-SCAN-08 | pre / H | Decryption response counts must equal requests; nullifier derivation counts must equal candidate/verified note counts. Short or excess batches fail with `IncompleteDecryption`/`IncompleteDerivation` with exact `got`/`want`. No nullifier request is made for an empty candidate/verified set. | [x] `decryption.rs::response_cardinality_and_empty_batches_are_checked_at_each_scan_stage`, `decryption.rs::nullifier_requests_preserve_candidate_order_before_metadata_sorting`. |
| INV-TX-SCAN-09 | post / H | Anonymous recipient scanning tries held viewing keys in order and only accepts plaintext naming the wallet owner; confidential scanning selects the embedded held viewing key. | [x] `decryption.rs::retired_viewing_keys_recover_anonymous_and_confidential_slots_with_exact_requests`, `decryption.rs::anonymous_scanning_skips_noise_and_foreign_owners_then_accepts_first_eligible_plaintext`. |
| INV-TX-SCAN-10 | frame / M | Verification borrows candidates and leaves the original `DecryptionResult` unchanged on both successful filtering and key-holder error. | [x] `decryption.rs::key_holder_failures_propagate_and_verification_preserves_candidates`, `decryption.rs::batch_spends_apply_before_or_after_publication_and_cached_nullifiers_are_untrusted`. |
| INV-TX-SCAN-11 | pre / H | Key-holder address/decrypt/derive errors propagate; successfully parsed payload conversion errors (for example unknown assets, missing first nullifier or missing ring ID) propagate, while malformed bytes are skipped. | [x] `decryption.rs::key_holder_failures_propagate_and_verification_preserves_candidates`, `decryption.rs::parsed_conversion_errors_propagate_instead_of_being_treated_as_cipher_noise`. |

## Key holders and asset registry

Source: [keys](../src/keys.rs), [registry](../src/asset.rs).

| ID | Kind / severity | Invariant | Coverage / required assertions |
|---|---|---|---|
| INV-TX-KEYS-01 | pre / H | Constructing a local holder without the address's viewing key returns `AuthorityViewingKeyMismatch`; a transaction-key request for an unheld key returns `UnknownViewingKey`. | [x] `keys.rs::a_holder_without_the_addresss_own_viewing_key_is_refused`, `a_foreign_viewing_key_is_refused`. |
| INV-TX-KEYS-02 | post / H | Local viewing-key enumeration preserves supplied order, including retired keys. | [x] `keys.rs::retired_viewing_keys_are_kept_after_the_current_one`. The constructor does not sort them. |
| INV-TX-KEYS-03 | post / C | Nullifier and merge derivation requests return the corresponding primitive result in request order; transaction viewing keys use the requested viewing key and first nullifier. | [x] `keys.rs::derive_nullifier_matches_the_key_itself`, `derive_answers_a_batch_in_request_order`, `transaction_keys_match_the_viewing_key_derivation`, and `key_batches_preserve_empty_mixed_and_repeated_requests` assert primitive results, order, repetitions and retired-key selection. |
| INV-TX-KEYS-04 | post / H | Local decrypt uses the requested viewing key and UTXO/ring-deposit cipher label, preserving batch order. | [x] `keys.rs::local_decryption_batches_route_labels_and_retired_keys` checks distinct known plaintexts for both labels, current/retired keys, order and unknown-key error. |
| INV-TX-KEYS-05 | post / H | Local-holder empty decrypt/derive/transaction-key requests return empty vectors; successful batches return exactly one result per request, and a failing member returns an error for the batch. | [ ] Partial: `keys.rs::key_batches_preserve_empty_mixed_and_repeated_requests` and `local_decryption_batches_route_labels_and_retired_keys` check empty/mixed/repeated batches and exact returned vectors; unknown-key later-position and direct keypair equivalence remain. |
| INV-TX-ASSET-01 | post / H | The default registry maps reserved SOL ID 1 to `SOL_MINT`; registered SPL IDs resolve to their exact mint and reverse lookup is consistent. | [x] `assets.rs::asset_registry_is_bijective_and_reserves_sol` checks SOL, two SPL IDs and forward/reverse/field lookup. |
| INV-TX-ASSET-02 | frame / H | Insertion rejects reserved SOL ID, duplicate ID and duplicate mint with exact errors, preserving the registry. | [x] `assets.rs::rejected_registry_insertions_are_atomic` checks exact errors, full snapshots and a successful later insertion. |
| INV-TX-ASSET-03 | pre / H | Unknown ID/mint lookups return `UnknownAsset`/`UnknownMint`; unmatched field lookup returns `None`. | [x] `assets.rs::asset_registry_is_bijective_and_reserves_sol` checks both unknown lookup errors and unmatched field. |

## Open implementation questions — not coverage claims

- Builder accounting compares the full `Mint` (address plus compact ID), while
  commitments and low-level public aggregation use the mint address. The builder
  does not enforce registry-consistent IDs, including the reserved SOL mapping.
  Do not certify arbitrary `Mint` inputs with canonical-registry fixtures alone.
- Constructor dummy detection uses only the zero owner. It skips dummy commitment
  validation, and balance/asset accumulation includes nonzero amounts supplied on
  such dummies. A desired rejection/normalization of malformed dummy fields needs
  an implementation decision; avoid asserting successful malformed-dummy funding.
- Builder settlement validation can accept zero-net requests and intermediate
  amounts above `u64::MAX` that later cancel; low-level public-slot derivation
  rejects these. Encryption success alone does not guarantee all proof-input
  derivation methods succeed.
- Manual `pad_utxos` takes a sender independently from the later encryption sender.
  Their equality is not validated. Scope successful self-change recovery tests to
  matching senders until the contract for mismatched senders is decided.
- Public proof-input fields and nested UTXOs remain mutable after encryption.
  Changing output tree/body without rebuilding external data can make them disagree.
- `WalletUtxo` conversion trusts stored fields; confidential construction verifies
  real commitments but trusts supplied nullifiers. Data hashes are supplied, not
  recomputed from arbitrary custom program preimages.
- Selecting a confidential transaction ring assigns output policy; it does not
  validate input membership in that ring or prove authority to spend every input.
  P256 detection and owner-signer assembly likewise do not verify signatures.
- `ExternalData::hash` trusts caller-supplied resolved account owners; it checks
  their count but does not resolve account indexes or validate inline-resolution
  equality. `PrivateTxHash` does not check the address-nullifier chain length.
- Output data/ring hashes are not carried in confidential plaintext. Recovery of
  custom-preimage or hash-only commitments needs the corresponding hash resolution;
  decrypting a plaintext alone does not establish recoverable spendability.
- Merge construction does not duplicate confidential commitment/tree-order checks;
  its new dummy inputs currently use tree ID zero. Do not claim arbitrary multi-tree
  merge correctness based on a zero-tree fixture. It also trusts stored nullifiers
  and permits repeated commitments; duplicate-input rejection/normalization and
  first-input dummy rejection are not constructor guarantees.
- Ring merge accepts input ring preimages/memos but does not carry them to its
  output. A caller-selected output ring-data hash affects the commitment but is
  absent from confidential plaintext; recovery requires external hash resolution.
  `MergeProofInputs::input_utxo_hashes` checks only data eligibility and skips
  dummies; its name does not imply recomputation or full merge validation.
- `MergeTransaction::encrypt_with_viewing_key` trusts its supplied transaction key
  and output blinding. It does not prove that the key was derived for the sender
  and first nullifier; use a correct key for recovery guarantees. Key-holder
  derivations happen before owner validation, so owner failure is not a guarantee
  of no key-holder calls or side effects.
- For a deficit larger than `u64::MAX`, the builder narrows the shortage into the
  `InsufficientBalance.requested` field with an unchecked cast. Rejection still
  occurs, but exact diagnostic magnitude is not a guarantee for such deficits.
- Balance accumulation saturates on overflow. Decide whether it should return an
  error rather than adding a test that silently blesses saturation.
- Singleton `from_utxos` encoders use only the first note; anonymous sender encoding
  overwrites repeated asset legs and takes the first owner. Plaintext sender slots
  do not enforce a shared owner or the SOL mint in slot 1. Do not claim arbitrary
  input-note preservation or cardinality rejection; scope round trips to each
  format's representable inputs until stricter validation is decided.
- `Data::new` and public plaintext structs permit invalid records. Validation is
  performed by specific wrappers, not every reconstruction path; proofless
  reconstruction also does not reject RingData without a ring program.
- Scanning ignores view tags, transaction `proofless` flags and message payloads;
  those fields are not authenticity checks. A plaintext bundle yields multiple
  candidates sharing the containing slot's published commitment and metadata.
  Do not equate decoded bundle length with independently verified outputs.
- Verification trusts supplied data hashes rather than validating their preimages,
  and does not bind compact asset IDs. Inconsistent IDs for the same mint retain
  the first accepted ID in its balance entry; use a consistent registry in balance
  guarantees rather than implying verification repairs arbitrary candidates.
- Scanning is batch-local and does not authenticate indexer leaf indices or establish
  global unspent status. It ignores anonymous sender, ring-deposit and legacy merge
  envelopes; these formats are not interchangeable with the separate ring-deposit API.
- A local holder checks viewing-key presence but not consistency of its nullifier
  key with the supplied address. Builder encryption accepts the first value of a
  nonempty key response; scanning checks exact response counts.
- Do not assume unauthenticated encryption rejects every wrong context. Test that
  incorrect data cannot become a verified spendable commitment, not that every
  ciphertext alteration necessarily yields a cipher error.

## Implementation priorities and evidence

Implement tests only after all five document reviews are complete. Prioritize the
actual wallet path and financial assertions before broadening parser matrices:

1. **Builder to recovered spendable notes:** independently construct valid input
   commitments; call `ConfidentialTransaction`, transfer/deposit/withdraw, pad and
   encrypt; decode recipient and change outputs and verify the published
   commitments. Assert a separate per-mint integer ledger, exact shape/order,
   ownership, ring and settlement fields (BUILD-10–15, ENC-01–06, SETTLE-04/09).
   Include bounded generated sequences with fixed reproducible seeds and explicit
   boundary fixtures; a round trip without expected amounts is insufficient.
2. **Invalid inputs and failed mutations:** isolate each constructor, tree-order,
   shape, capacity, overflow and settlement error with a valid control fixture;
   assert exact error fields and unchanged accessible state (BUILD-01–11/14–15,
   SETTLE-01–05). Use representable shortage amounts for exact error metadata;
   shortages beyond `u64::MAX` expose a separate open question below.
3. **Spend verification:** mixed owned/foreign/tampered/spent/duplicate batches,
   independent expected balances and metadata, batch-order permutations and
   key-holder request/response failures (SCAN-01–11, ENC-07/09, KEYS-03–05).
4. **Merge:** both supported sizes and both rings, exact amount/owner checks,
   successful recovered outputs, dummy positions and recorded derivation requests
   (MERGE-01–10). Success fixtures must satisfy the documented trust preconditions.
5. **Wire and hash boundaries:** fixed-layout bytes and existing protocol vectors,
   field-by-field tampering, malformed/trailing bytes, exact enum/length boundaries,
   registry mutation failures and sparse physical slots (HASH, WIRE, ASSET).

A row with multiple required behaviors stays partial until all listed assertions
exist; add exact test names as evidence, including generated-case coverage. Tests
must call public APIs and assert observable results, not include production source
by path or recreate private helpers. A helper used to build a valid input fixture
is acceptable; it must not also compute every expected result of the behavior
under test. Do not turn the implementation questions into successful-behavior
regression tests without first deciding the intended contract.

Test files: [construction](construction.rs), [settlement](settlement.rs),
[commitments](commitments.rs), [merge](merge.rs), [decryption](decryption.rs),
[formats](formats.rs), [assets](assets.rs), [behavior](behavior.rs), [keys](keys.rs),
[confidential](confidential.rs), [anonymous](anonymous.rs),
[proofless](proofless.rs), [hash vectors](hash_vectors.rs), and
[constant vectors](constants_vectors.rs). The fixed hash vectors are low-level
evidence; builder behavior is exercised separately through its public API.

## Execution and review record

Run `cargo test -p zolana-transaction --offline` from the repository root. Tests
are hermetic and use the existing dependencies. `just test-sdk-libs` includes this
crate in the broader SDK gate. No SBF build, prover, validator or indexer is needed.

Initial verification (2026-09-19): `cargo test -p zolana-transaction --offline`
passes all 36 integration tests: 18 formerly inline tests moved here (with two old
mint fixtures updated), one constants-vector test, and 17 repaired hash-vector
tests. There are zero inline unit tests and three existing ignored doctests.
The hash vectors use public low-level assembly with all golden bytes unchanged;
this is hash compatibility evidence, not builder coverage.
All five successive subagent document reviews completed before adding new tests.

The measured baseline for `sdk-libs/transaction/src` is **627/2825 lines (22.19%)**
and **78/305 functions (25.57%)** under `llvm-cov`. This excludes dependency
coverage and is not a branch-coverage claim. Re-run the same coverage scope after
new tests, retaining the invariant evidence as the semantic coverage assessment.

Final verification (2026-09-19): **114 integration tests pass**, zero inline unit
tests remain, and the same three pre-existing doctest examples remain ignored.
The 87 invariant rows have **77 covered and 10 partial** entries; the partial
entries name the remaining case matrices or independent-vector gaps. Open
implementation questions above are separate from those coverage counts.

| Source coverage | Repaired existing suite | Expanded suite |
|---|---|---|
| Lines | 627/2825 (22.19%) | 2658/2825 (94.09%) |
| Functions | 78/305 (25.57%) | 273/305 (89.51%) |
| Regions | 761/3724 (20.44%) | 3409/3724 (91.54%) |

Measured with `cargo llvm-cov -p zolana-transaction --offline --json --summary-only`
and aggregated only over report filenames containing `/sdk-libs/transaction/src/`.
Tests, dependencies and unrelated workspace crates are excluded from these totals.
Region coverage is not branch coverage. Formatting and source-scope checks also
passed: source edits only remove the five migrated inline test modules.

Post-implementation review strengthened merge recovery to use the intended owner's
viewing key as well as the transaction key, checked caller-supplied viewing-key
ordering, and changed scanner rejection tests to compare the complete spendable
result. `decryption.rs::altered_encryption_context_and_ciphertext_cannot_create_spendable_notes`
tests salt/key/slot/ciphertext changes with a valid control. Its ciphertext mutation
still parses as an amount-66 candidate for the original amount-67 commitment;
verification excludes it. This checks the commitment boundary without assuming an
authenticated cipher.

| Pass | Review focus | Result |
|---|---|---|
| 1 | Construction, balance, padding and mutation safety | Reviewed source and vector assertions: clarified layer-specific validation, change bounds, order and retry requirements; scoped balance guarantees to canonical inputs; recorded malformed-dummy, mint-ID, settlement and sender-consistency gaps; refreshed repaired-vector evidence. |
| 2 | Commitments, settlement, signer and ring binding | Reviewed both transaction and canonical program hash implementations: added settlement account/bump and owner-resolution cases, signer width/identity boundaries, P256 detection and hash default/domain checks; recorded unchecked ring authority, account resolution and hash-recovery trust boundaries. |
| 3 | Encoding, decryption and key-holder trust boundaries | Reviewed serialization, scanner, local-holder code and migrated tests: added exact wire-layout/proofless cases, sparse physical slots, failure propagation and empty/mixed batch routing; clarified validation layers, duplicate selection and unauthenticated decoding; recorded lossy encoder, metadata and preimage-verification boundaries. |
| 4 | Merge, coverage evidence and missing edge cases | Reviewed merge constructors, both encryption paths, owner checks, derivations and existing key assertions: added exact indexed error/data matrices, physical-slot dummy vectors, key-holder request routing and accessor filtering; clarified plaintext hash limits and recorded unchecked commitments, duplicate inputs and caller-supplied keys. |
| 5 | Independent final audit of requirements and testability | Checked source links, unique IDs and existing covered assertions; separated missing-context coverage, added transaction-key request routing, recorded oversized-deficit diagnostics, and prioritized independent wallet/balance/spend assertions. Recorded the measured baseline without presenting line coverage as invariant coverage. |
