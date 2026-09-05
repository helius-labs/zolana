use shielded_pool_tests::support::{
    fixtures::Pool,
    merge::write_user_record,
    transact::{advance_nullifier_queue_past_dummy_threshold, write_ring_config_account},
};

use solana_account::Account;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::merge_ring::MergeRingIxData,
        instruction_data::merge_transact::{
            MergeProof, MergeTransactIxData, MERGE_DEFAULT_INPUT_COUNT,
        },
        tag, MergeRing, MergeTransact,
    },
    state::{discriminator::RING_CONFIG, RingConfig},
};
use zolana_program_test::{Rejection, ZolanaProgramTest};
use zolana_test_utils::transact::fe;
use zolana_user_registry_interface::USER_REGISTRY_PROGRAM_ID;

/// Wire-valid default-rail merge data with a zeroed proof: eight distinct
/// nullifiers against root-history slot 0, so every parse and tree step
/// succeeds and only the checks under test can fail. The merge output is
/// ciphertext-free (recovered from the first input and its nullifier).
fn merge_ix_data(eddsa_owner: bool) -> MergeTransactIxData {
    MergeTransactIxData {
        expiry_unix_ts: u64::MAX,
        proof: MergeProof::zeroed(),
        output_utxo_hash: fe(41),
        eddsa_owner,
        private_tx_hash: [0u8; 32],
        nullifiers: (1..=MERGE_DEFAULT_INPUT_COUNT as u64).map(fe).collect(),
        utxo_tree_root_index: vec![0; MERGE_DEFAULT_INPUT_COUNT],
        nullifier_tree_root_index: vec![0; MERGE_DEFAULT_INPUT_COUNT],
    }
}

fn merge_env() -> (ZolanaProgramTest, Pubkey) {
    let Pool { rpc, tree, .. } = Pool::initialized();
    (rpc, tree)
}

fn merge_instruction(
    rpc: &ZolanaProgramTest,
    tree: &Pubkey,
    user_record: Pubkey,
    data: MergeTransactIxData,
) -> solana_instruction::Instruction {
    MergeTransact {
        input_tree: *tree,
        output_tree: *tree,
        payer: rpc.payer.pubkey(),
        user_record,
        data,
    }
    .instruction()
    .expect("valid merge instruction")
}

/// Build a deliberately invalid merge payload while retaining the canonical
/// account layout from the checked builder. Only parser-rejection tests should
/// bypass the client-side shape validation this way.
fn merge_instruction_with_unchecked_data(
    rpc: &ZolanaProgramTest,
    tree: &Pubkey,
    user_record: Pubkey,
    data: MergeTransactIxData,
) -> solana_instruction::Instruction {
    let mut instruction =
        merge_instruction(rpc, tree, user_record, merge_ix_data(data.eddsa_owner));
    instruction.data = vec![tag::MERGE_TRANSACT];
    instruction
        .data
        .extend(data.serialize().expect("test payload must serialize"));
    instruction
}

#[test]
fn merge_rejects_a_user_record_not_owned_by_the_registry() {
    let (mut rpc, tree) = merge_env();
    // A funded system-owned account standing in for the record.
    let impostor = Pubkey::new_unique();
    rpc.airdrop(&impostor, 1_000_000).expect("fund impostor");
    let tree_before = rpc.account_data(&tree).expect("tree data");

    let ix = merge_instruction(&rpc, &tree, impostor, merge_ix_data(true));
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a non-registry record account must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidUserRecord).assert_litesvm(error);
    assert_eq!(
        rpc.account_data(&tree).expect("tree data"),
        tree_before,
        "rejected merge must leave the tree untouched"
    );
}

#[test]
fn merge_rejects_a_malformed_user_record() {
    let (mut rpc, tree) = merge_env();
    // Registry-owned, but the body is garbage: the discriminator is wrong and
    // the borsh decode cannot succeed.
    let record = Pubkey::new_unique();
    rpc.svm
        .set_account(
            record,
            Account {
                lamports: 1_000_000_000,
                data: vec![0xAA; 16],
                owner: Pubkey::new_from_array(USER_REGISTRY_PROGRAM_ID),
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("write malformed record");

    let ix = merge_instruction(&rpc, &tree, record, merge_ix_data(true));
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a malformed user record must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidUserRecord).assert_litesvm(error);
}

#[test]
fn merge_rejects_a_p256_rail_without_a_registered_p256_owner() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    // Valid record, merging enabled, but no P256 owner registered while the
    // instruction selects the P256 rail.
    let record = write_user_record(&mut rpc, payer, None, true);

    let ix = merge_instruction(&rpc, &tree, record, merge_ix_data(false));
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a P256 merge without a registered P256 owner must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidUserRecord).assert_litesvm(error);
}

#[test]
fn merge_rejects_a_wrong_input_count_shape() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);

    // Seven nullifiers serialize fine but are not a supported merge input
    // count, so the decode rejects them before any account is touched.
    let mut data = merge_ix_data(true);
    data.nullifiers.pop();
    let ix = merge_instruction_with_unchecked_data(&rpc, &tree, record, data);
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a 7-input merge must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidMergeShape).assert_litesvm(error);

    // The three vectors disagreeing is rejected the same way, even when the
    // nullifier count itself is supported.
    let mut data = merge_ix_data(true);
    data.utxo_tree_root_index.pop();
    let ix = merge_instruction_with_unchecked_data(&rpc, &tree, record, data);
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("disagreeing vector lengths must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidMergeShape).assert_litesvm(error);
}

/// The wide shape parses and reaches proof verification rather than being
/// refused as a shape. The proof here is a dummy, so the expected outcome is a
/// verification failure: what this pins is that 36 inputs is accepted as a
/// shape, and that the widened account list is loaded.
#[test]
fn merge_accepts_the_wide_shape_and_fails_only_on_the_proof() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);

    const WIDE: usize = 36;
    let mut data = merge_ix_data(true);
    data.nullifiers = (1..=WIDE as u64).map(fe).collect();
    data.utxo_tree_root_index = vec![0; WIDE];
    data.nullifier_tree_root_index = vec![0; WIDE];
    let ix = merge_instruction(&rpc, &tree, record, data);
    // The wide shape does not fit the 200,000 CU default: 36 nullifier PDAs and
    // 36 queue insertions put it past it before the pairing even starts, so a
    // caller must raise the limit explicitly. The measured cost of a successful
    // wide merge, and its pinned ceiling, live in `merge/functional.rs`.
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let error = rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .expect_err("a dummy proof must not verify");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed)
        .at(1)
        .assert_litesvm(error);
}

#[test]
fn merge_rejects_an_expired_transaction() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);

    // The merge dispatch shares transact's expiry gate (`check_not_expired`).
    // Pin the sysvar clock one second past the instruction's expiry.
    let mut data = merge_ix_data(true);
    data.expiry_unix_ts = 1_000;
    let mut clock = rpc.svm.get_sysvar::<solana_clock::Clock>();
    clock.unix_timestamp = 1_001;
    rpc.svm.set_sysvar(&clock);
    let ix = merge_instruction(&rpc, &tree, record, data);
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("an expired merge must be rejected");
    Rejection::pool(ShieldedPoolError::ExpiredTransaction).assert_litesvm(error);
}

#[test]
fn merge_rejects_a_negative_clock() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);

    // A negative clock must reject regardless of `expiry_unix_ts` (here the
    // maximal one), before the `as u64` comparison could wrap it around.
    let data = merge_ix_data(true);
    let mut clock = rpc.svm.get_sysvar::<solana_clock::Clock>();
    clock.unix_timestamp = -1;
    rpc.svm.set_sysvar(&clock);
    let ix = merge_instruction(&rpc, &tree, record, data);
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a merge under a negative clock must be rejected");
    Rejection::pool(ShieldedPoolError::ExpiredTransaction).assert_litesvm(error);
}

#[test]
fn merge_rejects_a_non_writable_tree() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);

    let mut ix = merge_instruction(&rpc, &tree, record, merge_ix_data(true));
    // input_tree and output_tree are duplicate metas of one account; the
    // runtime unions their privileges, so both must be downgraded.
    ix.accounts
        .first_mut()
        .expect("input tree meta")
        .is_writable = false;
    ix.accounts
        .get_mut(1)
        .expect("output tree meta")
        .is_writable = false;
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a read-only tree must be rejected");
    Rejection::custom(u32::from(
        zolana_account_checks::AccountError::AccountNotMutable,
    ))
    .assert_litesvm(error);
}

#[test]
fn merge_rejects_an_unsigned_payer() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);

    // The instruction payer differs from the transaction fee payer and never
    // signs; the payer signer check is the only authorization on merge.
    let outsider = Pubkey::new_unique();
    let mut ix = MergeTransact {
        input_tree: tree,
        output_tree: tree,
        payer: outsider,
        user_record: record,
        data: merge_ix_data(true),
    }
    .instruction()
    .expect("valid merge instruction");
    ix.accounts.get_mut(2).expect("payer meta").is_signer = false;
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("an unsigned payer must be rejected");
    Rejection::custom(u32::from(
        zolana_account_checks::AccountError::InvalidSigner,
    ))
    .assert_litesvm(error);
}

#[test]
fn merge_ring_rejects_an_unsigned_ring_config() {
    let (mut rpc, tree) = merge_env();
    let mut ix = zolana_interface::instruction::MergeRing {
        input_tree: tree,
        output_tree: tree,
        ring_program_id: Pubkey::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID),
        payer: rpc.payer.pubkey(),
        data: merge_ix_data(true),
        output_ring_data_hash: fe(99),
    }
    .cpi_instruction()
    .expect("valid merge ring instruction");
    // The `ring_config` signature IS the ring authorization; without the ring
    // program's `invoke_signed` the flag must be rejected before the config is
    // even loaded (so the account does not need to exist).
    ix.accounts.get_mut(2).expect("ring config meta").is_signer = false;

    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("unsigned ring config must be rejected");
    Rejection::custom(u32::from(
        zolana_account_checks::AccountError::InvalidSigner,
    ))
    .assert_litesvm(error);
    rpc.last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[rpc.payer.pubkey()]);
}

#[test]
fn merge_rejects_dummy_inputs_after_capacity_threshold() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);

    // INV-TRANSACT-33, merge side: advance the nullifier progress metadata to
    // a valid near-capacity state with strictly fewer free nullifier leaves
    // than state leaves. The roots stay unchanged, so only the flipped
    // `allow_dummy_inputs` public input breaks proof verification.
    let mut account = rpc.svm.get_account(&tree).expect("tree account");
    {
        let mut on_chain = zolana_tree::TreeAccount::from_bytes(&mut account.data, tree.to_bytes())
            .expect("load tree");
        assert!(
            on_chain.allow_dummy_inputs().expect("dummy-input policy"),
            "fresh tree must allow dummy inputs"
        );
        advance_nullifier_queue_past_dummy_threshold(&mut on_chain);
        assert!(
            !on_chain.allow_dummy_inputs().expect("dummy-input policy"),
            "fixture must cross the dummy-input threshold"
        );
    }
    rpc.svm
        .set_account(tree, account)
        .expect("write threshold tree account");

    let ix = merge_instruction(&rpc, &tree, record, merge_ix_data(true));
    // The eight nullifier PDA creations precede proof verification, so the default
    // 200k budget no longer reaches it.
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let error = rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .expect_err("a merge past the capacity threshold must be rejected");
    // PR172 removed the explicit 7044 gate: the on-chain `allow_dummy_inputs`
    // flag is false while the merge proof assumes true, so the capacity
    // overflow now fails at proof verification.
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed)
        .at(1)
        .assert_litesvm(error);
    rpc.last_transaction_trace()
        .expect("capacity-gate transaction trace")
        .assert_rolled_back_except(&[payer]);
}

#[test]
fn merge_rejects_a_paused_tree() {
    let Pool {
        mut rpc,
        authority,
        tree,
    } = Pool::initialized();
    rpc.pause_tree(&authority, &tree, true).expect("pause tree");
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);

    let ix = merge_instruction(&rpc, &tree, record, merge_ix_data(true));
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a merge against a paused tree must be rejected");
    Rejection::pool(ShieldedPoolError::TreePaused).assert_litesvm(error);
}

#[test]
fn default_rail_merge_rejects_a_zeroed_proof_exactly() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    // Fully valid record and wire-valid merge data; the zeroed proof is the
    // only defect, so the failure is proof verification on the default
    // (registry-bound) rail.
    let record = write_user_record(&mut rpc, payer, None, true);
    let tree_before = rpc.account_data(&tree).expect("tree data");

    let ix = merge_instruction(&rpc, &tree, record, merge_ix_data(true));
    // Proof verification needs more than the 200k default budget.
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let error = rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .expect_err("a zeroed default-rail merge proof must be rejected");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed)
        .at(1)
        .assert_litesvm(error);
    assert_eq!(
        rpc.account_data(&tree).expect("tree data"),
        tree_before,
        "rejected merge must roll back the nullifier and output inserts"
    );
}

#[test]
fn default_rail_merge_rejects_undecompressable_proof_points_exactly() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);
    let tree_before = rpc.account_data(&tree).expect("tree data");

    // 0xFF-filled points carry invalid compression flag bits, so the verifier
    // fails at G1/G2 decompression -- the 7007 encoding error, distinct from
    // the 7008 pairing failure of a well-formed but non-verifying proof.
    let mut data = merge_ix_data(true);
    data.proof = MergeProof {
        a: [0xFF; 32],
        b: [0xFF; 64],
        c: [0xFF; 32],
    };
    let ix = merge_instruction(&rpc, &tree, record, data);
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let error = rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .expect_err("undecompressable merge proof points must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidTransactProofEncoding)
        .at(1)
        .assert_litesvm(error);
    assert_eq!(
        rpc.account_data(&tree).expect("tree data"),
        tree_before,
        "rejected merge must roll back the nullifier and output inserts"
    );
}

/// SPP-shaped ring merge instruction (as a ring program would CPI it, the
/// canonical `ring_auth` PDA marked signer).
fn merge_ring_cpi_instruction(
    rpc: &ZolanaProgramTest,
    tree: &Pubkey,
    data: MergeTransactIxData,
    output_ring_data_hash: [u8; 32],
) -> solana_instruction::Instruction {
    MergeRing {
        input_tree: *tree,
        output_tree: *tree,
        ring_program_id: Pubkey::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID),
        payer: rpc.payer.pubkey(),
        data,
        output_ring_data_hash,
    }
    .cpi_instruction()
    .expect("valid merge ring instruction")
}

/// Ring equivalent of [`merge_instruction_with_unchecked_data`], used only to
/// exercise the on-chain parser with a malformed merge shape.
fn merge_ring_cpi_instruction_with_unchecked_data(
    rpc: &ZolanaProgramTest,
    tree: &Pubkey,
    data: MergeTransactIxData,
    output_ring_data_hash: [u8; 32],
) -> solana_instruction::Instruction {
    let mut instruction = merge_ring_cpi_instruction(
        rpc,
        tree,
        merge_ix_data(data.eddsa_owner),
        output_ring_data_hash,
    );
    instruction.data = vec![tag::RING_MERGE_TRANSACT];
    instruction.data.extend(
        MergeRingIxData {
            output_ring_data_hash,
            merge: data,
        }
        .serialize()
        .expect("test payload must serialize"),
    );
    instruction
}

/// A valid-shaped `RingConfig` account written at a keypair address, so the
/// "ring_config" can sign a LiteSVM transaction without a ring program CPI.
/// Only the owner + size + discriminator + active-state checks apply
/// (INV-XC-26); the stored fields are never validated against a derivation.
fn write_fake_ring_config(
    rpc: &mut ZolanaProgramTest,
    address: Pubkey,
    discriminator: u8,
    paused: bool,
) {
    let config = RingConfig {
        discriminator,
        authority: [0u8; 32].into(),
        program_id: zolana_program_test::RING_TEST_PROGRAM_ID.into(),
        ring_authority_transact_is_enabled: 1,
        paused: u8::from(paused),
        bump: 0,
    };
    write_ring_config_account(
        rpc,
        address,
        rpc.program_id,
        bytemuck::bytes_of(&config).to_vec(),
    );
}

#[test]
fn merge_ring_rejects_a_ring_config_with_a_wrong_owner() {
    let (mut rpc, tree) = merge_env();
    // A signing account that is system-owned instead of SPP-owned.
    let impostor = Keypair::new();
    rpc.airdrop(&impostor.pubkey(), 1_000_000)
        .expect("fund impostor");

    let mut ix = merge_ring_cpi_instruction(&rpc, &tree, merge_ix_data(true), fe(90));
    ix.accounts.get_mut(2).expect("ring config meta").pubkey = impostor.pubkey();
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[&impostor])
        .expect_err("a ring config with a wrong owner must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidRingConfig).assert_litesvm(error);
    rpc.last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[rpc.payer.pubkey()]);
}

#[test]
fn merge_ring_rejects_a_ring_config_with_a_wrong_discriminator() {
    let (mut rpc, tree) = merge_env();
    // SPP-owned and correctly sized, but the discriminator byte is wrong.
    let fake = Keypair::new();
    write_fake_ring_config(&mut rpc, fake.pubkey(), RING_CONFIG + 1, false);

    let mut ix = merge_ring_cpi_instruction(&rpc, &tree, merge_ix_data(true), fe(91));
    ix.accounts.get_mut(2).expect("ring config meta").pubkey = fake.pubkey();
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[&fake])
        .expect_err("a ring config with a wrong discriminator must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidRingConfig).assert_litesvm(error);
    rpc.last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[rpc.payer.pubkey()]);
}

#[test]
fn merge_ring_rejects_an_unsigned_payer() {
    let (mut rpc, tree) = merge_env();
    // Valid signed ring config, so the payer signer check (third account) is
    // the branch that fires.
    let ring_config_signer = Keypair::new();
    write_fake_ring_config(&mut rpc, ring_config_signer.pubkey(), RING_CONFIG, false);

    let outsider = Pubkey::new_unique();
    let mut ix = MergeRing {
        input_tree: tree,
        output_tree: tree,
        ring_program_id: Pubkey::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID),
        payer: outsider,
        data: merge_ix_data(true),
        output_ring_data_hash: fe(92),
    }
    .cpi_instruction()
    .expect("valid merge ring instruction");
    ix.accounts.get_mut(2).expect("ring config meta").pubkey = ring_config_signer.pubkey();
    ix.accounts.get_mut(3).expect("payer meta").is_signer = false;
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[&ring_config_signer])
        .expect_err("an unsigned ring merge payer must be rejected");
    Rejection::custom(u32::from(
        zolana_account_checks::AccountError::InvalidSigner,
    ))
    .assert_litesvm(error);
    rpc.last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[rpc.payer.pubkey()]);
}

#[test]
fn merge_ring_rejects_a_paused_ring_config() {
    let (mut rpc, tree) = merge_env();
    let ring_config = Keypair::new();
    write_fake_ring_config(&mut rpc, ring_config.pubkey(), RING_CONFIG, true);

    let mut ix = merge_ring_cpi_instruction(&rpc, &tree, merge_ix_data(true), fe(94));
    ix.accounts.get_mut(2).expect("ring config meta").pubkey = ring_config.pubkey();
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[&ring_config])
        .expect_err("a paused ring config must reject ring merge");
    Rejection::pool(ShieldedPoolError::RingPaused).assert_litesvm(error);
    rpc.last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[rpc.payer.pubkey()]);
}

#[test]
fn merge_ring_rejects_a_wrong_input_count_shape_exactly() {
    let (mut rpc, tree) = merge_env();
    // Seven nullifiers violate the fixed 8-in/1-out shape at parse time, which
    // runs before any account (or the ring_config signature) is checked.
    let mut data = merge_ix_data(true);
    data.nullifiers.pop();
    let mut ix = merge_ring_cpi_instruction_with_unchecked_data(&rpc, &tree, data, fe(93));
    ix.accounts.get_mut(2).expect("ring config meta").is_signer = false;
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a 7-input ring merge must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidMergeShape).assert_litesvm(error);
    rpc.last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[rpc.payer.pubkey()]);
}

#[test]
fn merge_ring_rejects_a_paused_tree() {
    let Pool {
        mut rpc,
        authority,
        tree,
    } = Pool::initialized();
    rpc.load_ring_test_program()
        .expect("load ring test program");
    rpc.create_ring_config(&authority, &authority.pubkey(), true)
        .expect("create ring config");
    rpc.pause_tree(&authority, &tree, true).expect("pause tree");

    // Through the ring test program so the real `ring_auth` PDA signs; every
    // wire field is valid and the pause alone must halt the tree mutation.
    let ix = MergeRing {
        input_tree: tree,
        output_tree: tree,
        ring_program_id: Pubkey::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID),
        payer: rpc.payer.pubkey(),
        data: merge_ix_data(true),
        output_ring_data_hash: fe(95),
    }
    .instruction()
    .expect("valid merge ring instruction");
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a ring merge against a paused tree must be rejected");
    Rejection::pool(ShieldedPoolError::TreePaused).assert_litesvm(error);
    rpc.last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[rpc.payer.pubkey()]);
}

mod program_unit {
    use pinocchio::error::ProgramError;
    use shielded_pool_program::{testing::MergeTransactAccounts, ID};
    use zolana_account_checks::account_info::test_account_info::get_account_view;

    use super::*;

    #[test]
    fn rejects_invalid_system_program_with_specific_error() {
        let mut accounts = [
            get_account_view([1; 32], ID.to_bytes(), false, true, false, vec![]),
            get_account_view([2; 32], ID.to_bytes(), false, true, false, vec![]),
            get_account_view([3; 32], [0; 32], true, true, false, vec![]),
            get_account_view([4; 32], [0; 32], false, false, false, vec![]),
            get_account_view([5; 32], [0; 32], false, false, true, vec![]),
        ];

        let error = match MergeTransactAccounts::validate_and_parse(
            &mut accounts,
            MERGE_DEFAULT_INPUT_COUNT,
        ) {
            Ok(_) => panic!("invalid System Program must fail"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            ProgramError::Custom(ShieldedPoolError::InvalidSystemProgram as u32)
        );
    }

    /// The program account sits after the System Program and before the
    /// nullifier PDAs; any address other than SPP is rejected before the PDAs
    /// are read.
    #[test]
    fn rejects_wrong_program_account_with_incorrect_program_id() {
        let mut accounts = [
            get_account_view([1; 32], ID.to_bytes(), false, true, false, vec![]),
            get_account_view([2; 32], ID.to_bytes(), false, true, false, vec![]),
            get_account_view([3; 32], [0; 32], true, true, false, vec![]),
            get_account_view([4; 32], [0; 32], false, false, false, vec![]),
            get_account_view([0; 32], [0; 32], false, false, true, vec![]),
            get_account_view([6; 32], [0; 32], false, false, true, vec![]),
        ];

        let error = match MergeTransactAccounts::validate_and_parse(
            &mut accounts,
            MERGE_DEFAULT_INPUT_COUNT,
        ) {
            Ok(_) => panic!("a non-SPP program account must fail"),
            Err(error) => error,
        };
        assert_eq!(error, ProgramError::IncorrectProgramId);
    }
}
