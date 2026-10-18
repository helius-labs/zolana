//! Full custom-ring CPI into SPP with a registered merge owner.
//!
//! The ring-test stub creates authentic zero-valued input leaves. We replace
//! its program bytes with the custom ring after proving, preserving the ring
//! ID, SPP registration and tree. This tests the real custom wrapper without
//! needing an unrelated deposit proof in the merge fixture.

use custom_ring_interface::{
    CustomRingError, CustomRingMergeIxData, MemberRegistryRoot, RingMode, RingProgramConfig,
    MEMBER_REGISTRY_EMPTY_ROOT, MEMBER_REGISTRY_ROOT, MEMBER_REGISTRY_ROOT_HISTORY,
    RING_PROGRAM_CONFIG,
};
use custom_ring_sdk::{CustomRing, CustomRingMergeInstruction};
use shielded_pool_tests::support::{
    merge::{RealRingMerge, RealRingMergeProof},
    transact::{proof_env, tree_progress},
};
use solana_account::Account;
use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::ComputeBudgetConfig;
use zolana_interface::error::ShieldedPoolError;
use zolana_program_test::{workspace_path, Rejection};
use zolana_test_utils::nullifier_pda::assert_nullifier_pdas;

const MERGE_CU_LIMIT: u32 = 1_400_000;

fn account(owner: Pubkey, data: Vec<u8>) -> Account {
    Account {
        lamports: 1_000_000_000,
        data,
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

fn root_account(program: Pubkey, root: [u8; 32], next_index: u64) -> Account {
    let (_, bump) = Pubkey::find_program_address(&[MemberRegistryRoot::SEED], &program);
    let mut history = [[0; 32]; MEMBER_REGISTRY_ROOT_HISTORY];
    history[0] = root;
    let root = MemberRegistryRoot {
        discriminator: MEMBER_REGISTRY_ROOT,
        next_index: next_index.to_le_bytes(),
        bump,
        history_cursor: 0,
        history,
    };
    account(program, bytemuck::bytes_of(&root).to_vec())
}

fn install_custom_ring(
    pool: &mut shielded_pool_tests::support::fixtures::Pool,
    merge: &RealRingMerge,
) -> CustomRing {
    let program = merge.ring_program_id;
    let binary = std::fs::read(workspace_path("target/deploy/custom_ring_program.so"))
        .expect("build the custom ring SBF program first");
    pool.rpc
        .svm
        .add_program(program, &binary)
        .expect("replace ring-test stub with custom ring program");
    let ring = CustomRing::new(Address::new_from_array(program.to_bytes()));
    let (_, bump) = Pubkey::find_program_address(&[RingProgramConfig::SEED], &program);
    let auditor_pubkey: [u8; 33] =
        hex::decode("04708c2645c705baaf44f2ab947574174f9280df58be6fc2f6f2e8881b78a3115a")
            .expect("auditor public key")
            .try_into()
            .expect("tagged key length");
    let config = RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: Address::new_from_array(pool.authority.pubkey().to_bytes()),
        auditor_pubkey,
        bump,
        has_policy: 0,
        mode: RingMode::Off as u8,
    };
    pool.rpc
        .svm
        .set_account(
            Pubkey::new_from_array(*ring.config_pda().as_array()),
            account(program, bytemuck::bytes_of(&config).to_vec()),
        )
        .expect("write custom ring config");
    set_root(
        pool,
        ring,
        root_account(program, merge.data.member_registry_root, 2),
    );
    ring
}

fn set_root(
    pool: &mut shielded_pool_tests::support::fixtures::Pool,
    ring: CustomRing,
    root: Account,
) {
    pool.rpc
        .svm
        .set_account(
            Pubkey::new_from_array(*ring.member_registry_root_pda().as_array()),
            root,
        )
        .expect("write member registry root");
}

fn instruction(
    pool: &shielded_pool_tests::support::fixtures::Pool,
    ring: CustomRing,
    merge: &RealRingMerge,
) -> solana_instruction::Instruction {
    CustomRingMergeInstruction {
        ring,
        input_tree: Address::new_from_array(pool.tree.to_bytes()),
        output_tree: Address::new_from_array(pool.tree.to_bytes()),
        payer: Address::new_from_array(pool.rpc.payer.pubkey().to_bytes()),
        cosigner: None,
        data: CustomRingMergeIxData {
            registry_root_index: 0,
            output_ring_data_hash: merge.data.output_ring_data_hash,
            merge: merge.data.merge.clone(),
        },
    }
    .instruction()
}

#[test]
fn registered_merge_rejects_bad_roots_then_settles_through_spp() {
    let mut pool = proof_env();
    let merge = RealRingMergeProof {
        input_count: 8,
        real_input_count: 1,
    }
    .build(&mut pool);
    let ring = install_custom_ring(&mut pool, &merge);
    let ix = instruction(&pool, ring, &merge);
    let before = tree_progress(&pool.rpc, &pool.tree);

    // A missing history root cannot be supplied to the proof verifier.
    set_root(
        &mut pool,
        ring,
        root_account(merge.ring_program_id, [0; 32], 2),
    );
    let error = pool
        .rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix.clone()],
            &[],
            ComputeBudgetConfig::new(MERGE_CU_LIMIT),
        )
        .expect_err("unwritten registry root must fail");
    Rejection::custom(CustomRingError::StaleMemberRegistryRoot as u32).assert_litesvm(error);
    assert_eq!(tree_progress(&pool.rpc, &pool.tree), before);

    // The empty authenticated tree has no owner record for this proof.
    set_root(
        &mut pool,
        ring,
        root_account(merge.ring_program_id, MEMBER_REGISTRY_EMPTY_ROOT, 1),
    );
    let error = pool
        .rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix.clone()],
            &[],
            ComputeBudgetConfig::new(MERGE_CU_LIMIT),
        )
        .expect_err("unregistered owner root must fail");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    assert_eq!(tree_progress(&pool.rpc, &pool.tree), before);

    set_root(
        &mut pool,
        ring,
        root_account(merge.ring_program_id, merge.data.member_registry_root, 2),
    );
    pool.rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix],
            &[],
            ComputeBudgetConfig::new(MERGE_CU_LIMIT),
        )
        .expect("registered custom ring merge settles through SPP");
    let consumed = pool
        .rpc
        .last_transaction_trace()
        .expect("successful merge trace")
        .compute_units_consumed;
    println!("registered custom ring merge: {consumed} CU");
    assert!(consumed > 0 && consumed <= u64::from(MERGE_CU_LIMIT));
    assert_eq!(
        tree_progress(&pool.rpc, &pool.tree),
        (before.0 + 1, before.1 + 8)
    );
    assert_nullifier_pdas(&pool.rpc, &pool.tree, &merge.nullifiers)
        .expect("SPP created nullifier PDAs");
}

fn registered_compact_merge_settles(input_count: usize, real_input_count: usize) {
    let mut pool = proof_env();
    let merge = RealRingMergeProof {
        input_count,
        real_input_count,
    }
    .build_compact(&mut pool);
    assert_eq!(merge.data.merge.nullifiers.len(), real_input_count);
    let ring = install_custom_ring(&mut pool, &merge);
    let ix = instruction(&pool, ring, &merge);
    let before = tree_progress(&pool.rpc, &pool.tree);
    pool.rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix],
            &[],
            ComputeBudgetConfig::new(MERGE_CU_LIMIT),
        )
        .expect("registered compact merge settles through custom ring and SPP");
    let consumed = pool
        .rpc
        .last_transaction_trace()
        .expect("successful merge trace")
        .compute_units_consumed;
    println!("registered custom ring merge {input_count}/{real_input_count}: {consumed} CU");
    assert!(consumed > 0 && consumed <= u64::from(MERGE_CU_LIMIT));
    assert_eq!(
        tree_progress(&pool.rpc, &pool.tree),
        (before.0 + 1, before.1 + real_input_count as u64),
    );
    assert_nullifier_pdas(&pool.rpc, &pool.tree, &merge.data.merge.nullifiers)
        .expect("SPP created the real-input nullifier PDAs");
}

#[test]
fn registered_24_input_merge_settles_through_spp() {
    registered_compact_merge_settles(24, 24);
}

#[test]
fn registered_52_input_merge_settles_through_spp() {
    registered_compact_merge_settles(52, 50);
}
