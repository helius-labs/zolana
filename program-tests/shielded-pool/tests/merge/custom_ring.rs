//! Full custom-ring CPI into SPP with a registered merge owner.
//!
//! The ring-test stub creates authentic zero-valued input leaves. We replace
//! its program bytes with the custom ring after proving, preserving the ring
//! ID, SPP registration and tree. This tests the real custom wrapper without
//! needing an unrelated deposit proof in the merge fixture.

use bytemuck::Zeroable;
use custom_ring_interface::{
    CustomRingError, CustomRingMergeIxData, MemberRegistry, RingMode, RingProgramConfig,
    MEMBER_REGISTRY_EMPTY_ROOT, RING_PROGRAM_CONFIG,
};
use custom_ring_sdk::{CustomRing, CustomRingMergeInstruction};
use shielded_pool_tests::support::{
    fixtures::Pool,
    merge::{RealRingMerge, RealRingMergeProof},
    transact::{proof_env, tree_progress},
};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::ComputeBudgetConfig;
use zolana_interface::error::ShieldedPoolError;
use zolana_program_test::{workspace_path, Rejection};
use zolana_test_utils::nullifier_pda::assert_nullifier_pdas;

const MERGE_CU_LIMIT: u32 = 1_400_000;

struct InstalledRing {
    ring: CustomRing,
    program: Pubkey,
}

impl InstalledRing {
    fn install(pool: &mut Pool, merge: &RealRingMerge) -> Self {
        let program = merge.ring_program_id;
        let binary = std::fs::read(workspace_path("target/deploy/custom_ring_program.so"))
            .expect("build the custom ring SBF program first");
        pool.rpc
            .svm
            .add_program(program, &binary)
            .expect("replace ring-test stub with custom ring program");
        let installed = Self {
            ring: CustomRing::new(Address::new_from_array(program.to_bytes())),
            program,
        };
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
            mode: RingMode::Registry as u8,
            ..Zeroable::zeroed()
        };
        installed.write(
            pool,
            installed.ring.config_pda(),
            bytemuck::bytes_of(&config).to_vec(),
        );
        installed.set_registry(pool, installed.registry(merge.data.member_registry_root));
        installed
    }

    fn registry(&self, root: [u8; 32]) -> MemberRegistry {
        let (_, bump) = Pubkey::find_program_address(&[MemberRegistry::SEED], &self.program);
        let mut registry = MemberRegistry::new(bump, 0);
        registry.history[0].root = root;
        registry
    }

    fn set_registry(&self, pool: &mut Pool, registry: MemberRegistry) {
        self.write(
            pool,
            self.ring.registry_pda(),
            bytemuck::bytes_of(&registry).to_vec(),
        );
    }

    fn write(&self, pool: &mut Pool, address: Address, data: Vec<u8>) {
        pool.rpc
            .svm
            .set_account(
                Pubkey::new_from_array(address.to_bytes()),
                Account {
                    lamports: 1_000_000_000,
                    data,
                    owner: self.program,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .expect("write custom ring account");
    }

    fn merge_instruction(&self, pool: &Pool, merge: &RealRingMerge) -> Instruction {
        CustomRingMergeInstruction {
            ring: self.ring,
            input_tree: Address::new_from_array(pool.tree.to_bytes()),
            output_tree: Address::new_from_array(pool.tree.to_bytes()),
            payer: Address::new_from_array(pool.rpc.payer.pubkey().to_bytes()),
            co_signer: None,
            data: CustomRingMergeIxData {
                registry_root_index: 0,
                output_ring_data_hash: merge.data.output_ring_data_hash,
                disclosure: None,
                merge: merge.data.merge.clone(),
            },
        }
        .instruction()
        .expect("custom ring merge instruction")
    }
}

#[test]
fn registered_merge_rejects_bad_roots_then_settles_through_spp() {
    let mut pool = proof_env();
    let merge = RealRingMergeProof {
        input_count: 8,
        real_input_count: 1,
    }
    .build(&mut pool);
    let installed = InstalledRing::install(&mut pool, &merge);
    let ix = installed.merge_instruction(&pool, &merge);
    let before = tree_progress(&pool.rpc, &pool.tree);
    let send = |pool: &mut Pool| {
        pool.rpc
            .create_and_send_default_payer_transaction_with_budget(
                std::slice::from_ref(&ix),
                &[],
                ComputeBudgetConfig::new(MERGE_CU_LIMIT),
            )
    };

    installed.set_registry(&mut pool, installed.registry([0; 32]));
    let error = send(&mut pool).expect_err("an empty history slot must fail");
    Rejection::custom(CustomRingError::RootIndexEmpty as u32).assert_litesvm(error);
    assert_eq!(tree_progress(&pool.rpc, &pool.tree), before);

    let mut stale = installed.registry(merge.data.member_registry_root);
    stale.floor = 1u64.to_le_bytes();
    installed.set_registry(&mut pool, stale);
    let error = send(&mut pool).expect_err("a root below the floor must fail");
    Rejection::custom(CustomRingError::RootBelowFloor as u32).assert_litesvm(error);
    assert_eq!(tree_progress(&pool.rpc, &pool.tree), before);

    // The empty authenticated tree has no owner record for this proof.
    installed.set_registry(&mut pool, installed.registry(MEMBER_REGISTRY_EMPTY_ROOT));
    let error = send(&mut pool).expect_err("unregistered owner root must fail");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    assert_eq!(tree_progress(&pool.rpc, &pool.tree), before);

    installed.set_registry(
        &mut pool,
        installed.registry(merge.data.member_registry_root),
    );
    send(&mut pool).expect("registered custom ring merge settles through SPP");
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

/// The flag enters the SPP statement, a registered proof never verifies as anonymous.
#[test]
fn merge_ring_rejects_a_tampered_anonymous_flag() {
    let mut pool = proof_env();
    let mut merge = RealRingMergeProof {
        input_count: 8,
        real_input_count: 1,
    }
    .build(&mut pool);
    merge.data.anonymous = true;
    let ix = merge.instruction(&pool);
    let before = tree_progress(&pool.rpc, &pool.tree);
    let error = pool
        .rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix],
            &[],
            ComputeBudgetConfig::new(MERGE_CU_LIMIT),
        )
        .expect_err("a flipped anonymous flag must not verify");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    assert_eq!(tree_progress(&pool.rpc, &pool.tree), before);
}

fn registered_compact_merge_settles(input_count: usize, real_input_count: usize) {
    let mut pool = proof_env();
    let merge = RealRingMergeProof {
        input_count,
        real_input_count,
    }
    .build_compact(&mut pool);
    assert_eq!(merge.data.merge.nullifiers.len(), real_input_count);
    let installed = InstalledRing::install(&mut pool, &merge);
    let ix = installed.merge_instruction(&pool, &merge);
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
