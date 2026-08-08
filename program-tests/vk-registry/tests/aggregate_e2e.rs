//! Registered outer verify for an aggregate batch. Two real confidential
//! (2,3) legs settle against one recursive proof, and the outer pairing runs
//! through the registry account of the outer key. One registry account serves
//! the whole batch because the selector fixes one outer key. Needs
//! `just build-programs-vk-registry` and the local aggregate keys
//! (`ensure-aggregate-keys`).

use litesvm::LiteSVM;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use vk_registry_test::with_prepared_syscalls;
use zolana_client::{
    prover::{AggregateInputs, AggregateLeg},
    ProofCompressed, ProverClient,
};
use zolana_interface::{
    instruction::{
        builders::{append_vk_registry, InitVkRegistry},
        instruction_data::{
            aggregate_transact::{AggregateTransactIxData, EMPTY_LEG_PROOF},
            transact::TransactIxData,
        },
        tag, AggregateTransact,
    },
    verifying_keys::{
        catalog::VK_CATALOG, registry::VK_REGISTRY_SPECS, AggregateCircuitId, InnerCircuitKind,
    },
    N_PUBLIC_SLOTS,
};
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::{
    backend::LiteSvmPoolBackend, prover::spawn_workspace_prover,
    transact::build_valid_confidential_transact_legs,
};

const LEGS: u8 = 2;

fn registry_program_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
        .join("target/deploy-vk-registry/shielded_pool_program.so")
}

fn boot() -> LiteSvmPoolBackend {
    let path = registry_program_path();
    assert!(
        path.exists(),
        "missing {}; run `just build-programs-vk-registry` first",
        path.display()
    );
    let svm = with_prepared_syscalls(LiteSVM::new());
    let rpc = ZolanaProgramTest::with_svm_and_program_path(svm, &path)
        .expect("boot registry-enabled program");
    LiteSvmPoolBackend::with_rpc(rpc).expect("boot pool state")
}

fn catalog_index(name: &str) -> usize {
    VK_CATALOG
        .iter()
        .position(|(entry, _)| *entry == name)
        .expect("catalog entry")
}

fn init_registry(env: &mut LiteSvmPoolBackend, vk_index: usize) -> Pubkey {
    let builder = InitVkRegistry {
        payer: env.rpc.payer.pubkey(),
        vk_index: vk_index as u8,
    };
    for _ in 0..builder.transaction_count() {
        env.rpc
            .create_and_send_default_payer_transaction(&[builder.instruction()], &[])
            .expect("registry init step");
    }
    Pubkey::new_from_array(VK_REGISTRY_SPECS[vk_index].address)
}

/// A batch of `LEGS` confidential legs with a real outer proof. Legs carry
/// [`EMPTY_LEG_PROOF`]. The outer proof covers the chained hashes.
fn aggregate_ix(env: &mut LiteSvmPoolBackend) -> solana_instruction::Instruction {
    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let legs = build_valid_confidential_transact_legs(env, payer, tag::TRANSACT, LEGS)
        .expect("build confidential legs");

    let outer = ProverClient::local()
        .prove_aggregate(&AggregateInputs {
            inner: InnerCircuitKind::ConfidentialEddsa,
            num_inputs: 2,
            num_outputs: 3,
            legs: legs
                .iter()
                .map(|leg| AggregateLeg {
                    proof: leg.proof,
                    public_input_hash: leg.public_input_hash,
                })
                .collect(),
        })
        .expect("prove aggregate");
    let outer = ProofCompressed::try_from(outer).expect("compress outer");
    let (proof, bsb22_commitment) = outer
        .into_ring_p256_transact_parts()
        .expect("outer proof parts");

    let data = AggregateTransactIxData {
        circuit: AggregateCircuitId {
            kind: InnerCircuitKind::ConfidentialEddsa,
            num_inputs: 2,
            num_outputs: 3,
            num_public_asset_slots: N_PUBLIC_SLOTS as u8,
            batch: LEGS,
        },
        proof,
        bsb22_commitment,
        legs: legs
            .iter()
            .map(|leg| TransactIxData {
                proof: EMPTY_LEG_PROOF,
                ..leg.data.clone()
            })
            .collect(),
        leg_account_counts: Vec::new(),
    };
    AggregateTransact {
        payer,
        input_tree: tree,
        output_tree: tree,
        ring_program_ids: vec![Pubkey::default(); usize::from(LEGS)],
        owner_signers: vec![Vec::new(); usize::from(LEGS)],
        interface_transfer_accounts: vec![Vec::new(); usize::from(LEGS)],
        data,
    }
    .instruction()
}

fn send(env: &mut LiteSvmPoolBackend, ix: solana_instruction::Instruction) -> u64 {
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    env.rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .expect("aggregate transact");
    env.rpc
        .last_transaction_trace()
        .expect("transaction trace")
        .compute_units_consumed
}

#[test]
fn registered_aggregate_verifies_and_undercuts_the_plain_batch() {
    spawn_workspace_prover();

    let mut env = boot();
    let ix = aggregate_ix(&mut env);
    let plain_cu = send(&mut env, ix);

    let mut env = boot();
    let mut ix = aggregate_ix(&mut env);
    let registry = init_registry(
        &mut env,
        catalog_index("aggregate_transfer_confidential_2_3_b2"),
    );
    append_vk_registry(&mut ix, registry);
    let registered_cu = send(&mut env, ix);

    assert!(
        registered_cu < plain_cu,
        "registered batch ({registered_cu} CU) must undercut the plain batch ({plain_cu} CU)"
    );
    println!("aggregate CU: plain {plain_cu}, registered {registered_cu}");
}

#[test]
fn registered_aggregate_rejects_a_registry_for_another_key() {
    spawn_workspace_prover();

    let mut env = boot();
    let mut ix = aggregate_ix(&mut env);
    // A finalized registry for a DIFFERENT key must be rejected by the
    // address compare before any pairing runs.
    let registry = init_registry(&mut env, catalog_index("transfer_confidential_2_3"));
    append_vk_registry(&mut ix, registry);
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    assert!(
        env.rpc
            .create_and_send_default_payer_transaction(&[budget, ix], &[])
            .is_err(),
        "a registry for another key must be rejected"
    );
}
