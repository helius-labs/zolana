//! Proof-carrying transact against the registry-enabled program: the same
//! real (2,3) confidential proof verifies through today's path and through
//! the prepared-operand path, and the registered path is cheaper. Needs
//! `just build-programs-vk-registry` and the workspace prover (started
//! automatically; the transfer_confidential_2_3 proving key loads lazily).

use litesvm::LiteSVM;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use vk_registry_test::with_prepared_syscalls;
use zolana_interface::{
    instruction::{builders::append_vk_registry, builders::InitVkRegistry, tag, Transact},
    verifying_keys::{catalog::VK_CATALOG, registry::VK_REGISTRY_SPECS},
};
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::{
    backend::LiteSvmPoolBackend, prover::spawn_workspace_prover,
    transact::build_valid_confidential_transact_ix,
};

fn registry_program_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
        .join("target/deploy-vk-registry/shielded_pool_program.so")
}

/// Fresh pool over the registry-enabled program and shimmed syscalls. One
/// backend per transaction: the fixture's deterministic blindings mean a
/// second send would replay the same nullifiers.
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

fn transact_cu(env: &mut LiteSvmPoolBackend, with_registry: bool) -> u64 {
    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let data = build_valid_confidential_transact_ix(env, payer, tag::TRANSACT)
        .expect("build confidential transact");
    let mut ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction();

    if with_registry {
        let vk_index = VK_CATALOG
            .iter()
            .position(|(name, _)| *name == "transfer_confidential_2_3")
            .unwrap();
        let builder = InitVkRegistry {
            payer,
            vk_index: vk_index as u8,
        };
        for _ in 0..builder.transaction_count() {
            env.rpc
                .create_and_send_default_payer_transaction(&[builder.instruction()], &[])
                .expect("registry init step");
        }
        append_vk_registry(
            &mut ix,
            Pubkey::new_from_array(VK_REGISTRY_SPECS[vk_index].address),
        );
    }

    env.rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect("transact");
    env.rpc
        .last_transaction_trace()
        .expect("transaction trace")
        .compute_units_consumed
}

#[test]
fn registered_transact_verifies_and_undercuts_the_plain_path() {
    spawn_workspace_prover();

    let plain_cu = transact_cu(&mut boot(), false);
    let registered_cu = transact_cu(&mut boot(), true);

    // The registered path drops the alpha-beta pair and skips subgroup checks
    // and line preparation on gamma and delta. The exact figure belongs to
    // the tariff tests; here only the direction is pinned.
    assert!(
        registered_cu < plain_cu,
        "registered transact ({registered_cu} CU) must undercut the plain path ({plain_cu} CU)"
    );
    println!("transact CU: plain {plain_cu}, registered {registered_cu}");
}

#[test]
fn registered_transact_rejects_a_wrong_shape_registry() {
    spawn_workspace_prover();

    let mut env = boot();
    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let data = build_valid_confidential_transact_ix(&mut env, payer, tag::TRANSACT)
        .expect("build confidential transact");
    let mut ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction();
    // A finalized registry for a DIFFERENT shape must be rejected by the
    // address compare before any pairing runs.
    let other_index = VK_CATALOG
        .iter()
        .position(|(name, _)| *name == "transfer_confidential_1_1")
        .unwrap();
    let builder = InitVkRegistry {
        payer,
        vk_index: other_index as u8,
    };
    for _ in 0..builder.transaction_count() {
        env.rpc
            .create_and_send_default_payer_transaction(&[builder.instruction()], &[])
            .expect("registry init step");
    }
    append_vk_registry(
        &mut ix,
        Pubkey::new_from_array(VK_REGISTRY_SPECS[other_index].address),
    );
    assert!(
        env.rpc
            .create_and_send_default_payer_transaction(&[ix], &[])
            .is_err(),
        "wrong-shape registry account must be rejected"
    );
}
