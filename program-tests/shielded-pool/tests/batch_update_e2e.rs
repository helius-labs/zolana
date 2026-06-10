//! Forester batch-update e2e: the nullifier tree IS the Light batched address
//! tree, so a forester `batch_update_address_tree` (driven via the registry CPI
//! chain, like production) must advance the nullifier-tree root cache that
//! `transact` later resolves `nullifier_tree_root_index` against.
//!
//! This is the on-chain half of the one-tree collapse: it queues a real batch
//! of 248-bit values, submits a REAL Light address-append proof (baked by the
//! Go prover into fixtures/batch_update.json against the committed
//! batch_address-append_40_10 key), and asserts `root_history` advances to the
//! proof's new root. A mismatch between the Go-replayed queue and the on-chain
//! tree would fail Light's on-chain `verify_batch_address_update` loudly.
//!
//! Requires both `light_registry.so` and `shielded_pool_program.so` under
//! `target/deploy/`.

use light_batched_merkle_tree::merkle_tree::BatchedMerkleTreeAccount;
use light_program_test::{ForesterConfig, PoolTestRig, ProtocolConfig, RigError};
use light_prover_client::proof::{compress_proof, proof_from_json_struct, GnarkProofJson};
use serde::Deserialize;
use shielded_pool_program::instructions::create_pool_tree::init::{
    address_sub_tree_slice_mut, pool_tree_account_size,
};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::instruction::BatchUpdateAddressTreeData;

#[derive(Deserialize)]
struct BatchUpdateFixture {
    height: u32,
    values: Vec<String>,
    old_root: String,
    new_root: String,
    proof: GnarkProofJson,
}

fn load_fixture() -> BatchUpdateFixture {
    serde_json::from_str(include_str!("fixtures/batch_update.json"))
        .expect("valid batch_update fixture")
}

fn hex32(value: &str) -> [u8; 32] {
    let bytes = hex::decode(value.trim_start_matches("0x")).expect("valid field hex");
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn rig() -> Option<PoolTestRig> {
    match PoolTestRig::new() {
        Ok(mut r) => {
            r.airdrop(&r.payer.pubkey(), 5_000_000_000).ok();
            match r.load_registry() {
                Ok(()) => Some(r),
                Err(RigError::MissingProgram(_)) => {
                    eprintln!("skipping batch-update e2e: light_registry.so missing");
                    None
                }
                Err(e) => panic!("load_registry failed: {e}"),
            }
        }
        Err(RigError::MissingProgram(_)) => {
            eprintln!("skipping batch-update e2e: shielded_pool_program.so missing");
            None
        }
        Err(e) => panic!("rig boot failed: {e}"),
    }
}

/// Read nullifier-tree root cache slot `index` from the live pool account.
fn root_by_index(rig: &PoolTestRig, tree: &Pubkey, index: usize) -> [u8; 32] {
    let mut data = rig.account_data(tree).expect("pool account data");
    let tree_addr = pinocchio::Address::new_from_array(tree.to_bytes());
    let slice = address_sub_tree_slice_mut(&mut data).expect("address sub-tree slice");
    let parsed = BatchedMerkleTreeAccount::address_from_bytes(slice, &tree_addr).unwrap();
    *parsed.get_root_by_index(index).expect("root slot")
}

/// Set up a registered forester in the active phase of epoch 0 (mirrors the
/// production registry chain), so `forest_address_tree` can CPI into
/// shielded-pool with the registry's CPI authority as signer.
fn setup_forester(rig: &mut PoolTestRig) -> Keypair {
    let governance = Keypair::new();
    rig.airdrop(&governance.pubkey(), 1_000_000_000)
        .expect("airdrop governance");
    let config = ProtocolConfig {
        registration_phase_length: 5,
        active_phase_length: 1_000,
        ..ProtocolConfig::default()
    };
    rig.initialize_protocol_config(&governance, config)
        .expect("initialize_protocol_config");

    let forester = Keypair::new();
    rig.airdrop(&forester.pubkey(), 1_000_000_000)
        .expect("airdrop forester");
    rig.register_forester(&governance, &forester.pubkey(), ForesterConfig::default(), Some(1))
        .expect("register_forester");
    rig.register_forester_epoch(&forester, 0)
        .expect("register_forester_epoch");
    rig.warp_to_slot(config.registration_phase_length + 1)
        .expect("warp past registration");
    rig.finalize_registration(&forester, 0)
        .expect("finalize_registration");
    forester
}

#[test]
fn forester_batch_update_advances_nullifier_root_cache() {
    let Some(mut rig) = rig() else {
        return;
    };
    let fx = load_fixture();
    assert_eq!(fx.height, 40, "fixture must target the H=40 nullifier tree");

    let tree = rig
        .create_pool_tree(pool_tree_account_size() as u64)
        .expect("create_pool_tree");
    let forester = setup_forester(&mut rig);

    // Fresh tree: slot 0 holds Light's init root, slot 1 is still empty.
    assert_eq!(
        root_by_index(&rig, &tree.pubkey(), 0),
        hex32(&fx.old_root),
        "init root cache slot must be ADDRESS_TREE_INIT_ROOT_40"
    );
    assert_eq!(root_by_index(&rig, &tree.pubkey(), 1), [0u8; 32]);

    // Queue the exact 248-bit values the proof was built over, in order.
    let values: Vec<[u8; 32]> = fx.values.iter().map(|v| hex32(v)).collect();
    rig.insert_addresses(&tree, values).expect("insert_addresses");

    // Forester batch update via the registry CPI chain. Light verifies the
    // address-append proof on-chain; a queue/replay mismatch fails here.
    let (proof_a, proof_b, proof_c) = {
        let (a, b, c) = proof_from_json_struct(fx.proof);
        compress_proof(&a, &b, &c)
    };
    rig.forest_address_tree(
        &forester,
        &tree.pubkey(),
        0,
        BatchUpdateAddressTreeData {
            new_root: hex32(&fx.new_root),
            compressed_proof_a: proof_a,
            compressed_proof_b: proof_b,
            compressed_proof_c: proof_c,
        },
    )
    .expect("forest_address_tree must succeed with a valid proof");

    // The nullifier root cache advanced: slot 1 now holds the post-batch root
    // that `transact` will accept as a non-stale nullifier_tree_root_index.
    assert_eq!(
        root_by_index(&rig, &tree.pubkey(), 1),
        hex32(&fx.new_root),
        "root_history did not advance to the batch-update new root"
    );
    assert_ne!(
        root_by_index(&rig, &tree.pubkey(), 1),
        hex32(&fx.old_root),
        "new root must differ from the init root"
    );
}
