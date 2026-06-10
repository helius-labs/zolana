//! Forester batch-update e2e: the nullifier tree IS the Light batched address
//! tree, so a forester `batch_update_address_tree` (driven via the registry CPI
//! chain, like production) must advance the nullifier-tree root cache that
//! `transact` later resolves `nullifier_tree_root_index` against.
//!
//! The queue is seeded HONESTLY: the fixture bakes real Solana-rail transacts —
//! five SOL seed shields (each queues its view tag) plus one five-input SOL
//! transfer (queues five nullifiers + its view tag) — submitted in order, which
//! queues the exact 248-bit values (in queue order) the baked Light
//! address-append proof covers. So this exercises the real
//! transact -> queue -> forester pipeline end-to-end; a Go/on-chain queue
//! mismatch fails Light's on-chain `verify_batch_address_update` loudly.
//!
//! Requires both `light_registry.so` and `shielded_pool_program.so` under
//! `target/deploy/`.

use light_batched_merkle_tree::merkle_tree::BatchedMerkleTreeAccount;
use light_program_test::{ForesterConfig, PoolTestRig, ProtocolConfig, RigError};
use light_prover_client::proof::{
    bsb22_proof_bytes_from_json_struct, compress_proof, proof_from_json_struct, GnarkProofJson,
};
use serde::Deserialize;
use shielded_pool_program::instructions::create_pool_tree::init::{
    address_sub_tree_slice_mut, pool_tree_account_size,
};
use solana_account::Account as SolanaAccount;
use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{BatchUpdateAddressTreeData, InputUtxoSignerIndex, TransactData},
    SHIELDED_POOL_CPI_AUTHORITY,
};

#[derive(Deserialize)]
struct BatchUpdateFixture {
    height: u32,
    transacts: Vec<TransactFixture>,
    old_root: String,
    new_root: String,
    proof: GnarkProofJson,
}

// Subset of the generator's E2EFixture needed to submit the seed/spend transacts
// on-chain (all Solana-rail SOL: shields and one transfer).
#[derive(Clone, Debug, Deserialize)]
struct TransactFixture {
    name: String,
    expiry_unix_ts: u64,
    sender_view_tag: String,
    proof: serde_json::Value,
    relayer_fee: u16,
    nullifiers: Vec<String>,
    output_utxo_hashes: Vec<String>,
    utxo_tree_root_index: Vec<u16>,
    nullifier_tree_root_index: Vec<u16>,
    private_tx_hash: String,
    public_amount_mode: u8,
    public_sol_amount: Option<u64>,
    public_spl_amount: Option<u64>,
    encrypted_utxos: String,
    #[serde(default)]
    solana_owner_input_indices: Vec<u8>,
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

fn bytes_from_hex(value: &str) -> Vec<u8> {
    hex::decode(value.trim_start_matches("0x")).expect("valid bytes hex")
}

// The signer baked into the transact proofs (matches regen-spp-transact-fixtures
// and the batch-update fixture: Keypair::new_from_array([0x42; 32])).
fn fixture_payer() -> Keypair {
    Keypair::new_from_array([0x42; 32])
}

fn input_signer_indices(input_indices: &[u8]) -> Option<Vec<InputUtxoSignerIndex>> {
    if input_indices.is_empty() {
        return None;
    }
    Some(
        input_indices
            .iter()
            .map(|input_index| InputUtxoSignerIndex {
                account_index: 1,
                input_index: *input_index,
            })
            .collect(),
    )
}

fn transact_data(tf: &TransactFixture) -> TransactData {
    let proof: GnarkProofJson =
        serde_json::from_value(tf.proof.clone()).expect("valid gnark proof fixture");
    TransactData {
        expiry_unix_ts: tf.expiry_unix_ts,
        sender_view_tag: hex32(&tf.sender_view_tag),
        proof: bsb22_proof_bytes_from_json_struct(proof).expect("valid BSB22 proof fixture"),
        relayer_fee: tf.relayer_fee,
        public_amount_mode: tf.public_amount_mode,
        nullifiers: tf.nullifiers.iter().map(|v| hex32(v)).collect(),
        output_utxo_hashes: tf.output_utxo_hashes.iter().map(|v| hex32(v)).collect(),
        utxo_tree_root_index: tf.utxo_tree_root_index.clone(),
        nullifier_tree_root_index: tf.nullifier_tree_root_index.clone(),
        private_tx_hash: hex32(&tf.private_tx_hash),
        public_sol_amount: tf.public_sol_amount,
        public_spl_amount: tf.public_spl_amount,
        cpi_signer: None,
        in_utxo_signer_indices: input_signer_indices(&tf.solana_owner_input_indices),
        encrypted_utxos: bytes_from_hex(&tf.encrypted_utxos),
        requires_p256: false,
    }
}

// The pool CPI authority receives deposited SOL; pre-fund it so it is already
// rent-exempt (the seed shields deposit only a few lamports each, which would
// otherwise leave the destination below the rent-exempt minimum).
fn fund_cpi_authority(rig: &mut PoolTestRig) {
    rig.svm
        .set_account(
            Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY),
            SolanaAccount {
                lamports: 1_000_000,
                data: Vec::new(),
                owner: Pubkey::default(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("set cpi authority account");
}

// Extra accounts (beyond tree + signer) for a public SOL deposit, matching
// load_transact_accounts: system program, pool CPI authority, user SOL account.
fn sol_settlement_metas(user_sol: &Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new(Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY), false),
        AccountMeta::new(*user_sol, false),
    ]
}

fn submit_transact(rig: &mut PoolTestRig, tree: &Keypair, tf: &TransactFixture, user_sol: &Pubkey) {
    let data = transact_data(tf);
    let result = if data.public_sol_amount.unwrap_or(0) != 0 {
        rig.transact_with_extra_accounts(tree, data, sol_settlement_metas(user_sol))
    } else {
        rig.transact(tree, data)
    };
    result.unwrap_or_else(|err| panic!("submit transact {} failed: {err}", tf.name));
}

fn rig() -> Option<PoolTestRig> {
    match PoolTestRig::new_with_payer(fixture_payer()) {
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
    let user_sol = rig.payer.pubkey();
    fund_cpi_authority(&mut rig);

    // Fresh tree: slot 0 holds Light's init root, slot 1 is still empty.
    assert_eq!(
        root_by_index(&rig, &tree.pubkey(), 0),
        hex32(&fx.old_root),
        "init root cache slot must be ADDRESS_TREE_INIT_ROOT_40"
    );
    assert_eq!(root_by_index(&rig, &tree.pubkey(), 1), [0u8; 32]);

    // Honestly seed the queue: submit the seed shields + spend transfer in order.
    // Each transact queues [nullifiers..., view_tag]; after all of them the queue
    // holds the exact values (in order) the address-append proof covers.
    for tf in &fx.transacts {
        submit_transact(&mut rig, &tree, tf, &user_sol);
    }

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
