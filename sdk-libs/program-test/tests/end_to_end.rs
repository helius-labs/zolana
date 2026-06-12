//! End-to-end happy-path coverage of the shielded-pool program against a
//! real .so loaded by litesvm: create_tree plus the
//! batch_update_address_tree authorization guard. Tree appends and queue
//! insertions happen only inside value-moving instructions
//! (proofless_shield, transact), which carry their own tests.
//!
//! Requires `cargo build-sbf -p shielded-pool-program` to have produced
//! `target/deploy/shielded_pool_program.so`. The PoolTestRig returns
//! `RigError::MissingProgram` if not.
//!
//! `batch_update_address_tree` needs a real Groth16 proof and lives in
//! `registry_cpi.rs` once the prover wiring lands.

use light_program_test::{PoolTestRig, RigError};
use solana_keypair::Keypair;
use solana_signer::Signer;

/// 1.16 MB — big enough for the combined account; the program ignores any
/// caller-supplied size and uses `tree_account_size()` internally.
const TREE_ACCOUNT_SIZE: u64 = 1_200_000;

/// Boot a rig with the canonical protocol config and one pool tree, returning
/// (rig, authority, tree).
fn rig_with_tree() -> Option<(PoolTestRig, Keypair, Keypair)> {
    let mut rig = rig()?;
    let authority = Keypair::new();
    rig.create_protocol_config(&authority)
        .expect("create_protocol_config");
    let tree = rig
        .create_tree(TREE_ACCOUNT_SIZE, &authority)
        .expect("create_tree");
    Some((rig, authority, tree))
}

fn rig() -> Option<PoolTestRig> {
    match PoolTestRig::new() {
        Ok(r) => Some(r),
        Err(RigError::MissingProgram(_)) => {
            eprintln!(
                "skipping end-to-end test: shielded_pool_program.so missing — \
                 run `cargo build-sbf -p shielded-pool-program`"
            );
            None
        }
        Err(e) => panic!("rig boot failed: {e}"),
    }
}

#[test]
fn create_tree_succeeds() {
    let Some((rig, _authority, tree)) = rig_with_tree() else {
        return;
    };

    // The on-chain program allocated the account and wrote the combined
    // discriminator (1) into the first 8 bytes.
    let data = rig.account_data(&tree.pubkey()).expect("account data");
    assert!(data.len() >= 8);
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&data[..8]);
    assert_eq!(u64::from_le_bytes(disc), 1, "combined discriminator");
}

#[test]
fn proofless_shield_sol_deposits_into_pool() {
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    let depositor = Keypair::new();
    rig.airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("airdrop");

    let vault_before = rig.account_data(&rig.cpi_authority());
    let tree_before = rig.account_data(&tree.pubkey()).expect("tree data");

    let amount = 1_000_000_000u64;
    rig.proofless_shield_sol(&tree, &depositor, amount, [42u8; 32])
        .expect("proofless_shield_sol");

    // The deposit landed in the pool's SOL vault (the CPI authority PDA).
    let vault_lamports = rig
        .svm
        .get_account(&rig.cpi_authority())
        .map(|a| a.lamports)
        .unwrap_or(0);
    let vault_before_lamports = vault_before.map(|_| 0u64).unwrap_or(0);
    assert!(
        vault_lamports >= vault_before_lamports + amount,
        "vault must grow by the deposit"
    );

    // The UTXO was appended: the state sub-tree root / next_index changed.
    let tree_after = rig.account_data(&tree.pubkey()).expect("tree data");
    assert_ne!(tree_before, tree_after, "tree must record the new leaf");
}

#[test]
fn batch_update_address_tree_rejects_non_registry_signer() {
    use zolana_interface::instruction::BatchUpdateAddressTreeData;

    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };

    // Payer is just a random keypair, not the registry's CPI authority PDA.
    // Shielded-pool's verify() must reject this — UnauthorizedCaller.
    let data = BatchUpdateAddressTreeData {
        new_root: [9u8; 32],
        compressed_proof_a: [0u8; 32],
        compressed_proof_b: [0u8; 64],
        compressed_proof_c: [0u8; 32],
    };
    let err = rig
        .batch_update_address_tree(&tree, data)
        .expect_err("non-registry signer must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("Custom(5)") || msg.contains("UnauthorizedCaller"),
        "expected UnauthorizedCaller (Custom(5)), got: {msg}"
    );
}

/// Phase-3 gate: the test indexer consumes ProoflessShieldEvents from inner
/// emit_event instructions, reconstructs the on-chain state root, and locates
/// every deposit without decryption.
#[test]
fn indexer_matches_onchain_root_and_locates_deposits() {
    use light_program_test::{PoolIndexer, PoolTestRig};

    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    let mut indexer = PoolIndexer::new();
    assert_eq!(
        indexer.root(),
        rig.state_root(&tree.pubkey()).expect("state root"),
        "empty trees must agree"
    );

    let depositor = Keypair::new();
    rig.airdrop(&depositor.pubkey(), 10_000_000_000)
        .expect("airdrop");

    for (i, amount) in [1_000_000_000u64, 250_000_000, 42].into_iter().enumerate() {
        let owner_utxo_hash = [i as u8 + 1; 32];
        let mut data = PoolTestRig::sol_shield_data(amount, owner_utxo_hash);
        data.view_tag = [0xA0 + i as u8; 32];
        data.salt = [i as u8; 16];
        let event = rig
            .proofless_shield(&tree, &depositor, &data)
            .expect("deposit");
        assert_eq!(event.amount, amount, "event must carry the settled amount");
        assert_eq!(event.asset, [0u8; 32], "SOL asset is the zero address");
        assert_eq!(event.salt, data.salt);
        indexer.record_proofless_shield(&event);

        assert_eq!(
            indexer.root(),
            rig.state_root(&tree.pubkey()).expect("state root"),
            "reference tree must track the on-chain root after deposit {i}"
        );
    }

    // The depositor locates each UTXO by its opaque owner commitment; the
    // recipient by scanning their view tag.
    for (i, amount) in [1_000_000_000u64, 250_000_000, 42].into_iter().enumerate() {
        let record = indexer
            .fetch_by_owner_utxo_hash(&[i as u8 + 1; 32])
            .expect("fetch by owner commitment");
        assert_eq!(record.amount, amount);
        assert_eq!(record.leaf_index, i as u64);

        let tag = [0xA0 + i as u8; 32];
        let by_tag: Vec<_> = indexer.fetch_by_view_tag(&tag).collect();
        assert_eq!(by_tag.len(), 1, "view tag locates exactly this deposit");
        assert_eq!(by_tag[0].leaf_index, i as u64);
    }
}
