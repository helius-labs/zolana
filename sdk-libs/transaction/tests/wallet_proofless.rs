use zolana_interface::event::DepositView;
use zolana_keypair::constants::{SALT_LEN, VIEW_TAG_LEN};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{AssetRegistry, SyncTransaction, Wallet, DEFAULT_TAG_WINDOW, SOL_MINT};

fn self_consistent_deposit(keypair: &ShieldedKeypair, amount: u64) -> DepositView {
    let salt = [9u8; SALT_LEN];
    let blinding = keypair
        .viewing_key
        .derive_proofless_blinding(&salt)
        .expect("derive proofless blinding");
    let owner_hash = keypair.owner_hash().expect("owner hash");
    let owner_utxo_hash =
        zolana_transaction::owner_utxo_hash(&owner_hash, &blinding).expect("owner UTXO hash");
    let utxo_hash = zolana_transaction::utxo_hash(
        SOL_MINT,
        amount,
        &[0u8; 32],
        &[0u8; 32],
        None,
        &owner_utxo_hash,
    )
    .expect("UTXO hash");

    DepositView {
        view_tag: keypair.recipient_bootstrap_view_tag(),
        utxo_hash,
        asset: SOL_MINT.to_bytes(),
        amount,
        zone_program_id: None,
        policy_data_hash: None,
        owner_utxo_hash,
        salt,
        program_data_hash: None,
        program_data: None,
        zone_data: None,
        output_tree: [0u8; 32],
        leaf_index: 0,
    }
}

#[test]
fn sync_discovers_and_spends_proofless_deposit() {
    let keypair = ShieldedKeypair::new().expect("shielded keypair");
    let mut wallet = Wallet::new_from_keypair(&keypair).expect("wallet");
    let assets = AssetRegistry::default();
    let deposit = self_consistent_deposit(&keypair, 1_234);

    wallet
        .sync_keypair(
            &keypair,
            &[],
            std::slice::from_ref(&deposit),
            &assets,
            1,
            DEFAULT_TAG_WINDOW,
        )
        .expect("sync discovers deposit");
    assert_eq!(wallet.utxos.len(), 1, "deposit discovered");
    assert_eq!(wallet.utxos[0].hash, deposit.utxo_hash);
    assert!(!wallet.utxos[0].spent);
    let nullifier = wallet.utxos[0].nullifier;

    wallet
        .sync_keypair(
            &keypair,
            &[],
            std::slice::from_ref(&deposit),
            &assets,
            2,
            DEFAULT_TAG_WINDOW,
        )
        .expect("resync deposit");
    assert_eq!(wallet.utxos.len(), 1, "idempotent on re-sync");

    let spend = SyncTransaction {
        encrypted_utxos: Vec::new(),
        sender_view_tag: [0u8; VIEW_TAG_LEN],
        nullifiers: vec![nullifier],
    };
    wallet
        .sync_keypair(&keypair, &[spend], &[], &assets, 3, DEFAULT_TAG_WINDOW)
        .expect("sync marks spent");
    assert!(wallet.utxos[0].spent, "nullifier marks UTXO spent");
}
