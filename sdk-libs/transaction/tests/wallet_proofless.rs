use zolana_event::DepositView;
use zolana_keypair::{
    constants::{BLINDING_LEN, SALT_LEN},
    ShieldedKeypair,
};
use zolana_transaction::{
    owner_utxo_hash, utxo_hash, AssetRegistry, SyncTransaction, Wallet, DEFAULT_TAG_WINDOW,
    SOL_MINT, TRANSFER,
};

fn self_consistent_deposit(wallet: &Wallet, amount: u64) -> DepositView {
    let blinding = [9u8; BLINDING_LEN];
    let owner = wallet.keypair.owner_hash().expect("owner hash");
    let owner_utxo_hash = owner_utxo_hash(&owner, &blinding).expect("owner UTXO hash");
    let utxo_hash = utxo_hash(
        SOL_MINT,
        amount,
        &[0u8; 32],
        &[0u8; 32],
        None,
        &owner_utxo_hash,
    )
    .expect("UTXO hash");

    DepositView {
        view_tag: wallet.keypair.recipient_bootstrap_view_tag(),
        utxo_hash,
        asset: SOL_MINT.to_bytes(),
        amount,
        zone_program_id: None,
        policy_data_hash: None,
        owner,
        blinding,
        program_data_hash: None,
        program_data: None,
        zone_data: None,
        output_tree: [0u8; 32],
        leaf_index: 0,
    }
}

#[test]
fn sync_discovers_and_spends_proofless_deposit() {
    let mut wallet =
        Wallet::new(ShieldedKeypair::new().expect("shielded keypair")).expect("wallet");
    let assets = AssetRegistry::default();
    let deposit = self_consistent_deposit(&wallet, 1_234);

    wallet
        .sync(
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
        .sync(
            &[],
            std::slice::from_ref(&deposit),
            &assets,
            2,
            DEFAULT_TAG_WINDOW,
        )
        .expect("resync deposit");
    assert_eq!(wallet.utxos.len(), 1, "idempotent on re-sync");

    let spend = SyncTransaction {
        scheme: TRANSFER,
        tx_viewing_pk: wallet.keypair.viewing_pubkey(),
        salt: [0u8; SALT_LEN],
        output_slots: Vec::new(),
        nullifiers: vec![nullifier],
    };
    wallet
        .sync(
            std::slice::from_ref(&spend),
            &[],
            &assets,
            3,
            DEFAULT_TAG_WINDOW,
        )
        .expect("sync spend");
    assert!(wallet.utxos[0].spent, "deposit spent by its nullifier");
}
