use zolana_keypair::constants::{SALT_LEN, VIEW_TAG_LEN};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    owner_utxo_hash, utxo_hash, AssetRegistry, Data, ProoflessDepositEvent, SyncTransaction,
    Wallet, DEFAULT_TAG_WINDOW, SOL_MINT,
};

fn self_consistent_deposit(wallet: &Wallet, amount: u64) -> ProoflessDepositEvent {
    let salt = [9u8; SALT_LEN];
    let blinding = wallet
        .keypair
        .viewing_key
        .derive_proofless_blinding(&salt)
        .expect("derive proofless blinding");
    let owner_hash = wallet.keypair.owner_hash().expect("owner hash");
    let owner_utxo_hash = owner_utxo_hash(&owner_hash, &blinding).expect("owner UTXO hash");
    let utxo_hash = utxo_hash(
        SOL_MINT,
        amount,
        &[0u8; 32],
        &[0u8; 32],
        None,
        &owner_utxo_hash,
    )
    .expect("UTXO hash");

    ProoflessDepositEvent {
        view_tag: wallet.keypair.recipient_bootstrap_view_tag(),
        utxo_hash,
        owner_utxo_hash,
        salt,
        asset: SOL_MINT,
        amount,
        zone_program_id: None,
        program_data_hash: [0u8; 32],
        zone_data_hash: [0u8; 32],
        data: Data::new(Vec::new()),
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
        encrypted_utxos: Vec::new(),
        sender_view_tag: [0u8; VIEW_TAG_LEN],
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
