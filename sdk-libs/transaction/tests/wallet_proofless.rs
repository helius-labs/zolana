use zolana_event::{encode_output_data, ProoflessOutput};
use zolana_keypair::{constants::BLINDING_LEN, ShieldedKeypair};
use zolana_transaction::{
    owner_utxo_hash, utxo_hash, Address, AssetRegistry, LocalWalletAuthority, OutputContext,
    OutputSlot, ShieldedTransaction, Wallet, DEFAULT_TAG_WINDOW, SOL_MINT,
};

fn self_consistent_deposit(keypair: &ShieldedKeypair, amount: u64) -> ShieldedTransaction {
    let blinding = [9u8; BLINDING_LEN];
    let data_hash = [14u8; 32];
    let owner = keypair.owner_hash().expect("owner hash");
    let owner_utxo_hash = owner_utxo_hash(&owner, &blinding).expect("owner UTXO hash");
    let utxo_hash = utxo_hash(
        SOL_MINT,
        amount,
        &data_hash,
        &[0u8; 32],
        None,
        &owner_utxo_hash,
    )
    .expect("UTXO hash");

    let output = ProoflessOutput {
        owner,
        blinding,
        asset: SOL_MINT.to_bytes(),
        amount,
        data_hash: Some(data_hash),
        utxo_data: None,
        zone_program_id: None,
        zone_data_hash: None,
        zone_data: None,
        memo: Some(b"deposit memo".to_vec()),
    };

    ShieldedTransaction {
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: keypair.recipient_bootstrap_view_tag(),
            output_context: OutputContext {
                hash: utxo_hash,
                tree: Address::new_from_array([0u8; 32]),
                leaf_index: 0,
            },
            payload: encode_output_data(output),
        }],
        nullifiers: Vec::new(),
        proofless: true,
    }
}

#[test]
fn sync_discovers_and_spends_proofless_deposit() {
    let keypair = ShieldedKeypair::new().expect("shielded keypair");
    let authority = LocalWalletAuthority::new(Address::default(), &keypair);
    let mut wallet = Wallet::new(
        keypair.shielded_address().expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("wallet");
    let deposit = self_consistent_deposit(&keypair, 1_234);
    let deposit_hash = deposit
        .output_slots
        .first()
        .expect("deposit slot")
        .output_context
        .hash;

    wallet
        .sync(
            &authority,
            std::slice::from_ref(&deposit),
            1,
            DEFAULT_TAG_WINDOW,
        )
        .expect("sync discovers deposit");
    assert_eq!(wallet.utxos.len(), 1, "deposit discovered");
    let discovered = wallet.utxos.first().expect("discovered utxo");
    assert_eq!(discovered.output_context.hash, deposit_hash);
    assert_eq!(discovered.data_hash, Some([14u8; 32]));
    assert_eq!(discovered.zone_data_hash, None);
    assert!(!discovered.spent);
    assert_eq!(
        discovered.utxo.data.memo(),
        Some(b"deposit memo".as_slice()),
        "proofless memo survives decode into the discovered UTXO"
    );
    let nullifier = discovered.nullifier;

    wallet
        .sync(
            &authority,
            std::slice::from_ref(&deposit),
            2,
            DEFAULT_TAG_WINDOW,
        )
        .expect("resync deposit");
    assert_eq!(wallet.utxos.len(), 1, "idempotent on re-sync");

    let spend = ShieldedTransaction {
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        tx_viewing_pk: Some(keypair.viewing_pubkey()),
        salt: Some([0u8; 16]),
        output_slots: Vec::new(),
        nullifiers: vec![nullifier],
        proofless: false,
    };
    wallet
        .sync(
            &authority,
            std::slice::from_ref(&spend),
            3,
            DEFAULT_TAG_WINDOW,
        )
        .expect("sync spend");
    assert!(
        wallet.utxos.first().expect("spent utxo").spent,
        "deposit spent by its nullifier"
    );
}
