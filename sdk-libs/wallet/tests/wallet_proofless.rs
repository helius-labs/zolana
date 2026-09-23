use zolana_client::ProofInputUtxo;
use zolana_event::{encode_output_data, ProoflessOutput};

/// Raw id of the tree this test hashes UTXOs under.
const TEST_TREE_ID: u16 = 0;

use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    Address, AssetRegistry, OutputContext, OutputSlot, ShieldedTransaction, SOL_MINT,
};
use zolana_wallet::{KeypairWalletAuthority, Wallet, DEFAULT_TAG_WINDOW};

fn self_consistent_deposit(
    keypair: &ShieldedKeypair,
    amount: u64,
    tree_id: u16,
) -> ShieldedTransaction {
    let blinding = [9u8; 32];
    let data_hash = [14u8; 32];
    let owner = keypair.owner_hash().expect("owner hash");
    let utxo_hash = ProofInputUtxo::new(owner, &SOL_MINT, amount, &blinding, tree_id)
        .expect("proof input utxo")
        .with_data_hash(data_hash)
        .hash()
        .expect("UTXO hash");

    let output = ProoflessOutput {
        owner,
        blinding,
        asset: SOL_MINT.to_bytes(),
        amount,
        data_hash: Some(data_hash),
        utxo_data: None,
        ring_program_id: None,
        ring_data_hash: None,
        ring_data: None,
        memo: Some(b"deposit memo".to_vec()),
    };

    ShieldedTransaction {
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: keypair.recipient_bootstrap_view_tag(),
            output_context: OutputContext {
                hash: utxo_hash,
                tree_id,
                leaf_index: 0,
            },
            payload: encode_output_data(output),
        }],
        messages: Vec::new(),
        nullifiers: Vec::new(),
        proofless: true,
        ring_config: None,
        ring_program_id: None,
    }
}

#[test]
fn sync_discovers_and_spends_proofless_deposit() {
    let keypair = ShieldedKeypair::new_p256().expect("shielded keypair");
    let authority = KeypairWalletAuthority::new(Address::default(), &keypair);
    let mut wallet = Wallet::new(
        keypair.shielded_address().expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("wallet");
    let deposit = self_consistent_deposit(&keypair, 1_234, TEST_TREE_ID);
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
    assert_eq!(discovered.utxo_hash, deposit_hash);
    assert_eq!(discovered.data_hash, Some([14u8; 32]));
    assert_eq!(discovered.ring_data_hash, None);
    assert!(!wallet.is_spent(discovered));
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

    let input_utxo = ShieldedTransaction {
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        event_index: Some(0),
        tx_viewing_pk: Some(keypair.viewing_pubkey()),
        salt: Some([0u8; 16]),
        output_slots: Vec::new(),
        messages: Vec::new(),
        nullifiers: vec![nullifier],
        proofless: false,
        ring_config: None,
        ring_program_id: None,
    };
    wallet
        .sync(
            &authority,
            std::slice::from_ref(&input_utxo),
            3,
            DEFAULT_TAG_WINDOW,
        )
        .expect("sync input_utxo");
    assert!(
        wallet.is_spent(wallet.utxos.first().expect("spent utxo")),
        "deposit spent by its nullifier"
    );
}

/// The commitment folds the raw tree id in, so a deposit published in a tree
/// other than zero only matches its leaf when sync hashes it under the id the
/// slot reports. Sync used to hash every slot under a hardcoded zero, which
/// quietly turned every such deposit into an undecryptable candidate.
#[test]
fn sync_discovers_a_deposit_in_a_tree_other_than_zero() {
    const OTHER_TREE_ID: u16 = 3;
    let keypair = ShieldedKeypair::new_p256().expect("shielded keypair");
    let authority = KeypairWalletAuthority::new(Address::default(), &keypair);
    let mut wallet = Wallet::new(
        keypair.shielded_address().expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("wallet");
    let deposit = self_consistent_deposit(&keypair, 1_234, OTHER_TREE_ID);

    let report = wallet
        .sync(
            &authority,
            std::slice::from_ref(&deposit),
            1,
            DEFAULT_TAG_WINDOW,
        )
        .expect("sync discovers deposit");

    assert_eq!(report.undecryptable_candidates, 0);
    let discovered = wallet.utxos.first().expect("discovered utxo");
    assert_eq!(discovered.tree_id(), OTHER_TREE_ID);
    assert_eq!(discovered.utxo.amount, 1_234);
}
