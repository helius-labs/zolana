use zolana_keypair::{
    constants::BLINDING_LEN, viewing_key::ViewTag, ShieldedKeypair, SigningKey, ViewingKey,
};
use zolana_transaction::{
    transfer::{RecipientOutput, TransferSenderPlaintext, SENDER_SLOT_COUNT},
    wallet::SyncTransaction,
    AssetRegistry, Data, TransactionEncryption, Utxo, SOL_MINT, TRANSFER,
};

pub fn keypair_from_index(index: u16) -> ShieldedKeypair {
    let mut signing_bytes = [0u8; 32];
    signing_bytes[0] = 0x10;
    signing_bytes[1..3].copy_from_slice(&index.to_be_bytes());
    let mut viewing_bytes = [0u8; 32];
    viewing_bytes[0] = 0x20;
    viewing_bytes[1..3].copy_from_slice(&index.to_be_bytes());
    let signing = SigningKey::from_bytes(&signing_bytes).unwrap();
    let viewing = ViewingKey::from_bytes(&viewing_bytes).unwrap();
    ShieldedKeypair::from_keys(signing, viewing).unwrap()
}

pub fn unique31(counter: &mut u64, prefix: u8) -> [u8; BLINDING_LEN] {
    *counter += 1;
    let mut out = [0u8; BLINDING_LEN];
    out[0] = prefix;
    out[1..9].copy_from_slice(&counter.to_be_bytes());
    out
}

pub fn unique_nullifier(counter: &mut u64) -> [u8; 32] {
    *counter += 1;
    let mut out = [0u8; 32];
    out[0] = 0xAA;
    out[1..9].copy_from_slice(&counter.to_be_bytes());
    out
}

pub struct TransferSpec<'a> {
    pub sender: &'a ShieldedKeypair,
    pub recipient: &'a ShieldedKeypair,
    pub amount: u64,
    pub slot_tag: ViewTag,
    pub sender_view_tag: ViewTag,
    pub first_nullifier: [u8; 32],
    pub change_amount: u64,
    pub blinding: [u8; BLINDING_LEN],
    pub blinding_seed: [u8; BLINDING_LEN],
}

pub fn build_transfer(
    assets: &AssetRegistry,
    spec: TransferSpec<'_>,
) -> (SyncTransaction, Utxo, Vec<Utxo>) {
    let recipient_utxo = Utxo {
        owner: spec.recipient.signing_pubkey(),
        asset: SOL_MINT,
        amount: spec.amount,
        blinding: spec.blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let recipient_plaintext = recipient_utxo
        .to_recipient_plaintext(spec.sender.viewing_pubkey(), assets)
        .unwrap();
    let sender_plaintext = TransferSenderPlaintext {
        owner_pubkey: spec.sender.signing_pubkey(),
        spl_asset_id: 0,
        spl_amount: 0,
        sol_amount: spec.change_amount,
        blinding_seed: spec.blinding_seed,
        recipient_viewing_pks: vec![spec.recipient.viewing_pubkey()],
        spl_data: Data::default(),
        sol_data: Data::default(),
    };
    let change = sender_plaintext.clone().into_utxos(assets, None).unwrap();
    let blob = spec
        .sender
        .viewing_key
        .encrypt_transfer(
            &spec.first_nullifier,
            &sender_plaintext,
            &[RecipientOutput {
                view_tag: spec.slot_tag,
                plaintext: recipient_plaintext,
            }],
        )
        .unwrap();
    let output_slots = blob
        .to_output_ciphertexts(
            spec.sender_view_tag,
            SENDER_SLOT_COUNT,
            SENDER_SLOT_COUNT + blob.recipient_slots.len(),
        )
        .unwrap();
    let tx = SyncTransaction {
        scheme: TRANSFER,
        tx_viewing_pk: blob.tx_viewing_pk,
        salt: blob.salt,
        output_slots,
        nullifiers: vec![spec.first_nullifier],
    };
    (tx, recipient_utxo, change)
}
