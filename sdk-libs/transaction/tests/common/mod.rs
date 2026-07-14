#![allow(dead_code)]

use zolana_event::OutputDataEncoding;
use zolana_keypair::{
    constants::BLINDING_LEN, viewing_key::ViewTag, ShieldedKeypair, SigningKey, ViewingKey,
};
use zolana_transaction::{
    serialization::{
        anonymous::{
            AnonymousRecipient, AnonymousRecipientEncode, AnonymousSenderBundle,
            AnonymousSenderEncode, AnonymousTransferSenderPlaintext,
        },
        confidential_unified::{ConfidentialUnified, ConfidentialUnifiedEncode},
    },
    Address, AssetRegistry, Data, EncryptedScheme, OutputContext, OutputSlot, OwnerCx,
    ShieldedTransaction, Utxo, UtxoSerialization, SOL_MINT,
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

fn encrypted_payload(scheme: EncryptedScheme, ciphertext: Vec<u8>) -> Vec<u8> {
    let mut blob = Vec::with_capacity(1 + ciphertext.len());
    blob.push(scheme.as_byte());
    blob.extend_from_slice(&ciphertext);
    borsh::to_vec(&OutputDataEncoding::Encrypted(blob))
        .expect("output data serialization is infallible")
}

fn empty_slot() -> OutputSlot {
    OutputSlot {
        view_tag: [0u8; 32],
        output_context: OutputContext {
            hash: [0u8; 32],
            tree: Address::new_from_array([0u8; 32]),
            leaf_index: 0,
        },
        payload: Vec::new(),
    }
}

fn slot(view_tag: ViewTag, hash: [u8; 32], payload: Vec<u8>) -> OutputSlot {
    OutputSlot {
        view_tag,
        output_context: OutputContext {
            hash,
            tree: Address::new_from_array([0u8; 32]),
            leaf_index: 0,
        },
        payload,
    }
}

pub fn build_transfer(
    assets: &AssetRegistry,
    spec: TransferSpec<'_>,
) -> (ShieldedTransaction, Utxo, Vec<Utxo>) {
    let tx_key = spec
        .sender
        .viewing_key
        .get_transaction_viewing_key(&spec.first_nullifier)
        .unwrap();
    let tx_viewing_pk = tx_key.pubkey();
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&spec.first_nullifier[..16]);

    let recipient_utxo = Utxo {
        owner: spec.recipient.signing_pubkey(),
        asset: SOL_MINT,
        amount: spec.amount,
        blinding: spec.blinding,
        zone_program_id: None,
        data: Data::default(),
    };

    let sender_plaintext = AnonymousTransferSenderPlaintext {
        owner_pubkey: spec.sender.signing_pubkey(),
        spl_asset_id: 0,
        spl_amount: 0,
        sol_amount: spec.change_amount,
        blinding_seed: spec.blinding_seed,
        recipient_viewing_pks: vec![spec.recipient.viewing_pubkey()],
        spl_data: Data::default(),
        sol_data: Data::default(),
    };

    let sender_owner_cx = OwnerCx {
        owner: spec.sender.signing_pubkey(),
        assets,
        zone_program_id: None,
    };
    let change =
        AnonymousSenderBundle::into_utxos(sender_plaintext.clone(), &sender_owner_cx).unwrap();

    let sender_cx = AnonymousSenderEncode {
        tx: tx_key.clone(),
        self_pubkey: spec.sender.viewing_pubkey(),
        salt,
        slot_index: 0,
        blinding_seed: spec.blinding_seed,
        recipient_viewing_pks: vec![spec.recipient.viewing_pubkey()],
    };
    let sender_bytes = AnonymousSenderBundle::serialize(&sender_plaintext).unwrap();
    let sender_ciphertext = AnonymousSenderBundle::encrypt(&sender_bytes, &sender_cx).unwrap();
    let sender_payload = encrypted_payload(EncryptedScheme::AnonymousSender, sender_ciphertext);

    let nullifier_pk = spec.sender.nullifier_key.pubkey().unwrap();
    let sender_hash = change
        .first()
        .map(|utxo| utxo.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32]).unwrap())
        .unwrap_or([0u8; 32]);

    let recipient_owner_cx = OwnerCx {
        owner: spec.recipient.signing_pubkey(),
        assets,
        zone_program_id: None,
    };
    let recipient_cx = AnonymousRecipientEncode {
        tx: tx_key,
        recipient_pubkey: spec.recipient.viewing_pubkey(),
        sender_pubkey: spec.sender.viewing_pubkey(),
        salt,
        slot_index: 1,
    };
    let recipient_ciphertext = AnonymousRecipient::encode(
        std::slice::from_ref(&recipient_utxo),
        &recipient_owner_cx,
        spec.slot_tag,
        &recipient_cx,
    )
    .unwrap();

    let recipient_nullifier_pk = spec.recipient.nullifier_key.pubkey().unwrap();
    let recipient_hash = recipient_utxo
        .hash(&recipient_nullifier_pk, &[0u8; 32], &[0u8; 32])
        .unwrap();

    let output_slots = vec![
        slot(spec.sender_view_tag, sender_hash, sender_payload),
        empty_slot(),
        slot(
            recipient_ciphertext.view_tag,
            recipient_hash,
            recipient_ciphertext.data,
        ),
    ];

    let tx = ShieldedTransaction {
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        tx_viewing_pk: Some(tx_viewing_pk),
        salt: Some(salt),
        output_slots,
        nullifiers: vec![spec.first_nullifier],
        proofless: false,
    };
    (tx, recipient_utxo, change)
}

pub struct UnifiedTransferSpec<'a> {
    pub sender: &'a ShieldedKeypair,
    pub recipient: &'a ShieldedKeypair,
    pub amount: u64,
    pub change_amount: u64,
    pub first_nullifier: [u8; 32],
    pub blinding: [u8; BLINDING_LEN],
    pub change_blinding: [u8; BLINDING_LEN],
}

pub fn build_unified_transfer(
    assets: &AssetRegistry,
    spec: UnifiedTransferSpec<'_>,
) -> (ShieldedTransaction, Utxo, Utxo) {
    let tx_key = spec
        .sender
        .viewing_key
        .get_transaction_viewing_key(&spec.first_nullifier)
        .unwrap();
    let tx_viewing_pk = tx_key.pubkey();
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&spec.first_nullifier[..16]);

    let change_utxo = Utxo {
        owner: spec.sender.signing_pubkey(),
        asset: SOL_MINT,
        amount: spec.change_amount,
        blinding: spec.change_blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let recipient_utxo = Utxo {
        owner: spec.recipient.signing_pubkey(),
        asset: SOL_MINT,
        amount: spec.amount,
        blinding: spec.blinding,
        zone_program_id: None,
        data: Data::default(),
    };

    let sender_owner_cx = OwnerCx {
        owner: spec.sender.signing_pubkey(),
        assets,
        zone_program_id: None,
    };
    let change_ciphertext = ConfidentialUnified::encode(
        std::slice::from_ref(&change_utxo),
        &sender_owner_cx,
        spec.sender
            .signing_pubkey()
            .confidential_view_tag()
            .unwrap(),
        &ConfidentialUnifiedEncode {
            tx: tx_key.clone(),
            recipient_pubkey: spec.sender.viewing_pubkey(),
            salt,
            slot_index: 0,
        },
    )
    .unwrap();

    let recipient_owner_cx = OwnerCx {
        owner: spec.recipient.signing_pubkey(),
        assets,
        zone_program_id: None,
    };
    let recipient_ciphertext = ConfidentialUnified::encode(
        std::slice::from_ref(&recipient_utxo),
        &recipient_owner_cx,
        spec.recipient
            .signing_pubkey()
            .confidential_view_tag()
            .unwrap(),
        &ConfidentialUnifiedEncode {
            tx: tx_key,
            recipient_pubkey: spec.recipient.viewing_pubkey(),
            salt,
            slot_index: 1,
        },
    )
    .unwrap();

    let change_hash = change_utxo
        .hash(
            &spec.sender.nullifier_key.pubkey().unwrap(),
            &[0u8; 32],
            &[0u8; 32],
        )
        .unwrap();
    let recipient_hash = recipient_utxo
        .hash(
            &spec.recipient.nullifier_key.pubkey().unwrap(),
            &[0u8; 32],
            &[0u8; 32],
        )
        .unwrap();

    let output_slots = vec![
        slot(
            change_ciphertext.view_tag,
            change_hash,
            change_ciphertext.data,
        ),
        slot(
            recipient_ciphertext.view_tag,
            recipient_hash,
            recipient_ciphertext.data,
        ),
    ];

    let tx = ShieldedTransaction {
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        tx_viewing_pk: Some(tx_viewing_pk),
        salt: Some(salt),
        output_slots,
        nullifiers: vec![spec.first_nullifier],
        proofless: false,
    };
    (tx, change_utxo, recipient_utxo)
}
