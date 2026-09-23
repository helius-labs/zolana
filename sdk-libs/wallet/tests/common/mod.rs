#![allow(dead_code)]

use zolana_event::OutputDataEncoding;

/// Raw id of the tree these helpers hash UTXOs under. The SDK reads a single
/// tree today; the id only has to match between the hash and the tree the
/// commitment lands in.
pub const TEST_TREE_ID: u16 = 0;
const SENDER_SLOT_COUNT: usize = 2;

use zolana_keypair::{viewing_key::ViewTag, ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::{
    serialization::{
        anonymous::{
            AnonymousRecipient, AnonymousRecipientEncode, AnonymousSenderBundle,
            AnonymousSenderEncode, AnonymousTransferSenderPlaintext,
        },
        confidential::{Confidential, ConfidentialEncode},
    },
    Address, AssetRegistry, Data, EncryptedScheme, OutputContext, OutputSlot, OwnerCx,
    ShieldedTransaction, Utxo, UtxoSerialization,
};
use zolana_wallet::{KeypairWalletAuthority, Wallet};

pub fn keypair_from_index(index: u16) -> ShieldedKeypair {
    let mut signing_bytes = [0u8; 32];
    signing_bytes[0] = 0x10;
    signing_bytes[1..3].copy_from_slice(&index.to_be_bytes());
    let mut viewing_bytes = [0u8; 32];
    viewing_bytes[0] = 0x20;
    viewing_bytes[1..3].copy_from_slice(&index.to_be_bytes());
    let signing = SigningKey::from_p256_bytes(&signing_bytes).unwrap();
    let viewing = ViewingKey::from_bytes(&viewing_bytes).unwrap();
    ShieldedKeypair::with_viewing_key(signing, viewing).unwrap()
}

pub fn local_authority(keypair: &ShieldedKeypair) -> KeypairWalletAuthority<'_> {
    KeypairWalletAuthority::new(Address::default(), keypair)
}

pub fn wallet_for(keypair: &ShieldedKeypair, registry: AssetRegistry) -> Wallet {
    Wallet::new(keypair.shielded_address().unwrap(), registry).unwrap()
}

pub fn unique31(counter: &mut u64, prefix: u8) -> [u8; 32] {
    *counter += 1;
    let mut out = [0u8; 32];
    out[1] = prefix;
    out[2..10].copy_from_slice(&counter.to_be_bytes());
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
    pub blinding: [u8; 32],
    pub blinding_seed: [u8; 32],
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
            tree_id: 0,
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
            tree_id: 0,
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
        asset: zolana_transaction::Mint::SOL,
        amount: spec.amount,
        blinding: spec.blinding,
        ring_program_id: None,
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
        ring_program_id: None,
        // The sender bundle publishes a seed; the change blindings derive from
        // it and this nullifier.
        first_nullifier: Some(spec.first_nullifier),
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
        .map(|utxo| {
            utxo.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32], TEST_TREE_ID)
                .unwrap()
        })
        .unwrap_or([0u8; 32]);

    let recipient_owner_cx = OwnerCx {
        owner: spec.recipient.signing_pubkey(),
        assets,
        ring_program_id: None,
        // An anonymous recipient slot carries its blinding literally.
        first_nullifier: None,
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
        .hash(
            &recipient_nullifier_pk,
            &[0u8; 32],
            &[0u8; 32],
            TEST_TREE_ID,
        )
        .unwrap();

    let output_slots = vec![
        slot(spec.sender_view_tag, sender_hash, sender_payload),
        slot(
            recipient_ciphertext.view_tag,
            recipient_hash,
            recipient_ciphertext.data,
        ),
    ];

    let tx = ShieldedTransaction {
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        event_index: None,
        tx_viewing_pk: Some(tx_viewing_pk),
        salt: Some(salt),
        output_slots,
        messages: Vec::new(),
        nullifiers: vec![spec.first_nullifier],
        proofless: false,
        ring_config: None,
        ring_program_id: None,
    };
    (tx, recipient_utxo, change)
}

pub struct UnifiedTransferSpec<'a> {
    pub sender: &'a ShieldedKeypair,
    pub recipient: &'a ShieldedKeypair,
    pub amount: u64,
    pub change_amount: u64,
    pub first_nullifier: [u8; 32],
    pub blinding: [u8; 32],
    pub change_blinding: [u8; 32],
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
        asset: zolana_transaction::Mint::SOL,
        amount: spec.change_amount,
        blinding: spec.change_blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    let recipient_utxo = Utxo {
        owner: spec.recipient.signing_pubkey(),
        asset: zolana_transaction::Mint::SOL,
        amount: spec.amount,
        blinding: spec.blinding,
        ring_program_id: None,
        data: Data::default(),
    };

    let sender_owner_cx = OwnerCx {
        owner: spec.sender.signing_pubkey(),
        assets,
        ring_program_id: None,
        // A confidential slot carries its blinding literally.
        first_nullifier: None,
    };
    let change_ciphertext = Confidential::encode(
        std::slice::from_ref(&change_utxo),
        &sender_owner_cx,
        spec.sender
            .signing_pubkey()
            .confidential_view_tag()
            .unwrap(),
        &ConfidentialEncode {
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
        ring_program_id: None,
        first_nullifier: None,
    };
    let recipient_ciphertext = Confidential::encode(
        std::slice::from_ref(&recipient_utxo),
        &recipient_owner_cx,
        spec.recipient
            .signing_pubkey()
            .confidential_view_tag()
            .unwrap(),
        &ConfidentialEncode {
            tx: tx_key,
            recipient_pubkey: spec.recipient.viewing_pubkey(),
            salt,
            slot_index: SENDER_SLOT_COUNT as u32,
        },
    )
    .unwrap();

    let change_hash = change_utxo
        .hash(
            &spec.sender.nullifier_key.pubkey().unwrap(),
            &[0u8; 32],
            &[0u8; 32],
            TEST_TREE_ID,
        )
        .unwrap();
    let recipient_hash = recipient_utxo
        .hash(
            &spec.recipient.nullifier_key.pubkey().unwrap(),
            &[0u8; 32],
            &[0u8; 32],
            TEST_TREE_ID,
        )
        .unwrap();

    // The first `SENDER_SLOT_COUNT` positions are the sender's own change;
    // recipients start after them. A recipient parked inside that range reads
    // back as change, which nets the sender's history row to zero.
    let mut output_slots = vec![slot(
        change_ciphertext.view_tag,
        change_hash,
        change_ciphertext.data,
    )];
    output_slots.resize_with(SENDER_SLOT_COUNT, empty_slot);
    output_slots.push(slot(
        recipient_ciphertext.view_tag,
        recipient_hash,
        recipient_ciphertext.data,
    ));

    let tx = ShieldedTransaction {
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        event_index: None,
        tx_viewing_pk: Some(tx_viewing_pk),
        salt: Some(salt),
        output_slots,
        messages: Vec::new(),
        nullifiers: vec![spec.first_nullifier],
        proofless: false,
        ring_config: None,
        ring_program_id: None,
    };
    (tx, change_utxo, recipient_utxo)
}

/// A self-transfer with one confidential ciphertext per output.
pub fn split_transaction(
    owner: &ShieldedKeypair,
    input: &Utxo,
    parts: u8,
    seed: [u8; 32],
) -> (ShieldedTransaction, Vec<Utxo>) {
    use zolana_transaction::{
        serialization::confidential::ConfidentialOutputPlaintext,
        utxo::{derive_output_blinding_seed, derive_transact_output_blinding},
    };
    let nullifier_key = &owner.nullifier_key;
    let nullifier_pubkey = nullifier_key.pubkey().unwrap();
    let hash = input
        .hash(&nullifier_pubkey, &[0; 32], &[0; 32], TEST_TREE_ID)
        .unwrap();
    let first_nullifier = nullifier_key.nullifier(&hash, &input.blinding).unwrap();
    let tx = owner.get_transaction_viewing_key(&first_nullifier).unwrap();
    let salt = zolana_keypair::random_salt();
    let seed = derive_output_blinding_seed(&first_nullifier, &seed).unwrap();
    let view_tag = owner.signing_pubkey().confidential_view_tag().unwrap();
    let mut outputs = Vec::new();
    let mut output_slots = Vec::new();
    for index in 0..parts {
        let utxo = Utxo {
            owner: owner.signing_pubkey(),
            asset: input.asset,
            amount: input.amount / u64::from(parts),
            blinding: derive_transact_output_blinding(&first_nullifier, &seed, u32::from(index))
                .unwrap(),
            ring_program_id: input.ring_program_id,
            data: Data::default(),
        };
        let message = Confidential::encode_plaintext(
            &ConfidentialOutputPlaintext {
                asset_id: utxo.asset.asset_id,
                amount: utxo.amount,
                blinding: utxo.blinding,
                ring_program_id: utxo.ring_program_id,
                data: utxo.data.clone(),
            },
            view_tag,
            &ConfidentialEncode {
                tx: tx.clone(),
                recipient_pubkey: owner.viewing_pubkey(),
                salt,
                slot_index: u32::from(index),
            },
        )
        .unwrap();
        output_slots.push(OutputSlot {
            view_tag,
            output_context: OutputContext {
                hash: utxo
                    .hash(&nullifier_pubkey, &[0; 32], &[0; 32], TEST_TREE_ID)
                    .unwrap(),
                tree_id: TEST_TREE_ID,
                leaf_index: u64::from(index),
            },
            payload: message.data,
        });
        outputs.push(utxo);
    }
    (
        ShieldedTransaction {
            slot: 0,
            tx_signature: Default::default(),
            event_index: None,
            tx_viewing_pk: Some(tx.pubkey()),
            salt: Some(salt),
            output_slots,
            messages: vec![],
            nullifiers: vec![first_nullifier],
            proofless: false,
            ring_config: None,
            ring_program_id: None,
        },
        outputs,
    )
}
