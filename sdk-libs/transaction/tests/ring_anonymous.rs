//! `test-vectors/anonymous_recipient_encryption.json` pins the scheme-9 body, Go and TS share it.

use borsh::BorshDeserialize;
use serde::Deserialize;
use solana_address::Address;
use zolana_event::OutputDataEncoding;
use zolana_keypair::{PublicKey, ViewingKey, X25519Pubkey};
use zolana_transaction::{
    serialization::ring_anonymous::{
        ring_anonymous_message, RingAnonymousOutput, RingAnonymousOutputPlaintext,
        RingAnonymousSlot,
    },
    AssetRegistry, EncryptedScheme, TransactionError,
};

#[derive(Deserialize)]
struct Vector {
    tx_sk: String,
    tx_pk: String,
    recipient_viewing_sk: String,
    recipient_viewing_pk: String,
    ring_program_id: String,
    salt: String,
    slot: u8,
    asset_address: String,
    amount: u64,
    blinding: String,
    pair_u: String,
    plaintext: String,
    body: String,
}

fn vector() -> Vector {
    serde_json::from_str(include_str!(
        "../../../test-vectors/anonymous_recipient_encryption.json"
    ))
    .unwrap()
}

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

fn opening(vector: &Vector) -> RingAnonymousOutputPlaintext {
    RingAnonymousOutputPlaintext {
        asset_address: bytes(&vector.asset_address),
        amount: vector.amount,
        blinding: bytes(&vector.blinding),
        pair_u: bytes(&vector.pair_u),
    }
}

fn slot(vector: &Vector) -> RingAnonymousSlot {
    RingAnonymousSlot {
        tx_viewing_pk: X25519Pubkey::from_bytes(bytes(&vector.tx_pk)).unwrap(),
        recipient_pk: X25519Pubkey::from_bytes(bytes(&vector.recipient_viewing_pk)).unwrap(),
        salt: bytes(&vector.salt),
        slot: vector.slot,
    }
}

#[test]
fn sealing_and_opening_follow_the_shared_vector() {
    let vector = vector();
    let tx = ViewingKey::from_bytes(&bytes(&vector.tx_sk));
    let recipient = ViewingKey::from_bytes(&bytes(&vector.recipient_viewing_sk));
    let slot = slot(&vector);
    assert_eq!(tx.pubkey(), slot.tx_viewing_pk);
    assert_eq!(recipient.pubkey(), slot.recipient_pk);

    let opening = opening(&vector);
    assert_eq!(
        opening.to_bytes().to_vec(),
        hex::decode(&vector.plaintext).unwrap()
    );
    let body = slot.seal(&tx, &opening).unwrap();
    assert_eq!(body.to_vec(), hex::decode(&vector.body).unwrap());
    assert_eq!(body[0], EncryptedScheme::RingAnonymous.as_byte());

    assert_eq!(slot.open(&recipient, &body[1..]).unwrap(), opening);
    assert_eq!(slot.open_with_tx_key(&tx, &body[1..]).unwrap(), opening);
    // Another slot index keys another stream.
    let other = RingAnonymousSlot {
        slot: vector.slot + 1,
        ..slot
    };
    assert_ne!(other.open(&recipient, &body[1..]).ok(), Some(opening));
}

#[test]
fn the_message_frames_the_body_under_the_anonymous_scheme() {
    let vector = vector();
    let body: [u8; 105] = bytes(&vector.body);
    let message = ring_anonymous_message(&body, [9; 32]).unwrap();
    assert_eq!(message.view_tag, [9; 32]);
    let OutputDataEncoding::Encrypted(blob) =
        OutputDataEncoding::try_from_slice(&message.data).unwrap()
    else {
        panic!("encrypted output")
    };
    assert_eq!(blob, body.to_vec());
}

#[test]
fn the_opening_resolves_the_asset_by_address_and_the_pair_key() {
    let vector = vector();
    let ring = Address::new_from_array(bytes(&vector.ring_program_id));
    let mut opening = opening(&vector);
    let assets = AssetRegistry::default();
    assert!(matches!(
        RingAnonymousOutput::from_opening(opening, PublicKey::zeroed(), ring, &assets),
        Err(TransactionError::UnknownMint(_))
    ));
    opening.asset_address = [0; 32];
    // The vector's pair hint is a byte pattern, not a curve point, the note still opens.
    let output =
        RingAnonymousOutput::from_opening(opening, PublicKey::zeroed(), ring, &assets).unwrap();
    assert_eq!(output.utxo.amount, vector.amount);
    assert_eq!(output.utxo.ring_program_id, Some(ring));
    assert_eq!(output.pair_pk, None);
    assert!(output.utxo.data.is_empty());
    let pair = ViewingKey::new().pubkey();
    opening.pair_u = pair.u();
    let output =
        RingAnonymousOutput::from_opening(opening, PublicKey::zeroed(), ring, &assets).unwrap();
    assert_eq!(output.pair_pk, Some(pair));
}

#[test]
fn a_body_of_another_length_is_rejected() {
    let vector = vector();
    let body: [u8; 105] = bytes(&vector.body);
    let recipient = ViewingKey::from_bytes(&bytes(&vector.recipient_viewing_sk));
    for ciphertext in [&body[1..104], &body[..]] {
        assert!(matches!(
            slot(&vector).open(&recipient, ciphertext),
            Err(TransactionError::InvalidLength { expected: 104, .. })
        ));
    }
}
