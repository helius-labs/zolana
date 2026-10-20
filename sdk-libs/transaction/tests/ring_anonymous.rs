//! `test-vectors/ring_anonymous_plaintext.json` pins the scheme-9 layout for TS.

use borsh::BorshDeserialize;
use serde::Deserialize;
use solana_address::Address;
use zolana_event::OutputDataEncoding;
use zolana_keypair::{x25519::X25519_PUBKEY_LEN, PublicKey, ViewingKey, X25519Keypair};
use zolana_transaction::{
    serialization::{
        confidential::{ConfidentialEncode, ConfidentialOutputPlaintext},
        ring_anonymous::{RingAnonymous, RingAnonymousOutputPlaintext},
    },
    AssetRegistry, Data, EncryptedScheme, TransactionError,
};

#[derive(Deserialize)]
struct Vector {
    asset_id: u64,
    amount: u64,
    blinding: String,
    ring_program_id: String,
    pair_secret: String,
    pair_pk: String,
    plaintext: String,
}

fn vector() -> Vector {
    serde_json::from_str(include_str!(
        "../../../test-vectors/ring_anonymous_plaintext.json"
    ))
    .unwrap()
}

fn bytes32(hex: &str) -> [u8; 32] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

fn plaintext(vector: &Vector) -> RingAnonymousOutputPlaintext {
    RingAnonymousOutputPlaintext {
        output: ConfidentialOutputPlaintext {
            asset_id: vector.asset_id,
            amount: vector.amount,
            blinding: bytes32(&vector.blinding),
            ring_program_id: Some(Address::new_from_array(bytes32(&vector.ring_program_id))),
            data: Data::default(),
        },
        pair_pk: X25519Keypair::from_bytes(&bytes32(&vector.pair_secret)).pubkey(),
    }
}

#[test]
fn plaintext_matches_the_shared_vector() {
    let vector = vector();
    let plaintext = plaintext(&vector);
    assert_eq!(hex::encode(plaintext.pair_pk.as_bytes()), vector.pair_pk);
    let bytes = plaintext.serialize().unwrap();
    assert_eq!(hex::encode(&bytes), vector.plaintext);
    assert_eq!(
        RingAnonymousOutputPlaintext::deserialize(&bytes).unwrap(),
        plaintext
    );
}

#[test]
fn scheme_3_layout_is_unchanged() {
    let plaintext = plaintext(&vector());
    let scheme_3 = plaintext.output.serialize().unwrap();
    let scheme_9 = plaintext.serialize().unwrap();
    assert_eq!(scheme_9.len(), scheme_3.len() + X25519_PUBKEY_LEN);
    assert_eq!(&scheme_9[..scheme_3.len()], &scheme_3[..]);
    assert!(ConfidentialOutputPlaintext::deserialize(&scheme_9).is_err());
    assert!(RingAnonymousOutputPlaintext::deserialize(&scheme_3).is_err());
}

#[test]
fn pair_key_must_be_a_tagged_canonical_x25519_key() {
    let mut bytes = plaintext(&vector()).serialize().unwrap();
    let tag = bytes.len() - X25519_PUBKEY_LEN;
    bytes[tag] = 0x05;
    assert!(matches!(
        RingAnonymousOutputPlaintext::deserialize(&bytes),
        Err(TransactionError::Keypair(_))
    ));
}

struct Sealed {
    tx: ViewingKey,
    recipient: ViewingKey,
    body: Vec<u8>,
}

fn sealed(plaintext: &RingAnonymousOutputPlaintext) -> Sealed {
    let tx = ViewingKey::new();
    let recipient = ViewingKey::new();
    let message = RingAnonymous::encode_plaintext(
        plaintext,
        [0; 32],
        &ConfidentialEncode {
            tx: tx.clone(),
            recipient_pubkey: recipient.pubkey(),
            salt: [7; 16],
            slot_index: 2,
        },
    )
    .unwrap();
    let OutputDataEncoding::Encrypted(blob) =
        OutputDataEncoding::try_from_slice(&message.data).unwrap()
    else {
        panic!("encrypted output")
    };
    let (&scheme, body) = blob.split_first().unwrap();
    assert_eq!(scheme, EncryptedScheme::RingAnonymous.as_byte());
    Sealed {
        tx,
        recipient,
        body: body.to_vec(),
    }
}

#[test]
fn recipient_and_auditor_both_read_the_pair_key() {
    let plaintext = plaintext(&vector());
    let Sealed {
        tx,
        recipient,
        body,
    } = sealed(&plaintext);
    // No recipient key rides in front of the ciphertext.
    assert_eq!(body.len(), plaintext.serialize().unwrap().len());
    let opened = RingAnonymous::decrypt(&recipient, &body, &tx.pubkey(), [7; 16], 2).unwrap();
    assert_eq!(opened, plaintext);
    let audited =
        RingAnonymous::decrypt_with_tx_key(&tx, &recipient.pubkey(), &body, [7; 16], 2).unwrap();
    assert_eq!(audited, plaintext);
    let output = opened
        .into_output(PublicKey::zeroed(), &AssetRegistry::default())
        .unwrap();
    assert_eq!(output.utxo.amount, plaintext.output.amount);
    assert_eq!(
        output.utxo.ring_program_id,
        plaintext.output.ring_program_id
    );
    assert_eq!(output.pair_pk, plaintext.pair_pk);
}

#[test]
fn truncated_body_is_rejected() {
    let plaintext = plaintext(&vector());
    let Sealed {
        tx,
        recipient,
        body,
    } = sealed(&plaintext);
    let truncated = &body[..body.len() - 1];
    assert!(RingAnonymous::decrypt(&recipient, truncated, &tx.pubkey(), [7; 16], 2).is_err());
    let short = &body[..X25519_PUBKEY_LEN - 1];
    assert!(matches!(
        RingAnonymous::decrypt(&recipient, short, &tx.pubkey(), [7; 16], 2),
        Err(TransactionError::InvalidLength {
            expected: X25519_PUBKEY_LEN,
            actual: 32,
        })
    ));
}
