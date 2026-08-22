//! The tagged reader key encoding, which the on-chain reader record stores
//! verbatim.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use solana_address::Address;
use zolana_interface::custom_ring::{READER_KEY_ED25519, READER_KEY_P256};
use zolana_keypair::ViewingKey;
use zolana_ring_client::{ReaderKey, ReaderKeyError};

fn ed25519_address() -> Address {
    Address::new_from_array(ED25519_BASEPOINT_POINT.compress().to_bytes())
}

#[test]
fn tagged_reader_keys_round_trip_through_their_bytes() {
    let ed25519 = ReaderKey::ed25519(ed25519_address()).expect("Ed25519 reader");
    let p256 = ReaderKey::p256(ViewingKey::new().pubkey()).expect("P256 reader");

    for reader in [ed25519, p256] {
        let bytes = reader.to_bytes();
        assert_eq!(ReaderKey::from_bytes(bytes), Ok(reader));
    }
    assert_eq!(ed25519.to_bytes()[0], READER_KEY_ED25519);
    assert_eq!(p256.to_bytes()[0], READER_KEY_P256);
    // The two schemes never collide on one record address.
    let ring = Address::new_from_array([9u8; 32]);
    assert_ne!(ed25519.record_address(&ring), p256.record_address(&ring));
}

/// A PDA tag is a valid public key tag but names a scheme that cannot sign a
/// read.
#[test]
fn a_reader_key_tag_outside_the_two_signing_schemes_is_rejected() {
    let mut pda = [0u8; 34];
    pda[0] = 2;
    pda[1..33].copy_from_slice(&[6u8; 32]);
    assert_eq!(ReaderKey::from_bytes(pda), Err(ReaderKeyError::Scheme));

    let mut unknown = [0u8; 34];
    unknown[0] = 0xff;
    assert!(ReaderKey::from_bytes(unknown).is_err());
}

/// The Ed25519 body is a curve point, and the P256 body is a compressed key,
/// so neither scheme accepts arbitrary bytes.
#[test]
fn a_reader_key_body_that_is_not_a_point_is_rejected() {
    let mut off_curve = [0u8; 34];
    off_curve[0] = READER_KEY_ED25519;
    off_curve[1..33].copy_from_slice(&[1u8; 32]);
    assert_eq!(ReaderKey::from_bytes(off_curve), Err(ReaderKeyError::Body));

    let mut small_order = [0u8; 34];
    small_order[0] = READER_KEY_ED25519;
    assert_eq!(
        ReaderKey::from_bytes(small_order),
        Err(ReaderKeyError::Body)
    );
}
