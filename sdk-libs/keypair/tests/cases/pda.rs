use solana_address::Address;
use spr_keypair::{Curve, KeypairError, PublicKey};

fn pda(n: u8) -> Address {
    Address::new_from_array([n; 32])
}

pub(crate) fn owner_tag_is_not_hashed() {
    let address = pda(7);
    let as_pda = PublicKey::from_pda(&address);
    let as_ed25519 = PublicKey::from_ed25519(address.as_array());
    assert_ne!(as_pda, as_ed25519);
    assert_eq!(
        as_pda.confidential_view_tag().unwrap(),
        as_ed25519.confidential_view_tag().unwrap()
    );
    assert_eq!(
        as_pda.owner_proof_input_hash().unwrap(),
        as_ed25519.owner_proof_input_hash().unwrap()
    );
}

pub(crate) fn pda_public_key_encoding_round_trips() {
    let address = pda(7);
    let tagged = PublicKey::from_pda(&address);
    assert_eq!(tagged.curve().unwrap(), Curve::Pda);
    assert_eq!(tagged.as_pda().unwrap(), address.to_bytes());
    assert_eq!(
        tagged.as_ed25519(),
        Err(KeypairError::InvalidSignatureType(u8::from(Curve::Pda)))
    );

    let parsed = PublicKey::from_bytes(*tagged.as_bytes()).unwrap();
    assert_eq!(parsed, tagged);

    let mut padded = *tagged.as_bytes();
    padded[33] = 1;
    assert_eq!(
        PublicKey::from_bytes(padded),
        Err(KeypairError::InvalidPublicKey)
    );
}
