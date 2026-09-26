use serde::Deserialize;
use solana_address::Address;
use zolana_keypair::{
    PublicKey, ShieldedAddress, ShieldedKeypair, SigningKey, SHIELDED_ADDRESS_LEN,
};

#[derive(Deserialize)]
struct Holder {
    #[serde(with = "zolana_keypair::serde_helpers::address")]
    address: Address,
    #[serde(default, with = "zolana_keypair::serde_helpers::option_address")]
    ring_program_id: Option<Address>,
}

fn address() -> ShieldedAddress {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7; 32]))
        .unwrap()
        .shielded_address()
        .unwrap()
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    serde_json::from_value(serde_json::json!(bytes)).map_err(|error| error.to_string())
}

#[test]
fn a_shielded_address_decodes_only_from_its_valid_bytes() {
    let address = address();
    let bytes = address.to_bytes();
    let mut bad_curve = bytes;
    if let Some(tag) = bad_curve.first_mut() {
        *tag = 9;
    }

    assert_eq!(
        (
            decode::<ShieldedAddress>(&bytes).ok(),
            decode::<ShieldedAddress>(&bytes[..SHIELDED_ADDRESS_LEN - 1]).is_err(),
            decode::<ShieldedAddress>(&bad_curve).is_err(),
            serde_json::to_value(address).unwrap(),
        ),
        (Some(address), true, true, serde_json::json!(bytes.to_vec())),
    );
}

#[test]
fn a_public_key_decodes_the_dummy_owner_and_rejects_invalid_keys() {
    let signing_pubkey = address().signing_pubkey;
    let mut invalid = [0u8; 34];
    if let Some(tag) = invalid.first_mut() {
        *tag = 1;
    }
    if let Some(last) = invalid.last_mut() {
        *last = 1;
    }

    assert_eq!(
        (
            decode::<PublicKey>(&[0u8; 34]).ok(),
            decode::<PublicKey>(signing_pubkey.as_bytes()).ok(),
            decode::<PublicKey>(&invalid).is_err(),
        ),
        (Some(PublicKey::zeroed()), Some(signing_pubkey), true),
    );
}

#[test]
fn addresses_decode_from_base58_text() {
    let address = Address::new_from_array([3; 32]);
    let holder: Holder = serde_json::from_value(serde_json::json!({
        "address": address.to_string(),
        "ring_program_id": address.to_string(),
    }))
    .unwrap();
    let without_ring: Holder =
        serde_json::from_value(serde_json::json!({ "address": address.to_string() })).unwrap();
    let invalid = serde_json::from_value::<Holder>(serde_json::json!({ "address": "0OIl" }));

    assert_eq!(
        (
            holder.address,
            holder.ring_program_id,
            without_ring.ring_program_id,
            invalid.is_err(),
        ),
        (address, Some(address), None, true),
    );
}
