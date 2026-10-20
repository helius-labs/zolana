//! Shared cross-language ring address vectors.
//!
//! `test-vectors/ring_address.json` pins the `zolana:` payment request form
//! for every implementation. Regenerate with:
//!
//! ```bash
//! cargo test -p zolana-keypair --test ring_address print_ring_address_vectors -- --ignored --nocapture
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_address::Address;
use zolana_keypair::{
    ring_address::{RING_ADDRESS_CHECKSUM_DOMAIN, RING_ADDRESS_PAYLOAD_LEN},
    InboxSecret, KeypairError, RingAddress, RingPaymentRequest, ShieldedKeypair, SigningKey,
    ViewingKey,
};

const VECTORS_JSON: &str = include_str!("../../../test-vectors/ring_address.json");

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct RingAddressVectors {
    valid: Vec<ValidCase>,
    rejected: Vec<RejectedCase>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct ValidCase {
    name: String,
    uri: String,
    recipient: String,
    ring_program_id: String,
    inbox_secret: String,
    amount: Option<String>,
    mint: Option<String>,
    label: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct RejectedCase {
    name: String,
    uri: String,
    error: String,
}

fn fixture_address() -> RingAddress {
    let recipient = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7u8; 32]))
        .unwrap()
        .shielded_address()
        .unwrap();
    RingAddress {
        recipient,
        ring_program_id: Address::new_from_array([0x11; 32]),
        inbox_secret: ViewingKey::from_bytes(&[0x21; 32]).inbox_secret(0).unwrap(),
    }
}

fn valid_case(name: &str, request: &RingPaymentRequest) -> ValidCase {
    ValidCase {
        name: name.into(),
        uri: request.to_string(),
        recipient: hex::encode(request.address.recipient.to_bytes()),
        ring_program_id: request.address.ring_program_id.to_string(),
        inbox_secret: hex::encode(request.address.inbox_secret.as_bytes()),
        amount: request.amount.map(|amount| amount.to_string()),
        mint: request.mint.map(|mint| mint.to_string()),
        label: request.label.clone(),
    }
}

fn with_checksum(mut payload: [u8; RING_ADDRESS_PAYLOAD_LEN]) -> [u8; RING_ADDRESS_PAYLOAD_LEN] {
    let body_len = RING_ADDRESS_PAYLOAD_LEN - 4;
    let digest = Sha256::new()
        .chain_update(RING_ADDRESS_CHECKSUM_DOMAIN)
        .chain_update(&payload[..body_len])
        .finalize();
    payload[body_len..].copy_from_slice(&digest[..4]);
    payload
}

fn variant_name(error: KeypairError) -> String {
    let debug = format!("{error:?}");
    debug.split('(').next().unwrap_or(&debug).to_string()
}

fn compute() -> RingAddressVectors {
    let address = fixture_address();
    let bare = RingPaymentRequest::new(address.clone());
    let full = RingPaymentRequest {
        amount: Some(1_500_000),
        mint: Some(Address::new_from_array([0x33; 32])),
        label: Some("Coffee & cake ☕ 100%".into()),
        ..bare.clone()
    };
    let labelled = RingPaymentRequest {
        label: Some("rent".into()),
        ..bare.clone()
    };
    let valid = vec![
        valid_case("bare", &bare),
        valid_case("amount_mint_label", &full),
        valid_case("label_only", &labelled),
    ];

    let payload = address.to_bytes();
    let base58 = address.to_base58();
    let uri = |payload: &[u8]| format!("zolana:{}", bs58::encode(payload).into_string());
    let mut wrong_version = payload;
    wrong_version[0] = 2;
    let mut bad_checksum = payload;
    bad_checksum[RING_ADDRESS_PAYLOAD_LEN - 1] ^= 1;
    let mut bad_viewing_key = payload;
    bad_viewing_key[1 + 34 + 32] = 5;
    let rejected = vec![
        ("missing_scheme", base58.clone()),
        ("non_base58", format!("zolana:0{}", &base58[1..])),
        (
            "short_payload",
            uri(&payload[..RING_ADDRESS_PAYLOAD_LEN - 1]),
        ),
        ("long_payload", uri(&[payload.as_slice(), &[0]].concat())),
        ("unknown_version", uri(&with_checksum(wrong_version))),
        ("bad_checksum", uri(&bad_checksum)),
        ("bad_viewing_key", uri(&with_checksum(bad_viewing_key))),
        ("unknown_query_key", format!("{}?memo=hi", bare)),
        ("duplicate_query_key", format!("{}?amount=1&amount=2", bare)),
        ("fractional_amount", format!("{}?amount=1.5", bare)),
        ("signed_amount", format!("{}?amount=+1", bare)),
        ("bad_mint", format!("{}?mint=notAnAddress", bare)),
        ("bad_label_escape", format!("{}?label=%zz", bare)),
    ]
    .into_iter()
    .map(|(name, uri)| RejectedCase {
        name: name.into(),
        error: variant_name(uri.parse::<RingPaymentRequest>().unwrap_err()),
        uri,
    })
    .collect();
    RingAddressVectors { valid, rejected }
}

#[test]
fn shared_vectors_match() {
    let committed: RingAddressVectors = serde_json::from_str(VECTORS_JSON).unwrap();
    assert_eq!(committed, compute());
    for case in &committed.valid {
        let request: RingPaymentRequest = case.uri.parse().unwrap();
        assert_eq!(request.to_string(), case.uri, "{}", case.name);
        assert_eq!(
            hex::encode(request.address.recipient.to_bytes()),
            case.recipient
        );
        assert_eq!(
            request.address.ring_program_id.to_string(),
            case.ring_program_id
        );
        assert_eq!(
            request.address.inbox_secret,
            InboxSecret::from_bytes(hex::decode(&case.inbox_secret).unwrap().try_into().unwrap())
        );
        assert_eq!(
            request.address,
            RingAddress::from_base58(&request.address.to_base58()).unwrap()
        );
    }
    let expected_errors = [
        ("missing_scheme", "InvalidRingAddressScheme"),
        ("non_base58", "InvalidRingAddressBase58"),
        ("short_payload", "InvalidRingAddressLength"),
        ("long_payload", "InvalidRingAddressLength"),
        ("unknown_version", "UnknownRingAddressVersion"),
        ("bad_checksum", "InvalidRingAddressChecksum"),
        ("bad_viewing_key", "InvalidPublicKey"),
        ("unknown_query_key", "UnknownRingPaymentKey"),
        ("duplicate_query_key", "DuplicateRingPaymentKey"),
        ("fractional_amount", "InvalidRingPaymentAmount"),
        ("signed_amount", "InvalidRingPaymentAmount"),
        ("bad_mint", "InvalidRingPaymentMint"),
        ("bad_label_escape", "InvalidRingPaymentLabel"),
    ];
    assert_eq!(committed.rejected.len(), expected_errors.len());
    for (case, (name, error)) in committed.rejected.iter().zip(expected_errors) {
        assert_eq!((case.name.as_str(), case.error.as_str()), (name, error));
    }
}

#[test]
fn request_round_trips_every_field() {
    let request = RingPaymentRequest {
        address: fixture_address(),
        amount: Some(u64::MAX),
        mint: Some(Address::new_from_array([0x44; 32])),
        label: Some("a=b&c?d/é".into()),
    };
    assert_eq!(
        request.to_string().parse::<RingPaymentRequest>().unwrap(),
        request
    );
}

#[test]
#[ignore = "regenerates test-vectors/ring_address.json; run with --nocapture and commit the output"]
fn print_ring_address_vectors() {
    println!("{}", serde_json::to_string_pretty(&compute()).unwrap());
}
