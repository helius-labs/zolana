use serde::{Deserialize, Serialize};
use solana_address::Address;
use zolana_keypair::{hash::sha256, SigningKey};
use zolana_transaction::instructions::transact::{
    ring_spend_message, transact_message_hash, RING_SPEND_MESSAGE_PREFIX,
};

const RING_SPEND_MESSAGE_VECTOR_JSON: &str =
    include_str!("../../../test-vectors/ring_spend_message.json");

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct RingSpendMessageVector {
    description: String,
    prefix: String,
    ring_program_id: String,
    private_tx_hash: String,
    external_data_hash: String,
    digest: String,
    message: String,
    seed: String,
    public_key: String,
    signature: String,
}

fn decode<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value)
        .unwrap()
        .try_into()
        .unwrap_or_else(|_| panic!("{value} is not {N} bytes"))
}

fn committed() -> RingSpendMessageVector {
    serde_json::from_str(RING_SPEND_MESSAGE_VECTOR_JSON).unwrap()
}

fn compute_vector() -> RingSpendMessageVector {
    let ring_program_id = Address::new_from_array([0x5A; 32]);
    let private_tx_hash = [0x11u8; 32];
    let external_data_hash = [0x22u8; 32];
    let digest = transact_message_hash(&private_tx_hash, &external_data_hash);
    let message = ring_spend_message(&ring_program_id, &digest);
    let seed = [0x07u8; 32];
    let owner = SigningKey::from_ed25519_bytes(&seed);
    RingSpendMessageVector {
        description: committed().description,
        prefix: String::from_utf8(RING_SPEND_MESSAGE_PREFIX.to_vec()).unwrap(),
        ring_program_id: hex::encode(ring_program_id.as_array()),
        private_tx_hash: hex::encode(private_tx_hash),
        external_data_hash: hex::encode(external_data_hash),
        digest: hex::encode(digest),
        message: hex::encode(message),
        seed: hex::encode(seed),
        public_key: hex::encode(owner.pubkey().as_ed25519().unwrap()),
        signature: hex::encode(owner.sign_message(&message).unwrap()),
    }
}

#[test]
fn committed_ring_spend_message_vector_matches() {
    assert_eq!(committed(), compute_vector());
}

#[test]
fn committed_signature_verifies_under_the_committed_key_only_for_this_ring() {
    let vector = committed();
    let message: [u8; 84] = decode(&vector.message);
    let digest: [u8; 32] = decode(&vector.digest);
    let signature: [u8; 64] = decode(&vector.signature);
    let owner = SigningKey::from_ed25519_bytes(&decode(&vector.seed)).pubkey();
    assert_eq!(
        sha256(
            &[
                decode::<32>(&vector.private_tx_hash),
                decode::<32>(&vector.external_data_hash)
            ]
            .concat()
        ),
        digest
    );
    assert!(owner.verify_message(&message, &signature));
    assert!(!owner.verify_message(&digest, &signature));
    let other_ring = ring_spend_message(&Address::new_from_array([0x5B; 32]), &digest);
    assert!(!owner.verify_message(&other_ring, &signature));
}

#[test]
#[ignore = "regenerates test-vectors/ring_spend_message.json; run with --nocapture and commit the output"]
fn print_ring_spend_message_vector() {
    println!(
        "{}",
        serde_json::to_string_pretty(&compute_vector()).unwrap()
    );
}
