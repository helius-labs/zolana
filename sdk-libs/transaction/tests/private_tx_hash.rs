use serde::{Deserialize, Serialize};
use zolana_transaction::instructions::transact::{transact_message_hash, PrivateTxHash};

const PRIVATE_TX_HASH_VECTORS_JSON: &str =
    include_str!("../../../test-vectors/private_tx_hash.json");

const FIELD_MODULUS_MINUS_ONE: &str =
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct PrivateTxHashVectors {
    description: String,
    vectors: Vec<PrivateTxHashVector>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct PrivateTxHashVector {
    name: String,
    input_hashes: Vec<String>,
    output_hashes: Vec<String>,
    address_nullifiers: Vec<String>,
    blinding: String,
    private_tx_hash: String,
    external_data_hash: String,
    message_hash: String,
}

fn field(value: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some((_, tail)) = out.split_last_chunk_mut::<4>() {
        *tail = value.to_be_bytes();
    }
    out
}

fn fields(values: &[u32]) -> Vec<[u8; 32]> {
    values.iter().copied().map(field).collect()
}

fn decode(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn hexes(values: &[[u8; 32]]) -> Vec<String> {
    values.iter().map(hex::encode).collect()
}

fn vector(
    name: &str,
    inputs: &[[u8; 32]],
    outputs: &[[u8; 32]],
    address_nullifiers: &[[u8; 32]],
    blinding: [u8; 32],
    external_data_hash: [u8; 32],
) -> PrivateTxHashVector {
    let mut hash = PrivateTxHash::new(inputs, outputs, &blinding);
    hash.address_nullifiers = Some(address_nullifiers);
    let private_tx_hash = hash.hash().unwrap();
    PrivateTxHashVector {
        name: name.to_string(),
        input_hashes: hexes(inputs),
        output_hashes: hexes(outputs),
        address_nullifiers: hexes(address_nullifiers),
        blinding: hex::encode(blinding),
        private_tx_hash: hex::encode(private_tx_hash),
        external_data_hash: hex::encode(external_data_hash),
        message_hash: hex::encode(transact_message_hash(&private_tx_hash, &external_data_hash)),
    }
}

fn compute_vectors() -> PrivateTxHashVectors {
    let blinding = field(99);
    let external = field(55);
    let near_modulus = decode(FIELD_MODULUS_MINUS_ONE);
    let vectors = vec![
        vector(
            "compact",
            &fields(&[11]),
            &fields(&[21, 22]),
            &fields(&[0]),
            blinding,
            external,
        ),
        vector(
            "padded",
            &fields(&[11, 0]),
            &fields(&[21, 22, 0]),
            &fields(&[0, 0]),
            blinding,
            external,
        ),
        vector(
            "padding_moved",
            &fields(&[0, 11]),
            &fields(&[0, 21, 22]),
            &fields(&[0, 0]),
            blinding,
            external,
        ),
        vector(
            "address_nullifier",
            &fields(&[0, 11]),
            &fields(&[0, 21, 22]),
            &fields(&[31, 0]),
            blinding,
            external,
        ),
        vector(
            "two_inputs",
            &fields(&[11, 12]),
            &fields(&[21]),
            &fields(&[0, 0]),
            blinding,
            external,
        ),
        vector(
            "reordered_inputs",
            &fields(&[12, 11]),
            &fields(&[21]),
            &fields(&[0, 0]),
            blinding,
            external,
        ),
        vector(
            "single_slot_spend",
            &fields(&[11]),
            &fields(&[21]),
            &fields(&[0]),
            blinding,
            external,
        ),
        vector(
            "single_slot_address",
            &fields(&[11]),
            &fields(&[21]),
            &fields(&[31]),
            blinding,
            field(56),
        ),
        vector(
            "field_modulus_minus_one",
            &[near_modulus],
            &[near_modulus],
            &[near_modulus],
            near_modulus,
            near_modulus,
        ),
    ];
    PrivateTxHashVectors {
        description: "Known-answer vectors for private_tx_hash = Poseidon(nz(input_hashes), \
                      nz(output_hashes), nz(address_nullifiers), blinding) and for the transact \
                      message hash sha256(private_tx_hash || external_data_hash) a P256 owner \
                      signs, where nz is the nonzero hash chain of nonzero_hash_chain.json. \
                      Every value is a 32-byte big-endian hex string, and every vector names one \
                      address nullifier per input slot. compact, padded and padding_moved hold \
                      the same nonzero entries at different padding positions and share one \
                      private_tx_hash; address_nullifier differs from padding_moved only by a \
                      nonzero address nullifier; reordered_inputs swaps the two real inputs of \
                      two_inputs and differs from it; single_slot_spend, single_slot_address \
                      and field_modulus_minus_one hold one entry per list. padded and \
                      address_nullifier reproduce the Go host protocol.PrivateTxHash values. \
                      Produced by sdk-libs/transaction/tests/private_tx_hash.rs \
                      print_private_tx_hash_vectors: cargo test -p zolana-transaction --test \
                      private_tx_hash print_private_tx_hash_vectors -- --ignored --nocapture"
            .to_string(),
        vectors,
    }
}

fn committed() -> PrivateTxHashVectors {
    serde_json::from_str(PRIVATE_TX_HASH_VECTORS_JSON).unwrap()
}

fn committed_private_tx_hash(name: &str) -> String {
    committed()
        .vectors
        .into_iter()
        .find(|vector| vector.name == name)
        .map(|vector| vector.private_tx_hash)
        .unwrap()
}

#[test]
fn committed_private_tx_hash_vectors_match() {
    assert_eq!(committed(), compute_vectors());
}

#[test]
#[ignore = "regenerates test-vectors/private_tx_hash.json; run with --nocapture and commit the output"]
fn print_private_tx_hash_vectors() {
    println!(
        "{}",
        serde_json::to_string_pretty(&compute_vectors()).unwrap()
    );
}

#[test]
fn committed_padding_is_skipped_and_order_is_kept() {
    let compact = committed_private_tx_hash("compact");
    assert_eq!(committed_private_tx_hash("padded"), compact);
    assert_eq!(committed_private_tx_hash("padding_moved"), compact);
    assert_ne!(committed_private_tx_hash("address_nullifier"), compact);
    assert_ne!(
        committed_private_tx_hash("reordered_inputs"),
        committed_private_tx_hash("two_inputs")
    );
    assert_ne!(
        committed_private_tx_hash("single_slot_address"),
        committed_private_tx_hash("single_slot_spend")
    );
}

#[test]
fn committed_zero_address_nullifiers_equal_none() {
    for vector in committed().vectors.iter().filter(|vector| {
        vector
            .address_nullifiers
            .iter()
            .all(|value| decode(value) == [0; 32])
    }) {
        let inputs: Vec<[u8; 32]> = vector
            .input_hashes
            .iter()
            .map(|value| decode(value))
            .collect();
        let outputs: Vec<[u8; 32]> = vector
            .output_hashes
            .iter()
            .map(|value| decode(value))
            .collect();
        let hash = PrivateTxHash::new(&inputs, &outputs, &decode(&vector.blinding))
            .hash()
            .unwrap();
        assert_eq!(
            hex::encode(hash),
            vector.private_tx_hash,
            "vector {}",
            vector.name
        );
    }
}
