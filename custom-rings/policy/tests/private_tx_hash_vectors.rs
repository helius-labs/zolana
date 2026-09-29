use serde::Deserialize;
use zolana_ring_policy::mutation_private_tx_hash;

const PRIVATE_TX_HASH_VECTORS_JSON: &str =
    include_str!("../../../test-vectors/private_tx_hash.json");

#[derive(Deserialize)]
struct PrivateTxHashVectors {
    vectors: Vec<PrivateTxHashVector>,
}

#[derive(Deserialize)]
struct PrivateTxHashVector {
    name: String,
    input_hashes: Vec<String>,
    output_hashes: Vec<String>,
    address_nullifiers: Vec<String>,
    blinding: String,
    private_tx_hash: String,
}

fn decode(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn single(values: &[String]) -> Option<[u8; 32]> {
    match values {
        [value] => Some(decode(value)),
        _ => None,
    }
}

#[test]
fn mutation_private_tx_hash_matches_every_single_slot_vector() {
    let vectors: PrivateTxHashVectors = serde_json::from_str(PRIVATE_TX_HASH_VECTORS_JSON).unwrap();
    let mut checked = Vec::new();
    for vector in &vectors.vectors {
        let (Some(input), Some(output), Some(address)) = (
            single(&vector.input_hashes),
            single(&vector.output_hashes),
            single(&vector.address_nullifiers),
        ) else {
            continue;
        };
        let hash =
            mutation_private_tx_hash(input, output, address, &decode(&vector.blinding)).unwrap();
        assert_eq!(
            hex::encode(hash),
            vector.private_tx_hash,
            "vector {}",
            vector.name
        );
        checked.push(vector.name.as_str());
    }
    assert_eq!(
        checked,
        [
            "single_slot_spend",
            "single_slot_address",
            "field_modulus_minus_one"
        ]
    );
}
