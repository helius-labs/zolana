use serde::{Deserialize, Serialize};
use zolana_hasher::{hash_chain::create_nonzero_hash_chain_from_slice, Hasher, Poseidon};

const NONZERO_HASH_CHAIN_VECTORS_JSON: &str =
    include_str!("../../../test-vectors/nonzero_hash_chain.json");

const FIELD_MODULUS_MINUS_ONE: &str =
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct NonZeroHashChainVectors {
    description: String,
    vectors: Vec<NonZeroHashChainVector>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct NonZeroHashChainVector {
    name: String,
    inputs: Vec<String>,
    output: String,
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

fn vector(name: &str, inputs: &[[u8; 32]]) -> NonZeroHashChainVector {
    NonZeroHashChainVector {
        name: name.to_string(),
        inputs: inputs.iter().map(hex::encode).collect(),
        output: hex::encode(create_nonzero_hash_chain_from_slice(inputs).unwrap()),
    }
}

fn compute_vectors() -> NonZeroHashChainVectors {
    let mut vectors = vec![
        vector("empty", &[]),
        vector("single_zero", &fields(&[0])),
        vector("all_zero_4", &fields(&[0, 0, 0, 0])),
        vector("single", &fields(&[1])),
    ];
    vectors.extend([2u32, 3, 4, 5, 8, 36].iter().map(|&len| {
        let inputs: Vec<[u8; 32]> = (1..=len).map(field).collect();
        vector(&format!("len_{len}"), &inputs)
    }));
    vectors.extend([
        vector("leading_zero", &fields(&[0, 1])),
        vector("trailing_zero", &fields(&[1, 0])),
        vector("zeros_between", &fields(&[1, 0, 0, 2])),
        vector("padded_len_3", &fields(&[0, 1, 0, 2, 0, 0, 3, 0])),
        vector("reversed_len_3", &fields(&[3, 2, 1])),
        vector(
            "field_modulus_minus_one",
            &[decode(FIELD_MODULUS_MINUS_ONE), field(0), field(1)],
        ),
    ]);
    NonZeroHashChainVectors {
        description: "Known-answer vectors for the nonzero hash chain that folds the input, \
                      output and address chains of private_tx_hash, over 32-byte big-endian \
                      BN254 field elements: zero elements are skipped, the first nonzero e is \
                      taken as is, and every later nonzero e folds as h = Poseidon(h, e) using \
                      the 2-input permutation; a chain without a nonzero e is 0. Padding \
                      position does not change the result while the order of nonzero elements \
                      does. The len_<L> entries fold e[i] = i + 1; padded_len_3 equals \
                      len_3 and reversed_len_3 differs from it. Produced by \
                      program-libs/hasher/tests/nonzero_hash_chain.rs print_nonzero_hash_chain_vectors: \
                      cargo test -p zolana-hasher --test nonzero_hash_chain \
                      print_nonzero_hash_chain_vectors -- --ignored --nocapture"
            .to_string(),
        vectors,
    }
}

fn committed() -> NonZeroHashChainVectors {
    serde_json::from_str(NONZERO_HASH_CHAIN_VECTORS_JSON).unwrap()
}

fn committed_output(name: &str) -> String {
    committed()
        .vectors
        .into_iter()
        .find(|vector| vector.name == name)
        .map(|vector| vector.output)
        .unwrap()
}

#[test]
fn committed_nonzero_hash_chain_vectors_match() {
    assert_eq!(committed(), compute_vectors());
}

#[test]
#[ignore = "regenerates test-vectors/nonzero_hash_chain.json; run with --nocapture and commit the output"]
fn print_nonzero_hash_chain_vectors() {
    println!(
        "{}",
        serde_json::to_string_pretty(&compute_vectors()).unwrap()
    );
}

#[test]
fn committed_zero_chains_are_zero() {
    let zero = hex::encode([0u8; 32]);
    for name in ["empty", "single_zero", "all_zero_4"] {
        assert_eq!(committed_output(name), zero, "vector {name}");
    }
}

#[test]
fn committed_padding_is_skipped_and_order_is_kept() {
    assert_eq!(committed_output("padded_len_3"), committed_output("len_3"));
    assert_eq!(committed_output("leading_zero"), committed_output("single"));
    assert_eq!(
        committed_output("trailing_zero"),
        committed_output("single")
    );
    assert_ne!(
        committed_output("reversed_len_3"),
        committed_output("len_3")
    );
}

#[test]
fn committed_single_element_is_the_element() {
    assert_eq!(committed_output("single"), hex::encode(field(1)));
}

#[test]
fn committed_second_element_is_one_poseidon_call() {
    let expected = Poseidon::hashv(&[&field(1), &field(2)]).unwrap();
    assert_eq!(committed_output("len_2"), hex::encode(expected));
}
