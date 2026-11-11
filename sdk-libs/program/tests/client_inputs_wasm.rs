//! The wasm decoding of a generated client: a `Field` input arrives from
//! JavaScript as a decimal string and must be the canonical one.

use spr_program::{input, ClientInputs, Field};

#[input]
#[derive(ClientInputs)]
pub struct Commitment {
    pub value: Field,
    pub amount: u64,
}

fn decode(value: &str) -> Result<CommitmentClient, serde_json::Error> {
    serde_json::from_value(serde_json::json!({ "value": value, "amount": 3 }))
}

#[test]
fn a_canonical_decimal_decodes_to_its_field() {
    let client = decode("42").unwrap();
    assert_eq!((client.value, client.amount), (Field::from(42u64), 3));
}

#[test]
fn a_non_canonical_decimal_is_refused() {
    // The BN254 scalar modulus, the first value at or above it.
    let modulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
    for value in ["01", "+1", " 1", "0x01", "", modulus] {
        let Err(error) = decode(value) else {
            panic!("{value:?} must be refused");
        };
        assert!(
            error.to_string().contains("noncanonical field encoding"),
            "{value:?}: {error}"
        );
    }
}
