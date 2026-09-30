use ark_bn254::Fr;
use num_bigint::BigUint;
use zolana_program::circuit::Field;

pub struct Vector {
    pub name: String,
    pub input: String,
    pub output: String,
}
pub fn vectors() -> Vec<Vector> {
    let rows: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../../../../test-vectors/hash_bytes.json"
    ))
    .expect("hash bytes vectors");
    rows.into_iter()
        .map(|row| {
            let string = |key| {
                row.get(key)
                    .and_then(serde_json::Value::as_str)
                    .expect("vector string")
                    .to_owned()
            };
            Vector {
                name: string("name"),
                input: string("input"),
                output: string("output"),
            }
        })
        .collect()
}
pub fn native_hash<const N: usize>(bytes: &[u8; N]) -> Field {
    Field::from(Fr::from(BigUint::from_bytes_be(
        &zolana_hasher::primitives::hash_bytes(bytes).expect("native hash"),
    )))
}
impl Vector {
    pub fn bytes(&self) -> Vec<u8> {
        hex::decode(&self.input).expect("input hex")
    }
    pub fn hash(&self) -> Field {
        Field::from(Fr::from(BigUint::from_bytes_be(
            &hex::decode(&self.output).expect("output hex"),
        )))
    }
}
