use num_bigint::BigUint;
use serde_json::{json, Value};
#[derive(Debug, Clone)]
pub struct BatchAddressAppendInputs {
    pub public_input_hash: BigUint,
    pub old_root: BigUint,
    pub new_root: BigUint,
    pub hashchain_hash: BigUint,
    pub start_index: u64,
    pub low_element_values: Vec<BigUint>,
    pub low_element_indices: Vec<BigUint>,
    pub low_element_next_values: Vec<BigUint>,
    pub new_element_values: Vec<BigUint>,
    pub low_element_proofs: Vec<Vec<BigUint>>,
    pub new_element_proofs: Vec<Vec<BigUint>>,
    pub tree_height: u32,
    pub batch_size: u32,
}

impl BatchAddressAppendInputs {
    pub fn to_json(&self) -> Value {
        let scalar = |value: &BigUint| format!("0x{}", value.to_str_radix(16));
        let scalars = |values: &[BigUint]| values.iter().map(scalar).collect::<Vec<_>>();
        let paths =
            |values: &[Vec<BigUint>]| values.iter().map(|path| scalars(path)).collect::<Vec<_>>();
        json!({
            "circuitType": "address-append", "stateTreeHeight": 0,
            "publicInputHash": scalar(&self.public_input_hash),
            "oldRoot": scalar(&self.old_root), "newRoot": scalar(&self.new_root),
            "hashchainHash": scalar(&self.hashchain_hash), "startIndex": self.start_index,
            "treeHeight": self.tree_height, "batchSize": self.batch_size,
            "lowElementValues": scalars(&self.low_element_values),
            "lowElementIndices": scalars(&self.low_element_indices),
            "lowElementNextValues": scalars(&self.low_element_next_values),
            "newElementValues": scalars(&self.new_element_values),
            "lowElementProofs": paths(&self.low_element_proofs),
            "newElementProofs": paths(&self.new_element_proofs)
        })
    }
}
