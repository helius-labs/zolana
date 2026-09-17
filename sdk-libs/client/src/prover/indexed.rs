mod merge;
pub use merge::{IndexedMergePreparation, PreparedIndexedMerge};

mod transfer;
pub use transfer::{PreparedIndexedTransfer, ProvenIndexedTransfer};

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use solana_address::Address;
use zeroize::Zeroizing;
use zolana_hasher::{
    hash_chain::create_hash_chain_4_from_slice, primitives::is_canonical_bn254_scalar_be,
};
use zolana_interface::{
    instruction::instruction_data::{
        merge_transact::MERGE_SUPPORTED_INPUT_COUNTS, transact::TreeContext,
    },
    state::{NULLIFIER_TREE_ROOT_HISTORY_CAPACITY, STATE_ROOT_HISTORY_CAPACITY},
    tree_slot::{tree_slots_hash_chain, TreeSlot},
    INPUT_TREES, MAX_INPUT_TREES,
};

use super::{field::right_align_slice, Proof, SPP_SUPPORTED_SHAPES};
use crate::ClientError;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IndexedCircuit {
    TransferConfidential,
    TransferRing,
    TransferRingAuthority,
    TransferP256Ring,
    Merge,
    MergeRing,
}

#[derive(Clone, Debug, Serialize)]
pub struct IndexedTree {
    #[serde(serialize_with = "serialize_address")]
    pub tree: Address,
    pub id: u16,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedLookup {
    pub tree_slot: u8,
    #[serde(serialize_with = "serialize_commitment")]
    pub commitment: Option<[u8; 32]>,
}

pub struct IndexedProofData {
    pub witness: Zeroizing<String>,
    pub trees: Vec<IndexedTree>,
    pub inputs: Vec<IndexedLookup>,
    pub public_inputs: Vec<[u8; 32]>,
}

pub struct IndexedProofRequest {
    data: IndexedProofData,
    circuit: IndexedCircuit,
    min_context_slot: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct ResolvedProofTree {
    pub tree: Address,
    pub id: u16,
    pub utxo_root: [u8; 32],
    pub nullifier_root: [u8; 32],
    pub context: TreeContext,
}

#[derive(Clone, Debug)]
pub struct ProofResolution {
    pub trees: Vec<ResolvedProofTree>,
    pub public_input_hash: [u8; 32],
}

pub struct IndexedProof {
    pub proof: Proof,
    pub resolution: ProofResolution,
}

impl IndexedProofRequest {
    pub fn new(data: IndexedProofData) -> Result<Self, ClientError> {
        if data.witness.len() > 1 << 20 {
            return Err(invalid());
        }
        let metadata: PreparedMetadata =
            serde_json::from_str(&data.witness).map_err(|_| invalid())?;
        if metadata.tree_slots.is_some()
            || metadata.public_input_hash.is_some()
            || data.trees.is_empty()
            || data.trees.len() > MAX_INPUT_TREES
            || data.inputs.len() != metadata.inputs.len()
            || data.public_inputs.len() != metadata.circuit_type.public_input_count()
        {
            return Err(invalid());
        }
        match metadata.circuit_type {
            IndexedCircuit::Merge | IndexedCircuit::MergeRing => {
                if !MERGE_SUPPORTED_INPUT_COUNTS.contains(&metadata.inputs.len()) {
                    return Err(invalid());
                }
            }
            _ => {
                if metadata.n_inputs != Some(metadata.inputs.len())
                    || metadata.n_outputs != Some(metadata.outputs.len())
                {
                    return Err(invalid());
                }
                if !SPP_SUPPORTED_SHAPES.iter().any(|shape| {
                    shape.n_inputs() == metadata.inputs.len()
                        && shape.n_outputs() == metadata.outputs.len()
                }) || (metadata.circuit_type == IndexedCircuit::TransferRingAuthority
                    && metadata.inputs.len() != metadata.outputs.len())
                {
                    return Err(invalid());
                }
            }
        }
        if data
            .public_inputs
            .iter()
            .any(|field| !is_canonical_bn254_scalar_be(field))
        {
            return Err(invalid());
        }
        for (index, tree) in data.trees.iter().enumerate() {
            if tree.tree.to_bytes() != zolana_interface::pda::tree(tree.id).to_bytes()
                || data.trees[..index]
                    .iter()
                    .any(|previous| previous.id == tree.id)
            {
                return Err(invalid());
            }
        }
        let mut next_tree = 0usize;
        let mut previous = None;
        for (lookup, input) in data.inputs.iter().zip(metadata.inputs.iter()) {
            let slot = usize::from(lookup.tree_slot);
            if slot >= data.trees.len()
                || input.paths_supplied()
                || decode_field(&input.tree_slot)? != right_align_slice(&[lookup.tree_slot])?
            {
                return Err(invalid());
            }
            let (flag, real) = match metadata.circuit_type {
                IndexedCircuit::Merge | IndexedCircuit::MergeRing => (
                    input.domain.as_deref().ok_or_else(invalid)?,
                    right_align_slice(&zolana_interface::UTXO_DOMAIN.to_be_bytes())?,
                ),
                _ => (input.is_dummy.as_deref().ok_or_else(invalid)?, [0; 32]),
            };
            let flag = decode_field(flag).map_err(|_| invalid())?;
            let dummy = flag == scalar_one();
            if !dummy && flag != real {
                return Err(invalid());
            }
            if dummy != lookup.commitment.is_none()
                || lookup
                    .commitment
                    .as_ref()
                    .is_some_and(|field| !is_canonical_bn254_scalar_be(field))
            {
                return Err(invalid());
            }
            if previous != Some(slot) {
                if slot != next_tree || dummy {
                    return Err(invalid());
                }
                next_tree += 1;
            }
            previous = Some(slot);
        }
        if next_tree != data.trees.len() {
            return Err(invalid());
        }
        Ok(Self {
            data,
            circuit: metadata.circuit_type,
            min_context_slot: None,
        })
    }

    pub fn input_trees(&self) -> &[IndexedTree] {
        &self.data.trees
    }

    #[must_use]
    pub fn with_min_context_slot(mut self, slot: u64) -> Self {
        self.min_context_slot = Some(slot);
        self
    }

    pub(crate) fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Envelope<'a> {
            circuit_type: IndexedCircuit,
            trees: &'a [IndexedTree],
            inputs: &'a [IndexedLookup],
            public_inputs: Vec<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            min_context_slot: Option<u64>,
        }
        let envelope = Envelope {
            circuit_type: self.circuit,
            trees: &self.data.trees,
            inputs: &self.data.inputs,
            public_inputs: self.data.public_inputs.iter().map(hex_field).collect(),
            min_context_slot: self.min_context_slot,
        };
        let mut body = Zeroizing::new(serde_json::to_string(&envelope).map_err(|_| invalid())?);
        body.pop();
        body.push_str(",\"prepared\":");
        body.push_str(&self.data.witness);
        body.push('}');
        Ok(body)
    }

    pub(crate) fn validate(&self, proof: IndexedProof) -> Result<IndexedProof, ClientError> {
        let resolution = &proof.resolution;
        if resolution.trees.len() != self.data.trees.len() {
            return Err(invalid_resolution());
        }
        for (expected, resolved) in self.data.trees.iter().zip(&resolution.trees) {
            if expected.tree != resolved.tree || expected.id != resolved.id {
                return Err(invalid_resolution());
            }
        }
        // 1. Resolved roots must reproduce the caller's original public statement.
        if resolution.public_input_hash != resolution.hash(&self.data.public_inputs)? {
            return Err(invalid_resolution());
        }
        Ok(proof)
    }
}

impl ProofResolution {
    pub fn tree_slots(&self) -> Result<[TreeSlot; INPUT_TREES], ClientError> {
        if self.trees.is_empty() || self.trees.len() > MAX_INPUT_TREES {
            return Err(invalid_resolution());
        }
        let mut slots = [TreeSlot::ZERO; INPUT_TREES];
        for (slot, tree) in slots.iter_mut().zip(&self.trees) {
            if usize::from(tree.context.utxo_tree_root_index) >= STATE_ROOT_HISTORY_CAPACITY
                || u32::from(tree.context.nullifier_tree_root_index)
                    >= NULLIFIER_TREE_ROOT_HISTORY_CAPACITY
                || !is_canonical_bn254_scalar_be(&tree.utxo_root)
                || !is_canonical_bn254_scalar_be(&tree.nullifier_root)
            {
                return Err(invalid_resolution());
            }
            *slot = TreeSlot::new(tree.id, tree.utxo_root, tree.nullifier_root);
        }
        Ok(slots)
    }

    pub fn hash(&self, public_inputs: &[[u8; 32]]) -> Result<[u8; 32], ClientError> {
        if public_inputs.len() < 2
            || public_inputs
                .iter()
                .any(|field| !is_canonical_bn254_scalar_be(field))
        {
            return Err(invalid_resolution());
        }
        let mut transcript = public_inputs.to_vec();
        transcript.insert(2, tree_slots_hash_chain(&self.tree_slots()?)?);
        Ok(create_hash_chain_4_from_slice(&transcript)?)
    }
}

impl IndexedCircuit {
    fn public_input_count(self) -> usize {
        match self {
            Self::TransferConfidential | Self::TransferRing => 15,
            Self::TransferRingAuthority => 14,
            Self::TransferP256Ring => 17,
            Self::Merge => 7,
            Self::MergeRing => 8,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreparedMetadata {
    circuit_type: IndexedCircuit,
    inputs: Vec<PreparedInputMetadata>,
    n_inputs: Option<usize>,
    n_outputs: Option<usize>,
    #[serde(default)]
    outputs: Vec<serde::de::IgnoredAny>,
    tree_slots: Option<serde::de::IgnoredAny>,
    public_input_hash: Option<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreparedInputMetadata {
    tree_slot: String,
    domain: Option<String>,
    is_dummy: Option<String>,
    state_path_elements: Option<serde::de::IgnoredAny>,
    state_path_index: Option<serde::de::IgnoredAny>,
    nullifier_low_value: Option<serde::de::IgnoredAny>,
    nullifier_next_value: Option<serde::de::IgnoredAny>,
    nullifier_low_path_elements: Option<serde::de::IgnoredAny>,
    nullifier_low_path_index: Option<serde::de::IgnoredAny>,
}

impl PreparedInputMetadata {
    fn paths_supplied(&self) -> bool {
        self.state_path_elements.is_some()
            || self.state_path_index.is_some()
            || self.nullifier_low_value.is_some()
            || self.nullifier_next_value.is_some()
            || self.nullifier_low_path_elements.is_some()
            || self.nullifier_low_path_index.is_some()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolutionJson {
    trees: Vec<ResolvedTreeJson>,
    public_input_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolvedTreeJson {
    tree: String,
    id: u16,
    utxo_root: String,
    nullifier_root: String,
    utxo_root_index: u16,
    nullifier_root_index: u16,
}

pub(crate) fn decode_resolution(value: &serde_json::Value) -> Result<ProofResolution, ClientError> {
    let raw: ResolutionJson =
        serde_json::from_value(value.clone()).map_err(|_| invalid_resolution())?;
    let trees = raw
        .trees
        .into_iter()
        .map(|tree| {
            Ok(ResolvedProofTree {
                tree: tree.tree.parse().map_err(|_| invalid_resolution())?,
                id: tree.id,
                utxo_root: decode_field(&tree.utxo_root)?,
                nullifier_root: decode_field(&tree.nullifier_root)?,
                context: TreeContext {
                    utxo_tree_root_index: tree.utxo_root_index,
                    nullifier_tree_root_index: tree.nullifier_root_index,
                },
            })
        })
        .collect::<Result<Vec<_>, ClientError>>()?;
    let resolution = ProofResolution {
        trees,
        public_input_hash: decode_field(&raw.public_input_hash)?,
    };
    resolution.tree_slots()?;
    Ok(resolution)
}

fn serialize_address<S: serde::Serializer>(
    value: &Address,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}
fn serialize_commitment<S: serde::Serializer>(
    value: &Option<[u8; 32]>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value
        .map(|bytes| Address::from(bytes).to_string())
        .serialize(serializer)
}

pub(crate) fn hex_field(field: &[u8; 32]) -> String {
    format!("0x{}", BigUint::from_bytes_be(field).to_str_radix(16))
}

fn scalar_one() -> [u8; 32] {
    let mut field = [0; 32];
    field[31] = 1;
    field
}

fn decode_field(value: &str) -> Result<[u8; 32], ClientError> {
    let digits = value.strip_prefix("0x").ok_or_else(invalid_resolution)?;
    if digits.is_empty()
        || digits.len() > 64
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_resolution());
    }
    let field = BigUint::parse_bytes(digits.as_bytes(), 16).ok_or_else(invalid_resolution)?;
    let field = right_align_slice(&field.to_bytes_be())?;
    if !is_canonical_bn254_scalar_be(&field) {
        return Err(invalid_resolution());
    }
    Ok(field)
}

fn invalid() -> ClientError {
    ClientError::ProverServer("invalid indexed proof request".to_owned())
}
fn invalid_resolution() -> ClientError {
    ClientError::ProofParse("invalid proof resolution".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shared_transcript_vector() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/indexed-proof.json")).unwrap();
        let fields = fixture["publicInputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| decode_field(value.as_str().unwrap()).unwrap())
            .collect::<Vec<_>>();
        let trees = fixture["trees"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tree| {
                let id = u16::try_from(tree["id"].as_u64().unwrap()).unwrap();
                ResolvedProofTree {
                    tree: zolana_interface::pda::tree(id).to_bytes().into(),
                    id,
                    utxo_root: decode_field(tree["utxoRoot"].as_str().unwrap()).unwrap(),
                    nullifier_root: decode_field(tree["nullifierRoot"].as_str().unwrap()).unwrap(),
                    context: TreeContext {
                        utxo_tree_root_index: 0,
                        nullifier_tree_root_index: 0,
                    },
                }
            })
            .collect();
        let expected = decode_field(fixture["publicInputHash"].as_str().unwrap()).unwrap();
        let resolution = ProofResolution {
            trees,
            public_input_hash: expected,
        };
        assert_eq!(resolution.hash(&fields).unwrap(), expected);
    }

    fn request_data() -> IndexedProofData {
        IndexedProofData {
            witness: Zeroizing::new(
                json!({"circuitType":"transfer-confidential", "nInputs":1, "nOutputs":1,
                "inputs":[{"treeSlot":"0x0", "isDummy":"0x0"}], "outputs":[{}]})
                .to_string(),
            ),
            trees: vec![IndexedTree {
                tree: zolana_interface::pda::tree(3).to_bytes().into(),
                id: 3,
            }],
            inputs: vec![IndexedLookup {
                tree_slot: 0,
                commitment: Some(scalar_one()),
            }],
            public_inputs: vec![scalar_one(); 15],
        }
    }

    #[test]
    fn rejects_malformed_request_boundaries() {
        let mut data = request_data();
        data.trees[0].tree = Address::default();
        assert!(IndexedProofRequest::new(data).is_err());
        let mut data = request_data();
        data.public_inputs[0] = [255; 32];
        assert!(IndexedProofRequest::new(data).is_err());
        let mut data = request_data();
        *data.witness = data.witness.replace("0x0\"}", "0x2\"}");
        assert!(IndexedProofRequest::new(data).is_err());
        let mut data = request_data();
        data.inputs[0].commitment = None;
        assert!(IndexedProofRequest::new(data).is_err());
        let request = IndexedProofRequest::new(request_data())
            .unwrap()
            .with_min_context_slot(42);
        let body: serde_json::Value = serde_json::from_str(&request.body().unwrap()).unwrap();
        assert_eq!(body["minContextSlot"], 42);
        assert!(body["prepared"].get("treeSlots").is_none());
    }

    #[test]
    fn requires_exact_supported_shape() {
        let mut data = request_data();
        let mut wire: serde_json::Value = serde_json::from_str(&data.witness).unwrap();
        wire["nOutputs"] = json!(3);
        wire["outputs"] = json!([{}, {}, {}]);
        *data.witness = wire.to_string();
        assert!(IndexedProofRequest::new(data).is_err());
        let mut data = request_data();
        wire["nInputs"] = json!(36);
        wire["nOutputs"] = json!(2);
        wire["inputs"] = json!(vec![json!({"treeSlot":"0x0", "isDummy":"0x0"}); 36]);
        wire["outputs"] = json!([{}, {}]);
        *data.witness = wire.to_string();
        data.inputs = vec![data.inputs[0].clone(); 36];
        assert!(IndexedProofRequest::new(data).is_ok());
    }

    #[test]
    fn rejects_out_of_range_resolution() {
        let mut wire = json!({"trees":[{"tree":zolana_interface::pda::tree(3).to_string(),"id":3,
            "utxoRoot":"0x1","nullifierRoot":"0x2","utxoRootIndex":0,"nullifierRootIndex":0}],
            "publicInputHash":"0x1"});
        assert!(decode_resolution(&wire).is_ok());
        wire["trees"][0]["nullifierRootIndex"] = json!(NULLIFIER_TREE_ROOT_HISTORY_CAPACITY);
        assert!(decode_resolution(&wire).is_err());
        wire["trees"][0]["nullifierRootIndex"] = json!(0);
        wire["trees"][0]["utxoRootIndex"] = json!(STATE_ROOT_HISTORY_CAPACITY);
        assert!(decode_resolution(&wire).is_err());
        assert!(decode_field("0X01").is_err());
        assert!(decode_field(&format!("0x{}", "f".repeat(64))).is_err());
    }
}
