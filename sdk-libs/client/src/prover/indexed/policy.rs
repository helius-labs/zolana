use serde::Serialize;
use solana_address::Address;
use zeroize::{Zeroize, Zeroizing};
use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice, primitives::is_canonical_bn254_scalar_be,
};
use zolana_interface::{tree_slot::tree_slots_hash_chain, INPUT_TREES};

use super::{
    decode_resolution, hex_field, invalid, invalid_resolution, serialize_commitment, IndexedProof,
    ProofResolution, Request, ResolvedProofTree,
};
use crate::{
    prover::{ExpectedProvingKey, Proof},
    ClientError,
};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedPolicyLookup {
    pub tree_slot: u8,
    #[serde(serialize_with = "serialize_commitment")]
    pub commitment: Option<[u8; 32]>,
    #[serde(serialize_with = "serialize_commitment")]
    pub nullifier: Option<[u8; 32]>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedRegistry {
    pub ring_program_id: Address,
    #[serde(serialize_with = "serialize_hash")]
    pub root: [u8; 32],
    pub next_index: u64,
}

#[derive(Clone)]
pub struct IndexedPolicyData {
    pub registry: Option<IndexedRegistry>,
    pub trees: Vec<ResolvedProofTree>,
    pub inputs: Vec<IndexedPolicyLookup>,
    pub public_inputs: Vec<[u8; 32]>,
}

pub struct IndexedPolicyRequest {
    body: Zeroizing<String>,
    data: IndexedPolicyData,
    key: ExpectedProvingKey,
}

impl IndexedPolicyRequest {
    pub fn new(
        witness: Zeroizing<String>,
        key: ExpectedProvingKey,
        data: IndexedPolicyData,
    ) -> Result<Self, ClientError> {
        if witness.len() > 1 << 20
            || data.trees.is_empty()
            || data.trees.len() > INPUT_TREES
            || data.inputs.len() != 10
            || data
                .public_inputs
                .iter()
                .any(|value| !is_canonical_bn254_scalar_be(value))
        {
            return Err(invalid());
        }
        let mut prepared = SecretJson(serde_json::from_str(&witness).map_err(|_| invalid())?);
        let circuit = prepared
            .get("circuitType")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?
            .to_owned();
        let expected = match circuit.as_str() {
            "custom-ring-policy" | "custom-ring-delegate-policy" => 19,
            "custom-ring-compressed-policy" => 20,
            _ => return Err(invalid()),
        };
        if data.public_inputs.len() != expected {
            return Err(invalid());
        }
        let policy = if circuit == "custom-ring-policy" {
            &mut prepared.0
        } else {
            prepared.get_mut("policy").ok_or_else(invalid)?
        };
        let policy = policy.as_object_mut().ok_or_else(invalid)?;
        policy.remove("treeSlots");
        policy.remove("publicInputHash");
        let answers = policy
            .get_mut("answers")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or_else(invalid)?;
        if answers.len() != data.inputs.len() {
            return Err(invalid());
        }
        for (answer, lookup) in answers.iter_mut().zip(&data.inputs) {
            let answer = answer.as_object_mut().ok_or_else(invalid)?;
            if answer.get("enabled").and_then(serde_json::Value::as_bool)
                != Some(lookup.nullifier.is_some())
                || answer.get("treeSlot").and_then(serde_json::Value::as_u64)
                    != Some(u64::from(lookup.tree_slot))
                || usize::from(lookup.tree_slot) >= data.trees.len()
            {
                return Err(invalid());
            }
            for name in [
                "statePathElements",
                "statePathIndex",
                "nfPathElements",
                "nfPathIndex",
                "low",
                "next",
            ] {
                answer.remove(name);
            }
        }
        let outputs = policy
            .get_mut("outputs")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or_else(invalid)?;
        for output in outputs {
            output.as_object_mut().ok_or_else(invalid)?.remove("key");
        }
        for (i, tree) in data.trees.iter().enumerate() {
            if tree.tree != zolana_interface::pda::tree(tree.id)
                || data.trees[..i].iter().any(|known| known.id == tree.id)
            {
                return Err(invalid());
            }
        }
        let resolution = ProofResolution {
            trees: data.trees.clone(),
            public_input_hash: [0; 32],
        };
        resolution.tree_slots()?;
        let trees = data.trees.iter().map(|tree| serde_json::json!({"tree":tree.tree.to_string(),"id":tree.id,"fallback":{
            "tree":tree.tree.to_string(),"id":tree.id,"utxoRoot":hex_field(&tree.utxo_root),"nullifierRoot":hex_field(&tree.nullifier_root),"utxoRootIndex":tree.context.utxo_tree_root_index,"nullifierRootIndex":tree.context.nullifier_tree_root_index
        }})).collect::<Vec<_>>();
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Envelope<'a> {
            circuit_type: &'a str,
            prepared: &'a serde_json::Value,
            trees: &'a [serde_json::Value],
            inputs: &'a [IndexedPolicyLookup],
            public_inputs: Vec<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            registry: &'a Option<IndexedRegistry>,
        }
        let body = serde_json::to_string(&Envelope {
            circuit_type: &circuit,
            prepared: &prepared.0,
            trees: &trees,
            inputs: &data.inputs,
            public_inputs: data.public_inputs.iter().map(hex_field).collect(),
            registry: &data.registry,
        })
        .map_err(|_| invalid())?;
        Ok(Self {
            body: Zeroizing::new(body),
            data,
            key,
        })
    }
}

impl Request for IndexedPolicyRequest {
    type Output = IndexedProof;

    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        Ok(self.body.clone())
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        Ok(self.key.clone())
    }

    fn finish(
        &self,
        proof: Proof,
        resolution: serde_json::Value,
    ) -> Result<IndexedProof, ClientError> {
        let resolution = decode_resolution(resolution)?;
        self.check(&resolution)?;
        Ok(IndexedProof { proof, resolution })
    }
}

impl IndexedPolicyRequest {
    fn check(&self, resolution: &ProofResolution) -> Result<(), ClientError> {
        resolution.check_trees(self.data.trees.iter().map(|tree| (tree.tree, tree.id)))?;
        for (slot, (tree, expected)) in resolution.trees.iter().zip(&self.data.trees).enumerate() {
            let has_state =
                self.data.inputs.iter().any(|lookup| {
                    usize::from(lookup.tree_slot) == slot && lookup.commitment.is_some()
                });
            let has_nullifier =
                self.data.inputs.iter().any(|lookup| {
                    usize::from(lookup.tree_slot) == slot && lookup.nullifier.is_some()
                });
            if (!has_state
                && (tree.utxo_root != expected.utxo_root
                    || tree.context.utxo_tree_root_index != expected.context.utxo_tree_root_index))
                || (!has_nullifier
                    && (tree.nullifier_root != expected.nullifier_root
                        || tree.context.nullifier_tree_root_index
                            != expected.context.nullifier_tree_root_index))
            {
                return Err(invalid_resolution());
            }
        }
        let mut transcript = self.data.public_inputs.clone();
        transcript.insert(1, tree_slots_hash_chain(&resolution.tree_slots()?)?);
        if create_hash_chain_from_slice(&transcript)? != resolution.public_input_hash {
            return Err(invalid_resolution());
        }
        Ok(())
    }
}

pub(super) struct SecretJson(pub(super) serde_json::Value);
impl std::ops::Deref for SecretJson {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for SecretJson {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for SecretJson {
    fn drop(&mut self) {
        fn wipe(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::String(value) => value.zeroize(),
                serde_json::Value::Array(values) => values.iter_mut().for_each(wipe),
                serde_json::Value::Object(values) => values.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

fn serialize_hash<S: serde::Serializer>(
    value: &[u8; 32],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    Address::from(*value).to_string().serialize(serializer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_interface::instruction::instruction_data::transact::TreeContext;

    fn request(circuit: &str) -> IndexedPolicyRequest {
        let field = |n| {
            let mut value = [0; 32];
            value[31] = n;
            value
        };
        let mut policy = serde_json::json!({"circuitType":"custom-ring-policy","txViewingSk":"secret","treeSlots":[],"publicInputHash":"0x1","outputs":[],"answers":(0..10).map(|_|serde_json::json!({"enabled":false,"treeSlot":0,"low":"0x0","next":"0x0","statePathElements":[],"statePathIndex":0,"nfPathElements":[],"nfPathIndex":0})).collect::<Vec<_>>()});
        if circuit != "custom-ring-policy" {
            policy = serde_json::json!({"circuitType":circuit,"policy":policy,"transactionSalt":"0x00000000000000000000000000000000"});
        }
        IndexedPolicyRequest::new(
            Zeroizing::new(policy.to_string()),
            ExpectedProvingKey {
                name: "policy.key".into(),
                sha256: [0; 32],
            },
            IndexedPolicyData {
                registry: None,
                trees: vec![ResolvedProofTree {
                    tree: zolana_interface::pda::tree(3),
                    id: 3,
                    utxo_root: field(1),
                    nullifier_root: field(2),
                    context: TreeContext {
                        utxo_tree_root_index: 4,
                        nullifier_tree_root_index: 5,
                    },
                }],
                inputs: vec![
                    IndexedPolicyLookup {
                        tree_slot: 0,
                        commitment: None,
                        nullifier: None
                    };
                    10
                ],
                public_inputs: vec![
                    field(3);
                    if circuit == "custom-ring-compressed-policy" {
                        20
                    } else {
                        19
                    }
                ],
            },
        )
        .unwrap()
    }

    #[test]
    fn policy_resolution_rejects_changed_anchors_and_transcripts() {
        for circuit in [
            "custom-ring-policy",
            "custom-ring-compressed-policy",
            "custom-ring-delegate-policy",
        ] {
            let request = request(circuit);
            let mut resolution = ProofResolution {
                trees: request.data.trees.clone(),
                public_input_hash: [0; 32],
            };
            let mut transcript = request.data.public_inputs.clone();
            transcript.insert(
                1,
                tree_slots_hash_chain(&resolution.tree_slots().unwrap()).unwrap(),
            );
            resolution.public_input_hash = create_hash_chain_from_slice(&transcript).unwrap();
            for mutation in 0..7 {
                let mut changed = resolution.clone();
                match mutation {
                    1 => changed.trees[0].utxo_root[31] += 1,
                    2 => changed.trees[0].context.utxo_tree_root_index += 1,
                    3 => changed.trees[0].nullifier_root[31] += 1,
                    4 => changed.trees[0].tree = zolana_interface::pda::tree(4),
                    5 => changed.public_input_hash[31] ^= 1,
                    6 => changed.trees[0].context.nullifier_tree_root_index += 1,
                    _ => {}
                }
                assert_eq!(request.check(&changed).is_ok(), mutation == 0);
            }
            let body: serde_json::Value = serde_json::from_str(&request.body().unwrap()).unwrap();
            let prepared = if circuit == "custom-ring-policy" {
                &body["prepared"]
            } else {
                &body["prepared"]["policy"]
            };
            assert!(prepared.get("treeSlots").is_none());
            assert!(prepared["answers"][0].get("nfPathElements").is_none());
            assert_eq!(prepared["txViewingSk"], "secret");
        }
    }
}
