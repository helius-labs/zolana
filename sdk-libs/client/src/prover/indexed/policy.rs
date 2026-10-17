use serde::Serialize;
use solana_address::Address;
use zeroize::{Zeroize, Zeroizing};
use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice, primitives::is_canonical_bn254_scalar_be,
};
use zolana_interface::{tree_slot::tree_slots_hash_chain, INPUT_TREES};

use super::{
    decode_resolution, hex_field, invalid, invalid_resolution, serialize_address, IndexedProof,
    ProofResolution, Request, ResolvedProofTree,
};
use crate::{
    prover::{ExpectedProvingKey, Proof},
    ClientError,
};

/// A member registry the indexed prover opens records in, at the root the statement binds.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedRegistry {
    #[serde(serialize_with = "serialize_address")]
    pub ring_program_id: Address,
    #[serde(serialize_with = "serialize_hash")]
    pub root: [u8; 32],
    pub next_index: u64,
}

/// Leaves of a height 20 registry.
pub const MAX_REGISTRY_NEXT_INDEX: u64 = 1 << 20;

impl IndexedRegistry {
    fn check(&self) -> Result<(), ClientError> {
        if self.next_index == 0
            || self.next_index > MAX_REGISTRY_NEXT_INDEX
            || !is_canonical_bn254_scalar_be(&self.root)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// The policy statement chain less the folded audit prefix and the tree commitment.
pub const POLICY_PUBLIC_INPUTS: usize = 8;

#[derive(Clone)]
pub struct IndexedPolicyData {
    pub registry: IndexedRegistry,
    /// The curator registry the policy sources name, `None` without one.
    pub foreign_registry: Option<IndexedRegistry>,
    pub trees: Vec<ResolvedProofTree>,
    pub public_inputs: Vec<[u8; 32]>,
}

pub struct IndexedPolicyRequest {
    body: Zeroizing<String>,
    data: IndexedPolicyData,
    key: ExpectedProvingKey,
}

/// Witness fields the indexed prover fills from its own registry projection.
const REGISTRY_OPENINGS: [&str; 2] = ["subjects", "foreignSubjects"];

/// Only the general shaped family is resolvable without knowing registry indices.
fn policy_circuit_delegate(circuit: &str) -> Option<bool> {
    match circuit {
        "custom-ring-policy" => return Some(false),
        "custom-ring-delegate-policy" => return Some(true),
        _ => {}
    }
    let (tail, delegate) = if let Some(tail) = circuit.strip_prefix("custom-ring-delegate-policy-")
    {
        (tail, true)
    } else {
        (circuit.strip_prefix("custom-ring-policy-")?, false)
    };
    let mut parts = tail.split('-');
    let n: usize = parts.next()?.parse().ok()?;
    let m: usize = parts.next()?.parse().ok()?;
    let anonymous = match parts.next() {
        None => false,
        Some("anonymous") => true,
        _ => return None,
    };
    if parts.next().is_some() {
        return None;
    }
    let canonical = format!("{n}-{m}{}", if anonymous { "-anonymous" } else { "" });
    if canonical != tail || (anonymous && delegate) {
        return None;
    }
    let valid = if delegate {
        matches!((n, m), (2, 2) | (4, 4))
    } else if anonymous {
        matches!((n, m), (2, 2) | (2, 4) | (3, 4) | (4, 2))
    } else {
        matches!(n, 1 | 2 | 3 | 4 | 5 | 6 | 8 | 12 | 16) && matches!(m, 2 | 4)
    };
    valid.then_some(delegate)
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
            || data.public_inputs.len() != POLICY_PUBLIC_INPUTS
            || data
                .public_inputs
                .iter()
                .any(|value| !is_canonical_bn254_scalar_be(value))
        {
            return Err(invalid());
        }
        data.registry.check()?;
        if let Some(foreign) = &data.foreign_registry {
            foreign.check()?;
        }
        let mut prepared = SecretJson(serde_json::from_str(&witness).map_err(|_| invalid())?);
        let circuit = prepared
            .get("circuitType")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?
            .to_owned();
        let delegate = policy_circuit_delegate(&circuit).ok_or_else(invalid)?;
        let policy = if !delegate {
            &mut prepared.0
        } else {
            prepared.get_mut("policy").ok_or_else(invalid)?
        };
        let policy = policy.as_object_mut().ok_or_else(invalid)?;
        policy.remove("treeSlots");
        policy.remove("publicInputHash");
        for name in REGISTRY_OPENINGS {
            policy.remove(name);
        }
        let outputs = policy
            .get_mut("outputs")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or_else(invalid)?;
        for output in outputs {
            output.as_object_mut().ok_or_else(invalid)?.remove("ctHash");
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
            public_inputs: Vec<String>,
            registry: &'a IndexedRegistry,
            #[serde(skip_serializing_if = "Option::is_none")]
            foreign_registry: &'a Option<IndexedRegistry>,
        }
        let body = serde_json::to_string(&Envelope {
            circuit_type: &circuit,
            prepared: &prepared.0,
            trees: &trees,
            public_inputs: data.public_inputs.iter().map(hex_field).collect(),
            registry: &data.registry,
            foreign_registry: &data.foreign_registry,
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
    /// The prover reads no tree for the policy, every anchor must come back as sent.
    fn check(&self, resolution: &ProofResolution) -> Result<(), ClientError> {
        resolution.check_trees(self.data.trees.iter().map(|tree| (tree.tree, tree.id)))?;
        for (tree, expected) in resolution.trees.iter().zip(&self.data.trees) {
            if tree.utxo_root != expected.utxo_root
                || tree.nullifier_root != expected.nullifier_root
                || tree.context != expected.context
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

    fn field(n: u8) -> [u8; 32] {
        let mut value = [0; 32];
        value[31] = n;
        value
    }

    fn registry(byte: u8) -> IndexedRegistry {
        IndexedRegistry {
            ring_program_id: Address::from([byte; 32]),
            root: field(byte),
            next_index: 2,
        }
    }

    fn request(circuit: &str, foreign: bool) -> IndexedPolicyRequest {
        let mut policy = serde_json::json!({"circuitType":"custom-ring-policy","txViewingSk":"secret","treeSlots":[],"publicInputHash":"0x1","outputs":[{"amount":"0x1","ctHash":"0x2"}],"subjects":vec![serde_json::Value::Null; 9],"foreignRoot":"0x0","foreignSubjects":vec![serde_json::Value::Null; 9]});
        if policy_circuit_delegate(circuit) == Some(true) {
            policy = serde_json::json!({"circuitType":circuit,"policy":policy});
        } else {
            policy["circuitType"] = serde_json::Value::String(circuit.to_owned());
        }
        IndexedPolicyRequest::new(
            Zeroizing::new(policy.to_string()),
            ExpectedProvingKey {
                name: "policy.key".into(),
                sha256: [0; 32],
            },
            IndexedPolicyData {
                registry: registry(3),
                foreign_registry: foreign.then(|| registry(4)),
                trees: vec![ResolvedProofTree {
                    tree: zolana_interface::pda::tree(3),
                    id: 3,
                    utxo_root: field(1),
                    nullifier_root: field(2),
                    context: TreeContext {
                        utxo_tree_root_index: 4,
                        nullifier_tree_root_index: 3,
                    },
                }],
                public_inputs: vec![field(3); POLICY_PUBLIC_INPUTS],
            },
        )
        .unwrap()
    }

    #[test]
    fn policy_resolution_rejects_changed_anchors_and_transcripts() {
        for circuit in [
            "custom-ring-policy",
            "custom-ring-delegate-policy",
            "custom-ring-policy-16-4",
            "custom-ring-policy-3-4-anonymous",
            "custom-ring-delegate-policy-4-4",
        ] {
            let request = request(circuit, false);
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
            let prepared = if policy_circuit_delegate(circuit) == Some(false) {
                &body["prepared"]
            } else {
                &body["prepared"]["policy"]
            };
            assert!(prepared.get("treeSlots").is_none());
            assert!(prepared.get("subjects").is_none());
            assert!(prepared.get("foreignSubjects").is_none());
            assert!(prepared["outputs"][0].get("ctHash").is_none());
            assert_eq!(prepared["outputs"][0]["amount"], "0x1");
            assert_eq!(prepared["txViewingSk"], "secret");
            assert!(body.get("inputs").is_none());
            assert!(body.get("foreignRegistry").is_none());
            assert_eq!(body["registry"]["nextIndex"], 2);
        }
    }

    #[test]
    fn a_curator_registry_rides_along_when_the_sources_name_one() {
        let body: serde_json::Value =
            serde_json::from_str(&request("custom-ring-policy", true).body().unwrap()).unwrap();
        assert_eq!(
            body["foreignRegistry"]["ringProgramId"],
            Address::from([4; 32]).to_string()
        );
    }

    #[test]
    fn registry_is_sent_in_the_prover_encoding() {
        let ring_program_id = Address::from([3; 32]);
        let registry = serde_json::to_value(IndexedRegistry {
            ring_program_id,
            root: [9; 32],
            next_index: 2,
        })
        .unwrap();
        assert_eq!(
            registry,
            serde_json::json!({
                "ringProgramId": ring_program_id.to_string(),
                "root": Address::from([9; 32]).to_string(),
                "nextIndex": 2,
            })
        );
    }
}

#[cfg(test)]
mod shaped_names {
    use super::policy_circuit_delegate;

    #[test]
    fn only_shipped_general_policy_names_are_indexable() {
        for n in [1, 2, 3, 4, 5, 6, 8, 12, 16] {
            for m in [2, 4] {
                assert_eq!(
                    policy_circuit_delegate(&format!("custom-ring-policy-{n}-{m}")),
                    Some(false)
                );
            }
        }
        assert_eq!(
            policy_circuit_delegate("custom-ring-policy-3-4-anonymous"),
            Some(false)
        );
        assert_eq!(
            policy_circuit_delegate("custom-ring-delegate-policy-4-4"),
            Some(true)
        );
        for bad in [
            "custom-ring-policy-1-8",
            "custom-ring-policy-24-2",
            "custom-ring-policy-01-2",
            "custom-ring-policy-2-2-subtree",
            "custom-ring-policy-1-2-anonymous",
            "custom-ring-delegate-policy-2-4",
            "custom-ring-delegate-policy-2-2-anonymous",
        ] {
            assert_eq!(policy_circuit_delegate(bad), None, "{bad}");
        }
    }
}
