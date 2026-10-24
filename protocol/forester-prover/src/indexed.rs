use serde::{Deserialize, Serialize};
use solana_address::Address;
use zolana_hasher::{
    hash_chain::create_hash_chain_4_from_slice, primitives::is_canonical_bn254_scalar_be,
};

use crate::key::ExpectedProvingKey;
use crate::proof::coordinate;
use crate::{Error, Proof};

pub struct BatchAnchor {
    pub next_index: u64,
    pub root: [u8; 32],
}

pub struct IndexedBatchRequest {
    pub previous_batches: Vec<[u8; 32]>,
    pub tree: Address,
    pub tree_height: u32,
    pub batch_size: u32,
    pub start_index: u64,
    pub anchor: BatchAnchor,
    pub leaves_hash_chain: [u8; 32],
}

pub struct ProvenIndexedBatch {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub proof: zolana_interface::instruction::NullifierTreeProof,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BatchResolution {
    tree: String,
    start_index: u64,
    old_root: String,
    new_root: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BatchResolutionJson {
    batch: BatchResolution,
    public_input_hash: String,
}

impl IndexedBatchRequest {
    pub(crate) fn body(&self) -> Result<String, Error> {
        self.proving_key()?;
        if self.batch_size == 0 || self.tree_height >= 64 {
            return Err(invalid());
        }
        if self.anchor.next_index == 0
            || self.start_index < self.anchor.next_index
            || self.start_index > (1u64 << self.tree_height) - u64::from(self.batch_size)
            || !(self.start_index - self.anchor.next_index)
                .is_multiple_of(u64::from(self.batch_size))
            || (self.start_index - self.anchor.next_index) / u64::from(self.batch_size)
                != self.previous_batches.len() as u64
            || self
                .previous_batches
                .iter()
                .any(|hash| !is_canonical_bn254_scalar_be(hash))
            || !is_canonical_bn254_scalar_be(&self.anchor.root)
            || !is_canonical_bn254_scalar_be(&self.leaves_hash_chain)
        {
            return Err(invalid());
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Request {
            circuit_type: &'static str,
            tree: String,
            tree_height: u32,
            batch_size: u32,
            start_index: u64,
            anchor_index: u64,
            anchor_root: String,
            hashchain_hash: String,
            previous_batches: Vec<String>,
        }
        serde_json::to_string(&Request {
            circuit_type: "address-append",
            tree: self.tree.to_string(),
            tree_height: self.tree_height,
            batch_size: self.batch_size,
            start_index: self.start_index,
            anchor_index: self.anchor.next_index,
            anchor_root: hex_field(&self.anchor.root),
            hashchain_hash: hex_field(&self.leaves_hash_chain),
            previous_batches: self.previous_batches.iter().map(hex_field).collect(),
        })
        .map_err(|_| invalid())
    }

    pub(crate) fn proving_key(&self) -> Result<ExpectedProvingKey, Error> {
        ExpectedProvingKey::batch_address_append(self.tree_height, self.batch_size)
    }

    pub(crate) fn finish(
        &self,
        proof: Proof,
        resolution: serde_json::Value,
    ) -> Result<ProvenIndexedBatch, Error> {
        let BatchResolutionJson {
            batch,
            public_input_hash,
        } = serde_json::from_value(resolution).map_err(|_| invalid_resolution())?;
        let old_root = decode_field(&batch.old_root)?;
        let new_root = decode_field(&batch.new_root)?;
        if batch.tree != self.tree.to_string()
            || batch.start_index != self.start_index
            || (self.start_index == self.anchor.next_index && old_root != self.anchor.root)
        {
            return Err(invalid_resolution());
        }
        let mut index = [0; 32];
        index[24..].copy_from_slice(&self.start_index.to_be_bytes());
        let expected =
            create_hash_chain_4_from_slice(&[old_root, new_root, self.leaves_hash_chain, index])?;
        if expected != decode_field(&public_input_hash)? {
            return Err(invalid_resolution());
        }
        let proof = proof.compress()?;
        // Returned roots remain untrusted until proof verification.
        zolana_tree::nullifier_tree::verify::verify_batch_update(
            u64::from(self.batch_size),
            expected,
            &zolana_tree::nullifier_tree::proof::NullifierTreeProof {
                a: proof.a,
                b: proof.b,
                c: proof.c,
            },
        )
        .map_err(|_| Error::ProofVerification("invalid indexed batch proof".to_owned()))?;
        Ok(ProvenIndexedBatch {
            old_root,
            new_root,
            proof,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProofDataSource {
    Client,
    Prover,
}
fn invalid() -> Error {
    Error::Prover("invalid batch request".into())
}
fn invalid_resolution() -> Error {
    Error::ProofVerification("batch response does not match request".into())
}
fn hex_field(value: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(value))
}
fn decode_field(text: &str) -> Result<[u8; 32], Error> {
    let field = coordinate(text)?;
    if !is_canonical_bn254_scalar_be(&field) {
        return Err(invalid_resolution());
    }
    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_one() -> [u8; 32] {
        let mut value = [0; 32];
        value[31] = 1;
        value
    }

    fn request() -> IndexedBatchRequest {
        IndexedBatchRequest {
            tree: Address::new_from_array([4; 32]),
            tree_height: 40,
            batch_size: 10,
            start_index: 1,
            anchor: BatchAnchor {
                next_index: 1,
                root: [0; 32],
            },
            leaves_hash_chain: [0; 32],
            previous_batches: Vec::new(),
        }
    }

    fn proof() -> Proof {
        Proof {
            a: [0; 64],
            b: [0; 128],
            c: [0; 64],
        }
    }

    fn resolution(request: &IndexedBatchRequest) -> serde_json::Value {
        let mut index = [0; 32];
        index[24..].copy_from_slice(&request.start_index.to_be_bytes());
        let hash = create_hash_chain_4_from_slice(&[
            request.anchor.root,
            scalar_one(),
            request.leaves_hash_chain,
            index,
        ])
        .unwrap();
        serde_json::json!({
            "batch": {
                "tree": request.tree.to_string(),
                "startIndex": request.start_index,
                "oldRoot": hex_field(&request.anchor.root),
                "newRoot": "0x1",
            },
            "trees": [],
            "publicInputHash": hex_field(&hash),
        })
    }

    #[test]
    fn rejects_unbound_batch_responses() {
        let request = request();
        for corrupt in 0..6 {
            let mut resolution = resolution(&request);
            let batch = &mut resolution["batch"];
            match corrupt {
                0 => batch["tree"] = Address::default().to_string().into(),
                1 => batch["startIndex"] = (request.start_index + 10).into(),
                2 => batch["oldRoot"] = "0x2".into(),
                3 => batch["newRoot"] = "0x2".into(),
                4 => resolution["publicInputHash"] = "0x0".into(),
                _ => batch["newRoot"] = format!("0x{}", "ff".repeat(32)).into(),
            }
            assert!(request.finish(proof(), resolution).is_err());
        }
        assert!(matches!(
            request.finish(proof(), resolution(&request)),
            Err(Error::ProofVerification(_))
        ));
    }

    #[test]
    fn requires_commitments_for_every_preceding_batch() {
        let mut request = request();
        assert!(request.body().is_ok());
        request.start_index = 11;
        assert!(request.body().is_err());
        request.previous_batches.push([0; 32]);
        assert!(request.body().is_ok());
        request.start_index = 12;
        assert!(request.body().is_err());
        request.start_index = 11;
        request.previous_batches[0] = [255; 32];
        assert!(request.body().is_err());
    }
}
