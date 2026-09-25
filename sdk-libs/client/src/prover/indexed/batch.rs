use super::is_canonical_bn254_scalar_be;
use serde::{Deserialize, Serialize};
use solana_address::Address;
use zeroize::Zeroizing;
use zolana_hasher::hash_chain::create_hash_chain_4_from_slice;

use super::{decode_field, hex_field, invalid, invalid_resolution};
use crate::prover::ExpectedProvingKey;
use crate::{ClientError, Proof, ProofCompressed};

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

pub(crate) struct IndexedBatchResponse {
    pub proof: Proof,
    pub resolution: BatchResolution,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BatchResolution {
    pub tree: String,
    pub start_index: u64,
    pub old_root: String,
    pub new_root: String,
    #[serde(skip)]
    pub public_input_hash: [u8; 32],
}

impl IndexedBatchRequest {
    pub(crate) fn key(&self) -> Result<ExpectedProvingKey, ClientError> {
        ExpectedProvingKey::batch_address_append(self.tree_height, self.batch_size)
    }

    pub(crate) fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        self.key()?;
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
        .map(Zeroizing::new)
        .map_err(|_| invalid())
    }

    pub(crate) fn finish(
        &self,
        response: IndexedBatchResponse,
    ) -> Result<ProvenIndexedBatch, ClientError> {
        let resolution = response.resolution;
        let old_root = decode_field(&resolution.old_root)?;
        let new_root = decode_field(&resolution.new_root)?;
        if resolution.tree != self.tree.to_string()
            || resolution.start_index != self.start_index
            || (self.start_index == self.anchor.next_index && old_root != self.anchor.root)
        {
            return Err(invalid_resolution());
        }
        let mut index = [0; 32];
        index[24..].copy_from_slice(&self.start_index.to_be_bytes());
        let expected =
            create_hash_chain_4_from_slice(&[old_root, new_root, self.leaves_hash_chain, index])?;
        if expected != resolution.public_input_hash {
            return Err(invalid_resolution());
        }
        let proof = ProofCompressed::try_from(response.proof)?.to_nullifier_tree_proof()?;
        // 1. Returned roots remain untrusted until proof verification.
        zolana_tree::nullifier_tree::verify::verify_batch_update(
            u64::from(self.batch_size),
            expected,
            &zolana_tree::nullifier_tree::proof::NullifierTreeProof {
                a: proof.a,
                b: proof.b,
                c: proof.c,
            },
        )
        .map_err(|_| ClientError::ProofVerification("invalid indexed batch proof".to_owned()))?;
        Ok(ProvenIndexedBatch {
            old_root,
            new_root,
            proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn response(request: &IndexedBatchRequest) -> IndexedBatchResponse {
        let mut index = [0; 32];
        index[24..].copy_from_slice(&request.start_index.to_be_bytes());
        IndexedBatchResponse {
            proof: Proof {
                a: [0; 64],
                b: [0; 128],
                c: [0; 64],
                commitment: None,
            },
            resolution: BatchResolution {
                tree: request.tree.to_string(),
                start_index: request.start_index,
                old_root: hex_field(&request.anchor.root),
                new_root: "0x1".into(),
                public_input_hash: create_hash_chain_4_from_slice(&[
                    request.anchor.root,
                    super::super::scalar_one(),
                    request.leaves_hash_chain,
                    index,
                ])
                .unwrap(),
            },
        }
    }

    #[test]
    fn rejects_unbound_batch_responses() {
        let request = request();
        for corrupt in 0..6 {
            let mut response = response(&request);
            match corrupt {
                0 => response.resolution.tree = Address::default().to_string(),
                1 => response.resolution.start_index += 10,
                2 => response.resolution.old_root = "0x2".into(),
                3 => response.resolution.new_root = "0x2".into(),
                4 => response.resolution.public_input_hash = [0; 32],
                _ => response.resolution.new_root = format!("0x{}", "ff".repeat(32)),
            }
            assert!(request.finish(response).is_err());
        }
        assert!(matches!(
            request.finish(response(&request)),
            Err(ClientError::ProofVerification(_))
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
