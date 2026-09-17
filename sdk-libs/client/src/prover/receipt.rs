//! Nullifier receipt witness: batch non-inclusion of a published nullifier list
//! against one nullifier-tree root (`prover/server/circuits/nullifier_receipt`).
//! The witness is public data, so any party with the list and indexer access
//! can build it. Slots are padded with zeros up to the circuit shape.

use num_bigint::BigUint;
use zolana_hasher::hash_chain::create_hash_chain_4_from_slice;
use zolana_interface::{
    instruction::{
        instruction_data::merge_transact::MergeProof, VerifyReceiptData, RECEIPT_DOMAIN,
    },
    state::receipt::is_supported_capacity,
    tree_slot::tree_id_field,
};

use crate::{
    error::ClientError,
    prover::{
        field::{be, right_align},
        proof::{CompressedCommitments, ProofCompressed},
    },
    rpc::{NonInclusionProof, NULLIFIER_TREE_HEIGHT},
};

/// Non-inclusion witness of one receipt slot: the low leaf bracketing the
/// nullifier and its Merkle path at the receipt root.
#[derive(Debug, Clone)]
pub struct ReceiptWitness {
    pub low: BigUint,
    pub next: BigUint,
    pub index: BigUint,
    pub path: Vec<BigUint>,
}

/// Flat receipt witness. Mirrors `prover/server/prover/nullifier_receipt`
/// `Parameters`: `nullifiers` has the shape's length, active slots first.
#[derive(Debug, Clone)]
pub struct ReceiptInputs {
    pub tree_id: BigUint,
    pub root: BigUint,
    pub count: u16,
    pub nullifiers: Vec<BigUint>,
    pub witnesses: Vec<ReceiptWitness>,
    pub public_input_hash: BigUint,
}

/// Builder for a receipt over `nullifiers`, all fresh at `nullifier_root`.
pub struct ReceiptProver<'a> {
    pub tree_id: u16,
    pub nullifier_root: [u8; 32],
    /// In receipt slot order; `proofs[i]` is the non-inclusion proof of
    /// `nullifiers[i]` at `nullifier_root`.
    pub nullifiers: &'a [[u8; 32]],
    pub proofs: &'a [NonInclusionProof],
    /// Circuit shape (`RECEIPT_CAPACITIES`); the receipt account's capacity.
    pub capacity: usize,
}

impl ReceiptProver<'_> {
    pub fn build(&self) -> Result<ReceiptInputs, ClientError> {
        let count = self.nullifiers.len();
        let capacity = u16::try_from(self.capacity).map_err(|_| ClientError::ValueTooLong)?;
        if !is_supported_capacity(capacity) || count == 0 || count > self.capacity {
            return Err(ClientError::Prover(format!(
                "receipt: {count} nullifiers do not fit a {}-slot receipt",
                self.capacity
            )));
        }
        if self.proofs.len() != count {
            return Err(ClientError::Prover(format!(
                "receipt: {} proofs for {count} nullifiers",
                self.proofs.len()
            )));
        }
        let zero_witness = ReceiptWitness {
            low: BigUint::ZERO,
            next: BigUint::ZERO,
            index: BigUint::ZERO,
            path: vec![BigUint::ZERO; NULLIFIER_TREE_HEIGHT],
        };
        let mut witnesses = Vec::with_capacity(self.capacity);
        for (nullifier, proof) in self.nullifiers.iter().zip(self.proofs) {
            if proof.leaf != *nullifier || proof.root != self.nullifier_root {
                return Err(ClientError::Prover(
                    "receipt: non-inclusion proof does not match its nullifier and root".into(),
                ));
            }
            if proof.path.len() != NULLIFIER_TREE_HEIGHT {
                return Err(ClientError::Prover(format!(
                    "receipt: non-inclusion path length {}, want {NULLIFIER_TREE_HEIGHT}",
                    proof.path.len()
                )));
            }
            witnesses.push(ReceiptWitness {
                low: be(&proof.low_element),
                next: be(&proof.high_element),
                index: BigUint::from(proof.low_element_index),
                path: proof.path.iter().map(be).collect(),
            });
        }
        witnesses.resize(self.capacity, zero_witness);

        let mut slots = vec![[0u8; 32]; self.capacity];
        slots[..count].copy_from_slice(self.nullifiers);
        let count = u16::try_from(count).map_err(|_| ClientError::ValueTooLong)?;
        let fields = [
            right_align(&RECEIPT_DOMAIN.to_be_bytes()),
            tree_id_field(self.tree_id),
            self.nullifier_root,
            right_align(&count.to_be_bytes()),
            create_hash_chain_4_from_slice(&slots)?,
        ];
        let public_input_hash = create_hash_chain_4_from_slice(&fields)?;

        Ok(ReceiptInputs {
            tree_id: BigUint::from(self.tree_id),
            root: be(&self.nullifier_root),
            count,
            nullifiers: slots.iter().map(be).collect(),
            witnesses,
            public_input_hash: be(&public_input_hash),
        })
    }
}

impl ReceiptInputs {
    /// `verify_receipt` instruction data for this receipt proven at the tree's
    /// root-history position `nullifier_tree_root_index`.
    pub fn verify_data(
        &self,
        nullifier_tree_root_index: u16,
        proof: ProofCompressed,
    ) -> Result<VerifyReceiptData, ClientError> {
        let CompressedCommitments {
            commitment,
            commitment_pok,
        } = proof.commitment.ok_or_else(|| {
            ClientError::ProofParse("receipt proof is missing its BSB22 commitment".into())
        })?;
        Ok(VerifyReceiptData {
            nullifier_tree_root_index,
            count: self.count,
            proof: MergeProof {
                a: proof.a,
                b: proof.b,
                c: proof.c,
            },
            commitment,
            commitment_pok,
        })
    }
}
