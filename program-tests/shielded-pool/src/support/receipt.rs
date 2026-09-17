//! Real nullifier receipts: witness from the local indexed tree, proof from the
//! workspace prover, and the create/upload/verify lifecycle on LiteSVM.

use groth16_solana::groth16::Groth16Verifier;
use num_bigint::BigUint;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    prover::{ReceiptInputs, ReceiptProver},
    ComputeBudgetConfig, MerkleContext, NonInclusionProof, Proof, ProofCompressed, ProverClient,
};
use zolana_hasher::Poseidon;
use zolana_interface::{
    instruction::{
        CreateReceipt, CreateReceiptData, UploadReceipt, UploadReceiptData, VerifyReceipt,
    },
    verifying_keys::nullifier_receipt_8_0,
};
use zolana_merkle_tree::indexed::IndexedMerkleTree;

use super::fixtures::Pool;

/// Upload chunk that keeps `upload_receipt` well inside the transaction limit.
const UPLOAD_CHUNK: usize = 24;

fn fe(value: &BigUint) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = value.to_bytes_be();
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

pub struct RealReceipt {
    pub address: Pubkey,
    pub nonce: u64,
    pub inputs: ReceiptInputs,
    pub proof: Proof,
}

/// Receipt witness for `nullifiers` (slot order) against `nullifier_tree`.
pub fn receipt_inputs(
    tree: Pubkey,
    tree_id: u16,
    nullifier_tree: &IndexedMerkleTree<Poseidon, usize>,
    nullifiers: &[[u8; 32]],
    capacity: usize,
) -> ReceiptInputs {
    let root = nullifier_tree.root();
    let merkle_context = MerkleContext { tree_type: 0, tree };
    let proofs: Vec<NonInclusionProof> = nullifiers
        .iter()
        .map(|nullifier| {
            let proof = nullifier_tree
                .get_non_inclusion_proof(&BigUint::from_bytes_be(nullifier))
                .expect("non-inclusion proof");
            NonInclusionProof {
                leaf: *nullifier,
                merkle_context: merkle_context.clone(),
                path: proof.merkle_proof.to_vec(),
                low_element: proof.leaf_lower_range_value,
                low_element_index: proof.leaf_index as u64,
                high_element: proof.leaf_higher_range_value,
                high_element_index: 0,
                root,
                root_seq: 0,
                root_index: 0,
            }
        })
        .collect();
    ReceiptProver {
        tree_id,
        nullifier_root: root,
        nullifiers,
        proofs: &proofs,
        capacity,
    }
    .build()
    .expect("build receipt witness")
}

/// Prove `inputs` with the workspace prover and verify the proof locally.
pub fn prove_receipt_inputs(inputs: &ReceiptInputs) -> Proof {
    let proof = ProverClient::local()
        .prove_receipt(inputs)
        .expect("prove receipt");
    let commitment = proof
        .commitment
        .expect("receipt proof carries a commitment");
    let public_inputs = [fe(&inputs.public_input_hash)];
    let mut verifier = Groth16Verifier::new_with_commitment(
        &proof.a,
        &proof.b,
        &proof.c,
        &commitment.commitment,
        &commitment.commitment_pok,
        &public_inputs,
        receipt_verifying_key(inputs.nullifiers.len()),
    )
    .expect("construct receipt verifier");
    verifier.verify().expect("receipt proof verifies locally");
    proof
}

/// Build and prove a receipt for `nullifiers` (slot order) against
/// `nullifier_tree`, whose root must be the tree's current nullifier root.
pub fn prove_receipt(
    pool: &Pool,
    nullifier_tree: &IndexedMerkleTree<Poseidon, usize>,
    nullifiers: &[[u8; 32]],
    capacity: usize,
    nonce: u64,
) -> RealReceipt {
    let inputs = receipt_inputs(
        pool.tree,
        pool.tree_id,
        nullifier_tree,
        nullifiers,
        capacity,
    );
    let proof = prove_receipt_inputs(&inputs);
    let address = CreateReceipt {
        payer: pool.rpc.payer.pubkey(),
        tree: pool.tree,
        data: CreateReceiptData {
            nonce,
            capacity: capacity as u16,
        },
    }
    .receipt();
    RealReceipt {
        address,
        nonce,
        inputs,
        proof,
    }
}

pub fn receipt_verifying_key(
    capacity: usize,
) -> &'static groth16_solana::groth16::Groth16Verifyingkey<'static> {
    match capacity {
        8 => &nullifier_receipt_8_0::VERIFYINGKEY,
        other => panic!("no committed verifying key for a {other}-slot receipt"),
    }
}

impl RealReceipt {
    /// Create, upload and verify the receipt on chain with the pool payer as
    /// sponsor. Returns the compute units of the `verify_receipt` transaction.
    pub fn publish(&self, pool: &mut Pool) -> u64 {
        let payer = pool.rpc.payer.pubkey();
        let tree = pool.tree;
        let count = usize::from(self.inputs.count);
        let capacity = self.inputs.nullifiers.len() as u16;
        let nullifiers: Vec<[u8; 32]> = self.inputs.nullifiers[..count].iter().map(fe).collect();

        let create = CreateReceipt {
            payer,
            tree,
            data: CreateReceiptData {
                nonce: self.nonce,
                capacity,
            },
        };
        assert_eq!(create.receipt(), self.address, "receipt address");
        pool.rpc.svm.expire_blockhash();
        pool.rpc
            .create_and_send_default_payer_transaction(&[create.instruction()], &[])
            .expect("create receipt");

        for (chunk_index, chunk) in nullifiers.chunks(UPLOAD_CHUNK).enumerate() {
            let ix = UploadReceipt {
                sponsor: payer,
                receipt: self.address,
                data: UploadReceiptData {
                    offset: (chunk_index * UPLOAD_CHUNK) as u16,
                    nullifiers: chunk.to_vec(),
                },
            }
            .instruction();
            pool.rpc.svm.expire_blockhash();
            pool.rpc
                .create_and_send_default_payer_transaction(&[ix], &[])
                .expect("upload receipt slice");
        }

        let compressed = ProofCompressed::try_from(self.proof).expect("compress receipt proof");
        let ix = VerifyReceipt {
            receipt: self.address,
            tree,
            data: self
                .inputs
                .verify_data(0, compressed)
                .expect("verify_receipt data"),
        }
        .instruction();
        pool.rpc.svm.expire_blockhash();
        pool.rpc
            .create_and_send_default_payer_transaction_with_budget(
                &[ix],
                &[],
                ComputeBudgetConfig::new(1_400_000),
            )
            .expect("verify receipt");
        pool.rpc
            .last_transaction_trace()
            .expect("verify_receipt trace")
            .compute_units_consumed
    }
}
