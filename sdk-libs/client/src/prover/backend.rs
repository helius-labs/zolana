use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_transaction::instructions::transact::SppProofInputs;

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    prover::{
        client::{Delivery, ProveRequest},
        inputs::{BatchAddressAppendInputs, MergeInputs, TransferInputs, TransferP256Inputs},
        json::{
            to_json, to_json_batch_address_append, to_json_merge, to_json_merge_ring,
            to_json_p256_ring, to_json_ring, to_json_ring_authority,
        },
        proof::Proof,
        transact::witness::{assemble_with_dummy_policy, SpendProof},
    },
    rpc::NonInclusionProof,
};

/// Turns `/prove` request bodies into proofs.
///
/// [`ProverClient`](crate::ProverClient) sends each body to a prover server.
/// Implement [`Self::prove_body`] to prove somewhere else instead, such as in
/// process or on a mobile device, and pass the implementation to
/// [`ZolanaClient::with_prover`](crate::ZolanaClient::with_prover) or any
/// `&dyn Prover` parameter. The typed methods serialize their inputs with the
/// same encoder the server path uses, so every backend receives the same body.
///
/// A body carries nullifier secrets. An implementation must not log it or
/// persist it.
pub trait Prover: Send + Sync {
    /// Prove one serialized request, returning the uncompressed negated proof.
    ///
    /// `delivery` tells a server backend whether to wait for the proof or queue
    /// it. A backend that proves in process ignores it.
    fn prove_body(&self, body: &str, delivery: Delivery) -> Result<Proof, ClientError>;

    /// Prove a request body built by a downstream crate.
    fn prove(&self, request: &dyn ProveRequest) -> Result<Proof, ClientError> {
        self.prove_body(&request.body()?, request.delivery())
    }

    /// Prove a Solana-only (eddsa) transfer. Call
    /// [`ProofCompressed::try_from`](crate::ProofCompressed) for the wire format.
    fn prove_transfer(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.prove_body(&to_json(inputs)?, Delivery::InResponse)
    }

    /// Prove an 8-in/1-out merge.
    fn prove_merge(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        self.prove_body(&to_json_merge(inputs), Delivery::InResponse)
    }

    /// Prove a ring-authority transfer (anonymous, no signature). Reuses the
    /// Solana-only [`TransferInputs`] witness.
    fn prove_ring_authority(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.prove_body(&to_json_ring_authority(inputs)?, Delivery::InResponse)
    }

    /// Prove a policy-ring merge (`merge-ring`).
    fn prove_merge_ring(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        self.prove_body(&to_json_merge_ring(inputs), Delivery::InResponse)
    }

    /// Prove an eddsa confidential policy-ring transfer (`transfer-ring`).
    fn prove_transfer_ring(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.prove_body(&to_json_ring(inputs)?, Delivery::InResponse)
    }

    /// Prove a custom-ring P256 transfer.
    fn prove_transfer_p256_ring(&self, inputs: &TransferP256Inputs) -> Result<Proof, ClientError> {
        self.prove_body(&to_json_p256_ring(inputs)?, Delivery::InResponse)
    }

    /// Prove a nullifier-tree batch address-append update. Call
    /// [`ProofCompressed::try_from`](crate::ProofCompressed) for the SPP
    /// instruction wire format.
    fn prove_batch_address_append(
        &self,
        inputs: &BatchAddressAppendInputs,
    ) -> Result<Proof, ClientError> {
        self.prove_body(&to_json_batch_address_append(inputs), Delivery::Queued)
    }

    /// Assemble `proof_inputs` against the supplied Merkle and non-inclusion
    /// proofs, let `authority` complete the witness, prove it, and return the
    /// `Transact` instruction data.
    fn prove_transact(
        &self,
        proof_inputs: SppProofInputs,
        input_proofs: &[SpendProof],
        dummy_nullifier_proofs: &[NonInclusionProof],
        authority: &dyn ProofAuthority,
    ) -> Result<TransactIxData, ClientError> {
        self.prove_transact_with_dummy_policy(
            proof_inputs,
            input_proofs,
            dummy_nullifier_proofs,
            true,
            authority,
        )
    }

    fn prove_transact_with_dummy_policy(
        &self,
        proof_inputs: SppProofInputs,
        input_proofs: &[SpendProof],
        dummy_nullifier_proofs: &[NonInclusionProof],
        allow_dummy_inputs: bool,
        authority: &dyn ProofAuthority,
    ) -> Result<TransactIxData, ClientError> {
        let mut assembled = assemble_with_dummy_policy(
            proof_inputs,
            input_proofs,
            dummy_nullifier_proofs,
            allow_dummy_inputs,
        )?;
        let proof = assembled.prove(self, authority)?;
        Ok(assembled.with_proof(proof))
    }
}
