use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_transaction::instructions::transact::SppProofInputs;

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    prover::{
        client::ProveRequest,
        inputs::{BatchAddressAppendInputs, MergeInputs, TransferInputs, TransferP256Inputs},
        proof::Proof,
        requests,
        transact::witness::{assemble_with_dummy_policy, SpendProof},
    },
    rpc::NonInclusionProof,
};

/// Turns prover requests into proofs.
///
/// [`ProverClient`](crate::ProverClient) sends each request to a prover server.
/// Implement [`Self::prove`] to prove somewhere else instead, such as in
/// process or on a mobile device, and pass the implementation to
/// [`ZolanaClient::with_prover`](crate::ZolanaClient::with_prover) or any
/// `&dyn Prover` parameter. The typed proofs are [`ProverExt`] methods.
///
/// A body carries nullifier secrets. An implementation must not log it or
/// persist it.
pub trait Prover: Send + Sync {
    /// Prove one request, returning the uncompressed negated proof.
    ///
    /// The proof must come from the key [`ProveRequest::proving_key`] names,
    /// whose sha256 the on-chain verifier pins. A server backend checks the key
    /// the prover reports; an in-process backend verifies the key file against
    /// that sha256 when it loads it. [`ProveRequest::delivery`] tells a server
    /// backend whether to wait for the proof or queue it.
    ///
    /// Anything a request carries is a [`ProveRequest`] method, so a new one
    /// leaves this signature, and every implementation, unchanged.
    fn prove(&self, request: &dyn ProveRequest) -> Result<Proof, ClientError>;
}

/// The typed proofs, built on [`Prover::prove`] with the same encoder the
/// server path uses, so every backend receives the same body.
///
/// Implemented for every [`Prover`], and only through that blanket impl, so a
/// backend cannot override a typed method: every client path, including the
/// async ones that call [`Prover::prove`] directly, proves through `prove`.
pub trait ProverExt: Prover {
    /// Prove a Solana-only (eddsa) transfer. Call
    /// [`ProofCompressed::try_from`](crate::ProofCompressed) for the wire format.
    fn prove_transfer(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.prove(&requests::transfer(inputs)?)
    }

    /// Prove an 8-in/1-out merge.
    fn prove_merge(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        self.prove(&requests::merge(inputs)?)
    }

    /// Prove a ring-authority transfer (anonymous, no signature). Reuses the
    /// Solana-only [`TransferInputs`] witness.
    fn prove_ring_authority(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.prove(&requests::ring_authority(inputs)?)
    }

    /// Prove a policy-ring merge (`merge-ring`).
    fn prove_merge_ring(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        self.prove(&requests::merge_ring(inputs)?)
    }

    /// Prove an eddsa confidential policy-ring transfer (`transfer-ring`).
    fn prove_transfer_ring(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.prove(&requests::transfer_ring(inputs)?)
    }

    /// Prove a custom-ring P256 transfer.
    fn prove_transfer_p256_ring(&self, inputs: &TransferP256Inputs) -> Result<Proof, ClientError> {
        self.prove(&requests::transfer_p256_ring(inputs)?)
    }

    /// Prove a nullifier-tree batch address-append update. Call
    /// [`ProofCompressed::try_from`](crate::ProofCompressed) for the SPP
    /// instruction wire format.
    fn prove_batch_address_append(
        &self,
        inputs: &BatchAddressAppendInputs,
    ) -> Result<Proof, ClientError> {
        self.prove(&requests::batch_address_append(inputs)?)
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

impl<P: Prover + ?Sized> ProverExt for P {}
