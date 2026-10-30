use spr_interface::instruction::instruction_data::transact::TransactIxData;
use spr_transaction::instructions::transact::SppProofInputs;

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    prover::{
        client::ProveRequest,
        inputs::{BatchAddressAppendInputs, MergeInputs, TransferInputs},
        proof::Proof,
        requests,
        transact::{
            confidential_eddsa::ConfidentialEddsaTransferInputs,
            witness::{assemble_with_dummy_policy, SpendProof},
        },
    },
    rpc::NonInclusionProof,
};

/// Turns prover requests into proofs.
///
/// [`ProverClient`](crate::ProverClient) sends each request to a prover server.
/// Implement [`Self::prove`] to prove somewhere else instead, such as in
/// process or on a mobile device, and pass the implementation to
/// [`ZolanaClient::from_parts`](crate::ZolanaClient::from_parts) or any
/// `&dyn Prover` parameter. The typed proofs are [`ProverExt`] methods.
///
/// A body carries nullifier secrets. An implementation must not log it or
/// persist it.
pub trait Prover: Send + Sync {
    /// A server transport, when available, so clients can use its async and
    /// indexed routes without driving a second blocking runtime.
    fn server_client(&self) -> Option<&crate::AsyncProverClient> {
        None
    }

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
    ///
    /// An implementation returns its own failures as
    /// [`ClientError::ProverFailed`], which every client path passes on
    /// unchanged, so its caller can read them back.
    fn prove(&self, request: &dyn ProveRequest) -> Result<Proof, ClientError>;
}

/// The typed proofs, built on [`Prover::prove`] with the same encoder the
/// server path uses, so every backend receives the same body.
///
/// The blanket implementation uses shared request encoders, so a backend
/// receives the same proof inputs through the typed and high-level APIs.
pub trait ProverExt: Prover {
    /// Prove a Solana-only (Ed25519) transfer. Call
    /// [`ProofCompressed::try_from`](crate::ProofCompressed) for the wire format.
    fn prove_transfer(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.prove(&requests::transfer(inputs)?)
    }

    /// Prove a default-ring transfer one owner authorizes in-circuit
    /// (`transfer-confidential-eddsa`).
    fn prove_transfer_confidential_eddsa(
        &self,
        inputs: &ConfidentialEddsaTransferInputs,
    ) -> Result<Proof, ClientError> {
        self.prove(inputs)
    }

    /// Prove an 8-in/1-out merge.
    fn prove_merge(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        self.prove(&requests::merge(inputs)?)
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
