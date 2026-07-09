use anyhow::{bail, Result};
use swap_prover::{
    CancelProofResult, CreateProofResult, FillProofResult, FillVerifiableEncryptionProofResult,
};
use zolana_client::{assemble, Proof, ProofCompressed, ProverClient, ProverInputs, SpendProof};
use zolana_interface::instruction::instruction_data::transact::{TransactIxData, TransactProof};
use zolana_transaction::instructions::transact::SignedTransaction;

use crate::{
    err,
    instructions::{
        cancel::CancelProofInputParams, create_swap::CreateSwapProofInputParams,
        fill::FillProofInputParams,
        fill_verifiable_encryption::FillVerifiableEncryptionProofInputParams,
    },
};

pub struct SwapProverClient;

impl SwapProverClient {
    pub fn new_ffi() -> Self {
        Self
    }

    pub fn prove_create_swap(
        &self,
        inputs: &CreateSwapProofInputParams,
    ) -> Result<CreateProofResult> {
        inputs.into_proof_inputs()?.prove().map_err(err)
    }

    pub fn prove_fill(&self, inputs: &FillProofInputParams) -> Result<FillProofResult> {
        inputs.into_proof_inputs()?.prove().map_err(err)
    }

    pub fn prove_cancel(&self, inputs: &CancelProofInputParams) -> Result<CancelProofResult> {
        inputs.into_proof_inputs()?.prove().map_err(err)
    }

    pub fn prove_fill_verifiable_encryption(
        &self,
        inputs: &FillVerifiableEncryptionProofInputParams,
    ) -> Result<FillVerifiableEncryptionProofResult> {
        inputs.into_proof_inputs()?.prove().map_err(err)
    }
}

pub fn pack_transact_proof(proof: &Proof) -> Result<TransactProof> {
    Ok(ProofCompressed::try_from(*proof)
        .map_err(err)?
        .to_transact_proof())
}

pub fn prove_transact(
    signed: SignedTransaction,
    spend_proofs: &[SpendProof],
    prover: &ProverClient,
) -> Result<TransactIxData> {
    let assembled = assemble(signed, spend_proofs).map_err(err)?;
    let proof = match &assembled.prover_inputs {
        ProverInputs::Eddsa(inputs) => prover.prove_transfer(inputs).map_err(err)?,
        ProverInputs::P256(_) => bail!("order lifecycle instructions use the eddsa rail"),
    };
    Ok(assembled.with_proof(pack_transact_proof(&proof)?))
}
