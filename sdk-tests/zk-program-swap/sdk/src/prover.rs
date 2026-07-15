use anyhow::{bail, Result};
use swap_prover::{
    CancelProofInputs, CreateProofInputs, FillProofInputs, FillVerifiableEncryptionProofInputs,
    OrderProof,
};
use zolana_client::{assemble, Proof, ProofCompressed, ProverClient, ProverInputs, SpendProof};
use zolana_interface::instruction::instruction_data::transact::{TransactIxData, TransactProof};
use zolana_transaction::instructions::transact::SppProofInputs;

use crate::err;

#[derive(Default)]
pub struct SwapProverClient;

impl SwapProverClient {
    pub fn new() -> Self {
        Self
    }

    pub fn prove_create_swap(&self, inputs: &CreateProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_fill(&self, inputs: &FillProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_cancel(&self, inputs: &CancelProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_fill_verifiable_encryption(
        &self,
        inputs: &FillVerifiableEncryptionProofInputs,
    ) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }
}

pub fn compress_transact_proof(proof: &Proof) -> Result<TransactProof> {
    Ok(ProofCompressed::try_from(*proof)
        .map_err(err)?
        .to_transact_proof())
}

pub fn prove_transact(
    proof_inputs: SppProofInputs,
    spend_proofs: &[SpendProof],
    prover: &ProverClient,
) -> Result<TransactIxData> {
    let assembled = assemble(proof_inputs, spend_proofs).map_err(err)?;
    let proof = match &assembled.prover_inputs {
        ProverInputs::Eddsa(inputs) => prover.prove_transfer(inputs).map_err(err)?,
        ProverInputs::P256(_) => bail!("order lifecycle instructions use the eddsa rail"),
    };
    Ok(assembled.with_proof(compress_transact_proof(&proof)?))
}
