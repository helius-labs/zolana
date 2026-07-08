use anyhow::{bail, Result};
use zolana_client::{assemble, Proof, ProofCompressed, ProverClient, ProverInputs, SpendProof};
use zolana_interface::instruction::instruction_data::transact::{TransactIxData, TransactProof};
use zolana_transaction::instructions::transact::SignedTransaction;

use crate::err;

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
