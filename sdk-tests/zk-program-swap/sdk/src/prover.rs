use anyhow::{bail, Result};
use zolana_client::{assemble, Proof, ProofCompressed, ProverClient, ProverInputs, SpendProof};
use zolana_interface::instruction::instruction_data::transact::{TransactIxData, TransactProof};
use zolana_transaction::instructions::transact::SignedTransaction;

use crate::{err, CancelProof, CreateProof, FillProof, FillVerifiableEncryptionProof};

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

pub fn create_proof_ix(proof: &swap_prover::OrderProof) -> CreateProof {
    CreateProof {
        proof_a: proof.proof_a,
        proof_b: proof.proof_b,
        proof_c: proof.proof_c,
    }
}

pub fn cancel_proof_ix(proof: &swap_prover::OrderProof) -> CancelProof {
    CancelProof {
        proof_a: proof.proof_a,
        proof_b: proof.proof_b,
        proof_c: proof.proof_c,
    }
}

pub fn fill_proof_ix(proof: &swap_prover::OrderProof) -> FillProof {
    FillProof {
        proof_a: proof.proof_a,
        proof_b: proof.proof_b,
        proof_c: proof.proof_c,
    }
}

pub fn fill_verifiable_encryption_proof_ix(
    proof: &swap_prover::OrderProof,
) -> FillVerifiableEncryptionProof {
    let (commitment, commitment_pok) = proof
        .commitment
        .expect("fill proof carries a BSB22 commitment");
    FillVerifiableEncryptionProof {
        proof_a: proof.proof_a,
        proof_b: proof.proof_b,
        proof_c: proof.proof_c,
        commitment,
        commitment_pok,
    }
}
