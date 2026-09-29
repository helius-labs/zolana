use anyhow::Result;
use timelock_escrow_prover::FundingProofInput;
use zolana_keypair::{hash::poseidon, ShieldedAddress};

use crate::{
    err,
    zk_program::{ProgramState, ProgramUtxo},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Funding {
    pub creator: ShieldedAddress,
}

impl ProgramState for Funding {
    type ProofInputs = FundingProofInput;

    fn data_hash(&self) -> Result<[u8; 32]> {
        poseidon(&[&self.proof_inputs()?.owner_hash]).map_err(err)
    }

    fn proof_inputs(&self) -> Result<FundingProofInput> {
        Ok(FundingProofInput {
            owner_hash: self.creator.owner_hash().map_err(err)?,
        })
    }
}

pub type FundingUtxo = ProgramUtxo<Funding>;
