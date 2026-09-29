use anyhow::{anyhow, Result};
use timelock_escrow_program::instructions::shared::u64_right_align;
use timelock_escrow_prover::EscrowTermsProofInput;
use zolana_keypair::{hash::poseidon, ShieldedAddress};

use crate::{
    err,
    zk_program::{ProgramState, ProgramUtxo},
};

pub trait DataHash {
    fn data_hash(&self) -> Result<[u8; 32]>;
}

impl DataHash for EscrowTermsProofInput {
    fn data_hash(&self) -> Result<[u8; 32]> {
        poseidon(&[&self.owner_hash, &u64_right_align(self.unlock)]).map_err(err)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowTerms {
    pub creator: ShieldedAddress,
    pub unlock_timestamp: u64,
}

impl EscrowTerms {
    pub fn from_utxo_data(creator: ShieldedAddress, utxo_data: &[u8]) -> Result<Self> {
        let unlock_timestamp: [u8; 8] = utxo_data.try_into().map_err(|_| {
            anyhow!(
                "escrow utxo data is {} bytes, the unlock timestamp is 8",
                utxo_data.len()
            )
        })?;
        Ok(Self {
            creator,
            unlock_timestamp: u64::from_le_bytes(unlock_timestamp),
        })
    }
}

impl ProgramState for EscrowTerms {
    type ProofInputs = EscrowTermsProofInput;

    fn data_hash(&self) -> Result<[u8; 32]> {
        self.proof_inputs()?.data_hash()
    }

    fn proof_inputs(&self) -> Result<EscrowTermsProofInput> {
        Ok(EscrowTermsProofInput {
            owner_hash: self.creator.owner_hash().map_err(err)?,
            unlock: self.unlock_timestamp,
        })
    }

    fn utxo_data(&self) -> Vec<u8> {
        self.unlock_timestamp.to_le_bytes().to_vec()
    }
}

pub type EscrowUtxo = ProgramUtxo<EscrowTerms>;
