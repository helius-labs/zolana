use pinocchio::{error::ProgramError, Address, ProgramResult};
use spr_interface::instruction::instruction_data::transact::TransactIxDataRef;
use spr_program::{cpi::PdaSigner, program::PdaOwner};
use wincode::{config::DefaultConfig, SchemaReadOwned};

use crate::error::TimelockEscrowError;

pub struct IxData<'a, A> {
    pub args: A,
    pub private_tx_hash: &'a [u8; 32],
    pub transact: &'a [u8],
}

impl<'a, A: SchemaReadOwned<DefaultConfig, Dst = A>> IxData<'a, A> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ProgramError> {
        let mut transact = data;
        let args = wincode::deserialize_from(&mut transact)
            .map_err(|_| TimelockEscrowError::InvalidInstructionData)?;
        let private_tx_hash = TransactIxDataRef::from_bytes(transact)
            .map_err(|_| TimelockEscrowError::InvalidInstructionData)?
            .private_tx_hash;
        Ok(Self {
            args,
            private_tx_hash,
            transact,
        })
    }
}

#[inline(always)]
pub fn check_after_window(now: i64, unlock_unix_ts: u64) -> ProgramResult {
    if now >= 0 && (now as u64) > unlock_unix_ts {
        Ok(())
    } else {
        Err(TimelockEscrowError::NotYetUnlocked.into())
    }
}

/// The escrow authority PDA of `creator`: it owns the escrowed UTXOs and signs
/// their transact CPIs.
pub fn escrow_authority(creator: &Address) -> PdaSigner<[&[u8]; 2]> {
    PdaSigner::find(crate::escrow_authority_seeds(creator), &crate::ID)
}

/// The owner hash of the escrow authority PDA `address`.
pub fn escrow_authority_owner_hash(address: &Address) -> Result<[u8; 32], TimelockEscrowError> {
    Ok(*PdaOwner::new(address)
        .map_err(|_| TimelockEscrowError::HashingFailed)?
        .owner_hash())
}
