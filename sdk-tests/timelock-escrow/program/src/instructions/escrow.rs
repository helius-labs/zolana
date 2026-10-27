use light_program_profiler::profile;
use pinocchio::{AccountView, ProgramResult};
use spr_account_checks::AccountIterator;
use spr_hasher::primitives::solana_owner_identity;
use spr_program::CompressedProof;
use wincode::{SchemaRead, SchemaWrite};

use crate::{
    error::TimelockEscrowError,
    instructions::shared::{EscrowAuthority, IxData},
    verifier::escrow,
};

pub mod slot {
    pub const SOURCE: usize = 0;
    pub const CHANGE: usize = 0;
    pub const ESCROW: usize = 1;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct EscrowArgs {
    pub proof: CompressedProof,
    pub viewing_pubkey: [u8; 33],
}

#[inline(never)]
#[profile]
pub fn process_escrow_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let creator = *iter.next_signer("creator")?.address();
    let creator_identity =
        solana_owner_identity(creator.as_array()).map_err(TimelockEscrowError::from)?;
    let escrow_authority = EscrowAuthority::find(&creator);

    let IxData {
        args: EscrowArgs {
            proof,
            viewing_pubkey,
        },
        private_tx_hash,
        transact,
    } = IxData::<EscrowArgs>::parse(data)?;

    escrow::Verifier {
        proof: &proof,
        public_inputs: escrow::PublicInputs {
            escrow_owner: spr_program::verifier::address_hash(
                &escrow_authority.owner_hash()?,
                &viewing_pubkey,
            )
            .map_err(TimelockEscrowError::from)?,
            creator_identity,
        },
        private_tx_hash,
        transfers: &[],
    }
    .verify()
    .map_err(TimelockEscrowError::from)?;

    let spp_accounts = iter.remaining()?;
    escrow_authority.invoke_transact(spp_accounts, transact)
}
