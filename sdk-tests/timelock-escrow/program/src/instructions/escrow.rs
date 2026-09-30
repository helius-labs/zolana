use light_program_profiler::profile;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_hasher::primitives::solana_owner_identity;
use zolana_program::CompressedProof;

use crate::{
    error::TimelockEscrowError,
    instructions::shared::{EscrowAuthority, IxData},
    zk::{escrow, Groth16Proof},
};

pub mod slot {
    pub const SOURCE: usize = 0;
    pub const CHANGE: usize = 0;
    pub const ESCROW: usize = 1;
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
        args: proof,
        private_tx_hash,
        transact,
    } = IxData::<CompressedProof>::parse(data)?;

    escrow::verify(
        &Groth16Proof {
            a: &proof.a,
            b: &proof.b,
            c: &proof.c,
        },
        &escrow::PublicInputs {
            escrow_owner: escrow_authority.owner_hash()?,
            creator_identity,
        },
        private_tx_hash,
    )
    .map_err(TimelockEscrowError::from)?;

    let spp_accounts = iter.remaining()?;
    escrow_authority.invoke_transact(spp_accounts, transact)
}
