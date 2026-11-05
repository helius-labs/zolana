use light_program_profiler::profile;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use spr_account_checks::AccountIterator;
use spr_hasher::primitives::solana_owner_identity;
use spr_program::CompressedProof;
use wincode::{SchemaRead, SchemaWrite};

use crate::{
    error::TimelockEscrowError,
    instructions::shared::{check_after_window, escrow_authority, IxData},
    verifier::withdraw,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct WithdrawArgs {
    pub proof: CompressedProof,
    pub unlock_timestamp: u64,
}

#[inline(never)]
#[profile]
pub fn process_withdraw_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("caller")?;
    let creator = *iter.next_signer("creator")?.address();
    let creator_identity =
        solana_owner_identity(creator.as_array()).map_err(TimelockEscrowError::from)?;

    let IxData {
        args: WithdrawArgs {
            proof,
            unlock_timestamp,
        },
        private_tx_hash,
        transact,
    } = IxData::<WithdrawArgs>::parse(data)?;

    let clock = Clock::get()?;
    check_after_window(clock.unix_timestamp, unlock_timestamp)?;

    withdraw::Verifier {
        proof: &proof,
        public_inputs: withdraw::PublicInputs {
            unlock: unlock_timestamp,
            creator_identity,
        },
        private_tx_hash,
        transfers: &[],
    }
    .verify()
    .map_err(TimelockEscrowError::from)?;

    let spp_accounts = iter.remaining()?;
    escrow_authority(&creator).invoke_transact::<16>(spp_accounts, transact)
}
