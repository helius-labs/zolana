use light_program_profiler::profile;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_hasher::primitives::solana_owner_identity;
use zolana_program::CompressedProof;

use crate::{
    error::TimelockEscrowError,
    instructions::shared::{check_after_window, EscrowAuthority, IxData},
    zk::{withdraw, Groth16Proof},
};

pub mod slot {
    pub const ESCROW: usize = 0;
    pub const SOURCE_OUTPUT: usize = 0;
}

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

    withdraw::verify(
        &Groth16Proof {
            a: &proof.a,
            b: &proof.b,
            c: &proof.c,
        },
        &withdraw::PublicInputs {
            unlock: unlock_timestamp,
            creator_identity,
        },
        private_tx_hash,
    )
    .map_err(TimelockEscrowError::from)?;

    let spp_accounts = iter.remaining()?;
    EscrowAuthority::find(&creator).invoke_transact(spp_accounts, transact)
}
