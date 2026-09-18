use arrayvec::ArrayVec;
use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, instruction::instruction_data::merge_transact::MAX_MERGE_INPUTS,
};

use crate::instructions::ring_config::loader::load_active_ring_config;

/// Validated accounts for `merge_ring`, in loader order: `input_tree` and
/// `output_tree` (writable), `ring_config` (the ring's `ring_auth` PDA, signer),
/// `payer` (signer), System Program, the program account (for the `emit_event`
/// self-CPI), then one writable nullifier PDA per input and an optional writable
/// cache. The `ring_config` must sign, be unpaused, and be a valid
/// SPP-owned config: only the ring program can sign for its `ring_auth` PDA, so
/// the signature plus the owner + discriminator + active-state check is the
/// ring's authorization.
pub struct MergeRingAccounts<'a> {
    pub input_tree: &'a mut AccountView,
    pub output_tree: &'a mut AccountView,
    pub payer: &'a AccountView,
    pub nullifier_pdas: ArrayVec<&'a mut AccountView, MAX_MERGE_INPUTS>,
    pub cache: Option<(&'a mut AccountView, u8)>,
    /// The calling ring's `program_id`, read from the signed `ring_config`. Bound
    /// into the proof as the UTXO `ring_program_id`.
    pub ring_program_id: Address,
}

impl<'a> MergeRingAccounts<'a> {
    pub fn validate_and_parse(
        accounts: &'a mut [AccountView],
        input_count: usize,
        cache_slot: Option<u8>,
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let input_tree = iter.next_mut("input_tree")?;
        let output_tree = iter.next_mut("output_tree")?;
        let ring_config = iter.next_signer("ring_config")?;
        let ring_program_id = load_active_ring_config(ring_config)?.program_id;
        let payer = iter.next_signer("payer")?;
        let system_program = iter.next_account("system_program")?;
        if !pinocchio_system::check_id(system_program.address()) {
            return Err(ShieldedPoolError::InvalidSystemProgram.into());
        }
        let shielded_pool_program = iter.next_account("shielded_pool_program")?;
        if !address_eq(shielded_pool_program.address(), &crate::ID) {
            return Err(ProgramError::IncorrectProgramId);
        }
        let mut nullifier_pdas = ArrayVec::new();
        for _ in 0..input_count {
            nullifier_pdas
                .try_push(iter.next_mut("nullifier_pda")?)
                .map_err(|_| ShieldedPoolError::InvalidMergeShape)?;
        }
        let cache = cache_slot
            .map(|slot| iter.next_mut("cache").map(|account| (account, slot)))
            .transpose()?;
        if !iter.remaining_unchecked_mut()?.is_empty() {
            return Err(ShieldedPoolError::InvalidMergeShape.into());
        }
        Ok(Self {
            cache,
            input_tree,
            output_tree,
            payer,
            nullifier_pdas,
            ring_program_id,
        })
    }
}
