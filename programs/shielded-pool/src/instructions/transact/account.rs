use arrayvec::ArrayVec;
use pinocchio::{address::address_eq, error::ProgramError, AccountView};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::{
        transact::{InterfaceTransfer, TransactIxDataRef},
        BorrowedList,
    },
    MAX_INTERFACE_TRANSFERS,
};

use crate::instructions::ring_config::loader::load_active_ring_config;
use crate::instructions::settlement::Settlement;

/// Validated transact accounts. Settlement groups are kept as the shared
/// account slice plus one validated byte per transfer, and rebuilt on demand
/// by [`Self::settlements`], so the struct stays small enough to return by
/// value inside the SBF stack frame.
pub struct TransactAccounts<'a> {
    pub payer: &'a AccountView,
    pub input_tree: &'a mut AccountView,
    pub output_tree: &'a mut AccountView,
    pub nullifier_pdas: &'a mut [AccountView],
    pub owner_signers: &'a [AccountView],
    pub settlement_accounts: &'a [AccountView],
    pub settlement_aux: ArrayVec<u8, MAX_INTERFACE_TRANSFERS>,
}

impl<'a> TransactAccounts<'a> {
    /// 1. payer - mut signer
    /// 2. input tree - mut
    /// 3. output tree - mut
    /// 4. self program - program id match
    /// 5. system program - program id match
    /// 6. one writable nullifier PDA per input
    /// 7. zero or more owner signers (a contiguous signer run)
    /// 8. one account group per interface transfer
    pub fn validate_and_parse(
        accounts: &'a mut [AccountView],
        ix: &TransactIxDataRef<'_>,
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);

        let payer: &AccountView = iter.next_signer("payer")?;
        let input_tree = iter.next_mut("input_tree")?;
        let output_tree = iter.next_mut("output_tree")?;
        validate_program_prefix(&mut iter)?;

        Self::from_iter(iter, ix, payer, input_tree, output_tree, true)
    }

    pub(crate) fn from_iter(
        mut iter: AccountIterator<'a>,
        ix: &TransactIxDataRef<'_>,
        payer: &'a AccountView,
        input_tree: &'a mut AccountView,
        output_tree: &'a mut AccountView,
        allow_owner_signers: bool,
    ) -> Result<Self, ProgramError> {
        let nullifier_pdas = iter.next_slice_mut(ix.inputs.len(), "nullifier_pda")?;

        let remaining = iter.remaining_unchecked()?;
        let signer_count = remaining
            .iter()
            .position(|account| !account.is_signer())
            .unwrap_or(remaining.len());
        if signer_count > usize::from(ix.circuit.num_inputs())
            || (!allow_owner_signers && signer_count != 0)
        {
            return Err(ShieldedPoolError::InvalidTransactShape.into());
        }
        let (owner_signers, settlement_accounts) = remaining.split_at(signer_count);

        let mut settlement_aux = ArrayVec::new();
        let mut rest = settlement_accounts;
        for transfer in ix.interface_transfers.try_iter() {
            let transfer = transfer.map_err(|_| ProgramError::InvalidInstructionData)?;
            let (group, tail) = rest
                .split_at_checked(transfer.settlement_account_count())
                .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
            rest = tail;
            let aux = Settlement::from_group(transfer, group, 0)?.validate(transfer)?;
            settlement_aux
                .try_push(aux)
                .map_err(|_| ShieldedPoolError::TooManyInterfaceTransfers)?;
        }
        if !rest.is_empty() {
            return Err(ShieldedPoolError::InvalidTransactShape.into());
        }

        Ok(Self {
            payer,
            input_tree,
            output_tree,
            nullifier_pdas,
            owner_signers,
            settlement_accounts,
            settlement_aux,
        })
    }

    /// Rebuilds each transfer's validated settlement from the stored account
    /// slice, yielding it together with the transfer it settles.
    pub(crate) fn settlements<'s, 't>(
        &'s self,
        transfers: BorrowedList<'t, InterfaceTransfer>,
    ) -> impl ExactSizeIterator<Item = Result<(InterfaceTransfer, Settlement<'a>), ProgramError>>
           + use<'a, 's, 't> {
        let mut rest = self.settlement_accounts;
        transfers
            .try_iter()
            .zip(self.settlement_aux.iter().copied())
            .map(move |(transfer, aux)| {
                let transfer = transfer.map_err(|_| ProgramError::InvalidInstructionData)?;
                let (group, tail) = rest
                    .split_at_checked(transfer.settlement_account_count())
                    .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
                rest = tail;
                Ok((transfer, Settlement::from_group(transfer, group, aux)?))
            })
    }
}

pub struct RingTransactAccounts;

impl RingTransactAccounts {
    /// Parse the accounts shared by `ring_transact` and `ring_authority_transact`:
    /// `payer`, `input_tree`, `output_tree`, SPP, System Program, the `RingConfig`
    /// account (the ring's `ring_auth` PDA), one nullifier PDA per input, then
    /// owner signers and settlement accounts. Returns the parsed transact accounts and the ring's
    /// `program_id`, read from the validated, unpaused `RingConfig` (never
    /// re-derived; the create-time `ring_auth` derivation already bound it).
    /// `require_enabled` additionally requires
    /// `ring_authority_transact_is_enabled` (only `ring_authority_transact` sets it).
    pub fn validate_and_parse<'a>(
        accounts: &'a mut [AccountView],
        ix: &TransactIxDataRef<'_>,
        require_ring_authority_enabled: bool,
    ) -> Result<(TransactAccounts<'a>, [u8; 32]), ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let payer: &AccountView = iter.next_signer("payer")?;
        let input_tree = iter.next_mut("input_tree")?;
        let output_tree = iter.next_mut("output_tree")?;
        validate_program_prefix(&mut iter)?;
        // The `ring_config` must sign (only the ring program can sign for its
        // `ring_auth` PDA); validate owner / discriminator / active state and
        // read the bound ring `program_id`.
        let ring_config = iter.next_signer("ring_config")?;
        let (ring_program_id, ring_authority_is_enabled) = {
            let config = load_active_ring_config(ring_config)?;
            (config.program_id.to_bytes(), config.enabled())
        };
        if require_ring_authority_enabled && !ring_authority_is_enabled {
            return Err(ShieldedPoolError::RingAuthorityTransactDisabled.into());
        }
        // Ring authority instruction does not require any signatures.
        let allow_owner_signers = !require_ring_authority_enabled;
        let transact_accounts = TransactAccounts::from_iter(
            iter,
            ix,
            payer,
            input_tree,
            output_tree,
            allow_owner_signers,
        )?;
        Ok((transact_accounts, ring_program_id))
    }
}

fn validate_program_prefix(iter: &mut AccountIterator<'_>) -> Result<(), ProgramError> {
    let shielded_pool_program = iter.next_account("shielded_pool_program")?;
    if !address_eq(shielded_pool_program.address(), &crate::ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let system_program = iter.next_account("system_program")?;
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ShieldedPoolError::InvalidSystemProgram.into());
    }
    Ok(())
}
