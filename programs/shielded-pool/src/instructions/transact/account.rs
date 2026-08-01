use arrayvec::ArrayVec;
use pinocchio::{address::address_eq, error::ProgramError, AccountView};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{InterfaceTransfer, TransactIxDataRef},
        validate_interface_transfers,
    },
    MAX_INTERFACE_TRANSFERS,
};

use crate::instructions::ring_config::loader::load_ring_config;
use crate::instructions::settlement::{
    validate_sol_settlement, validate_spl_deposit_settlement, validate_spl_withdrawal_settlement,
    Settlement, SettlementAccountsSol, SplDepositAccounts, SplWithdrawalAccounts,
};

pub struct TransactAccounts<'a> {
    pub payer: &'a AccountView,
    pub input_tree: &'a mut AccountView,
    pub output_tree: &'a mut AccountView,
    pub owner_signers: &'a [AccountView],
    pub settlements: ArrayVec<Settlement<'a>, MAX_INTERFACE_TRANSFERS>,
}

impl<'a> TransactAccounts<'a> {
    /// 1. payer - mut signer
    /// 2. input tree - mut
    /// 3. output tree - mut
    /// 4. self program - program id match
    /// 5. system program - program id match
    /// 6. N signers - signer
    ///    6 + N: transfer settlement accounts -
    pub fn validate_and_parse(
        accounts: &'a mut [AccountView],
        ix: &TransactIxDataRef<'_>,
    ) -> Result<Box<Self>, ProgramError> {
        let mut iter = AccountIterator::new(accounts);

        let payer: &AccountView = iter.next_signer("payer")?;
        let input_tree = iter.next_mut("input_tree")?;
        let output_tree = iter.next_mut("output_tree")?;
        validate_program_prefix(&mut iter)?;

        Self::from_iter(iter, ix, payer, input_tree, output_tree, true)
    }

    /// 1. Validate spl interface transfers.
    pub(crate) fn from_iter(
        iter: AccountIterator<'a>,
        ix: &TransactIxDataRef<'_>,
        payer: &'a AccountView,
        input_tree: &'a mut AccountView,
        output_tree: &'a mut AccountView,
        allow_owner_signers: bool,
    ) -> Result<Box<Self>, ProgramError> {
        // Check non-zero amounts and the protocol transfer bound.
        validate_interface_transfers(&ix.interface_transfers)?;

        let remaining = iter.remaining_unchecked_mut()?;
        // 2. Search first account that is not signer.
        let signer_count = remaining
            .iter()
            .position(|account| !account.is_signer())
            .unwrap_or(remaining.len());
        if signer_count > usize::from(ix.circuit.num_inputs())
            || (!allow_owner_signers && signer_count != 0)
        {
            return Err(ShieldedPoolError::InvalidTransactShape.into());
        }
        let (owner_signers, settlement_accounts) = remaining.split_at_mut(signer_count);
        // 3. Check transfer settlement accounts.
        let mut iter = AccountIterator::new(settlement_accounts);
        let mut settlements = ArrayVec::new();
        for transfer in &ix.interface_transfers {
            let settlement = match transfer {
                InterfaceTransfer::SplDeposit {
                    spl_interface_bump, ..
                } => {
                    let mint_account = iter.next_account("mint")?;
                    let spl_interface_account = iter.next_account("spl_interface")?;
                    let token_authority = iter.next_account("token_authority")?;
                    let user_token_account = iter.next_account("user_token_account")?;
                    let token_program = iter.next_account("token_program")?;
                    let mint_state = validate_spl_deposit_settlement(
                        mint_account,
                        spl_interface_account,
                        user_token_account,
                        token_program,
                        *spl_interface_bump,
                        token_authority,
                    )?;
                    Settlement::SplDeposit(SplDepositAccounts {
                        mint_account,
                        decimals: mint_state.decimals,
                        spl_interface_account,
                        token_authority_account: token_authority,
                        user_token_account,
                        token_program_account: token_program,
                    })
                }
                InterfaceTransfer::SplWithdrawal {
                    spl_interface_bump, ..
                } => {
                    let cpi_authority = iter.next_non_mut("cpi_authority")?;
                    let mint_account = iter.next_account("mint")?;
                    let spl_interface_account = iter.next_account("spl_interface")?;
                    let user_token_account = iter.next_account("user_token_account")?;
                    let token_program = iter.next_account("token_program")?;
                    let mint_state = validate_spl_withdrawal_settlement(
                        cpi_authority,
                        mint_account,
                        spl_interface_account,
                        user_token_account,
                        token_program,
                        *spl_interface_bump,
                    )?;
                    Settlement::SplWithdrawal(SplWithdrawalAccounts {
                        cpi_authority_account: cpi_authority,
                        mint_account,
                        decimals: mint_state.decimals,
                        spl_interface_account,
                        user_token_account,
                        token_program_account: token_program,
                    })
                }
                InterfaceTransfer::SolDeposit { .. } => {
                    let sol_interface = iter.next_account("sol_interface")?;
                    let recipient = iter.next_account("recipient")?;
                    let sol_interface_bump = validate_sol_settlement(sol_interface, recipient)?;
                    Settlement::SolDeposit(SettlementAccountsSol {
                        sol_interface_account: sol_interface,
                        sol_interface_bump,
                        recipient_account: recipient,
                    })
                }
                InterfaceTransfer::SolWithdrawal { .. } => {
                    let sol_interface = iter.next_account("sol_interface")?;
                    let recipient = iter.next_account("recipient")?;
                    let sol_interface_bump = validate_sol_settlement(sol_interface, recipient)?;
                    Settlement::SolWithdrawal(SettlementAccountsSol {
                        sol_interface_account: sol_interface,
                        sol_interface_bump,
                        recipient_account: recipient,
                    })
                }
            };
            settlements
                .try_push(settlement)
                .map_err(|_| ShieldedPoolError::TooManyInterfaceTransfers)?;
        }
        if !iter.iterator_is_empty() {
            return Err(ShieldedPoolError::InvalidTransactShape.into());
        }

        Ok(Box::new(Self {
            payer,
            input_tree,
            output_tree,
            owner_signers,
            settlements,
        }))
    }
}

pub struct RingTransactAccounts;

impl RingTransactAccounts {
    /// Parse the accounts shared by `ring_transact` and `ring_authority_transact`:
    /// `payer`, `input_tree`, `output_tree`, SPP, System Program, the `RingConfig`
    /// account (the ring's `ring_auth` PDA), then owner signers and settlement
    /// accounts. Returns the parsed transact accounts and the ring's
    /// `program_id`, read from the validated `RingConfig` (never re-derived; the
    /// create-time `ring_auth` derivation already bound it). `require_enabled`
    /// additionally requires
    /// `ring_authority_transact_is_enabled` (only `ring_authority_transact` sets it).
    pub fn validate_and_parse<'a>(
        accounts: &'a mut [AccountView],
        ix: &TransactIxDataRef<'_>,
        require_ring_authority_enabled: bool,
    ) -> Result<(Box<TransactAccounts<'a>>, [u8; 32]), ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let payer: &AccountView = iter.next_signer("payer")?;
        let input_tree = iter.next_mut("input_tree")?;
        let output_tree = iter.next_mut("output_tree")?;
        validate_program_prefix(&mut iter)?;
        // The `ring_config` must sign (only the ring program can sign for its
        // `ring_auth` PDA); validate owner / discriminator and read the bound ring
        // `program_id`.
        let ring_config = iter.next_signer("ring_config")?;
        let (ring_program_id, ring_authority_is_enabled) = {
            let config = load_ring_config(ring_config)?;
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
