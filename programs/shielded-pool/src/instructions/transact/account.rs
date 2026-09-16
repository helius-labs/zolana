use arrayvec::ArrayVec;
use pinocchio::{address::address_eq, error::ProgramError, AccountView};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{InterfaceTransfer, TransactIxDataRef},
        validate_interface_transfers,
    },
    shape::owner_signer_slots,
    INPUT_TREES, MAX_INPUT_TREES, MAX_INTERFACE_TRANSFERS,
};

use super::verify::MAX_INPUTS;
use crate::instructions::ring_config::loader::load_active_ring_config;
use crate::instructions::settlement::{
    validate_sol_settlement, validate_spl_deposit_settlement, validate_spl_withdrawal_settlement,
    Settlement, SettlementAccountsSol, SplDepositAccounts, SplWithdrawalAccounts,
};

pub struct TransactAccounts<'a> {
    pub payer: &'a AccountView,
    /// One account per declared tree context, in context order. An input's
    /// `tree_index` selects its tree from this run.
    pub input_trees: ArrayVec<&'a mut AccountView, INPUT_TREES>,
    pub output_tree: &'a mut AccountView,
    pub nullifier_pdas: ArrayVec<&'a mut AccountView, { MAX_INPUTS + MAX_INPUT_TREES }>,
    pub owner_signers: &'a [AccountView],
    pub settlements: ArrayVec<Settlement<'a>, MAX_INTERFACE_TRANSFERS>,
}

impl<'a> TransactAccounts<'a> {
    /// 1. payer - mut signer
    /// 2. output tree - mut
    /// 3. self program - program id match
    /// 4. system program - program id match
    /// 5. T input trees - mut, one per declared tree context, in context order
    ///    5 + T: I nullifier PDAs - mut, one per input in `inputs` order
    ///    5 + T + I: N signers - signer
    ///    5 + T + I + N: transfer settlement accounts -
    pub fn validate_and_parse(
        accounts: &'a mut [AccountView],
        ix: &TransactIxDataRef<'_>,
    ) -> Result<Box<Self>, ProgramError> {
        let mut iter = AccountIterator::new(accounts);

        let payer: &AccountView = iter.next_signer("payer")?;
        let output_tree = iter.next_mut("output_tree")?;
        validate_program_prefix(&mut iter)?;
        let input_trees = parse_input_trees(&mut iter, ix)?;

        Self::from_iter(iter, ix, payer, input_trees, output_tree, true)
    }

    /// 1. Validate spl interface transfers.
    pub(crate) fn from_iter(
        mut iter: AccountIterator<'a>,
        ix: &TransactIxDataRef<'_>,
        payer: &'a AccountView,
        input_trees: ArrayVec<&'a mut AccountView, INPUT_TREES>,
        output_tree: &'a mut AccountView,
        allow_owner_signers: bool,
    ) -> Result<Box<Self>, ProgramError> {
        // Check non-zero amounts and the protocol transfer bound.
        validate_interface_transfers(&ix.interface_transfers)?;

        let mut this = Box::new(Self {
            payer,
            input_trees,
            output_tree,
            nullifier_pdas: ArrayVec::new(),
            owner_signers: &[],
            settlements: ArrayVec::new(),
        });
        let mut nullifier_accounts = 0;
        for (index, tree) in this.input_trees.iter().enumerate() {
            let inputs = ix
                .inputs
                .iter()
                .filter(|input| usize::from(input.tree_index) == index)
                .count();
            nullifier_accounts +=
                crate::instructions::nullifier_pda::nullifier_account_count(tree, inputs)?;
        }
        for _ in 0..nullifier_accounts {
            this.nullifier_pdas
                .try_push(iter.next_mut("nullifier_pda")?)
                .map_err(|_| ShieldedPoolError::InvalidTransactShape)?;
        }

        let remaining = iter.remaining_unchecked_mut()?;
        // 2. Search first account that is not signer.
        let signer_count = remaining
            .iter()
            .position(|account| !account.is_signer())
            .unwrap_or(remaining.len());
        if signer_count > owner_signer_slots(usize::from(ix.circuit.num_inputs()))
            || (!allow_owner_signers && signer_count != 0)
        {
            return Err(ShieldedPoolError::InvalidTransactShape.into());
        }
        let (owner_signers, settlement_accounts) = remaining.split_at_mut(signer_count);
        this.owner_signers = owner_signers;
        // 3. Check transfer settlement accounts: exactly one group per leg, sized
        //    by the shared layout the event parser also reads.
        let settlement_account_count = ix
            .interface_transfers
            .iter()
            .try_fold(0usize, |total, transfer| {
                total.checked_add(transfer.settlement_account_count())
            })
            .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
        if settlement_accounts.len() != settlement_account_count {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }
        let mut iter = AccountIterator::new(settlement_accounts);
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
            this.settlements
                .try_push(settlement)
                .map_err(|_| ShieldedPoolError::TooManyInterfaceTransfers)?;
        }

        Ok(this)
    }
}

pub struct RingTransactAccounts;

impl RingTransactAccounts {
    /// Parse the accounts shared by `ring_transact` and `ring_authority_transact`:
    /// `payer`, `output_tree`, SPP, System Program, the `RingConfig`
    /// account (the ring's `ring_auth` PDA), the input-tree run, one writable nullifier PDA per input
    /// in `inputs` order, then owner signers and settlement
    /// accounts. Returns the parsed transact accounts and the ring's
    /// `program_id`, read from the validated, unpaused `RingConfig` (never
    /// re-derived; the create-time `ring_auth` derivation already bound it).
    /// `require_enabled` additionally requires
    /// `ring_authority_transact_is_enabled` (only `ring_authority_transact` sets it).
    pub fn validate_and_parse<'a>(
        accounts: &'a mut [AccountView],
        ix: &TransactIxDataRef<'_>,
        require_ring_authority_enabled: bool,
    ) -> Result<(Box<TransactAccounts<'a>>, [u8; 32]), ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let payer: &AccountView = iter.next_signer("payer")?;
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
        let input_trees = parse_input_trees(&mut iter, ix)?;
        // Ring authority instruction does not require any signatures.
        let allow_owner_signers = !require_ring_authority_enabled;
        let transact_accounts = TransactAccounts::from_iter(
            iter,
            ix,
            payer,
            input_trees,
            output_tree,
            allow_owner_signers,
        )?;
        Ok((transact_accounts, ring_program_id))
    }
}

/// The input-tree run after the fixed prefix: one writable tree per declared
/// tree context, in context order. The caller must validate the context count
/// with `validate_input_tree_contexts` first. Duplicate trees are rejected here
/// so no tree is credited or queued twice in one instruction.
fn parse_input_trees<'a>(
    iter: &mut AccountIterator<'a>,
    ix: &TransactIxDataRef<'_>,
) -> Result<ArrayVec<&'a mut AccountView, INPUT_TREES>, ProgramError> {
    let tree_count = ix.tree_contexts.len();
    let mut input_trees: ArrayVec<&'a mut AccountView, INPUT_TREES> = ArrayVec::new();
    for _ in 0..tree_count {
        let input_tree = iter.next_mut("input_tree")?;
        if input_trees
            .iter()
            .any(|tree| address_eq(tree.address(), input_tree.address()))
        {
            return Err(ShieldedPoolError::DuplicateInputTree.into());
        }
        input_trees
            .try_push(input_tree)
            .map_err(|_| ShieldedPoolError::InvalidTreeContextCount)?;
    }
    Ok(input_trees)
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

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_account_checks::account_info::test_account_info::get_account_view;
    use zolana_interface::instruction::instruction_data::transact::{
        CircuitId, InputUtxo, TransactProof, TreeContext,
    };
    use zolana_tree::{NullifierFilterMode, SppTreeLayout};

    #[test]
    fn mixed_tree_nullifier_accounts_leave_owner_signers_intact() {
        for compact in [false, true] {
            for mode in [
                NullifierFilterMode::Off,
                NullifierFilterMode::Active,
                NullifierFilterMode::Retired,
            ] {
                if !compact && mode != NullifierFilterMode::Off {
                    continue;
                }
                for compact_first in [false, true] {
                    let compact_index = usize::from(!compact_first);
                    let tree_data = |index| {
                        let offset = core::mem::offset_of!(SppTreeLayout, _reserved);
                        let mut bytes = vec![0; offset + 2];
                        if index == compact_index {
                            bytes[offset] = u8::from(compact);
                            bytes[offset + 1] = mode as u8;
                        }
                        bytes
                    };
                    let account = |address, signer, writable, data| {
                        get_account_view(
                            address,
                            crate::ID.to_bytes(),
                            signer,
                            writable,
                            false,
                            data,
                        )
                    };
                    let mut accounts = vec![
                        account([1; 32], true, true, vec![]),
                        account([2; 32], false, true, vec![]),
                        account(crate::ID.to_bytes(), false, false, vec![]),
                        account([0; 32], false, false, vec![]),
                        account([3; 32], false, true, tree_data(0)),
                        account([4; 32], false, true, tree_data(1)),
                    ];
                    let count = MAX_INPUTS + usize::from(mode == NullifierFilterMode::Active);
                    accounts.extend(
                        (0..count)
                            .map(|index| account([index as u8 + 20; 32], false, true, vec![])),
                    );
                    accounts.push(account([100; 32], true, false, vec![]));
                    let ix = TransactIxDataRef {
                        expiry_unix_ts: 0,
                        tx_viewing_pk: &[0; 33],
                        salt: &[0; 16],
                        interface_transfers: vec![],
                        data_hash: None,
                        ring_data_hash: None,
                        outputs: vec![],
                        messages: vec![],
                        private_tx_hash: &[0; 32],
                        circuit: CircuitId::ConfidentialEddsa(
                            MAX_INPUTS as u8,
                            2,
                            zolana_interface::N_PUBLIC_SLOTS as u8,
                        ),
                        proof: TransactProof::zeroed(),
                        inputs: (0..2)
                            .flat_map(|index| {
                                let count = if index == compact_index {
                                    1
                                } else {
                                    MAX_INPUTS - 1
                                };
                                std::iter::repeat_n(
                                    InputUtxo {
                                        nullifier_hash: [0; 32],
                                        tree_index: index as u8,
                                    },
                                    count,
                                )
                            })
                            .collect(),
                        tree_contexts: vec![
                            TreeContext {
                                utxo_tree_root_index: 0,
                                nullifier_tree_root_index: 0,
                            };
                            2
                        ],
                    };
                    let parsed = TransactAccounts::validate_and_parse(&mut accounts, &ix).unwrap();
                    assert_eq!(parsed.nullifier_pdas.len(), count);
                    assert_eq!(parsed.owner_signers.len(), 1);
                    assert_eq!(parsed.owner_signers[0].address().to_bytes(), [100; 32]);
                }
            }
        }
    }
}
