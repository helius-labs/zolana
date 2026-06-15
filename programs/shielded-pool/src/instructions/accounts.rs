use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_interface::{
    instruction::{InputUtxoSignerIndex, TransactIxData, PUBLIC_AMOUNT_WITHDRAW_SPL},
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_CPI_AUTHORITY_BUMP, SOL_INTERFACE_PDA_SEED,
};

use crate::{
    error::ShieldedPoolError,
    instructions::settlement::{PublicSettlement, SettlementAccounts},
};

/// CPI-signer PDA seed for a general program owner (`transact`,
/// `proofless_shield`). Distinct from [`ZONE_AUTH_SEED`]: a general program
/// owner and a policy zone are different capabilities.
pub(crate) const CPI_SIGNER_SEED: &[u8] = b"auth";

/// CPI-signer PDA seed for a policy zone (`zone_proofless_shield`, and the
/// reserved zone instructions). See spec: Zone Accounts (`zone_auth`).
pub(crate) const ZONE_AUTH_SEED: &[u8] = b"zone_auth";

pub struct TransactAccounts<'a> {
    pub tree: &'a mut AccountView,
    pub settlement: SettlementAccounts<'a>,
}

pub(crate) fn load_transact_accounts<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
    data: &TransactIxData,
    cpi_signer_seed: &[u8],
) -> Result<TransactAccounts<'a>, ProgramError> {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let account_snapshot = account_snapshot(accounts);
    validate_cpi_signer(&account_snapshot, data, cpi_signer_seed)?;
    let input_owner_pubkeys = validate_input_signer_indices(&account_snapshot, data)?;

    let (tree_slice, tail) = accounts.split_at_mut(1);
    let tree = &mut tree_slice[0];
    let (signer_slice, tail) = tail.split_at_mut(1);
    let signer = &signer_slice[0];
    let cpi_signer_accounts = usize::from(data.cpi_signer.is_some());
    if tail.len() < cpi_signer_accounts {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (_cpi_signer_slice, settlement_slice) = tail.split_at_mut(cpi_signer_accounts);

    if !signer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !tree.is_writable() || !tree.owned_by(program_id) {
        return Err(ShieldedPoolError::InvalidTreeAccounts.into());
    }
    crate::instructions::protocol_config::processor::assert_tree_not_paused(tree)?;

    let mut settlement = SettlementAccounts::empty(signer);
    settlement.solana_owner_pubkeys = input_owner_pubkeys;
    let settlement_requirements = PublicSettlement::try_from(data)?;
    let mut cursor = 0usize;

    if settlement_requirements.needs_system_program() {
        if settlement_slice.len() < cursor + 2 {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        settlement.system_program = Some(&settlement_slice[cursor]);
        settlement.sol_interface = Some(&settlement_slice[cursor + 1]);
        cursor += 2;
    }

    if settlement_requirements.has_public_sol() {
        if settlement_slice.len() <= cursor {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        settlement.user_sol_account = Some(&settlement_slice[cursor]);
        cursor += 1;
    }

    if settlement_requirements.has_public_spl() {
        if settlement.spl_vault_authority.is_none()
            && data.public_amount_mode == PUBLIC_AMOUNT_WITHDRAW_SPL
        {
            if settlement_slice.len() <= cursor {
                return Err(ProgramError::NotEnoughAccountKeys);
            }
            settlement.spl_vault_authority = Some(&settlement_slice[cursor]);
            cursor += 1;
        }
        if settlement_slice.len() < cursor + 4 {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        settlement.user_spl_token_account = Some(&settlement_slice[cursor]);
        settlement.spl_token_interface = Some(&settlement_slice[cursor + 1]);
        settlement.spl_asset_registry = Some(&settlement_slice[cursor + 2]);
        settlement.token_program = Some(&settlement_slice[cursor + 3]);
        cursor += 4;
    }

    if cursor != settlement_slice.len() {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    if let Some(sol_interface) = settlement.sol_interface {
        let (expected, bump) =
            Address::derive_program_address(&[SOL_INTERFACE_PDA_SEED], program_id)
                .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
        if *sol_interface.address() != expected {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }
        settlement.sol_interface_bump = Some(bump);
    }

    if let Some(spl_vault_authority) = settlement.spl_vault_authority {
        let expected = Address::from(SHIELDED_POOL_CPI_AUTHORITY);
        if *spl_vault_authority.address() != expected {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }
        settlement.spl_vault_authority_bump = Some(SHIELDED_POOL_CPI_AUTHORITY_BUMP);
    }

    Ok(TransactAccounts { tree, settlement })
}

#[derive(Clone, Copy)]
struct AccountSnapshot {
    address: Address,
    is_signer: bool,
}

fn account_snapshot(accounts: &[AccountView]) -> Vec<AccountSnapshot> {
    accounts
        .iter()
        .map(|account| AccountSnapshot {
            address: *account.address(),
            is_signer: account.is_signer(),
        })
        .collect()
}

fn validate_cpi_signer(
    accounts: &[AccountSnapshot],
    data: &TransactIxData,
    seed: &[u8],
) -> Result<(), ProgramError> {
    let Some(cpi_signer) = data.cpi_signer else {
        return Ok(());
    };
    let account = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let bump = [cpi_signer.bump];
    let expected = derive_cpi_signer_address(cpi_signer.program_id, &bump, seed)?;
    if account.address != expected {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    Ok(())
}

fn validate_input_signer_indices(
    accounts: &[AccountSnapshot],
    data: &TransactIxData,
) -> Result<Vec<[u8; 32]>, ProgramError> {
    let mut owner_pubkeys = vec![[0u8; 32]; data.inputs.len()];
    if data.inputs.is_empty() {
        if data
            .in_utxo_signer_indices
            .as_ref()
            .is_some_and(|indices| !indices.is_empty())
        {
            return Err(ShieldedPoolError::InvalidTransactShape.into());
        }
        return Ok(owner_pubkeys);
    }

    let indices = data.in_utxo_signer_indices.as_deref().unwrap_or(&[]);
    if indices.len() > data.inputs.len() {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }

    let mut seen = vec![false; data.inputs.len()];
    for index in indices {
        validate_input_signer_index(
            accounts,
            data.inputs.len(),
            index,
            &mut seen,
            &mut owner_pubkeys,
        )?;
    }
    Ok(owner_pubkeys)
}

fn validate_input_signer_index(
    accounts: &[AccountSnapshot],
    active_inputs: usize,
    index: &InputUtxoSignerIndex,
    seen: &mut [bool],
    owner_pubkeys: &mut [[u8; 32]],
) -> Result<(), ProgramError> {
    let input_index = index.input_index as usize;
    if input_index >= active_inputs {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    if seen[input_index] {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    let account = accounts
        .get(index.account_index as usize)
        .ok_or(ShieldedPoolError::InvalidTransactShape)?;
    if !account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    owner_pubkeys[input_index] = account.address.to_bytes();
    seen[input_index] = true;
    Ok(())
}

fn derive_cpi_signer_address(
    program_id: [u8; 32],
    bump: &[u8; 1],
    seed: &[u8],
) -> Result<Address, ProgramError> {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        Address::create_program_address(&[seed, bump.as_slice()], &Address::from(program_id))
            .map_err(|_| ShieldedPoolError::InvalidSettlementAccounts.into())
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        let _ = (program_id, bump, seed);
        Err(ShieldedPoolError::InvalidSettlementAccounts.into())
    }
}
