use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address,
};
use zolana_interface::{
    instruction::{
        InputUtxoSignerIndex, TransactData, PUBLIC_AMOUNT_DEPOSIT, PUBLIC_AMOUNT_NONE,
        PUBLIC_AMOUNT_WITHDRAW,
    },
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_CPI_AUTHORITY_BUMP,
};

use crate::{error::ShieldedPoolError, instructions::transact::settlement::SettlementAccounts};

const SPP_MAX_INPUTS: usize = 5;
const SPP_MAX_OUTPUTS: usize = 8;

pub struct TransactAccounts<'a> {
    pub tree: &'a mut AccountView,
    pub settlement: SettlementAccounts<'a>,
}

pub fn verify<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
    data: &TransactData,
) -> Result<TransactAccounts<'a>, ProgramError> {
    if data.utxo_tree_root_index.len() != data.nullifiers.len()
        || data.nullifier_tree_root_index.len() != data.nullifiers.len()
    {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }

    if super::proof::canonical_shape(data).is_err()
        || data.nullifiers.len() > SPP_MAX_INPUTS
        || data.output_utxo_hashes.len() > SPP_MAX_OUTPUTS
    {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }

    if data.nullifiers.is_empty()
        && data
            .output_utxo_hashes
            .iter()
            .all(|hash| hash.iter().all(|b| *b == 0))
    {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }

    let now = Clock::get()?.unix_timestamp;
    if now >= 0 && (now as u64) > data.expiry_unix_ts {
        return Err(ShieldedPoolError::ExpiredTransaction.into());
    }

    let sol_amount = data.public_sol_amount.unwrap_or(0);
    let spl_amount = data.public_spl_amount.unwrap_or(0);
    match data.public_amount_mode {
        PUBLIC_AMOUNT_NONE => {
            if sol_amount != 0 || spl_amount != 0 || data.relayer_fee != 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
        }
        PUBLIC_AMOUNT_DEPOSIT => {
            if sol_amount == 0 && spl_amount == 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
            if data.relayer_fee != 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
        }
        PUBLIC_AMOUNT_WITHDRAW => {
            if sol_amount == 0 && spl_amount == 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
            // Relayer fees are paid in SOL, so SPL-only withdrawals cannot carry one.
            if data.relayer_fee != 0 && sol_amount == 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
        }
        _ => return Err(ShieldedPoolError::InvalidTransactShape.into()),
    }

    load_transact_accounts(program_id, accounts, data, sol_amount != 0, spl_amount != 0)
}

fn load_transact_accounts<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
    data: &TransactData,
    needs_sol: bool,
    needs_spl: bool,
) -> Result<TransactAccounts<'a>, ProgramError> {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let account_snapshot = account_snapshot(accounts);
    validate_cpi_signer(&account_snapshot, data)?;
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
        return Err(ShieldedPoolError::InvalidPoolTreeAccounts.into());
    }
    crate::instructions::protocol_config::processor::assert_tree_not_paused(tree)?;

    let mut settlement = SettlementAccounts::empty(signer);
    settlement.solana_owner_pubkeys = input_owner_pubkeys;
    let mut cursor = 0usize;

    if needs_sol {
        if settlement_slice.len() < cursor + 3 {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        settlement.system_program = Some(&settlement_slice[cursor]);
        settlement.cpi_authority = Some(&settlement_slice[cursor + 1]);
        settlement.user_sol_account = Some(&settlement_slice[cursor + 2]);
        cursor += 3;
    }

    if needs_spl {
        if settlement.cpi_authority.is_none() {
            if settlement_slice.len() <= cursor {
                return Err(ProgramError::NotEnoughAccountKeys);
            }
            settlement.cpi_authority = Some(&settlement_slice[cursor]);
            cursor += 1;
        }
        if settlement_slice.len() < cursor + 4 {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        settlement.user_spl_token_account = Some(&settlement_slice[cursor]);
        settlement.spl_vault = Some(&settlement_slice[cursor + 1]);
        settlement.spl_asset_registry = Some(&settlement_slice[cursor + 2]);
        settlement.token_program = Some(&settlement_slice[cursor + 3]);
        cursor += 4;
    }

    if cursor != settlement_slice.len() {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    if let Some(cpi_authority) = settlement.cpi_authority {
        let expected = Address::from(SHIELDED_POOL_CPI_AUTHORITY);
        if *cpi_authority.address() != expected {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }
        settlement.cpi_authority_bump = Some(SHIELDED_POOL_CPI_AUTHORITY_BUMP);
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
    data: &TransactData,
) -> Result<(), ProgramError> {
    let Some(cpi_signer) = data.cpi_signer else {
        return Ok(());
    };
    let account = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let bump = [cpi_signer.bump];
    let expected = derive_cpi_signer_address(cpi_signer.program_id, &bump)?;
    if account.address != expected {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    Ok(())
}

fn validate_input_signer_indices(
    accounts: &[AccountSnapshot],
    data: &TransactData,
) -> Result<Vec<[u8; 32]>, ProgramError> {
    let mut owner_pubkeys = vec![[0u8; 32]; data.nullifiers.len()];
    if data.nullifiers.is_empty() {
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
    if indices.len() > data.nullifiers.len() {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }

    let mut seen = [false; SPP_MAX_INPUTS];
    for index in indices {
        validate_input_signer_index(
            accounts,
            data.nullifiers.len(),
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
    seen: &mut [bool; SPP_MAX_INPUTS],
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
) -> Result<Address, ProgramError> {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        Address::create_program_address(&[b"auth", bump.as_slice()], &Address::from(program_id))
            .map_err(|_| ShieldedPoolError::InvalidSettlementAccounts.into())
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        let _ = (program_id, bump);
        Err(ShieldedPoolError::InvalidSettlementAccounts.into())
    }
}
