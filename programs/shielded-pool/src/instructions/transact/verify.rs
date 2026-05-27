use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address,
};
use zolana_interface::{
    instruction::{
        TransactData, PUBLIC_AMOUNT_DEPOSIT, PUBLIC_AMOUNT_NONE, PUBLIC_AMOUNT_WITHDRAW,
    },
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_CPI_AUTHORITY_BUMP,
};

use crate::{error::ShieldedPoolError, instructions::transact::settlement::SettlementAccounts};

const SPP_INPUTS: usize = 1;
const SPP_OUTPUTS: usize = 2;

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

    if data.nullifiers.len() > SPP_INPUTS || data.output_utxo_hashes.len() > SPP_OUTPUTS {
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
            if sol_amount != 0
                || spl_amount != 0
                || data.public_spl_asset_id != 0
                || data.relayer_fee != 0
            {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
        }
        PUBLIC_AMOUNT_DEPOSIT => {
            if sol_amount == 0 && spl_amount == 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
            if spl_amount == 0 && data.public_spl_asset_id != 0 {
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
            if spl_amount == 0 && data.public_spl_asset_id != 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
            if data.relayer_fee != 0 && sol_amount == 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
        }
        _ => return Err(ShieldedPoolError::InvalidTransactShape.into()),
    }

    load_transact_accounts(program_id, accounts, sol_amount != 0, spl_amount != 0)
}

fn load_transact_accounts<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
    needs_sol: bool,
    needs_spl: bool,
) -> Result<TransactAccounts<'a>, ProgramError> {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let (signer_slice, tail) = accounts.split_at_mut(1);
    let signer = &signer_slice[0];
    let (tree_slice, settlement_slice) = tail.split_at_mut(1);
    let tree = &mut tree_slice[0];

    if !signer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !tree.is_writable() || !tree.owned_by(program_id) {
        return Err(ShieldedPoolError::InvalidPoolTreeAccounts.into());
    }

    let mut settlement = SettlementAccounts::empty(signer);
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
