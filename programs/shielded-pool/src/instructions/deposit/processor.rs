use light_hasher::{Hasher, Poseidon};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::error::ShieldedPoolError;
use zolana_interface::instruction::instruction_data::proofless_shield::CpiSignerData;
use zolana_interface::instruction::{
    ProoflessShieldIxData, ZoneProoflessShieldIxData, PUBLIC_AMOUNT_DEPOSIT_SOL,
    PUBLIC_AMOUNT_DEPOSIT_SPL,
};
use zolana_interface::state::discriminator::TREE_ACCOUNT_DISCRIMINATOR;
use zolana_interface::{UTXO_DOMAIN, ZONE_AUTH_PDA_SEED};
use zolana_tree::TreeAccount;

use super::account::ProoflessShieldAccounts;
use super::event::{emit_proofless_event, ProoflessOutputCtx};
use crate::instructions::hash::{field_from_u64, solana_pk_hash};
use crate::instructions::settlement::{settle_sol, settle_spl, Settlement};
use crate::instructions::shared::CPI_SIGNER_SEED;

/// Parsed instruction request shared across this instruction's submodules.
pub(crate) struct DepositParams {
    pub view_tag: [u8; 32],
    pub owner_utxo_hash: [u8; 32],
    pub salt: [u8; 16],
    pub public_amount: Option<u64>,
    pub public_amount_mode: u8,
    pub cpi_signer: Option<CpiSignerData>,
    pub cpi_signer_seed: &'static [u8],
    pub program_data_hash: Option<[u8; 32]>,
    pub program_data: Option<Vec<u8>>,
    pub policy_data_hash: Option<[u8; 32]>,
    pub zone_data: Option<Vec<u8>>,
}

pub fn process_proofless_shield(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: ProoflessShieldIxData,
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let depositor = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !depositor.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.cpi_signer.is_some() {
        let cpi_signer = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
        if !cpi_signer.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }
    }
    if (data.program_data_hash.is_some() || data.program_data.is_some())
        && data.cpi_signer.is_none()
    {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    process_deposit(
        program_id,
        accounts,
        DepositParams {
            view_tag: data.view_tag,
            owner_utxo_hash: data.owner_utxo_hash,
            salt: data.salt,
            public_amount: data.public_amount,
            public_amount_mode: data.public_amount_mode,
            cpi_signer: data.cpi_signer,
            cpi_signer_seed: CPI_SIGNER_SEED,
            program_data_hash: data.program_data_hash,
            program_data: data.program_data,
            policy_data_hash: None,
            zone_data: None,
        },
    )
}

pub fn process_zone_proofless_shield(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: ZoneProoflessShieldIxData,
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let depositor = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !depositor.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let zone_auth = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !zone_auth.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    process_deposit(
        program_id,
        accounts,
        DepositParams {
            view_tag: data.view_tag,
            owner_utxo_hash: data.owner_utxo_hash,
            salt: data.salt,
            public_amount: data.public_amount,
            public_amount_mode: data.public_amount_mode,
            cpi_signer: Some(data.cpi_signer),
            cpi_signer_seed: ZONE_AUTH_PDA_SEED,
            program_data_hash: data.program_data_hash,
            program_data: data.program_data,
            policy_data_hash: data.policy_data_hash,
            zone_data: data.zone_data,
        },
    )
}

fn process_deposit(
    program_id: &Address,
    accounts: &mut [AccountView],
    d: DepositParams,
) -> ProgramResult {
    // Proofless shields are deposit-only; reject withdraw / NONE / unknown modes.
    let needs_spl = match d.public_amount_mode {
        PUBLIC_AMOUNT_DEPOSIT_SOL => false,
        PUBLIC_AMOUNT_DEPOSIT_SPL => true,
        _ => return Err(ShieldedPoolError::InvalidTransactShape.into()),
    };
    let amount = d.public_amount.unwrap_or(0);

    let parsed = ProoflessShieldAccounts::validate_and_parse(
        program_id,
        accounts,
        d.cpi_signer,
        d.cpi_signer_seed,
        needs_spl,
    )?;

    let asset = parsed.asset;
    let asset_field = solana_pk_hash(&asset)?;

    let zero = [0u8; 32];
    let program_data_hash = d.program_data_hash.unwrap_or(zero);
    let policy_data_hash = d.policy_data_hash.unwrap_or(zero);
    let zone_program_id = match d.cpi_signer {
        Some(cpi) => solana_pk_hash(&cpi.program_id)?,
        None => zero,
    };
    let utxo_hash = Poseidon::hashv(&[
        field_from_u64(u64::from(UTXO_DOMAIN)).as_slice(),
        asset_field.as_slice(),
        field_from_u64(amount).as_slice(),
        program_data_hash.as_slice(),
        policy_data_hash.as_slice(),
        zone_program_id.as_slice(),
        d.owner_utxo_hash.as_slice(),
    ])
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    let mut output_tree = [0u8; 32];
    output_tree.copy_from_slice(parsed.tree.address().as_ref());
    let first_output_leaf_index = {
        let mut tree =
            TreeAccount::from_account_view_mut(parsed.tree, program_id, TREE_ACCOUNT_DISCRIMINATOR)
                .map_err(ShieldedPoolError::from)?;
        let index = tree.utxo_tree.next_index();
        tree.utxo_tree.append(utxo_hash);
        index
    };

    // Proofless shields are deposit-only; the SOL rail always deposits.
    match &parsed.settlement {
        Settlement::Sol(sol) => settle_sol(sol, amount, true)?,
        Settlement::Spl(spl) => settle_spl(spl, amount)?,
    }

    emit_proofless_event(
        d,
        ProoflessOutputCtx {
            utxo_hash,
            asset,
            needs_spl,
            amount,
            first_output_leaf_index,
            output_tree,
        },
    )
}
