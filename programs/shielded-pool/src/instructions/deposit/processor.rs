use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{CpiData, DepositIxData, ZoneDepositIxData},
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    UTXO_DOMAIN,
};
use zolana_tree::TreeAccount;

use super::{
    account::DepositAccounts,
    event::{emit_proofless_event, ProoflessOutputCtx},
};
use crate::instructions::{
    hash::{field_from_u64, solana_pk_hash},
    settlement::{settle_sol, settle_spl, Settlement},
};

pub(crate) struct ZoneData {
    pub data_hash: [u8; 32],
    pub data: Vec<u8>,
}

pub(crate) struct DepositParams {
    pub view_tag: [u8; 32],
    pub owner: [u8; 32],
    pub blinding: [u8; 31],
    pub public_amount: Option<u64>,
    pub program: Option<CpiData>,
    pub zone: Option<ZoneData>,
}

#[profile]
pub fn process_deposit(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data =
        DepositIxData::deserialize(data).map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let depositor = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !depositor.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    process_deposit_internal::<false>(
        accounts,
        DepositParams {
            view_tag: data.view_tag,
            owner: data.owner,
            blinding: data.blinding,
            public_amount: data.public_amount,
            program: data.program,
            zone: None,
        },
    )
}

pub fn process_zone_deposit(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = ZoneDepositIxData::deserialize(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let depositor = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !depositor.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    process_deposit_internal::<true>(
        accounts,
        DepositParams {
            view_tag: data.view_tag,
            owner: data.owner,
            blinding: data.blinding,
            public_amount: data.public_amount,
            program: data.program,
            zone: Some(ZoneData {
                data_hash: data.zone_data_hash,
                data: data.zone_data,
            }),
        },
    )
}

fn process_deposit_internal<const HAS_ZONE: bool>(
    accounts: &mut [AccountView],
    d: DepositParams,
) -> ProgramResult {
    let amount = match d.public_amount {
        Some(amount) if amount > 0 => amount,
        _ => return Err(ShieldedPoolError::InvalidTransactShape.into()),
    };

    let (parsed, zone_program_id) =
        DepositAccounts::validate_and_parse::<HAS_ZONE>(&crate::ID, accounts)?;
    let needs_spl = matches!(parsed.settlement, Settlement::Spl(_));

    let asset = parsed.asset;
    let asset_field = solana_pk_hash(&asset)?;

    let zero = [0u8; 32];
    let data_hash = match &d.program {
        Some(program) => program.data_hash,
        None => zero,
    };
    let (zone_data_hash, zone_id_field) = match (&d.zone, &zone_program_id) {
        (Some(zone), Some(program_id)) => (zone.data_hash, solana_pk_hash(program_id)?),
        _ => (zero, zero),
    };
    let zone_hash = hash_with_program_id(&zone_data_hash, &zone_id_field)?;
    let mut blinding = [0u8; 32];
    blinding[1..].copy_from_slice(&d.blinding);
    let owner_utxo_hash = Poseidon::hashv(&[d.owner.as_slice(), blinding.as_slice()])
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
    let utxo_hash = Poseidon::hashv(&[
        field_from_u64(u64::from(UTXO_DOMAIN)).as_slice(),
        asset_field.as_slice(),
        field_from_u64(amount).as_slice(),
        data_hash.as_slice(),
        zone_hash.as_slice(),
        owner_utxo_hash.as_slice(),
    ])
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    let mut output_tree = [0u8; 32];
    output_tree.copy_from_slice(parsed.tree.address().as_ref());
    let first_output_leaf_index = {
        let mut tree =
            TreeAccount::from_account_view_mut(parsed.tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
                .map_err(ShieldedPoolError::from)?;
        let index = tree.utxo_tree().next_index();
        tree.utxo_tree().append(utxo_hash);
        index
    };

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
            zone_program_id,
        },
    )
}

fn hash_with_program_id(
    data_hash: &[u8; 32],
    program_id_field: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    Poseidon::hashv(&[data_hash.as_slice(), program_id_field.as_slice()])
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed.into())
}
