use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{DepositIxData, ZoneDepositIxData},
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

/// Zone data committed into the UTXO's `zone_hash`. Unlike the program side, the
/// zone carries no `cpi_signer`: its `program_id` is read from the `ZoneConfig`
/// account (the signing `zone_auth` PDA), not from instruction data.
pub(crate) struct ZoneData {
    pub data_hash: [u8; 32],
    pub data: Vec<u8>,
}

/// Parsed instruction request shared across this instruction's submodules.
pub(crate) struct DepositParams {
    pub view_tag: [u8; 32],
    pub owner: [u8; 32],
    pub blinding: [u8; 31],
    pub public_amount: Option<u64>,
    /// Authorizing zone (`zone_hash`). Only `zone_deposit` populates it; the
    /// zone's `program_id` comes from the loaded `ZoneConfig`, not from here.
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
    // Account 2 is the `ZoneConfig` (the zone's `zone_auth` PDA); its signature,
    // owner/discriminator, and `program_id` are checked in `validate_and_parse`.
    process_deposit_internal::<true>(
        accounts,
        DepositParams {
            view_tag: data.view_tag,
            owner: data.owner,
            blinding: data.blinding,
            public_amount: data.public_amount,
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
    // A deposit must shield a positive amount; reject a missing or zero amount.
    let amount = match d.public_amount {
        Some(amount) if amount > 0 => amount,
        _ => return Err(ShieldedPoolError::InvalidTransactShape.into()),
    };

    // SOL vs SPL is inferred from the settlement accounts the caller passes. The
    // zone's `program_id` is read from the loaded `ZoneConfig` (returned here),
    // never derived. Proofless deposits carry no program signer.
    let (parsed, zone_program_id) =
        DepositAccounts::validate_and_parse::<HAS_ZONE>(&crate::ID, accounts, None)?;
    let needs_spl = matches!(parsed.settlement, Settlement::Spl(_));

    let asset = parsed.asset;
    let asset_field = solana_pk_hash(&asset)?;

    // A proofless deposit carries no program data and cannot create an address:
    // its `program_hash` preimage is all zero (`Poseidon(address=0,
    // program_data_hash=0)`). The zone side keeps its two-part commitment: pair
    // the `zone_data_hash` with the `ZoneConfig`-read id (pk_field-encoded) into
    // `zone_hash`. An absent zone hashes over zeros.
    let zero = [0u8; 32];
    let program_hash = hash_with_program_id(&zero, &zero)?;
    let (zone_data_hash, zone_id_field) = match (&d.zone, &zone_program_id) {
        (Some(zone), Some(program_id)) => (zone.data_hash, solana_pk_hash(program_id)?),
        _ => (zero, zero),
    };
    let zone_hash = hash_with_program_id(&zone_data_hash, &zone_id_field)?;
    // Nest the recipient `owner` with the right-aligned `blinding` into the
    // owner commitment, matching the SDK's `owner_utxo_hash`.
    let mut blinding = [0u8; 32];
    blinding[1..].copy_from_slice(&d.blinding);
    let owner_utxo_hash = Poseidon::hashv(&[d.owner.as_slice(), blinding.as_slice()])
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
    let utxo_hash = Poseidon::hashv(&[
        field_from_u64(u64::from(UTXO_DOMAIN)).as_slice(),
        asset_field.as_slice(),
        field_from_u64(amount).as_slice(),
        program_hash.as_slice(),
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
            zone_program_id,
        },
    )
}

/// Fold a two-field sub-commitment: `program_hash = Poseidon(address,
/// program_data_hash)` (both zero for proofless) and `zone_hash =
/// Poseidon(zone_data_hash, zone_id_field)`. An absent side passes zeros.
fn hash_with_program_id(
    first: &[u8; 32],
    second: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    Poseidon::hashv(&[first.as_slice(), second.as_slice()])
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed.into())
}
