use bytemuck::Zeroable;
use custom_ring_interface::{
    CoSignScope, CoSigner, SetCoSignerIxData, WithdrawalThresholdRow, MAX_CO_SIGNER_THRESHOLDS,
};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_authorized_config, load_cosigner_mut},
        shared::PdaCreate,
    },
    state::CoSignerInitParams,
};

#[inline(never)]
pub fn process_set_cosigner_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let SetCoSignerIxData {
        signer,
        scope,
        thresholds,
    } = wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    let scope = CoSignScope::new(scope).ok_or(CustomRingError::InvalidCoSignerScope)?;
    if signer == [0; 32] {
        return Err(CustomRingError::InvalidCoSigner.into());
    }
    if thresholds.len() > MAX_CO_SIGNER_THRESHOLDS {
        return Err(CustomRingError::InvalidCoSignerThresholds.into());
    }
    let mut rows = [WithdrawalThresholdRow::zeroed(); MAX_CO_SIGNER_THRESHOLDS];
    for (index, threshold) in thresholds.iter().enumerate() {
        if thresholds[..index]
            .iter()
            .any(|earlier| earlier.mint == threshold.mint)
        {
            return Err(CustomRingError::InvalidCoSignerThresholds.into());
        }
        rows[index] = WithdrawalThresholdRow {
            mint: Address::new_from_array(threshold.mint),
            amount: threshold.amount.to_le_bytes(),
        };
    }

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config_account = iter.next_account("config")?;
    let cosigner_account = iter.next_mut("cosigner")?;
    let system_program = iter.next_account("system_program")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    load_authorized_config(program_id, config_account, authority)?;

    let params = |bump| CoSignerInitParams {
        signer: Address::new_from_array(signer),
        scope: scope.bits(),
        thresholds: rows,
        threshold_count: thresholds.len() as u8,
        bump,
    };
    if let Some(mut existing) = load_cosigner_mut(program_id, cosigner_account)? {
        *existing = params(existing.bump).value();
        return Ok(());
    }
    let bump = PdaCreate {
        program_id,
        payer,
        seeds: &[CoSigner::SEED],
        mismatch: CustomRingError::InvalidCoSigner,
    }
    .create::<CoSigner>(cosigner_account)?;
    params(bump).init(cosigner_account)
}
