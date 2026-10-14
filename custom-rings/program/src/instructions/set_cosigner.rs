use bytemuck::Zeroable;
use custom_ring_interface::{
    CoSignScope, CoSigner, CustomRingError, SetCoSignerIxData, WithdrawalThresholdRow, CO_SIGNER,
    MAX_CO_SIGNER_THRESHOLDS,
};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::instructions::{
    loader::load_authorized_config,
    shared::{check_system_program, parse, upsert},
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
    } = parse(data)?;
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
    let config = iter.next_account("config")?;
    let cosigner = iter.next_mut("cosigner")?;
    let system_program = iter.next_account("system_program")?;

    check_system_program(system_program)?;
    load_authorized_config(program_id, config, authority)?;
    upsert(program_id, payer, cosigner, &[CoSigner::SEED], |bump| {
        CoSigner {
            discriminator: CO_SIGNER,
            signer: Address::new_from_array(signer),
            scope: scope.bits(),
            threshold_count: thresholds.len() as u8,
            thresholds: rows,
            bump,
        }
    })
}
