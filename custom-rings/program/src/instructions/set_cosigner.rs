use bytemuck::Zeroable;
use custom_ring_interface::{SetCoSignerIxData, WithdrawalThresholdRow, MAX_CO_SIGNER_THRESHOLDS};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::instructions::{
    loader::load_authorized_config_mut,
    shared::{no_data, parse},
};

#[inline(never)]
pub fn process_set_cosigner_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: SetCoSignerIxData = parse(data)?;
    let scope = ix.check()?;
    let mut rows = [WithdrawalThresholdRow::zeroed(); MAX_CO_SIGNER_THRESHOLDS];
    for (row, threshold) in rows.iter_mut().zip(&ix.thresholds) {
        *row = WithdrawalThresholdRow {
            mint: Address::new_from_array(threshold.mint),
            amount: threshold.amount.to_le_bytes(),
        };
    }

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("config")?;
    let mut config = load_authorized_config_mut(program_id, config, authority)?;
    config.co_signer = Address::new_from_array(ix.signer);
    config.co_sign_scope = scope.bits();
    config.threshold_count = ix.thresholds.len() as u8;
    config.thresholds = rows;
    Ok(())
}

#[inline(never)]
pub fn process_clear_cosigner_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    no_data(data)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("config")?;
    let mut config = load_authorized_config_mut(program_id, config, authority)?;
    config.co_signer = Address::default();
    config.co_sign_scope = 0;
    config.threshold_count = 0;
    config.thresholds = [WithdrawalThresholdRow::zeroed(); MAX_CO_SIGNER_THRESHOLDS];
    Ok(())
}
