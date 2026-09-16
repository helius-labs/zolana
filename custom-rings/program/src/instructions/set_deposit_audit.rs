use custom_ring_interface::{DepositAudit, SetDepositAuditIxData};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_authorized_config, load_deposit_audit_mut},
        shared::PdaCreate,
    },
    state::DepositAuditInit,
};

pub fn process_set_deposit_audit_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let SetDepositAuditIxData { required } =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    if required > 1 {
        return Err(CustomRingError::InvalidDepositAudit.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let audit = iter.next_mut("deposit_audit")?;
    let system = iter.next_account("system_program")?;
    // 1. Require the config authority before changing deposit disclosure
    // requirements.
    if !pinocchio_system::check_id(system.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    load_authorized_config(program_id, config, authority)?;
    // 2. Update or create the canonical setting without resizing the ring
    // config.
    if let Some(mut existing) = load_deposit_audit_mut(program_id, audit)? {
        existing.required = required;
        return Ok(());
    }
    let bump = PdaCreate {
        program_id,
        payer,
        seeds: &[DepositAudit::SEED],
        mismatch: CustomRingError::InvalidDepositAudit,
    }
    .create::<DepositAudit>(audit)?;
    DepositAuditInit { required, bump }.init(audit)
}
