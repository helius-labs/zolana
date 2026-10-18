use custom_ring_interface::{CustomRingError, DepositAudit, SetDepositAuditIxData, DEPOSIT_AUDIT};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::instructions::{
    loader::load_authorized_config,
    shared::{check_system_program, parse, upsert},
};

#[inline(never)]
pub fn process_set_deposit_audit_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let SetDepositAuditIxData { required } = parse(data)?;
    if !required {
        return Err(CustomRingError::DepositAuditRequired.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let audit = iter.next_mut("deposit_audit")?;
    let system_program = iter.next_account("system_program")?;

    check_system_program(system_program)?;
    load_authorized_config(program_id, config, authority)?;
    upsert(program_id, payer, audit, &[DepositAudit::SEED], |bump| {
        DepositAudit {
            discriminator: DEPOSIT_AUDIT,
            required: u8::from(required),
            bump,
        }
    })
}
