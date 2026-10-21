use custom_ring_interface::{MemberRegistry, RecordQueue};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::{
    instructions::{
        loader::load_authorized_config,
        shared::{check_system_program, no_data, Pda},
    },
    state::Init,
};

#[inline(never)]
pub fn process_create_member_registry_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    no_data(data)?;
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let registry = iter.next_mut("registry")?;
    let queue = iter.next_mut("queue")?;
    let system_program = iter.next_account("system_program")?;

    check_system_program(system_program)?;
    load_authorized_config(program_id, config, authority)?;
    let slot = Clock::get()?.slot;
    let bump = Pda {
        program_id,
        seeds: &[MemberRegistry::SEED],
    }
    .create::<MemberRegistry>(payer, registry)?;
    Init(&*Box::new(MemberRegistry::new(bump, slot))).init(registry)?;
    let bump = Pda {
        program_id,
        seeds: &[RecordQueue::SEED],
    }
    .create::<RecordQueue>(payer, queue)?;
    Init(&RecordQueue::new(bump)).init(queue)
}
