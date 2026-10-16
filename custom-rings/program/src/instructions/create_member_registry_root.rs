use custom_ring_interface::{CustomRingError, MemberRegistryRoot};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    instructions::{
        loader::load_authorized_config,
        shared::{check_system_program, create_pda},
    },
    state::{empty_member_registry_root, Init},
};

#[inline(never)]
pub fn process_create_member_registry_root_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(CustomRingError::InvalidInstructionData.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let root = iter.next_mut("member_registry_root")?;
    let system_program = iter.next_account("system_program")?;

    check_system_program(system_program)?;
    load_authorized_config(program_id, config, authority)?;
    let bump =
        create_pda::<MemberRegistryRoot, 1>(program_id, payer, root, &[MemberRegistryRoot::SEED])?;
    Init(&empty_member_registry_root(bump)).init(root)
}
