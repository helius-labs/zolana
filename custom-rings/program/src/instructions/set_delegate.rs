use custom_ring_interface::{
    CustomRingError, Delegate, MemberRegistryRoot, RingMode, RingProgramConfig, DELEGATE,
};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    instructions::{
        loader::{check_upgrade_authority, load, load_mut},
        shared::{check_system_program, create_pda},
    },
    state::Init,
};

#[inline(never)]
pub fn process_set_delegate_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let delegate: [u8; 32] = data
        .try_into()
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    if delegate == [0; 32] {
        return Err(CustomRingError::InvalidDelegate.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("config")?;
    let delegate_account = iter.next_mut("delegate_pda")?;
    let member_registry_root = iter.next_account("member_registry_root")?;
    let system_program = iter.next_account("system_program")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;

    check_system_program(system_program)?;
    check_upgrade_authority(program_id, authority, program, program_data)?;
    // The delegate is permanent for the instructions of the deployed binary.
    if delegate_account.data_len() != 0 {
        load::<Delegate>(program_id, delegate_account)?;
        return Err(CustomRingError::DelegateAlreadySet.into());
    }
    let bump = create_pda::<Delegate, 1>(program_id, payer, delegate_account, &[Delegate::SEED])?;
    // The delegate recovers nullifier secrets from the records every output key escrows into.
    let mut ring = load_mut::<RingProgramConfig>(program_id, config)?;
    // An anonymous ring hides the owner a delegate would sign for.
    match ring.mode().ok_or(CustomRingError::InvalidRingMode)? {
        RingMode::Anonymous => return Err(CustomRingError::AnonymousRingRefused.into()),
        RingMode::Off | RingMode::Registry => {}
    }
    if ring.has_policy == 0 {
        return Err(CustomRingError::DelegateRequiresPolicy.into());
    }
    load::<MemberRegistryRoot>(program_id, member_registry_root)?;
    ring.mode = RingMode::Registry as u8;
    drop(ring);
    Init(&Delegate {
        discriminator: DELEGATE,
        delegate: Address::new_from_array(delegate),
        bump,
    })
    .init(delegate_account)
}
