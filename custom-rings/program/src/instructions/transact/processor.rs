use custom_ring_interface::{
    CustomRingError, InstructionTag, RailSigner, RingRail, RingTransactData,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};

use super::{
    accounts::TransactCheck,
    verify::{escrows_keys, RingStatements},
};
use crate::instructions::loader::{load_config, load_spp_tree_root, validate_spp_program};

#[inline(never)]
pub fn process_transact_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
    tag: InstructionTag,
) -> ProgramResult {
    let slot = Clock::get()?.slot;
    let config_account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let config = Box::new(*load_config(program_id, config_account)?);
    let signer = RailSigner::new(tag, &config)?;
    let transfer = RingTransactData::parse(data, signer.rail())?;
    let data = transfer.data();
    // The disclosure chain hashes trailing zeros alike, honest fields are padded nonzero.
    if data.disclosure.contains(&[0; 32]) {
        return Err(CustomRingError::ZeroDisclosureField.into());
    }
    let validated = TransactCheck {
        program_id,
        config: &config,
        data,
        signer,
        slot,
    }
    .validate(accounts)?;
    let epoch = match data.rail {
        RingRail::Anonymous => data.epoch(slot)?,
        RingRail::Confidential | RingRail::Delegate => 0,
    };
    let first_contact_root = match data.anchor {
        Some(anchor) => load_spp_tree_root(
            accounts
                .get_mut(usize::from(anchor.tree))
                .ok_or(CustomRingError::FirstContactRootMissing)?,
            anchor.root_index,
        )?,
        None => [0; 32],
    };
    // A bad SPP proof point is refused before either pairing.
    let spp_data = data.spp_instruction_data(&config)?;
    RingStatements {
        program_id,
        config: &config,
        transfer: &transfer,
        accounts: &validated,
        epoch,
        first_contact_root: &first_contact_root,
        key_escrow: escrows_keys(&config)?,
    }
    .verify()?;
    let spp = accounts
        .get(validated.spp..)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    validate_spp_program(spp)?;
    validated.ring_auth.invoke(spp, &spp_data)
}
