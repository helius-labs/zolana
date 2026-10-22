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
    // 1. The config's mode and delegate fix the rail and the signer it trusts.
    let config_account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let config = Box::new(*load_config(program_id, config_account)?);
    let signer = RailSigner::new(tag, &config)?;
    // 2. Every length follows from the flags and the shape, trailing bytes refused.
    let transfer = RingTransactData::parse(data, signer.rail())?;
    let data = transfer.data();
    // 3. The disclosure chain hashes trailing zeros alike, honest fields are padded nonzero.
    if data.disclosure.contains(&[0; 32]) {
        return Err(CustomRingError::ZeroDisclosureField.into());
    }
    // 4. Each account sits in the slot the statements and SPP read it from.
    let validated = TransactCheck {
        program_id,
        config: &config,
        data,
        signer,
        slot,
    }
    .validate(accounts)?;
    // 5. An anonymous statement binds the landing epoch and the first-contact tree root.
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
    // 6. A bad SPP proof point is refused before either pairing.
    let spp_data = data.spp_instruction_data(&config)?;
    // 7. The audit proof and the policy proof verify over values the program derives.
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
    // 8. SPP verifies its own proof over the expanded data the ring PDA signs.
    let spp = accounts
        .get(validated.spp..)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    validate_spp_program(spp)?;
    validated.ring_auth.invoke(spp, &spp_data)
}
