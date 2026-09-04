use crate::instructions::shared::caused_by;
use borsh::BorshDeserialize;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, instruction::CreateRingConfigData, state::RingConfig,
};

use super::init::RingConfigInitParams;
use crate::instructions::protocol_config::loader::load_protocol_config;

pub fn process_create_ring_config(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = CreateRingConfigData::try_from_slice(data)
        .map_err(caused_by(ShieldedPoolError::InvalidInstructionData))?;
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer("payer")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let ring_config = iter.next_mut("ring_config")?;
    let system_program = iter.next_account("system_program")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }

    // The ring config account IS the ring's `ring_auth` PDA. It must sign its own
    // creation (the ring CPIs this instruction with `invoke_signed(["ring_auth",
    // bump])`), and this is the SOLE place the derivation is ever checked. Every
    // later ring instruction only loads the account by discriminator and requires
    // its signature -- never re-deriving.
    if !ring_config.is_signer() {
        return Err(ShieldedPoolError::InvalidRingConfig.into());
    }
    // Canonical derivation (find_program_address): never trust a bump from
    // instruction data for account creation.
    let (expected, ring_auth_bump) = derive_ring_auth(&data.program_id);
    if *ring_config.address() != expected {
        return Err(ShieldedPoolError::InvalidRingConfig.into());
    }

    {
        let protocol = load_protocol_config(protocol_config)?;
        if !protocol.allows_permissionless_ring_creation()
            && protocol
                .check_ring_creation_authority(payer.address())
                .is_err()
        {
            return Err(ShieldedPoolError::UnauthorizedCaller.into());
        }
    }

    // `ring_config`'s signature is propagated from the ring program's outer
    // `invoke_signed`, so SPP supplies no seeds; it only sets owner = SPP so the
    // program can store the config in the ring's own PDA.
    pinocchio_system::create_account_with_minimum_balance(
        ring_config,
        RingConfig::SIZE,
        &crate::ID,
        payer,
        None,
    )
    .map_err(caused_by(ShieldedPoolError::InvalidRingConfig))?;

    RingConfigInitParams {
        authority: data.authority,
        program_id: data.program_id,
        ring_authority_transact_is_enabled: data.ring_authority_transact_is_enabled,
        bump: ring_auth_bump,
    }
    .init(ring_config)
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn derive_ring_auth(program_id: &Address) -> (Address, u8) {
    Address::find_program_address(&[zolana_interface::RING_AUTH_PDA_SEED], program_id)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn derive_ring_auth(_program_id: &Address) -> (Address, u8) {
    unimplemented!("PDA derivation requires Solana runtime syscalls")
}
