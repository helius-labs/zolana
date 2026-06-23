use borsh::BorshDeserialize;
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::CreateZoneConfigData,
    state::{discriminator::ZONE_CONFIG, ZoneConfig},
    SPP_ZONE_CONFIG_PDA_SEED,
};

use crate::instructions::protocol_config::loader::load_protocol_config;

pub fn process_create_zone_config(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = CreateZoneConfigData::try_from_slice(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer("payer")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let config = iter.next_mut("zone_config")?;
    let zone_auth = iter.next_signer("zone_auth")?;
    let system_program = iter.next_account("system_program")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    validate_zone_auth(zone_auth, &data.program_id, data.zone_auth_bump)?;

    {
        let protocol = load_protocol_config(protocol_config)?;
        if !protocol.allows_permissionless_zone_creation()
            && protocol
                .check_zone_creation_authority(payer.address())
                .is_err()
        {
            return Err(ShieldedPoolError::UnauthorizedCaller.into());
        }
    }

    let bump = CreatePdaAccount {
        fee_payer: payer,
        new_account: &mut *config,
        owner: &crate::ID,
        policy_program_id: &data.program_id,
        bump: data.zone_config_bump,
    }
    .execute()?;

    let mut bytes = config
        .try_borrow_mut()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    let cfg: &mut ZoneConfig = bytemuck::from_bytes_mut(&mut bytes[..]);
    cfg.discriminator = ZONE_CONFIG;
    cfg.authority = data.authority;
    cfg.zone_authority_transact_is_enabled = u8::from(data.zone_authority_transact_is_enabled);
    cfg.bump = bump;
    Ok(())
}

struct CreatePdaAccount<'a> {
    fee_payer: &'a AccountView,
    new_account: &'a mut AccountView,
    owner: &'a Address,
    policy_program_id: &'a Address,
    bump: u8,
}

impl CreatePdaAccount<'_> {
    #[inline(always)]
    fn execute(self) -> Result<u8, ProgramError> {
        let (expected, bump) = derive_zone_config_pda(self.policy_program_id, self.owner);
        if *self.new_account.address() != expected || self.bump != bump {
            return Err(ShieldedPoolError::InvalidZoneConfig.into());
        }
        let bump_seed = [bump];
        let seeds = [
            Seed::from(SPP_ZONE_CONFIG_PDA_SEED),
            Seed::from(self.policy_program_id.as_ref()),
            Seed::from(bump_seed.as_slice()),
        ];
        let signer = Signer::from(seeds.as_ref());
        pinocchio_system::create_account_with_minimum_balance_signed(
            self.new_account,
            ZoneConfig::SIZE,
            self.owner,
            self.fee_payer,
            None,
            &[signer],
        )
        .map_err(|_| ShieldedPoolError::InvalidZoneConfig)?;
        Ok(bump)
    }
}

fn validate_zone_auth(
    zone_auth: &AccountView,
    policy_program_id: &Address,
    zone_auth_bump: u8,
) -> ProgramResult {
    let bump = [zone_auth_bump];
    let expected = derive_zone_auth(policy_program_id, &bump)?;
    if *zone_auth.address() != expected {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    Ok(())
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn derive_zone_config_pda(policy_program_id: &Address, program_id: &Address) -> (Address, u8) {
    Address::find_program_address(
        &[SPP_ZONE_CONFIG_PDA_SEED, policy_program_id.as_ref()],
        program_id,
    )
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn derive_zone_config_pda(_policy_program_id: &Address, _program_id: &Address) -> (Address, u8) {
    unimplemented!("PDA derivation requires Solana runtime syscalls")
}

fn derive_zone_auth(policy_program_id: &Address, bump: &[u8; 1]) -> Result<Address, ProgramError> {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        Address::create_program_address(
            &[zolana_interface::ZONE_AUTH_PDA_SEED, bump.as_slice()],
            policy_program_id,
        )
        .map_err(|_| ShieldedPoolError::InvalidZoneConfig.into())
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        let _ = (policy_program_id, bump);
        Err(ShieldedPoolError::InvalidZoneConfig.into())
    }
}
