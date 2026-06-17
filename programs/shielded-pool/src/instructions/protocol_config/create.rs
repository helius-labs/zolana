use light_account_checks::{checks::check_data_is_zeroed, AccountIterator};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::CreateProtocolConfigData,
    state::{discriminator::PROTOCOL_CONFIG, ProtocolConfig},
    SPP_PROTOCOL_CONFIG_PDA_SEED,
};

use crate::instructions::shared::{verify_pda, CreatePdaAccount};

pub fn process_create_protocol_config(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = *bytemuck::try_from_bytes::<CreateProtocolConfigData>(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let fee_payer = iter.next_signer("fee_payer")?;
    let protocol_config = iter.next_mut("protocol_config")?;
    let system_program = iter.next_account("system_program")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if *fee_payer.address() != data.protocol_authority {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }

    let bump = verify_pda(
        protocol_config.address(),
        &[SPP_PROTOCOL_CONFIG_PDA_SEED],
        &crate::ID,
    )?;

    CreatePdaAccount {
        fee_payer,
        new_account: &mut *protocol_config,
        space: ProtocolConfig::SIZE,
        owner: &crate::ID,
        signer_seeds: [SPP_PROTOCOL_CONFIG_PDA_SEED],
        bump,
    }
    .execute()
    .map_err(|_| ShieldedPoolError::InvalidProtocolConfig)?;

    ProtocolConfigInitParams {
        protocol_authority: data.protocol_authority,
        tree_creation_authority: data.tree_creation_authority,
        tree_creation_is_permissionless: data.tree_creation_is_permissionless,
        forester_authority: data.forester_authority,
        zone_creation_authority: data.zone_creation_authority,
        zone_creation_is_permissionless: data.zone_creation_is_permissionless,
        merge_authority: data.merge_authority,
    }
    .init(protocol_config)
}

struct ProtocolConfigInitParams {
    protocol_authority: Address,
    tree_creation_authority: Address,
    tree_creation_is_permissionless: u8,
    forester_authority: Address,
    zone_creation_authority: Address,
    zone_creation_is_permissionless: u8,
    merge_authority: Address,
}

impl ProtocolConfigInitParams {
    #[inline(always)]
    fn init(self, account: &mut AccountView) -> ProgramResult {
        let mut data = account.try_borrow_mut()?;
        check_data_is_zeroed::<1>(&data)?;
        let config: &mut ProtocolConfig = bytemuck::from_bytes_mut(&mut data[..]);
        config.discriminator = PROTOCOL_CONFIG;
        config.protocol_authority = self.protocol_authority;
        config.tree_creation_authority = self.tree_creation_authority;
        config.tree_creation_is_permissionless = self.tree_creation_is_permissionless;
        config.forester_authority = self.forester_authority;
        config.zone_creation_authority = self.zone_creation_authority;
        config.zone_creation_is_permissionless = self.zone_creation_is_permissionless;
        config.merge_authority = self.merge_authority;
        Ok(())
    }
}
