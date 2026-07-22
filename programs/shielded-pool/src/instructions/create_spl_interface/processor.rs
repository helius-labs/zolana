use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, state::SplAssetRegistry, SPL_ASSET_VAULT_PDA_SEED,
    SPL_TOKEN_ACCOUNT_LEN, SPL_TOKEN_PROGRAM_ID,
};

use super::init::{RegistryInitParams, SplInterfaceInitParams};
use crate::instructions::{
    create_asset_counter::load_spl_asset_counter_mut,
    protocol_config::loader::load_protocol_config,
    shared::{verify_pda, CreatePdaAccount},
};

pub fn process_create_spl_interface(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    // If spl interface account creation is not permissionless check authority matches.
    let protocol_config = iter.next_account("protocol_config")?;
    // Asset counter pda, provides the unique asset id. Is incremented.
    let asset_counter = iter.next_mut("asset_counter")?;
    // Registered mint pda, maps asset id to mint pubkey.
    let registry_entry = iter.next_mut("registry_entry")?;
    // Checked by cpi to token program for spl_interface account creation.
    let mint = iter.next_account("mint")?;
    let spl_interface = iter.next_mut("spl_interface")?;
    let system_program = iter.next_account("system_program")?;
    let token_program = iter.next_account("token_program")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    // TODO: add t22 support
    if *token_program.address() != Address::from(SPL_TOKEN_PROGRAM_ID) {
        return Err(ProgramError::IncorrectProgramId);
    }

    {
        let config = load_protocol_config(protocol_config)?;
        if !config.allows_permissionless_spl_interface_creation() {
            config
                .check_protocol_authority(authority.address())
                .map_err(ShieldedPoolError::from)?;
        }
    }

    let mint_key = *mint.address();

    let asset_id = {
        let mut counter = load_spl_asset_counter_mut(asset_counter)?;
        counter
            .check_discriminator()
            .map_err(|_| ShieldedPoolError::InvalidSplAssetRegistry)?;
        counter
            .allocate_id()
            .map_err(|_| ShieldedPoolError::InvalidSplAssetRegistry)?
    };
    // Create asset registry account.
    {
        let registry_bump = verify_pda(
            registry_entry.address(),
            &[SplAssetRegistry::SEED, mint_key.as_ref()],
            &crate::ID,
        )?;
        if registry_entry.data_len() != 0 {
            return Err(ShieldedPoolError::InvalidSplAssetRegistry.into());
        }
        CreatePdaAccount {
            fee_payer: authority,
            new_account: &mut *registry_entry,
            space: SplAssetRegistry::SIZE,
            owner: &crate::ID,
            signer_seeds: [SplAssetRegistry::SEED, mint_key.as_ref()],
            bump: registry_bump,
        }
        .execute()
        .map_err(|_| ShieldedPoolError::InvalidSplAssetRegistry)?;
        RegistryInitParams {
            mint: mint_key,
            asset_id,
        }
        .init(registry_entry)?;
    }
    // Spl interface account.
    {
        let spl_interface_bump = verify_pda(
            spl_interface.address(),
            &[SPL_ASSET_VAULT_PDA_SEED, mint_key.as_ref()],
            &crate::ID,
        )?;
        if spl_interface.data_len() != 0 {
            return Err(ShieldedPoolError::InvalidSplAssetRegistry.into());
        }
        CreatePdaAccount {
            fee_payer: authority,
            new_account: &mut *spl_interface,
            space: SPL_TOKEN_ACCOUNT_LEN,
            owner: token_program.address(),
            signer_seeds: [SPL_ASSET_VAULT_PDA_SEED, mint_key.as_ref()],
            bump: spl_interface_bump,
        }
        .execute()
        .map_err(|_| ShieldedPoolError::InvalidSplAssetRegistry)?;
        SplInterfaceInitParams {
            token_program,
            spl_interface,
            mint,
        }
        .init()
    }
}
