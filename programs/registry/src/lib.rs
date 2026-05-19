// Allow deprecated to suppress warnings from anchor_lang::AccountInfo::realloc
// which is used in the #[program] macro but we don't directly control
#![allow(deprecated)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::diverging_sub_expression)]
//! Registry program — admin and forester-registration slice only.
//!
//! All v1/v2 tree instructions, the compressible/ctoken instructions, and the
//! light-system-program registration paths were removed in the shielded-pool
//! reshape. One new forester instruction for the combined address+state tree
//! type will be added in a later phase.

use anchor_lang::prelude::*;

pub mod constants;
pub mod epoch;
pub mod errors;
pub mod forester;
pub mod protocol_config;
pub mod selection;
pub mod utils;

pub use crate::epoch::{finalize_registration::*, register_epoch::*, report_work::*};
pub use forester::forest_address_tree::*;
pub use protocol_config::{initialize::*, update::*};
pub use selection::forester::*;

use anchor_lang::solana_program::pubkey::Pubkey;
use errors::RegistryError;
use protocol_config::state::ProtocolConfig;

#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "light-registry",
    project_url: "lightprotocol.com",
    contacts: "email:security@lightprotocol.com",
    policy: "https://github.com/Lightprotocol/light-protocol/blob/main/SECURITY.md",
    source_code: "https://github.com/Lightprotocol/light-protocol"
}

declare_id!("Lighton6oQpVkeewmo2mcPTQQp7kYHr4fWpAgJyEmDX");

#[program]
pub mod light_registry {
    use super::*;
    use crate::protocol_config::update::check_protocol_config;

    /// Initializes the protocol config pda. Can only be called once by the
    /// program account keypair.
    pub fn initialize_protocol_config(
        ctx: Context<InitializeProtocolConfig>,
        bump: u8,
        protocol_config: ProtocolConfig,
    ) -> Result<()> {
        ctx.accounts.protocol_config_pda.authority = ctx.accounts.authority.key();
        ctx.accounts.protocol_config_pda.bump = bump;
        check_protocol_config(protocol_config)?;
        ctx.accounts.protocol_config_pda.config = protocol_config;
        Ok(())
    }

    pub fn update_protocol_config(
        ctx: Context<UpdateProtocolConfig>,
        protocol_config: Option<ProtocolConfig>,
    ) -> Result<()> {
        if let Some(new_authority) = ctx.accounts.new_authority.as_ref() {
            ctx.accounts.protocol_config_pda.authority = new_authority.key();
        }
        if let Some(protocol_config) = protocol_config {
            if protocol_config.genesis_slot != ctx.accounts.protocol_config_pda.config.genesis_slot
            {
                msg!("Genesis slot cannot be changed.");
                return err!(RegistryError::InvalidConfigUpdate);
            }
            if protocol_config.active_phase_length
                != ctx.accounts.protocol_config_pda.config.active_phase_length
            {
                msg!(
                    "Active phase length must not be changed, otherwise epochs will repeat {} {}.",
                    protocol_config.active_phase_length,
                    ctx.accounts.protocol_config_pda.config.active_phase_length
                );
                return err!(RegistryError::InvalidConfigUpdate);
            }
            check_protocol_config(protocol_config)?;
            ctx.accounts.protocol_config_pda.config = protocol_config;
        }
        Ok(())
    }

    pub fn register_forester(
        ctx: Context<RegisterForester>,
        _bump: u8,
        authority: Pubkey,
        config: ForesterConfig,
        weight: Option<u64>,
    ) -> Result<()> {
        ctx.accounts.forester_pda.authority = authority;
        ctx.accounts.forester_pda.config = config;

        if let Some(weight) = weight {
            ctx.accounts.forester_pda.active_weight = weight;
        }
        Ok(())
    }

    pub fn update_forester_pda(
        ctx: Context<UpdateForesterPda>,
        config: Option<ForesterConfig>,
    ) -> Result<()> {
        if let Some(authority) = ctx.accounts.new_authority.as_ref() {
            ctx.accounts.forester_pda.authority = authority.key();
        }
        if let Some(config) = config {
            ctx.accounts.forester_pda.config = config;
        }
        Ok(())
    }

    pub fn update_forester_pda_weight(
        ctx: Context<UpdateForesterPdaWeight>,
        new_weight: u64,
    ) -> Result<()> {
        ctx.accounts.forester_pda.active_weight = new_weight;
        Ok(())
    }

    /// Registers the forester for the epoch.
    /// 1. Only the forester can register herself for the epoch.
    /// 2. Protocol config is copied.
    /// 3. Epoch account is created if needed.
    pub fn register_forester_epoch<'info>(
        ctx: Context<'info, RegisterForesterEpoch<'info>>,
        epoch: u64,
    ) -> Result<()> {
        if ctx.accounts.epoch_pda.registered_weight == 0 {
            (*ctx.accounts.epoch_pda).clone_from(&EpochPda {
                epoch,
                protocol_config: ctx.accounts.protocol_config.config,
                total_work: 0,
                registered_weight: 0,
            });
        }
        let current_solana_slot = anchor_lang::solana_program::clock::Clock::get()?.slot;
        let current_epoch = ctx
            .accounts
            .epoch_pda
            .protocol_config
            .get_latest_register_epoch(current_solana_slot)?;

        if current_epoch != epoch {
            return err!(RegistryError::InvalidEpoch);
        }
        process_register_for_epoch(
            &ctx.accounts.authority.key(),
            &mut ctx.accounts.forester_pda,
            &mut ctx.accounts.forester_epoch_pda,
            &mut ctx.accounts.epoch_pda,
            current_solana_slot,
        )?;
        Ok(())
    }

    pub fn finalize_registration<'info>(
        ctx: Context<'info, FinalizeRegistration<'info>>,
    ) -> Result<()> {
        let current_solana_slot = anchor_lang::solana_program::clock::Clock::get()?.slot;
        let current_active_epoch = ctx
            .accounts
            .epoch_pda
            .protocol_config
            .get_current_active_epoch(current_solana_slot)?;
        if current_active_epoch != ctx.accounts.epoch_pda.epoch {
            return err!(RegistryError::InvalidEpoch);
        }
        ctx.accounts.forester_epoch_pda.total_epoch_weight =
            Some(ctx.accounts.epoch_pda.registered_weight);
        ctx.accounts.forester_epoch_pda.finalize_counter += 1;
        if ctx.accounts.forester_epoch_pda.finalize_counter
            > ctx
                .accounts
                .forester_epoch_pda
                .protocol_config
                .finalize_counter_limit
        {
            return err!(RegistryError::FinalizeCounterExceeded);
        }

        Ok(())
    }

    pub fn report_work<'info>(ctx: Context<'info, ReportWork<'info>>) -> Result<()> {
        let current_solana_slot = anchor_lang::solana_program::clock::Clock::get()?.slot;
        ctx.accounts
            .epoch_pda
            .protocol_config
            .is_report_work_phase(current_solana_slot, ctx.accounts.epoch_pda.epoch)?;
        if ctx.accounts.epoch_pda.epoch != ctx.accounts.forester_epoch_pda.epoch {
            return err!(RegistryError::InvalidEpoch);
        }
        if ctx.accounts.forester_epoch_pda.has_reported_work {
            return err!(RegistryError::ForesterAlreadyReportedWork);
        }
        ctx.accounts.epoch_pda.total_work += ctx.accounts.forester_epoch_pda.work_counter;
        ctx.accounts.forester_epoch_pda.has_reported_work = true;
        Ok(())
    }

    /// Drives a single batched-address-tree root update on the shielded-pool
    /// program. Registry CPIs into shielded-pool with its CPI authority PDA
    /// as signer and bumps the forester's work counter for the epoch.
    pub fn forest_address_tree<'info>(
        ctx: Context<'info, ForestAddressTree<'info>>,
        bump: u8,
        data: zolana_interface::instruction::BatchUpdateAddressTreeData,
    ) -> Result<()> {
        forester::forest_address_tree::process_forest_address_tree(ctx, bump, data)
    }
}
