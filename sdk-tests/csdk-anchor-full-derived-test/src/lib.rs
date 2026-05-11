#![allow(deprecated)]
#![allow(clippy::useless_asref)]

use anchor_lang::prelude::*;
use light_account::{
    derive_light_cpi_signer, derive_light_rent_sponsor_pda, light_program, CpiSigner,
};

pub mod d8_builder_paths;
pub mod instructions;
pub mod state;

pub use d8_builder_paths::*;
pub use state::d1_field_types::single_pubkey::{PackedSinglePubkeyRecord, SinglePubkeyRecord};

declare_id!("FAMipfVEhN4hjCLpKCvjDXXfzLsoVTqQccXzePz1L1ah");

pub const LIGHT_CPI_SIGNER: CpiSigner =
    derive_light_cpi_signer!("FAMipfVEhN4hjCLpKCvjDXXfzLsoVTqQccXzePz1L1ah");

pub const PROGRAM_RENT_SPONSOR_DATA: ([u8; 32], u8) =
    derive_light_rent_sponsor_pda!("FAMipfVEhN4hjCLpKCvjDXXfzLsoVTqQccXzePz1L1ah");

#[inline]
pub fn program_rent_sponsor() -> Pubkey {
    Pubkey::from(PROGRAM_RENT_SPONSOR_DATA.0)
}

#[light_program]
#[program]
pub mod csdk_anchor_full_derived_test {
    use super::{
        d8_builder_paths::{D8PdaOnly, D8PdaOnlyParams},
        LIGHT_CPI_SIGNER,
    };

    pub fn d8_pda_only<'info>(
        ctx: Context<'_, '_, '_, 'info, D8PdaOnly<'info>>,
        params: D8PdaOnlyParams,
    ) -> Result<()> {
        ctx.accounts.d8_pda_only_record.owner = params.owner;
        Ok(())
    }
}
