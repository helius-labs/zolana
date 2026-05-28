//! Registry forester instruction for SPP nullifier-tree batches. The
//! shielded-pool program verifies both the Light queue update proof and the
//! SPP full-field nullifier indexed-tree update proof.

use anchor_lang::{
    prelude::*,
    solana_program::{
        instruction::{AccountMeta, Instruction},
        program::invoke_signed,
        pubkey::Pubkey,
    },
};
use zolana_interface::{
    instruction::{encode_instruction, tag, BatchUpdateNullifierTreeData},
    SHIELDED_POOL_PROGRAM_ID,
};

use crate::{
    constants::{CPI_AUTHORITY_PDA_SEED, DEFAULT_WORK_V1},
    epoch::register_epoch::ForesterEpochPda,
    errors::RegistryError,
    selection::forester::ForesterPda,
};

#[derive(Accounts)]
pub struct ForestNullifierTree<'info> {
    /// Forester's signing authority. Must match `forester_pda.authority`.
    pub authority: Signer<'info>,

    /// Forester record (validates `authority`).
    #[account(seeds = [crate::constants::FORESTER_SEED, authority.key().as_ref()], bump,
              has_one = authority)]
    pub forester_pda: Account<'info, ForesterPda>,

    /// Per-epoch forester record. Validates this forester is registered for
    /// the current epoch and accumulates the work counter.
    #[account(mut,
              seeds = [crate::constants::FORESTER_EPOCH_SEED,
                       forester_pda.key().as_ref(),
                       forester_epoch_pda.epoch.to_le_bytes().as_slice()],
              bump)]
    pub forester_epoch_pda: Account<'info, ForesterEpochPda>,

    /// The shielded-pool pool-tree account.
    /// CHECK: validated by the shielded-pool program itself.
    #[account(mut)]
    pub pool_tree: UncheckedAccount<'info>,

    /// Registry's CPI authority PDA — signs the CPI into shielded-pool.
    /// CHECK: derivation verified by anchor's seeds constraint.
    #[account(seeds = [CPI_AUTHORITY_PDA_SEED], bump)]
    pub cpi_authority: UncheckedAccount<'info>,

    /// The shielded-pool program being called.
    /// CHECK: address pinned to SHIELDED_POOL_PROGRAM_ID.
    #[account(address = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID))]
    pub shielded_pool_program: UncheckedAccount<'info>,
}

pub fn process_forest_nullifier_tree<'info>(
    ctx: Context<'info, ForestNullifierTree<'info>>,
    data: BatchUpdateNullifierTreeData,
) -> Result<()> {
    if ctx.accounts.forester_epoch_pda.authority != ctx.accounts.authority.key() {
        return err!(RegistryError::InvalidForester);
    }

    let cpi_data = encode_instruction(tag::BATCH_UPDATE_NULLIFIER_TREE, &data);
    let cpi_ix = Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(ctx.accounts.cpi_authority.key(), true),
            AccountMeta::new(ctx.accounts.pool_tree.key(), false),
        ],
        data: cpi_data,
    };

    let cpi_bump = ctx.bumps.cpi_authority;
    let cpi_seeds: &[&[u8]] = &[CPI_AUTHORITY_PDA_SEED, &[cpi_bump]];
    invoke_signed(
        &cpi_ix,
        &[
            ctx.accounts.cpi_authority.to_account_info(),
            ctx.accounts.pool_tree.to_account_info(),
            ctx.accounts.shielded_pool_program.to_account_info(),
        ],
        &[cpi_seeds],
    )?;

    ctx.accounts.forester_epoch_pda.work_counter = ctx
        .accounts
        .forester_epoch_pda
        .work_counter
        .checked_add(DEFAULT_WORK_V1)
        .ok_or(RegistryError::ArithmeticOverflow)?;

    Ok(())
}
