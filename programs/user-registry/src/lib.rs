#![allow(clippy::too_many_arguments)]

use anchor_lang::prelude::*;

pub mod constants;
pub mod error;
pub mod state;

use constants::USER_RECORD_SEED;
use error::UserRegistryError;
use state::{
    validate_canonical_nullifier_pubkey, validate_optional_p256_pubkey, validate_p256_pubkey,
    SyncDelegateEntry, UserRecord,
};

declare_id!("9EwHPNdsPHMt7kaUZaXDTaj92HVC8CL4Q16io4Vu87t4");

#[program]
pub mod user_registry {
    use super::*;

    /// Creates a per-owner record with static shielded keys and no sync delegate.
    pub fn register(
        ctx: Context<Register>,
        owner_p256: Option<[u8; state::P256_PUBKEY_LEN]>,
        nullifier_pubkey: [u8; state::NULLIFIER_PUBKEY_LEN],
        viewing_pubkey: [u8; state::P256_PUBKEY_LEN],
    ) -> Result<()> {
        validate_optional_p256_pubkey(&owner_p256)?;
        validate_p256_pubkey(&viewing_pubkey)?;
        validate_canonical_nullifier_pubkey(&nullifier_pubkey)?;

        let record = &mut ctx.accounts.user_record;
        record.owner = ctx.accounts.owner.key();
        record.owner_p256 = owner_p256;
        record.nullifier_pubkey = nullifier_pubkey;
        record.viewing_pubkey = viewing_pubkey;
        record.sync_delegate = None;
        record.entries = Vec::new();
        Ok(())
    }

    /// Appoints or replaces the sync delegate and appends a sync-delegate entry.
    pub fn set_sync_delegate(
        ctx: Context<SetSyncDelegate>,
        sync_delegate: Pubkey,
        sync_pubkey: [u8; state::P256_PUBKEY_LEN],
        viewing_pubkey: [u8; state::P256_PUBKEY_LEN],
    ) -> Result<()> {
        validate_p256_pubkey(&sync_pubkey)?;
        validate_p256_pubkey(&viewing_pubkey)?;

        let record = &mut ctx.accounts.user_record;
        record.sync_delegate = Some(sync_delegate);
        record.entries.push(SyncDelegateEntry {
            sync_pubkey,
            viewing_pubkey,
            created_at: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }

    /// Appends a new sync-delegate entry without changing the sync delegate address.
    pub fn rotate_sync_delegate(
        ctx: Context<RotateSyncDelegate>,
        sync_pubkey: [u8; state::P256_PUBKEY_LEN],
        viewing_pubkey: [u8; state::P256_PUBKEY_LEN],
    ) -> Result<()> {
        validate_p256_pubkey(&sync_pubkey)?;
        validate_p256_pubkey(&viewing_pubkey)?;

        let record = &mut ctx.accounts.user_record;
        require!(
            record.sync_delegate.is_some(),
            UserRegistryError::SyncDelegateNotSet
        );
        record.entries.push(SyncDelegateEntry {
            sync_pubkey,
            viewing_pubkey,
            created_at: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }

    /// Clears the active sync delegate. Entry history is preserved.
    pub fn revoke(ctx: Context<Revoke>) -> Result<()> {
        ctx.accounts.validate_signer()?;
        let record = &mut ctx.accounts.user_record;
        require!(
            record.sync_delegate.is_some(),
            UserRegistryError::SyncDelegateNotSet
        );
        record.sync_delegate = None;
        Ok(())
    }

    /// Closes the record and refunds rent. Only allowed before any sync-delegate entry.
    pub fn close(_ctx: Context<CloseRecord>) -> Result<()> {
        require!(
            _ctx.accounts.user_record.entries.is_empty(),
            UserRegistryError::RecordNotEmpty
        );
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Register<'info> {
    #[account(
        init,
        payer = owner,
        space = UserRecord::space_for(0),
        seeds = [USER_RECORD_SEED, owner.key().as_ref()],
        bump,
    )]
    pub user_record: Account<'info, UserRecord>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetSyncDelegate<'info> {
    #[account(
        mut,
        seeds = [USER_RECORD_SEED, owner.key().as_ref()],
        bump,
        has_one = owner,
        realloc = UserRecord::space_for(user_record.entries.len() + 1),
        realloc::payer = owner,
        realloc::zero = false,
    )]
    pub user_record: Account<'info, UserRecord>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RotateSyncDelegate<'info> {
    #[account(
        mut,
        seeds = [USER_RECORD_SEED, user_record.owner.as_ref()],
        bump,
        realloc = UserRecord::space_for(user_record.entries.len() + 1),
        realloc::payer = sync_delegate,
        realloc::zero = false,
        constraint = user_record.sync_delegate == Some(sync_delegate.key()) @ UserRegistryError::InvalidSyncDelegate,
    )]
    pub user_record: Account<'info, UserRecord>,
    #[account(mut)]
    pub sync_delegate: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Revoke<'info> {
    #[account(
        mut,
        seeds = [USER_RECORD_SEED, user_record.owner.as_ref()],
        bump,
    )]
    pub user_record: Account<'info, UserRecord>,
    pub signer: Signer<'info>,
}

impl<'info> Revoke<'info> {
    pub fn validate_signer(&self) -> Result<()> {
        let signer_key = self.signer.key();
        let record = &self.user_record;
        let authorized = signer_key == record.owner
            || record
                .sync_delegate
                .is_some_and(|sync_delegate| sync_delegate == signer_key);
        require!(authorized, UserRegistryError::UnauthorizedSigner);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CloseRecord<'info> {
    #[account(
        mut,
        close = owner,
        has_one = owner,
        seeds = [USER_RECORD_SEED, owner.key().as_ref()],
        bump,
    )]
    pub user_record: Account<'info, UserRecord>,
    #[account(mut)]
    pub owner: Signer<'info>,
}
