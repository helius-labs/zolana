use anyhow::{anyhow, bail, Result};
use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use spl_discriminator::{ArrayDiscriminator, SplDiscriminate};

/// kVault's zero-copy account layout, including the Anchor discriminator.
/// Scaled fractions use little-endian bytes because host `u128` alignment
/// differs from Solana's account layout.
#[derive(Debug, Clone, Copy, Pod, Zeroable, SplDiscriminate)]
#[discriminator_hash_input("account:VaultState")]
#[repr(C)]
pub struct VaultState {
    pub discriminator: ArrayDiscriminator,
    pub vault_admin_authority: Address,
    pub base_vault_authority: Address,
    pub base_vault_authority_bump: u64,
    pub token_mint: Address,
    pub token_mint_decimals: u64,
    pub token_vault: Address,
    pub token_program: Address,
    pub shares_mint: Address,
    pub shares_mint_decimals: u64,
    pub token_available: u64,
    pub shares_issued: u64,
    pub available_crank_funds: u64,
    pub unallocated_weight: u64,
    pub performance_fee_bps: u64,
    pub management_fee_bps: u64,
    pub last_fee_charge_timestamp: u64,
    pub prev_aum_sf: [u8; 16],
    pub pending_fees_sf: [u8; 16],
    pub vault_allocation_strategy: [VaultAllocation; 25],
    pub padding_1: [[u8; 16]; 256],
    pub min_deposit_amount: u64,
    pub min_withdraw_amount: u64,
    pub min_invest_amount: u64,
    pub min_invest_delay_slots: u64,
    pub crank_fund_fee_per_reserve: u64,
    pub pending_admin: Address,
    pub cumulative_earned_interest_sf: [u8; 16],
    pub cumulative_mgmt_fees_sf: [u8; 16],
    pub cumulative_perf_fees_sf: [u8; 16],
    pub name: [u8; 40],
    pub vault_lookup_table: Address,
    pub vault_farm: Address,
    pub creation_timestamp: u64,
    pub unallocated_tokens_cap: u64,
    pub allocation_admin: Address,
    pub withdrawal_penalty_lamports: u64,
    pub withdrawal_penalty_bps: u64,
    pub first_loss_capital_farm: Address,
    pub allow_allocations_in_whitelisted_reserves_only: u8,
    pub allow_invest_in_whitelisted_reserves_only: u8,
    pub padding_2: [u8; 6],
    pub deposit_cap: u64,
    pub reward_info: VaultRewardInfo,
    pub padding_3: [[u8; 16]; 232],
}

impl VaultState {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn from_account_bytes(data: &[u8]) -> Result<Self> {
        let state: Self = bytemuck::try_pod_read_unaligned(data)
            .map_err(|error| anyhow!("unsupported kVault VaultState layout: {error}"))?;
        if state.discriminator != Self::SPL_DISCRIMINATOR {
            bail!("invalid kVault VaultState discriminator");
        }
        Ok(state)
    }
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct VaultAllocation {
    pub reserve: Address,
    pub ctoken_vault: Address,
    pub target_allocation_weight: u64,
    pub token_allocation_cap: u64,
    pub ctoken_vault_bump: u64,
    pub config_padding: [u64; 127],
    pub ctoken_allocation: u64,
    pub last_invest_slot: u64,
    pub token_target_allocation_sf: [u8; 16],
    pub state_padding: [u64; 128],
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct VaultRewardInfo {
    pub reward_per_second: u64,
    pub last_issuance_ts: u64,
    pub rewards_available: u64,
    pub cumulative_rewards_distributed_analytics: u64,
    pub padding: [u64; 8],
}

const _: () = assert!(VaultState::SIZE == 62_552);
const _: () = assert!(core::mem::align_of::<VaultState>() == 8);
const _: () = assert!(core::mem::size_of::<VaultAllocation>() == 2160);
const _: () = assert!(core::mem::size_of::<VaultRewardInfo>() == 96);
const _: () = assert!(core::mem::offset_of!(VaultState, token_available) == 224);
const _: () = assert!(core::mem::offset_of!(VaultState, shares_issued) == 232);
const _: () = assert!(core::mem::offset_of!(VaultState, pending_fees_sf) == 296);
const _: () = assert!(core::mem::offset_of!(VaultState, vault_allocation_strategy) == 312);
