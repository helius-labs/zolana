use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::pda::spl_token_program_id;

pub const PROGRAM_ID: Address =
    Address::from_str_const("KvauGMspG5k6rtzrqqn7WNn3oZdyKqLKwK2XWQ8FLjd");
pub const KLEND_PROGRAM_ID: Address =
    Address::from_str_const("KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD");
const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0; 32]);
const SYSVAR_RENT_ID: Address =
    Address::from_str_const("SysvarRent111111111111111111111111111111111");

pub const VAULT_STATE_SIZE: usize = 8 + 62544;
const GLOBAL_CONFIG_SIZE: usize = 8 + 1024;
const TOKEN_AVAILABLE_OFFSET: usize = 8 + 216;
const SHARES_ISSUED_OFFSET: usize = 8 + 224;
const PENDING_FEES_OFFSET: usize = 8 + 288;
const TOKEN_ACCOUNT_AMOUNT_OFFSET: usize = 64;

fn discriminator(preimage: &str) -> [u8; 8] {
    let hash = Sha256::digest(preimage.as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(hash.get(..8).unwrap_or_default());
    out
}

fn pda(seeds: &[&[u8]]) -> Address {
    Address::find_program_address(seeds, &PROGRAM_ID).0
}

fn event_authority() -> Address {
    pda(&[b"__event_authority"])
}

pub fn global_config() -> Address {
    pda(&[b"global_config"])
}

pub fn global_config_account(admin: &Address) -> Account {
    let mut data = vec![0u8; GLOBAL_CONFIG_SIZE];
    for (range, bytes) in [
        (0..8, discriminator("account:GlobalConfig").as_slice()),
        (8..40, admin.as_ref()),
        (40..72, admin.as_ref()),
    ] {
        if let Some(slot) = data.get_mut(range) {
            slot.copy_from_slice(bytes);
        }
    }
    Account {
        lamports: 1_000_000_000,
        data,
        owner: PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultAccounts {
    pub vault: Address,
    pub token_mint: Address,
    pub authority: Address,
    pub token_vault: Address,
    pub shares_mint: Address,
}

impl VaultAccounts {
    pub fn new(vault: Address, token_mint: Address) -> Self {
        Self {
            vault,
            token_mint,
            authority: pda(&[b"authority", vault.as_ref()]),
            token_vault: pda(&[b"token_vault", vault.as_ref()]),
            shares_mint: pda(&[b"shares", vault.as_ref()]),
        }
    }
}

pub struct InitVault {
    pub admin: Address,
    pub admin_token_account: Address,
    pub accounts: VaultAccounts,
}

impl InitVault {
    pub fn instruction(&self) -> Instruction {
        let token_program = spl_token_program_id();
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(self.admin, true),
                AccountMeta::new(self.accounts.vault, true),
                AccountMeta::new_readonly(self.accounts.authority, false),
                AccountMeta::new(self.accounts.token_vault, false),
                AccountMeta::new_readonly(self.accounts.token_mint, false),
                AccountMeta::new(self.accounts.shares_mint, false),
                AccountMeta::new(self.admin_token_account, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                AccountMeta::new_readonly(SYSVAR_RENT_ID, false),
                AccountMeta::new_readonly(token_program, false),
                AccountMeta::new_readonly(token_program, false),
            ],
            data: discriminator("global:init_vault").to_vec(),
        }
    }
}

pub struct UserAccounts {
    pub user: Address,
    pub token_account: Address,
    pub shares_account: Address,
}

pub struct Deposit<'a> {
    pub vault: &'a VaultAccounts,
    pub user: &'a UserAccounts,
    pub max_amount: u64,
}

impl Deposit<'_> {
    pub fn instruction(&self) -> Instruction {
        let token_program = spl_token_program_id();
        let mut data = discriminator("global:deposit").to_vec();
        data.extend_from_slice(&self.max_amount.to_le_bytes());
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(self.user.user, true),
                AccountMeta::new(self.vault.vault, false),
                AccountMeta::new(self.vault.token_vault, false),
                AccountMeta::new_readonly(self.vault.token_mint, false),
                AccountMeta::new_readonly(self.vault.authority, false),
                AccountMeta::new(self.vault.shares_mint, false),
                AccountMeta::new(self.user.token_account, false),
                AccountMeta::new(self.user.shares_account, false),
                AccountMeta::new_readonly(KLEND_PROGRAM_ID, false),
                AccountMeta::new_readonly(token_program, false),
                AccountMeta::new_readonly(token_program, false),
                AccountMeta::new_readonly(event_authority(), false),
                AccountMeta::new_readonly(PROGRAM_ID, false),
            ],
            data,
        }
    }
}

pub struct WithdrawFromAvailable<'a> {
    pub vault: &'a VaultAccounts,
    pub user: &'a UserAccounts,
    pub shares: u64,
}

impl WithdrawFromAvailable<'_> {
    pub fn instruction(&self) -> Instruction {
        let token_program = spl_token_program_id();
        let mut data = discriminator("global:withdraw_from_available").to_vec();
        data.extend_from_slice(&self.shares.to_le_bytes());
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(self.user.user, true),
                AccountMeta::new(self.vault.vault, false),
                AccountMeta::new_readonly(global_config(), false),
                AccountMeta::new(self.vault.token_vault, false),
                AccountMeta::new_readonly(self.vault.authority, false),
                AccountMeta::new(self.user.token_account, false),
                AccountMeta::new(self.vault.token_mint, false),
                AccountMeta::new(self.user.shares_account, false),
                AccountMeta::new(self.vault.shares_mint, false),
                AccountMeta::new_readonly(token_program, false),
                AccountMeta::new_readonly(token_program, false),
                AccountMeta::new_readonly(KLEND_PROGRAM_ID, false),
                AccountMeta::new_readonly(event_authority(), false),
                AccountMeta::new_readonly(PROGRAM_ID, false),
            ],
            data,
        }
    }
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or_else(|| anyhow!("account too short for a u64 at {offset}"))?;
    Ok(u64::from_le_bytes(bytes.try_into()?))
}

fn read_u128(data: &[u8], offset: usize) -> Result<u128> {
    let bytes = data
        .get(offset..offset + 16)
        .ok_or_else(|| anyhow!("account too short for a u128 at {offset}"))?;
    Ok(u128::from_le_bytes(bytes.try_into()?))
}

fn account_data(rpc: &SolanaRpc, address: &Address) -> Result<Vec<u8>> {
    Ok(rpc
        .get_account(*address)?
        .ok_or_else(|| anyhow!("account {address} missing"))?
        .data)
}

pub fn token_balance(rpc: &SolanaRpc, account: &Address) -> Result<u64> {
    read_u64(&account_data(rpc, account)?, TOKEN_ACCOUNT_AMOUNT_OFFSET)
}

fn mul_div_floor(a: u64, b: u64, divisor: u64) -> Result<u64> {
    if divisor == 0 {
        bail!("division by zero in share math");
    }
    Ok(u64::try_from(
        u128::from(a) * u128::from(b) / u128::from(divisor),
    )?)
}

fn mul_div_ceil(a: u64, b: u64, divisor: u64) -> Result<u64> {
    if divisor == 0 {
        bail!("division by zero in share math");
    }
    Ok(u64::try_from(
        (u128::from(a) * u128::from(b)).div_ceil(u128::from(divisor)),
    )?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultState {
    pub token_available: u64,
    pub shares_issued: u64,
    pub pending_fees_sf: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositOutcome {
    pub tokens: u64,
    pub shares: u64,
    pub after: VaultState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawOutcome {
    pub tokens: u64,
    pub shares: u64,
    pub after: VaultState,
}

impl VaultState {
    pub fn read(rpc: &SolanaRpc, vault: &Address) -> Result<Self> {
        Self::from_data(&account_data(rpc, vault)?)
    }

    pub fn from_data(data: &[u8]) -> Result<Self> {
        Ok(Self {
            token_available: read_u64(data, TOKEN_AVAILABLE_OFFSET)?,
            shares_issued: read_u64(data, SHARES_ISSUED_OFFSET)?,
            pending_fees_sf: read_u128(data, PENDING_FEES_OFFSET)?,
        })
    }

    fn aum(&self) -> Result<u64> {
        if self.pending_fees_sf != 0 {
            bail!(
                "vault carries pending fees {}, the share math assumes a fee-free vault",
                self.pending_fees_sf
            );
        }
        Ok(self.token_available)
    }

    pub fn deposit(&self, amount: u64) -> Result<DepositOutcome> {
        let aum = self.aum()?;
        let (shares, tokens) = if self.shares_issued == 0 {
            (amount, amount)
        } else {
            let shares = mul_div_floor(self.shares_issued, amount, aum)?;
            (shares, mul_div_ceil(aum, shares, self.shares_issued)?)
        };
        if shares == 0 {
            bail!("a deposit of {amount} mints no shares");
        }
        Ok(DepositOutcome {
            tokens,
            shares,
            after: Self {
                token_available: self.token_available + tokens,
                shares_issued: self.shares_issued + shares,
                pending_fees_sf: self.pending_fees_sf,
            },
        })
    }

    pub fn withdraw(&self, shares: u64) -> Result<WithdrawOutcome> {
        let aum = self.aum()?;
        if shares > self.shares_issued {
            bail!(
                "withdrawing {shares} shares of {} issued",
                self.shares_issued
            );
        }
        let tokens = if shares == self.shares_issued {
            aum
        } else {
            mul_div_floor(aum, shares, self.shares_issued)?
        };
        if tokens == 0 {
            bail!("a withdrawal of {shares} shares pays no tokens");
        }
        let burned = mul_div_ceil(tokens, self.shares_issued, aum)?.min(shares);
        Ok(WithdrawOutcome {
            tokens,
            shares: burned,
            after: Self {
                token_available: self.token_available - tokens,
                shares_issued: self.shares_issued - burned,
                pending_fees_sf: self.pending_fees_sf,
            },
        })
    }
}
