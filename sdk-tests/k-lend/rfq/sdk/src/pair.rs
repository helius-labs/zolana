use anyhow::{anyhow, bail, Result};
use solana_address::Address;
use zolana_client::{Rpc, SolanaRpc};

use crate::state::VaultState as VaultAccount;

pub const PROGRAM_ID: Address =
    Address::from_str_const("KvauGMspG5k6rtzrqqn7WNn3oZdyKqLKwK2XWQ8FLjd");

fn pda(seeds: &[&[u8]]) -> Address {
    Address::find_program_address(seeds, &PROGRAM_ID).0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pair {
    pub vault: Address,
    pub token_mint: Address,
    pub authority: Address,
    pub token_vault: Address,
    pub shares_mint: Address,
}

impl Pair {
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

fn account_data(rpc: &SolanaRpc, address: &Address) -> Result<Vec<u8>> {
    let account = rpc
        .get_account(*address)?
        .ok_or_else(|| anyhow!("account {address} missing"))?;
    if account.owner != PROGRAM_ID || account.executable {
        bail!("account {address} is not a kVault state account");
    }
    Ok(account.data)
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
        let account = VaultAccount::from_account_bytes(data)?;
        if account
            .vault_allocation_strategy
            .iter()
            .any(|allocation| allocation.reserve != Address::default())
        {
            bail!("allocated kVaults require reserve AUM pricing; this example supports unallocated vaults");
        }
        Ok(Self {
            token_available: account.token_available,
            shares_issued: account.shares_issued,
            pending_fees_sf: u128::from_le_bytes(account.pending_fees_sf),
        })
    }

    fn aum(&self) -> Result<u64> {
        // This example models an unallocated, fee-free vault. Pending fees are
        // fixed-point values and production AUM also includes reserve holdings;
        // rejecting them avoids pricing production shares from cash alone.
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
                token_available: self
                    .token_available
                    .checked_add(tokens)
                    .ok_or_else(|| anyhow!("vault token balance overflow"))?,
                shares_issued: self
                    .shares_issued
                    .checked_add(shares)
                    .ok_or_else(|| anyhow!("vault share supply overflow"))?,
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

#[cfg(test)]
mod tests;
