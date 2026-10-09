use anyhow::{anyhow, bail, Result};
use solana_address::Address;
use zolana_client::{Rpc, SolanaRpc};

pub const PROGRAM_ID: Address =
    Address::from_str_const("KvauGMspG5k6rtzrqqn7WNn3oZdyKqLKwK2XWQ8FLjd");
const TOKEN_AVAILABLE_OFFSET: usize = 8 + 216;
const SHARES_ISSUED_OFFSET: usize = 8 + 224;
const PENDING_FEES_OFFSET: usize = 8 + 288;

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
