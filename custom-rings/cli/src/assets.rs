//! Funding checks run before paid instructions.

use custom_ring_sdk::{DepositAsset, DepositSplAccounts};
use solana_address::Address;
use spl_token_2022_interface::{
    extension::{
        transfer_fee::TransferFeeConfig, BaseStateWithExtensions, ExtensionType,
        PodStateWithExtensions,
    },
    pod::{PodAccount, PodMint},
};
use thiserror::Error;
use zolana_client::{ClientError, ProgramAccountsFilter, Rpc, SolanaRpc};
use zolana_interface::{
    pda,
    state::{discriminator::SPL_ASSET_REGISTRY, SplAssetRegistry},
    SHIELDED_POOL_PROGRAM_ID, SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_ACCOUNT_INITIALIZED,
    SPL_TOKEN_PROGRAM_ID,
};
use zolana_transaction::{AssetRegistry, TransactionError, SOL_MINT};

#[derive(Debug, Error)]
pub enum AssetError {
    #[error(transparent)]
    Client(Box<ClientError>),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error("mint {0} is not registered with SPP")]
    NotRegistered(Address),
    #[error("invalid SPP asset registry account {0}")]
    InvalidRegistry(Address),
    #[error("mint {0} is not a valid SPL or Token-2022 mint")]
    UnsupportedMint(Address),
    #[error("mint {0} charges transfer fees that SPP deposits do not support")]
    TransferFeeDeposit(Address),
    #[error("token account {0} is missing, frozen, or does not belong to the payer and mint")]
    InvalidTokenAccount(Address),
    #[error("token account {account} holds {held} base units, the deposit needs {needed}")]
    InsufficientTokens {
        account: Address,
        held: u64,
        needed: u64,
    },
    #[error("--token-account applies only to an SPL mint")]
    TokenAccountForSol,
}

impl From<ClientError> for AssetError {
    fn from(error: ClientError) -> Self {
        Self::Client(Box::new(error))
    }
}

/// Keeps a registered mint's token metadata for preflight funding checks.
pub struct ResolvedAsset {
    pub mint: Address,
    pub registry: AssetRegistry,
    token_program: Option<Address>,
    transfer_fee: Option<TransferFeeConfig>,
}

/// Identifies the payer's public funds that will back a ring deposit.
pub struct DepositFunding {
    pub payer: Address,
    pub token_account: Option<Address>,
    pub amount: u64,
}

pub fn resolve(rpc: &SolanaRpc, mint: Address) -> Result<ResolvedAsset, AssetError> {
    let mut registry = AssetRegistry::default();
    let filter =
        ProgramAccountsFilter::new(SplAssetRegistry::SIZE).with_memcmp(0, [SPL_ASSET_REGISTRY]);
    for (address, account) in rpc
        .get_program_accounts_filtered(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID), &filter)?
    {
        let entry = SplAssetRegistry::from_account_bytes(&account.data)
            .map_err(|_| AssetError::InvalidRegistry(address))?;
        if account.owner != Address::new_from_array(SHIELDED_POOL_PROGRAM_ID)
            || address != pda::spl_asset_registry(&entry.mint)
        {
            return Err(AssetError::InvalidRegistry(address));
        }
        registry.insert(entry.asset_id, entry.mint)?;
    }
    if registry.asset_id(&mint).is_err() {
        return Err(AssetError::NotRegistered(mint));
    }
    let mut transfer_fee = None;
    let token_program = if mint == SOL_MINT {
        None
    } else {
        let account = rpc
            .get_account(mint)?
            .ok_or(AssetError::UnsupportedMint(mint))?;
        if ![SPL_TOKEN_PROGRAM_ID, SPL_TOKEN_2022_PROGRAM_ID].contains(account.owner.as_array()) {
            return Err(AssetError::UnsupportedMint(mint));
        }
        let state = PodStateWithExtensions::<PodMint>::unpack(&account.data)
            .map_err(|_| AssetError::UnsupportedMint(mint))?;
        if !bool::from(state.base.is_initialized) {
            return Err(AssetError::UnsupportedMint(mint));
        }
        if state
            .get_extension_types()
            .map_err(|_| AssetError::UnsupportedMint(mint))?
            .contains(&ExtensionType::TransferFeeConfig)
        {
            transfer_fee = Some(
                *state
                    .get_extension::<TransferFeeConfig>()
                    .map_err(|_| AssetError::UnsupportedMint(mint))?,
            );
        }
        Some(account.owner)
    };
    Ok(ResolvedAsset {
        mint,
        registry,
        token_program,
        transfer_fee,
    })
}

impl ResolvedAsset {
    pub fn deposit(
        &self,
        rpc: &SolanaRpc,
        funding: DepositFunding,
    ) -> Result<DepositAsset, AssetError> {
        let DepositFunding {
            payer,
            token_account,
            amount,
        } = funding;
        let Some(token_program) = self.token_program else {
            return if token_account.is_some() {
                Err(AssetError::TokenAccountForSol)
            } else {
                Ok(DepositAsset::Sol)
            };
        };
        if let Some(fee) = &self.transfer_fee {
            let epoch = rpc
                .client()
                .get_epoch_info()
                .map_err(|error| ClientError::Rpc(error.to_string()))?
                .epoch;
            if deposit_fee_active(fee, epoch) {
                return Err(AssetError::TransferFeeDeposit(self.mint));
            }
        }
        let token_account = token_account.unwrap_or_else(|| {
            pda::associated_token_address_with_program(&payer, &self.mint, &token_program)
        });
        let account = rpc
            .get_account(token_account)?
            .ok_or(AssetError::InvalidTokenAccount(token_account))?;
        FundingAccount {
            address: token_account,
            token_program,
            payer,
            mint: self.mint,
            amount,
        }
        .validate(account.owner, &account.data)?;
        Ok(DepositAsset::Spl(DepositSplAccounts {
            mint: self.mint,
            user_token: token_account,
            token_program,
        }))
    }
}

/// Checks the token account authorized to fund the requested mint and deposit amount.
struct FundingAccount {
    address: Address,
    token_program: Address,
    payer: Address,
    mint: Address,
    amount: u64,
}

impl FundingAccount {
    fn validate(self, owner: Address, data: &[u8]) -> Result<(), AssetError> {
        let Self {
            address,
            token_program,
            payer,
            mint,
            amount,
        } = self;
        let state = PodStateWithExtensions::<PodAccount>::unpack(data)
            .map_err(|_| AssetError::InvalidTokenAccount(address))?;
        if owner != token_program
            || state.base.mint.to_bytes() != mint.to_bytes()
            || state.base.owner.to_bytes() != payer.to_bytes()
            || state.base.state != SPL_TOKEN_ACCOUNT_INITIALIZED
        {
            return Err(AssetError::InvalidTokenAccount(address));
        }
        let held = u64::from(state.base.amount);
        if held < amount {
            return Err(AssetError::InsufficientTokens {
                account: address,
                held,
                needed: amount,
            });
        }
        Ok(())
    }
}

fn deposit_fee_active(config: &TransferFeeConfig, epoch: u64) -> bool {
    let fee = config.get_epoch_fee(epoch);
    u16::from(fee.transfer_fee_basis_points) != 0 && u64::from(fee.maximum_fee) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_interface::{SPL_TOKEN_ACCOUNT_LEN, SPL_TOKEN_ACCOUNT_STATE_OFFSET};

    #[test]
    fn deposit_fee_check_uses_the_active_epoch_schedule() {
        let mut config = TransferFeeConfig::default();
        config.newer_transfer_fee.epoch = 7u64.into();
        config.newer_transfer_fee.transfer_fee_basis_points = 100u16.into();
        config.newer_transfer_fee.maximum_fee = 5u64.into();
        assert!(!deposit_fee_active(&config, 6));
        assert!(deposit_fee_active(&config, 7));
        config.newer_transfer_fee.maximum_fee = 0u64.into();
        assert!(!deposit_fee_active(&config, 7));
    }
    #[test]
    fn funding_account_checks_both_token_programs_and_never_crosses_mints() {
        let payer = Address::new_from_array([3; 32]);
        let mint = Address::new_from_array([4; 32]);
        let account = Address::new_from_array([5; 32]);
        for program in [SPL_TOKEN_PROGRAM_ID, SPL_TOKEN_2022_PROGRAM_ID] {
            let program = Address::new_from_array(program);
            let mut data = vec![0; SPL_TOKEN_ACCOUNT_LEN];
            data[..32].copy_from_slice(mint.as_array());
            data[32..64].copy_from_slice(payer.as_array());
            data[64..72].copy_from_slice(&17u64.to_le_bytes());
            data[SPL_TOKEN_ACCOUNT_STATE_OFFSET] = SPL_TOKEN_ACCOUNT_INITIALIZED;
            let funding = |mint, amount| FundingAccount {
                address: account,
                token_program: program,
                payer,
                mint,
                amount,
            };
            assert!(funding(mint, 17).validate(program, &data).is_ok());
            assert!(matches!(
                funding(mint, 18).validate(program, &data),
                Err(AssetError::InsufficientTokens { .. })
            ));
            assert!(funding(Address::default(), 1)
                .validate(program, &data)
                .is_err());
            assert!(funding(mint, 1)
                .validate(Address::default(), &data)
                .is_err());
            assert!(funding(mint, 1)
                .validate(program, &data[..SPL_TOKEN_ACCOUNT_LEN - 1])
                .is_err());
            data[SPL_TOKEN_ACCOUNT_STATE_OFFSET] = 2;
            assert!(funding(mint, 1).validate(program, &data).is_err());
        }
    }
}
