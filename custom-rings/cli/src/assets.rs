//! Funding checks run before paid instructions.

use anyhow::{anyhow, ensure, Result};
use custom_ring_sdk::{DepositAsset, DepositSplAccounts};
use solana_account::Account;
use solana_address::Address;
use spl_token_2022_interface::{
    extension::{
        transfer_fee::TransferFeeConfig, BaseStateWithExtensions, ExtensionType,
        PodStateWithExtensions,
    },
    pod::{PodAccount, PodMint},
};
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{
    pda, SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_ACCOUNT_INITIALIZED, SPL_TOKEN_PROGRAM_ID,
};
use zolana_transaction::{AssetRegistry, SOL_MINT};

pub struct ResolvedAsset {
    pub mint: Address,
    pub registry: AssetRegistry,
    /// The token program and the fee schedule of an SPL mint.
    token: Option<(Address, Option<TransferFeeConfig>)>,
}

/// The registry is read strictly, one invalid entry fails the whole read.
pub fn resolve(rpc: &SolanaRpc, mint: Address) -> Result<ResolvedAsset> {
    let registry = rpc.asset_registry()?;
    ensure!(
        registry.asset_id(&mint).is_ok(),
        "mint {mint} is not registered with SPP"
    );
    let token = (mint != SOL_MINT).then(|| token(rpc, mint)).transpose()?;
    Ok(ResolvedAsset {
        mint,
        registry,
        token,
    })
}

fn token(rpc: &SolanaRpc, mint: Address) -> Result<(Address, Option<TransferFeeConfig>)> {
    let unsupported = || anyhow!("mint {mint} is not a valid SPL or Token-2022 mint");
    let account = rpc.get_account(mint)?.ok_or_else(unsupported)?;
    let state = PodStateWithExtensions::<PodMint>::unpack(&account.data)
        .ok()
        .filter(|state| bool::from(state.base.is_initialized))
        .filter(|_| {
            [SPL_TOKEN_PROGRAM_ID, SPL_TOKEN_2022_PROGRAM_ID].contains(account.owner.as_array())
        })
        .ok_or_else(unsupported)?;
    let types = state.get_extension_types().map_err(|_| unsupported())?;
    let fee = match types.contains(&ExtensionType::TransferFeeConfig) {
        true => Some(
            *state
                .get_extension::<TransferFeeConfig>()
                .map_err(|_| unsupported())?,
        ),
        false => None,
    };
    Ok((account.owner, fee))
}

impl ResolvedAsset {
    /// The payer's associated token account unless `token_account` names another.
    pub fn deposit(
        &self,
        rpc: &SolanaRpc,
        payer: Address,
        token_account: Option<Address>,
        amount: u64,
    ) -> Result<DepositAsset> {
        let Some((token_program, fee)) = self.token else {
            ensure!(
                token_account.is_none(),
                "--token-account applies only to an SPL mint"
            );
            return Ok(DepositAsset::Sol);
        };
        if let Some(fee) = &fee {
            ensure!(
                !deposit_fee_active(fee, rpc.client().get_epoch_info()?.epoch),
                "mint {} charges transfer fees that SPP deposits do not support",
                self.mint
            );
        }
        let spl = DepositSplAccounts {
            mint: self.mint,
            user_token: token_account.unwrap_or_else(|| {
                pda::associated_token_address_with_program(&payer, &self.mint, &token_program)
            }),
            token_program,
        };
        let account = rpc.get_account(spl.user_token)?;
        validate_funding(&spl, account.as_ref(), payer, amount)?;
        Ok(DepositAsset::Spl(spl))
    }
}

fn validate_funding(
    spl: &DepositSplAccounts,
    account: Option<&Account>,
    payer: Address,
    amount: u64,
) -> Result<()> {
    let invalid = || {
        anyhow!(
            "token account {} is missing, frozen, or does not belong to the payer and mint",
            spl.user_token
        )
    };
    let account = account.ok_or_else(invalid)?;
    let state =
        PodStateWithExtensions::<PodAccount>::unpack(&account.data).map_err(|_| invalid())?;
    let base = state.base;
    ensure!(
        account.owner == spl.token_program
            && base.mint.to_bytes() == spl.mint.to_bytes()
            && base.owner.to_bytes() == payer.to_bytes()
            && base.state == SPL_TOKEN_ACCOUNT_INITIALIZED,
        invalid()
    );
    let held = u64::from(base.amount);
    ensure!(
        held >= amount,
        "token account {} holds {held} base units, the deposit needs {amount}",
        spl.user_token
    );
    Ok(())
}

fn deposit_fee_active(config: &TransferFeeConfig, epoch: u64) -> bool {
    let fee = config.get_epoch_fee(epoch);
    u16::from(fee.transfer_fee_basis_points) != 0 && u64::from(fee.maximum_fee) != 0
}

#[cfg(test)]
mod tests {
    use zolana_interface::{SPL_TOKEN_ACCOUNT_LEN, SPL_TOKEN_ACCOUNT_STATE_OFFSET};

    use super::*;

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
        let address = Address::new_from_array([5; 32]);
        for program in [SPL_TOKEN_PROGRAM_ID, SPL_TOKEN_2022_PROGRAM_ID] {
            let program = Address::new_from_array(program);
            let mut data = vec![0; SPL_TOKEN_ACCOUNT_LEN];
            data[..32].copy_from_slice(mint.as_array());
            data[32..64].copy_from_slice(payer.as_array());
            data[64..72].copy_from_slice(&17u64.to_le_bytes());
            data[SPL_TOKEN_ACCOUNT_STATE_OFFSET] = SPL_TOKEN_ACCOUNT_INITIALIZED;
            let account = |owner, data: &[u8]| Account {
                owner,
                data: data.to_vec(),
                ..Account::default()
            };
            let funding = |owner, data: &[u8], mint, amount| {
                let spl = DepositSplAccounts {
                    mint,
                    user_token: address,
                    token_program: program,
                };
                validate_funding(&spl, Some(&account(owner, data)), payer, amount)
            };
            assert!(funding(program, &data, mint, 17).is_ok());
            let short = funding(program, &data, mint, 18).expect_err("short");
            assert!(short.to_string().contains("holds 17 base units"), "{short}");
            assert!(funding(program, &data, Address::default(), 1).is_err());
            assert!(funding(Address::default(), &data, mint, 1).is_err());
            assert!(funding(program, &data[..SPL_TOKEN_ACCOUNT_LEN - 1], mint, 1).is_err());
            data[SPL_TOKEN_ACCOUNT_STATE_OFFSET] = 2;
            assert!(funding(program, &data, mint, 1).is_err());
        }
    }
}
