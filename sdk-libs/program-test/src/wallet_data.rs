use solana_pubkey::Pubkey;
use zolana_interface::instruction::{AssetDeposit, DepositAsset, DepositSplAccounts};
use zolana_keypair::shielded::ShieldedAddress;
use zolana_transaction::{derive_blinding, TransactionError};

use crate::{ProgramTestError, ZolanaProgramTest};

pub(crate) struct WalletShieldFields {
    pub view_tag: [u8; 32],
    pub owner: [u8; 32],
    pub blinding: [u8; 32],
}

pub(crate) fn wallet_shield_fields(
    recipient: &ShieldedAddress,
    blinding_seed: &[u8; 32],
    position: u8,
) -> Result<WalletShieldFields, ProgramTestError> {
    let (view_tag, owner) = wallet_shield_identity(recipient)?;
    Ok(WalletShieldFields {
        view_tag,
        owner,
        blinding: derive_blinding(blinding_seed, position),
    })
}

/// The public recipient material a proofless deposit carries. SPP derives the
/// blinding itself, so the plain `deposit` rail needs nothing else.
pub(crate) fn wallet_shield_identity(
    recipient: &ShieldedAddress,
) -> Result<([u8; 32], [u8; 32]), ProgramTestError> {
    let owner = recipient.owner_hash().map_err(TransactionError::from)?;
    Ok((recipient.viewing_pubkey.x(), owner))
}

impl ZolanaProgramTest {
    pub fn sol_shield_data(lamports: u64, owner: [u8; 32]) -> AssetDeposit {
        AssetDeposit {
            asset: DepositAsset::Sol,
            view_tag: [0u8; 32],
            owner,
            amount: lamports,
            utxo_data: None,
            memo: None,
        }
    }

    pub fn spl_shield_data(
        amount: u64,
        owner: [u8; 32],
        mint: &Pubkey,
        user_token: &Pubkey,
    ) -> AssetDeposit {
        Self::spl_shield_data_with_program(
            amount,
            owner,
            mint,
            user_token,
            Self::token_program_id(),
        )
    }

    pub fn spl_shield_data_with_program(
        amount: u64,
        owner: [u8; 32],
        mint: &Pubkey,
        user_token: &Pubkey,
        token_program: Pubkey,
    ) -> AssetDeposit {
        AssetDeposit {
            asset: Self::spl_asset_with_program(mint, user_token, token_program),
            view_tag: [0u8; 32],
            owner,
            amount,
            utxo_data: None,
            memo: None,
        }
    }

    pub fn wallet_sol_shield_data(
        lamports: u64,
        recipient: &ShieldedAddress,
    ) -> Result<AssetDeposit, ProgramTestError> {
        let (view_tag, owner) = wallet_shield_identity(recipient)?;
        Ok(AssetDeposit {
            asset: DepositAsset::Sol,
            view_tag,
            owner,
            amount: lamports,
            utxo_data: None,
            memo: None,
        })
    }

    pub fn wallet_spl_shield_data(
        amount: u64,
        recipient: &ShieldedAddress,
        mint: &Pubkey,
        user_token: &Pubkey,
    ) -> Result<AssetDeposit, ProgramTestError> {
        let (view_tag, owner) = wallet_shield_identity(recipient)?;
        Ok(AssetDeposit {
            asset: Self::spl_asset(mint, user_token),
            view_tag,
            owner,
            amount,
            utxo_data: None,
            memo: None,
        })
    }

    pub fn spl_asset(mint: &Pubkey, user_token: &Pubkey) -> DepositAsset {
        Self::spl_asset_with_program(mint, user_token, Self::token_program_id())
    }

    pub fn spl_asset_with_program(
        mint: &Pubkey,
        user_token: &Pubkey,
        token_program: Pubkey,
    ) -> DepositAsset {
        DepositAsset::Spl(DepositSplAccounts {
            mint: *mint,
            user_token: *user_token,
            token_program,
        })
    }
}
