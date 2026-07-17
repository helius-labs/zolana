use zolana_interface::instruction::DepositIxData;
use zolana_keypair::{constants::BLINDING_LEN, shielded::ShieldedAddress};
use zolana_transaction::{derive_blinding, TransactionError};

use crate::{ProgramTestError, ZolanaProgramTest};

pub(crate) struct WalletShieldFields {
    pub view_tag: [u8; 32],
    pub owner: [u8; 32],
    pub blinding: [u8; BLINDING_LEN],
}

pub(crate) fn wallet_shield_fields(
    recipient: &ShieldedAddress,
    blinding_seed: &[u8; BLINDING_LEN],
    position: u8,
) -> Result<WalletShieldFields, ProgramTestError> {
    let blinding = derive_blinding(blinding_seed, position);
    let owner = recipient.owner_hash().map_err(TransactionError::from)?;
    Ok(WalletShieldFields {
        view_tag: recipient.viewing_pubkey.x(),
        owner,
        blinding,
    })
}

impl ZolanaProgramTest {
    pub fn sol_shield_data(
        lamports: u64,
        owner: [u8; 32],
        blinding: [u8; BLINDING_LEN],
    ) -> DepositIxData {
        DepositIxData {
            view_tag: [0u8; 32],
            owner,
            blinding,
            amount: lamports,
            utxo_data: None,
            memo: None,
        }
    }

    pub fn spl_shield_data(
        amount: u64,
        owner: [u8; 32],
        blinding: [u8; BLINDING_LEN],
    ) -> DepositIxData {
        DepositIxData {
            view_tag: [0u8; 32],
            owner,
            blinding,
            amount,
            utxo_data: None,
            memo: None,
        }
    }

    pub fn wallet_sol_shield_data(
        lamports: u64,
        recipient: &ShieldedAddress,
        blinding_seed: &[u8; BLINDING_LEN],
        position: u8,
    ) -> Result<DepositIxData, ProgramTestError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok(DepositIxData {
            view_tag: fields.view_tag,
            owner: fields.owner,
            blinding: fields.blinding,
            amount: lamports,
            utxo_data: None,
            memo: None,
        })
    }

    pub fn wallet_spl_shield_data(
        amount: u64,
        recipient: &ShieldedAddress,
        blinding_seed: &[u8; BLINDING_LEN],
        position: u8,
    ) -> Result<DepositIxData, ProgramTestError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok(DepositIxData {
            view_tag: fields.view_tag,
            owner: fields.owner,
            blinding: fields.blinding,
            amount,
            utxo_data: None,
            memo: None,
        })
    }
}
