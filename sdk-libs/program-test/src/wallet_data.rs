use rings_interface::instruction::DepositIxData;
use rings_keypair::constants::BLINDING_LEN;
use rings_transaction::{derive_blinding, TransactionError, Wallet};

use crate::{ProgramTestError, RingsProgramTest};

pub(crate) struct WalletShieldFields {
    pub view_tag: [u8; 32],
    pub owner: [u8; 32],
    pub blinding: [u8; BLINDING_LEN],
}

pub(crate) fn wallet_shield_fields(
    recipient: &Wallet,
    blinding_seed: &[u8; BLINDING_LEN],
    position: u8,
) -> Result<WalletShieldFields, ProgramTestError> {
    let blinding = derive_blinding(blinding_seed, position);
    let owner = recipient
        .keypair
        .owner_hash()
        .map_err(TransactionError::from)?;
    Ok(WalletShieldFields {
        view_tag: recipient.keypair.recipient_bootstrap_view_tag(),
        owner,
        blinding,
    })
}

impl RingsProgramTest {
    pub fn sol_shield_data(
        lamports: u64,
        owner: [u8; 32],
        blinding: [u8; BLINDING_LEN],
    ) -> DepositIxData {
        DepositIxData {
            view_tag: [0u8; 32],
            owner,
            blinding,
            public_amount: Some(lamports),
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
            public_amount: Some(amount),
            utxo_data: None,
            memo: None,
        }
    }

    pub fn wallet_sol_shield_data(
        lamports: u64,
        recipient: &Wallet,
        blinding_seed: &[u8; BLINDING_LEN],
        position: u8,
    ) -> Result<DepositIxData, ProgramTestError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok(DepositIxData {
            view_tag: fields.view_tag,
            owner: fields.owner,
            blinding: fields.blinding,
            public_amount: Some(lamports),
            utxo_data: None,
            memo: None,
        })
    }

    pub fn wallet_spl_shield_data(
        amount: u64,
        recipient: &Wallet,
        blinding_seed: &[u8; BLINDING_LEN],
        position: u8,
    ) -> Result<DepositIxData, ProgramTestError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok(DepositIxData {
            view_tag: fields.view_tag,
            owner: fields.owner,
            blinding: fields.blinding,
            public_amount: Some(amount),
            utxo_data: None,
            memo: None,
        })
    }
}
