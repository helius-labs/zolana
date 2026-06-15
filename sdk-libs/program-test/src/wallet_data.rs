use zolana_interface::{
    event::ProoflessShieldEvent,
    instruction::{ProoflessShieldIxData, PUBLIC_AMOUNT_DEPOSIT_SOL, PUBLIC_AMOUNT_DEPOSIT_SPL},
};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_transaction::{
    owner_utxo_hash, Address, Data, DataRecord, ProoflessDepositEvent, TransactionError, Wallet,
};

use crate::{ProgramTestError, ZolanaProgramTest};

pub fn proofless_event_for_wallet(event: &ProoflessShieldEvent) -> ProoflessDepositEvent {
    let mut records = Vec::new();
    if let Some(zone_data) = event.zone_data.clone() {
        records.push(DataRecord::ZoneData(zone_data));
    }
    if let Some(program_data) = event.program_data.clone() {
        records.push(DataRecord::ProgramData(program_data));
    }
    ProoflessDepositEvent {
        view_tag: event.view_tag,
        utxo_hash: event.utxo_hash,
        owner_utxo_hash: event.owner_utxo_hash,
        salt: event.salt,
        asset: Address::new_from_array(event.asset),
        amount: event.amount,
        zone_program_id: event.zone_program_id.map(Address::new_from_array),
        program_data_hash: event.program_data_hash.unwrap_or([0u8; 32]),
        zone_data_hash: event.policy_data_hash.unwrap_or([0u8; 32]),
        data: Data::new(records),
    }
}

pub(crate) struct WalletShieldFields {
    pub view_tag: [u8; 32],
    pub owner_utxo_hash: [u8; 32],
    pub salt: [u8; 16],
}

pub(crate) fn wallet_shield_fields(
    recipient: &Wallet,
    blinding_seed: &[u8; BLINDING_LEN],
    position: u8,
) -> Result<WalletShieldFields, ProgramTestError> {
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&blinding_seed[..16]);
    salt[15] ^= position;
    let blinding = recipient
        .keypair
        .viewing_key
        .derive_proofless_blinding(&salt)
        .map_err(TransactionError::from)?;
    let owner_hash = recipient
        .keypair
        .owner_hash()
        .map_err(TransactionError::from)?;
    let owner_utxo_hash = owner_utxo_hash(&owner_hash, &blinding)?;
    Ok(WalletShieldFields {
        view_tag: recipient.keypair.recipient_bootstrap_view_tag(),
        owner_utxo_hash,
        salt,
    })
}

impl ZolanaProgramTest {
    pub fn sol_shield_data(lamports: u64, owner_utxo_hash: [u8; 32]) -> ProoflessShieldIxData {
        ProoflessShieldIxData {
            view_tag: [0u8; 32],
            owner_utxo_hash,
            salt: [0u8; 16],
            public_amount_mode: PUBLIC_AMOUNT_DEPOSIT_SOL,
            public_amount: Some(lamports),
            program_data_hash: None,
            program_data: None,
            cpi_signer: None,
        }
    }

    pub fn spl_shield_data(amount: u64, owner_utxo_hash: [u8; 32]) -> ProoflessShieldIxData {
        ProoflessShieldIxData {
            view_tag: [0u8; 32],
            owner_utxo_hash,
            salt: [0u8; 16],
            public_amount_mode: PUBLIC_AMOUNT_DEPOSIT_SPL,
            public_amount: Some(amount),
            program_data_hash: None,
            program_data: None,
            cpi_signer: None,
        }
    }

    pub fn wallet_sol_shield_data(
        lamports: u64,
        recipient: &Wallet,
        blinding_seed: &[u8; BLINDING_LEN],
        position: u8,
    ) -> Result<ProoflessShieldIxData, ProgramTestError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok(ProoflessShieldIxData {
            view_tag: fields.view_tag,
            owner_utxo_hash: fields.owner_utxo_hash,
            salt: fields.salt,
            public_amount_mode: PUBLIC_AMOUNT_DEPOSIT_SOL,
            public_amount: Some(lamports),
            program_data_hash: None,
            program_data: None,
            cpi_signer: None,
        })
    }

    pub fn wallet_spl_shield_data(
        amount: u64,
        recipient: &Wallet,
        blinding_seed: &[u8; BLINDING_LEN],
        position: u8,
    ) -> Result<ProoflessShieldIxData, ProgramTestError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok(ProoflessShieldIxData {
            view_tag: fields.view_tag,
            owner_utxo_hash: fields.owner_utxo_hash,
            salt: fields.salt,
            public_amount_mode: PUBLIC_AMOUNT_DEPOSIT_SPL,
            public_amount: Some(amount),
            program_data_hash: None,
            program_data: None,
            cpi_signer: None,
        })
    }
}
