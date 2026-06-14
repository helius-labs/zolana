use zolana_interface::instruction::{ProoflessShieldEvent, ProoflessShieldIxData};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_transaction::{Address, Data, DataRecord, ProoflessDepositEvent, Wallet};

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
    let blinding = recipient.proofless_blinding(&salt)?;
    let owner_utxo_hash = recipient.proofless_owner_utxo_hash(&blinding)?;
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
            public_sol_amount: Some(lamports),
            public_spl_amount: None,
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
            public_sol_amount: None,
            public_spl_amount: Some(amount),
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
            public_sol_amount: Some(lamports),
            public_spl_amount: None,
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
            public_sol_amount: None,
            public_spl_amount: Some(amount),
            program_data_hash: None,
            program_data: None,
            cpi_signer: None,
        })
    }
}
