use swap_program::instructions::shared::u64_to_field;
use zolana_keypair::{hash::poseidon, KeypairError};

use crate::bytes_to_decimal_string;

pub const UTXO_DOMAIN: u64 = 1;

#[derive(Debug, Clone, Copy)]
pub struct UtxoFieldElements {
    pub domain: [u8; 32],
    pub owner: [u8; 32],
    pub asset: [u8; 32],
    pub amount: [u8; 32],
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub zone_data_hash: [u8; 32],
    pub zone_program_id: [u8; 32],
}

impl UtxoFieldElements {
    pub fn plain(
        owner: [u8; 32],
        asset: [u8; 32],
        amount: u64,
        blinding: [u8; 32],
        data_hash: [u8; 32],
    ) -> Self {
        Self {
            domain: u64_to_field(UTXO_DOMAIN),
            owner,
            asset,
            amount: u64_to_field(amount),
            blinding,
            data_hash,
            zone_data_hash: [0u8; 32],
            zone_program_id: [0u8; 32],
        }
    }

    pub fn hash(&self) -> Result<[u8; 32], KeypairError> {
        let owner_utxo_hash = poseidon(&[&self.owner, &self.blinding])?;
        let zone_hash = poseidon(&[&self.zone_data_hash, &self.zone_program_id])?;
        poseidon(&[
            &self.domain,
            &self.asset,
            &self.amount,
            &self.data_hash,
            &zone_hash,
            &owner_utxo_hash,
        ])
    }

    pub fn witness_entries(&self, prefix: &str) -> Vec<(String, Vec<String>)> {
        let fields: [(&str, &[u8; 32]); 8] = [
            ("Domain", &self.domain),
            ("Owner", &self.owner),
            ("Asset", &self.asset),
            ("Amount", &self.amount),
            ("Blinding", &self.blinding),
            ("DataHash", &self.data_hash),
            ("ZoneDataHash", &self.zone_data_hash),
            ("ZoneProgramID", &self.zone_program_id),
        ];
        fields
            .iter()
            .map(|(suffix, value)| {
                (
                    format!("{prefix}_{suffix}"),
                    vec![bytes_to_decimal_string(value)],
                )
            })
            .collect()
    }
}
