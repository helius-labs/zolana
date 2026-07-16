use swap_program::instructions::shared::u64_right_align;

use crate::bytes_to_decimal_string;

pub const TAKE_MODE_DERIVED: u64 = 0;
pub const TAKE_MODE_VERIFIABLE: u64 = 1;

#[derive(Debug, Clone, Copy)]
pub struct OrderTermsProofInput {
    pub destination_asset: [u8; 32],
    pub destination_amount: u64,
    pub maker_owner_hash: [u8; 32],
    pub maker_viewing_pk: [u8; 33],
    pub expiry: u64,
    pub taker_pk_fe: [u8; 32],
    pub take_mode: u64,
}

impl OrderTermsProofInput {
    pub fn witness_entries(&self, prefix: &str) -> Vec<(String, Vec<String>)> {
        let scalars: [(&str, [u8; 32]); 6] = [
            ("DestinationAsset", self.destination_asset),
            (
                "DestinationAmount",
                u64_right_align(self.destination_amount),
            ),
            ("MakerOwnerHash", self.maker_owner_hash),
            ("Expiry", u64_right_align(self.expiry)),
            ("TakerPkFe", self.taker_pk_fe),
            ("TakeMode", u64_right_align(self.take_mode)),
        ];
        let mut entries: Vec<(String, Vec<String>)> = scalars
            .iter()
            .map(|(suffix, value)| {
                (
                    format!("{prefix}_{suffix}"),
                    vec![bytes_to_decimal_string(value)],
                )
            })
            .collect();
        entries.push((
            format!("{prefix}_MakerViewingPk"),
            self.maker_viewing_pk
                .iter()
                .map(|b| b.to_string())
                .collect(),
        ));
        entries
    }
}
