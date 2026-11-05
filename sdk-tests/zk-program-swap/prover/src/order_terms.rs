use spr_gnark_ffi_prover::decimal;
use spr_hasher::primitives::right_align;

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
                right_align(&self.destination_amount.to_be_bytes()),
            ),
            ("MakerOwnerHash", self.maker_owner_hash),
            ("Expiry", right_align(&self.expiry.to_be_bytes())),
            ("TakerPkFe", self.taker_pk_fe),
            ("TakeMode", right_align(&self.take_mode.to_be_bytes())),
        ];
        let mut entries: Vec<(String, Vec<String>)> = scalars
            .iter()
            .map(|(suffix, value)| (format!("{prefix}_{suffix}"), vec![decimal(value)]))
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

/// The witness keys one `orderterms.OrderTerms` prefix must produce, spelled out
/// from the Go field names for the exact-key-set tests.
#[cfg(test)]
pub(crate) fn expected_order_terms_witness_keys(prefix: &str) -> Vec<String> {
    [
        "DestinationAsset",
        "DestinationAmount",
        "MakerOwnerHash",
        "MakerViewingPk",
        "Expiry",
        "TakerPkFe",
        "TakeMode",
    ]
    .iter()
    .map(|suffix| format!("{prefix}_{suffix}"))
    .collect()
}
