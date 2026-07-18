use timelock_escrow_program::instructions::shared::u64_right_align;

use crate::bytes_to_decimal_string;

#[derive(Debug, Clone, Copy)]
pub struct EscrowTermsProofInput {
    pub owner_hash: [u8; 32],
    pub unlock: u64,
}

impl EscrowTermsProofInput {
    pub fn witness_entries(&self, prefix: &str) -> Vec<(String, Vec<String>)> {
        let scalars: [(&str, [u8; 32]); 2] = [
            ("OwnerHash", self.owner_hash),
            ("Unlock", u64_right_align(self.unlock)),
        ];
        scalars
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
