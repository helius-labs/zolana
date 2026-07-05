use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, MergeTransactIxData, MergeZoneIxData},
    pda, PROGRAM_ID_PUBKEY,
};

/// Builder for the `merge_zone` instruction, the policy-zone analog of
/// [`super::merge_transact::MergeTransact`]. The account layout mirrors the
/// program loader (`MergeZoneAccounts::validate_and_parse`): `tree` (writable),
/// `zone_config` (the zone's `zone_auth` PDA), `payer` (signer), and the program
/// account last for the `emit_event` self-CPI. Instruction data is the
/// zone-chosen `merge_view_tag` followed by the `MergeTransactIxData` body.
pub struct MergeZone {
    pub tree: Pubkey,
    /// Calling zone program; its `zone_config` (canonical `zone_auth` PDA) signs.
    pub zone_program_id: Pubkey,
    pub payer: Pubkey,
    pub data: MergeTransactIxData,
    /// Zone-chosen opaque tag indexing the merged output; it may repeat across
    /// merges (replay protection comes from the input nullifiers).
    pub merge_view_tag: [u8; 32],
}

impl MergeZone {
    /// Instruction sent to the zone program, which CPIs into SPP. The `zone_auth`
    /// PDA is not a transaction-level signer; the zone program signs for it.
    pub fn instruction(&self) -> Instruction {
        self.build_instruction(self.zone_program_id, false)
    }

    /// The SPP instruction a zone program constructs for its own CPI: program id
    /// is SPP and the `zone_auth` PDA is passed as a signer.
    pub fn cpi_instruction(&self) -> Instruction {
        self.build_instruction(PROGRAM_ID_PUBKEY, true)
    }

    fn build_instruction(&self, program_id: Pubkey, auth_signer: bool) -> Instruction {
        let zone_config = pda::zone_auth(&self.zone_program_id).0;

        let ix_data = MergeZoneIxData {
            merge_view_tag: self.merge_view_tag,
            merge: self.data.clone(),
        };
        let mut instruction_data = vec![tag::ZONE_MERGE_TRANSACT];
        instruction_data.extend_from_slice(
            &ix_data
                .serialize()
                .expect("shielded-pool instruction serialization is infallible"),
        );

        let accounts = vec![
            AccountMeta::new(self.tree, false),
            AccountMeta::new_readonly(zone_config, auth_signer),
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
        ];

        Instruction {
            program_id,
            accounts,
            data: instruction_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> MergeTransactIxData {
        MergeTransactIxData {
            expiry_unix_ts: u64::MAX,
            proof: [0u8; 192],
            output_utxo_hash: [0u8; 32],
            nullifiers: vec![[0u8; 32]; 8],
            utxo_tree_root_index: vec![0; 8],
            nullifier_tree_root_index: vec![0; 8],
            private_tx_hash: [0u8; 32],
            encrypted_utxo: vec![0u8; 110],
            eddsa_owner: false,
        }
    }

    /// The instruction targets the zone program, lays out `tree`, `zone_config`,
    /// `payer`, program account, and tags the data with `ZONE_MERGE_TRANSACT`
    /// followed by the 32-byte `merge_view_tag`.
    #[test]
    fn instruction_account_order_and_zone_config() {
        let zone_program_id = Pubkey::new_unique();
        let builder = MergeZone {
            tree: Pubkey::new_unique(),
            zone_program_id,
            payer: Pubkey::new_unique(),
            data: data(),
            merge_view_tag: [7u8; 32],
        };

        let ix = builder.instruction();
        assert_eq!(ix.program_id, zone_program_id);
        assert_eq!(ix.data.first(), Some(&tag::ZONE_MERGE_TRANSACT));
        assert_eq!(ix.data.get(1..33), Some(&[7u8; 32][..]));

        let zone_config = pda::zone_auth(&zone_program_id).0;
        let keys: Vec<_> = ix.accounts.iter().map(|m| m.pubkey).collect();
        assert_eq!(
            keys,
            vec![builder.tree, zone_config, builder.payer, PROGRAM_ID_PUBKEY]
        );
        // `.instruction()` targets the zone program, so the `zone_auth` PDA is not
        // a transaction-level signer.
        assert!(!ix.accounts[1].is_signer);
        assert!(ix.accounts[2].is_signer);
    }

    #[test]
    fn cpi_instruction_marks_zone_auth_signer() {
        let zone_program_id = Pubkey::new_unique();
        let builder = MergeZone {
            tree: Pubkey::new_unique(),
            zone_program_id,
            payer: Pubkey::new_unique(),
            data: data(),
            merge_view_tag: [0u8; 32],
        };

        let ix = builder.cpi_instruction();
        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.accounts[1].pubkey, pda::zone_auth(&zone_program_id).0);
        assert!(ix.accounts[1].is_signer);
    }
}
