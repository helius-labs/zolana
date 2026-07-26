use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        builders::transact::{append_public_leg_accounts, TransactLegAccounts},
        tag, TransactIxData,
    },
    pda, PROGRAM_ID_PUBKEY,
};

/// Builder for the `zone_authority_transact` instruction: a zone-authority state
/// transition (freeze, thaw, permanent-delegate transfer) over zone-owned UTXOs.
/// The account layout matches `zone_transact` (the loader reuses
/// `ZoneTransactAccounts`): `payer`, `tree`, the `ZoneConfig` (the zone's
/// `zone_auth` PDA, which must have `zone_authority_transact_is_enabled` set),
/// the optional public-amount accounts, then the program account last for the
/// `emit_event` self-CPI.
pub struct ZoneAuthorityTransact {
    pub payer: Pubkey,
    pub tree: Pubkey,
    /// Calling zone program; its `ZoneConfig` (canonical `zone_auth` PDA) signs.
    pub zone_program_id: Pubkey,
    pub legs: Vec<TransactLegAccounts>,
    pub data: TransactIxData,
}

impl ZoneAuthorityTransact {
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

        let mut instruction_data = vec![tag::ZONE_AUTHORITY_TRANSACT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("shielded-pool instruction serialization is infallible"),
        );

        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new(self.tree, false),
            AccountMeta::new_readonly(zone_config, auth_signer),
        ];
        append_public_leg_accounts(&mut accounts, &self.data.public_legs, &self.legs);
        accounts.push(AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false));

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
    use crate::instruction::instruction_data::transact::{
        CircuitId, TransactIxData, TransactProof,
    };

    fn empty_data() -> TransactIxData {
        TransactIxData {
            proof: TransactProof::zeroed_eddsa(),
            expiry_unix_ts: u64::MAX,
            private_tx_hash: [0u8; 32],
            circuit: CircuitId::ZoneAuthority(0, 0, 3),
            p256_signing_pk_x: None,
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            inputs: Vec::new(),
            public_legs: Vec::new(),
            data_hash: None,
            zone_data_hash: None,
            outputs: Vec::new(),
            messages: Vec::new(),
        }
    }

    #[test]
    fn instruction_account_order_and_zone_config() {
        let zone_program_id = Pubkey::new_unique();
        let builder = ZoneAuthorityTransact {
            payer: Pubkey::new_unique(),
            tree: Pubkey::new_unique(),
            zone_program_id,
            legs: Vec::new(),
            data: empty_data(),
        };

        let ix = builder.instruction();
        assert_eq!(ix.program_id, zone_program_id);
        assert_eq!(ix.data.first(), Some(&tag::ZONE_AUTHORITY_TRANSACT));

        let zone_config = pda::zone_auth(&zone_program_id).0;
        let keys: Vec<_> = ix.accounts.iter().map(|m| m.pubkey).collect();
        assert_eq!(
            keys,
            vec![
                builder.payer,
                builder.tree,
                zone_config,
                Pubkey::default(),
                PROGRAM_ID_PUBKEY
            ]
        );
        assert!(!ix.accounts[2].is_signer);
    }

    #[test]
    fn cpi_instruction_marks_zone_auth_signer() {
        let zone_program_id = Pubkey::new_unique();
        let builder = ZoneAuthorityTransact {
            payer: Pubkey::new_unique(),
            tree: Pubkey::new_unique(),
            zone_program_id,
            legs: Vec::new(),
            data: empty_data(),
        };

        let ix = builder.cpi_instruction();
        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.accounts[2].pubkey, pda::zone_auth(&zone_program_id).0);
        assert!(ix.accounts[2].is_signer);
    }
}
