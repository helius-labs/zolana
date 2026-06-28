use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{builders::transact::TransactWithdrawal, tag, TransactIxData},
    pda, PROGRAM_ID_PUBKEY, SOL_INTERFACE_PUBKEY,
};

/// Builder for the `zone_authority_transact` instruction: a zone-authority state
/// transition (freeze, thaw, permanent-delegate transfer) over zone-owned UTXOs.
/// The account layout matches `zone_transact` (the loader reuses
/// `ZoneTransactAccounts`): `payer`, `tree`, the `ZoneConfig` (the zone's
/// `zone_auth` PDA, which must have `zone_authority_transact_is_enabled` set), an
/// optional inner `cpi_signer`, the optional public-amount accounts, then the
/// program account last for the `emit_event` self-CPI.
pub struct ZoneAuthorityTransact {
    pub payer: Pubkey,
    pub tree: Pubkey,
    /// Calling zone program; its `ZoneConfig` (canonical `zone_auth` PDA) signs.
    pub zone_program_id: Pubkey,
    pub cpi_signer: Option<Pubkey>,
    pub withdrawal: Option<TransactWithdrawal>,
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
        if let Some(cpi_signer) = self.cpi_signer {
            accounts.push(AccountMeta::new_readonly(cpi_signer, true));
        }
        match &self.withdrawal {
            Some(TransactWithdrawal::Sol(sol)) => {
                accounts.push(AccountMeta::new(SOL_INTERFACE_PUBKEY, false));
                accounts.push(AccountMeta::new(sol.recipient, false));
                accounts.push(AccountMeta::new_readonly(Pubkey::default(), false));
            }
            Some(TransactWithdrawal::Spl(spl)) => {
                if let Some(cpi_authority) = spl.cpi_authority {
                    accounts.push(AccountMeta::new_readonly(cpi_authority, false));
                }
                accounts.push(AccountMeta::new(spl.vault, false));
                accounts.push(AccountMeta::new(spl.recipient, false));
                accounts.push(AccountMeta::new(spl.user_token_account, false));
                accounts.push(AccountMeta::new_readonly(spl.token_program, false));
            }
            None => {}
        }
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
    use crate::instruction::instruction_data::transact::{TransactIxData, TransactProof};

    fn empty_data() -> TransactIxData {
        TransactIxData {
            proof: TransactProof::zeroed_eddsa(),
            expiry_unix_ts: u64::MAX,
            relayer_fee: 0,
            private_tx_hash: [0u8; 32],
            p256_signing_pk_field: None,
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            inputs: Vec::new(),
            public_sol_amount: None,
            public_spl_amount: None,
            cpi_signer: None,
            program_data_hash: None,
            zone_data_hash: None,
            output_utxo_hashes: Vec::new(),
            output_ciphertexts: Vec::new(),
        }
    }

    #[test]
    fn instruction_account_order_and_zone_config() {
        let zone_program_id = Pubkey::new_unique();
        let builder = ZoneAuthorityTransact {
            payer: Pubkey::new_unique(),
            tree: Pubkey::new_unique(),
            zone_program_id,
            cpi_signer: None,
            withdrawal: None,
            data: empty_data(),
        };

        let ix = builder.instruction();
        assert_eq!(ix.program_id, zone_program_id);
        assert_eq!(ix.data.first(), Some(&tag::ZONE_AUTHORITY_TRANSACT));

        let zone_config = pda::zone_auth(&zone_program_id).0;
        let keys: Vec<_> = ix.accounts.iter().map(|m| m.pubkey).collect();
        assert_eq!(
            keys,
            vec![builder.payer, builder.tree, zone_config, PROGRAM_ID_PUBKEY]
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
            cpi_signer: None,
            withdrawal: None,
            data: empty_data(),
        };

        let ix = builder.cpi_instruction();
        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.accounts[2].pubkey, pda::zone_auth(&zone_program_id).0);
        assert!(ix.accounts[2].is_signer);
    }
}
