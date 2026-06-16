use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::{Pubkey, PubkeyError};

use crate::{
    instruction::{tag, ProoflessShieldSplAccounts, ZoneProoflessShieldIxData},
    pda, SHIELDED_POOL_PROGRAM_ID,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZoneProoflessShieldAccounts {
    pub tree: Pubkey,
    pub depositor: Pubkey,
    pub spl: Option<ProoflessShieldSplAccounts>,
}

impl ZoneProoflessShieldAccounts {
    pub fn sol(tree: Pubkey, depositor: Pubkey) -> Self {
        Self {
            tree,
            depositor,
            spl: None,
        }
    }

    pub fn spl(tree: Pubkey, depositor: Pubkey, spl: ProoflessShieldSplAccounts) -> Self {
        Self {
            tree,
            depositor,
            spl: Some(spl),
        }
    }
}

impl ZoneProoflessShieldIxData {
    pub fn instruction(
        &self,
        accounts: ZoneProoflessShieldAccounts,
    ) -> Result<Instruction, PubkeyError> {
        let zone_program = Pubkey::new_from_array(self.cpi_signer.program_id);
        let zone_auth = pda::zone_auth_with_bump(&zone_program, self.cpi_signer.bump)?;

        Ok(self.build_instruction(zone_program, zone_auth, accounts, false))
    }

    pub fn cpi_instruction(
        &self,
        accounts: ZoneProoflessShieldAccounts,
    ) -> Result<Instruction, PubkeyError> {
        let zone_program = Pubkey::new_from_array(self.cpi_signer.program_id);
        let zone_auth = pda::zone_auth_with_bump(&zone_program, self.cpi_signer.bump)?;

        Ok(self.build_instruction(
            Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            zone_auth,
            accounts,
            true,
        ))
    }

    fn build_instruction(
        &self,
        program_id: Pubkey,
        zone_auth: Pubkey,
        accounts: ZoneProoflessShieldAccounts,
        zone_auth_signer: bool,
    ) -> Instruction {
        let mut data = vec![tag::ZONE_PROOFLESS_SHIELD];
        data.extend_from_slice(
            &self
                .serialize()
                .expect("zone proofless ix data serialization is infallible"),
        );

        let mut account_metas = vec![
            AccountMeta::new(accounts.tree, false),
            AccountMeta::new(accounts.depositor, true),
            AccountMeta::new_readonly(zone_auth, zone_auth_signer),
        ];
        match accounts.spl {
            Some(spl) => account_metas.extend([
                AccountMeta::new(spl.user_token, false),
                AccountMeta::new(spl.vault, false),
                AccountMeta::new_readonly(spl.registry, false),
                AccountMeta::new_readonly(spl.token_program, false),
            ]),
            None => account_metas.extend([
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new(pda::sol_interface(), false),
                AccountMeta::new(accounts.depositor, false),
            ]),
        }
        account_metas.push(AccountMeta::new_readonly(
            Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            false,
        ));

        Instruction {
            program_id,
            accounts: account_metas,
            data,
        }
    }
}
