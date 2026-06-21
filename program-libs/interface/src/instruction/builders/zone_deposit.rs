use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::{Pubkey, PubkeyError};

use crate::{
    instruction::{tag, CpiSignerData, DepositSplAccounts, ZoneDepositIxData},
    pda, PROGRAM_ID_PUBKEY,
};

pub struct ZoneDeposit {
    pub tree: Pubkey,
    pub depositor: Pubkey,
    pub spl: Option<DepositSplAccounts>,
    pub view_tag: [u8; 32],
    pub owner: [u8; 32],
    pub blinding: [u8; 31],
    pub public_amount: Option<u64>,
    pub cpi_signer: CpiSignerData,
    pub policy_data_hash: Option<[u8; 32]>,
    pub zone_data: Option<Vec<u8>>,
    pub program_data_hash: Option<[u8; 32]>,
    pub program_data: Option<Vec<u8>>,
}

impl ZoneDeposit {
    pub fn instruction(&self) -> Result<Instruction, PubkeyError> {
        let zone_program = Pubkey::new_from_array(self.cpi_signer.program_id);
        let zone_auth = pda::zone_auth_with_bump(&zone_program, self.cpi_signer.bump)?;

        Ok(self.build_instruction(zone_program, zone_auth, false))
    }

    pub fn cpi_instruction(&self) -> Result<Instruction, PubkeyError> {
        let zone_program = Pubkey::new_from_array(self.cpi_signer.program_id);
        let zone_auth = pda::zone_auth_with_bump(&zone_program, self.cpi_signer.bump)?;

        Ok(self.build_instruction(PROGRAM_ID_PUBKEY, zone_auth, true))
    }

    fn build_instruction(
        &self,
        program_id: Pubkey,
        zone_auth: Pubkey,
        zone_auth_signer: bool,
    ) -> Instruction {
        let ix_data = ZoneDepositIxData {
            view_tag: self.view_tag,
            owner: self.owner,
            blinding: self.blinding,
            public_amount: self.public_amount,
            cpi_signer: self.cpi_signer,
            policy_data_hash: self.policy_data_hash,
            zone_data: self.zone_data.clone(),
            program_data_hash: self.program_data_hash,
            program_data: self.program_data.clone(),
        };

        let mut data = vec![tag::ZONE_DEPOSIT];
        data.extend_from_slice(
            &ix_data
                .serialize()
                .expect("zone proofless ix data serialization is infallible"),
        );

        let mut account_metas = vec![
            AccountMeta::new(self.tree, false),
            AccountMeta::new(self.depositor, true),
            AccountMeta::new_readonly(zone_auth, zone_auth_signer),
        ];
        match self.spl {
            Some(spl) => account_metas.extend([
                AccountMeta::new(spl.user_token, false),
                AccountMeta::new(spl.vault, false),
                AccountMeta::new_readonly(spl.registry, false),
                AccountMeta::new_readonly(spl.token_program, false),
            ]),
            None => account_metas.extend([
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new(pda::sol_interface(), false),
                AccountMeta::new(self.depositor, false),
            ]),
        }
        account_metas.push(AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false));

        Instruction {
            program_id,
            accounts: account_metas,
            data,
        }
    }
}
