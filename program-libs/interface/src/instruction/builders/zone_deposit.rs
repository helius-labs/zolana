use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, CpiData, DepositSplAccounts, ZoneDepositIxData},
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
    /// Calling zone program's id; its (canonical) `zone_auth` PDA is the signing
    /// `ZoneConfig` account.
    pub zone_program_id: Pubkey,
    pub zone_data_hash: [u8; 32],
    pub zone_data: Vec<u8>,
    /// Application data committed into the UTXO's `data_hash`, authorized by the
    /// `ZoneConfig` account; `None` if the zone deposit carries no application
    /// data.
    pub program: Option<CpiData>,
}

impl ZoneDeposit {
    pub fn instruction(&self) -> Instruction {
        self.build_instruction(self.zone_program_id, false)
    }

    pub fn cpi_instruction(&self) -> Instruction {
        self.build_instruction(PROGRAM_ID_PUBKEY, true)
    }

    fn build_instruction(&self, program_id: Pubkey, auth_signer: bool) -> Instruction {
        // The `ZoneConfig` account is the zone's canonical `zone_auth` PDA: it
        // signs and its stored `program_id` becomes the UTXO's `zone_program_id`.
        let zone_config = pda::zone_auth(&self.zone_program_id).0;

        let ix_data = ZoneDepositIxData {
            view_tag: self.view_tag,
            owner: self.owner,
            blinding: self.blinding,
            public_amount: self.public_amount,
            zone_data_hash: self.zone_data_hash,
            zone_data: self.zone_data.clone(),
            program: self.program.clone(),
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
            AccountMeta::new_readonly(zone_config, auth_signer),
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
