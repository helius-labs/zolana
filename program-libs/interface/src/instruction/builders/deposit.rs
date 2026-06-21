use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, CpiSignerData, DepositIxData},
    pda, PROGRAM_ID_PUBKEY,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositSplAccounts {
    pub user_token: Pubkey,
    pub vault: Pubkey,
    pub registry: Pubkey,
    pub token_program: Pubkey,
}

pub struct Deposit {
    pub tree: Pubkey,
    pub depositor: Pubkey,
    pub spl: Option<DepositSplAccounts>,
    pub view_tag: [u8; 32],
    pub owner: [u8; 32],
    pub blinding: [u8; 31],
    pub public_amount: Option<u64>,
    pub program_data_hash: Option<[u8; 32]>,
    pub program_data: Option<Vec<u8>>,
    pub cpi_signer: Option<CpiSignerData>,
}

impl Deposit {
    pub fn instruction(&self) -> Instruction {
        let ix_data = DepositIxData {
            view_tag: self.view_tag,
            owner: self.owner,
            blinding: self.blinding,
            public_amount: self.public_amount,
            program_data_hash: self.program_data_hash,
            program_data: self.program_data.clone(),
            cpi_signer: self.cpi_signer,
        };

        let mut data = vec![tag::DEPOSIT];
        data.extend_from_slice(
            &ix_data
                .serialize()
                .expect("proofless ix data serialization is infallible"),
        );

        let mut accounts = vec![
            AccountMeta::new(self.tree, false),
            AccountMeta::new(self.depositor, true),
        ];
        match self.spl {
            Some(spl) => accounts.extend([
                AccountMeta::new(spl.user_token, false),
                AccountMeta::new(spl.vault, false),
                AccountMeta::new_readonly(spl.registry, false),
                AccountMeta::new_readonly(spl.token_program, false),
            ]),
            None => accounts.extend([
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new(pda::sol_interface(), false),
                AccountMeta::new(self.depositor, false),
            ]),
        }
        accounts.push(AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false));

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data,
        }
    }
}
