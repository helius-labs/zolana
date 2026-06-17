use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, DepositIxData},
    pda, SHIELDED_POOL_PROGRAM_ID,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositAccounts {
    pub tree: Pubkey,
    pub depositor: Pubkey,
    pub spl: Option<DepositSplAccounts>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositSplAccounts {
    pub user_token: Pubkey,
    pub vault: Pubkey,
    pub registry: Pubkey,
    pub token_program: Pubkey,
}

impl DepositAccounts {
    pub fn sol(tree: Pubkey, depositor: Pubkey) -> Self {
        Self {
            tree,
            depositor,
            spl: None,
        }
    }

    pub fn spl(tree: Pubkey, depositor: Pubkey, spl: DepositSplAccounts) -> Self {
        Self {
            tree,
            depositor,
            spl: Some(spl),
        }
    }

    pub fn account_metas(self) -> Vec<AccountMeta> {
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
        accounts.push(AccountMeta::new_readonly(
            Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            false,
        ));
        accounts
    }
}

impl DepositIxData {
    pub fn instruction(&self, accounts: DepositAccounts) -> Instruction {
        let mut data = vec![tag::DEPOSIT];
        data.extend_from_slice(
            &self
                .serialize()
                .expect("proofless ix data serialization is infallible"),
        );

        Instruction {
            program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            accounts: accounts.account_metas(),
            data,
        }
    }
}
