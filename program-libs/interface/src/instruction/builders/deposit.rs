use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, DepositIxData, UtxoData},
    pda, PROGRAM_ID_PUBKEY,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositSplAccounts {
    pub user_token: Pubkey,
    pub spl_token_interface: Pubkey,
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
    pub amount: u64,
    /// Application data committed into the deposited UTXO's `data_hash`,
    /// authorized by the payer; `None` for a plain user deposit.
    pub utxo_data: Option<UtxoData>,
    /// Optional free-form memo emitted in the clear with the proofless output.
    pub memo: Option<Vec<u8>>,
}

impl Deposit {
    pub fn instruction(&self) -> Instruction {
        let ix_data = DepositIxData {
            view_tag: self.view_tag,
            owner: self.owner,
            blinding: self.blinding,
            amount: self.amount,
            utxo_data: self.utxo_data.clone(),
            memo: self.memo.clone(),
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
                AccountMeta::new(spl.spl_token_interface, false),
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
