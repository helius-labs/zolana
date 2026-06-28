use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::{Pubkey, PubkeyError};

use crate::{
    instruction::{tag, CpiData, DepositIxData},
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
    /// Program governing the deposited UTXO (its `auth` PDA signs); `None` for a
    /// plain user deposit.
    pub program: Option<CpiData>,
}

impl Deposit {
    pub fn instruction(&self) -> Result<Instruction, PubkeyError> {
        let ix_data = DepositIxData {
            view_tag: self.view_tag,
            owner: self.owner,
            blinding: self.blinding,
            public_amount: self.public_amount,
            program: self.program.clone(),
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
        if let Some(program) = &self.program {
            let program_id = Pubkey::new_from_array(program.cpi_signer.program_id);
            let auth = pda::cpi_signer_with_bump(&program_id, program.cpi_signer.bump)?;
            accounts.push(AccountMeta::new_readonly(auth, true));
        }
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

        Ok(Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data,
        })
    }
}
