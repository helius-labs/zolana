use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, TransactIxData},
    PROGRAM_ID_PUBKEY,
};

/// Batch incarnation of pure-shielded multi-transact (tag 53).
pub struct BatchTransact {
    pub payer: Pubkey,
    pub input_tree: Pubkey,
    pub output_tree: Pubkey,
    pub signers: Vec<Pubkey>,
    pub entries: Vec<TransactIxData>,
}

impl BatchTransact {
    pub fn instruction(&self) -> Instruction {
        assert!(
            (1..=4).contains(&self.entries.len()),
            "batch_transact supports 1..=4 entries"
        );
        let mut data = vec![tag::BATCH_TRANSACT, self.entries.len() as u8];
        for entry in &self.entries {
            assert!(
                entry.interface_transfers.is_empty(),
                "batch_transact is pure shielded only"
            );
            let body = entry
                .serialize()
                .expect("transact serialization is infallible");
            let len = u16::try_from(body.len()).expect("entry fits u16");
            data.extend_from_slice(&len.to_le_bytes());
            data.extend_from_slice(&body);
        }
        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new(self.input_tree, false),
            AccountMeta::new(self.output_tree, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ];
        for s in &self.signers {
            accounts.push(AccountMeta::new_readonly(*s, true));
        }
        accounts.push(AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false));
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data,
        }
    }
}
