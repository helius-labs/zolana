use alloc::vec;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{tag, CreateCacheData},
    pda, PROGRAM_ID_PUBKEY,
};

pub struct CreateCache {
    pub payer: Pubkey,
    pub data: CreateCacheData,
}

impl CreateCache {
    pub fn cache(&self) -> Pubkey {
        pda::cache(&self.payer, self.data.nonce).0
    }

    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::CREATE_CACHE];
        instruction_data.extend_from_slice(
            &wincode::serialize(&self.data)
                .expect("shielded-pool instruction serialization is infallible"),
        );

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new(self.cache(), false),
                AccountMeta::new_readonly(Pubkey::default(), false),
            ],
            data: instruction_data,
        }
    }
}

pub struct CloseCache {
    pub cache: Pubkey,
    pub rent_recipient: Pubkey,
    /// Write authority signing an early close. Optional after expiry.
    pub writer: Option<Pubkey>,
}

impl CloseCache {
    pub fn instruction(&self) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new(self.cache, false),
            AccountMeta::new(self.rent_recipient, false),
        ];
        if let Some(writer) = self.writer {
            accounts.push(AccountMeta::new_readonly(writer, true));
        }
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: vec![tag::CLOSE_CACHE],
        }
    }
}
