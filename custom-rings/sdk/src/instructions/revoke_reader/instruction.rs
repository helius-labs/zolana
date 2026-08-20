use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::{
    config_pda, instructions::grant_reader::reader_ix_data, reader_record_pda, shared::ReaderKey,
    tag, PROGRAM_ID,
};

/// Closes `reader`'s record, which ends its delegated ring-scope reads.
pub struct RevokeReader {
    /// The config authority.
    pub authority: Address,
    pub reader: ReaderKey,
    /// Receives the record's rent.
    pub rent_recipient: Address,
}

impl RevokeReader {
    pub fn instruction(self) -> Instruction {
        let Self {
            authority,
            reader,
            rent_recipient,
        } = self;
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new_readonly(config_pda(), false),
                AccountMeta::new(reader_record_pda(&reader), false),
                AccountMeta::new(rent_recipient, false),
            ],
            data: reader_ix_data(tag::REVOKE_READER, reader),
        }
    }
}
