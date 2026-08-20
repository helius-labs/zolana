use custom_ring_program::instructions::grant_reader::ReaderIxData;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::{config_pda, reader_record_pda, tag, PROGRAM_ID};

/// Delegates ring-scope reads on the ring RPC to `reader`. The record it
/// creates is what the RPC checks, so a Squads-held authority can delegate by
/// proposal and the authority key never has to sign a read attestation itself.
pub struct GrantReader {
    pub payer: Address,
    /// The config authority.
    pub authority: Address,
    pub reader: Address,
}

impl GrantReader {
    pub fn instruction(self) -> Instruction {
        let Self {
            payer,
            authority,
            reader,
        } = self;
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new_readonly(config_pda(), false),
                AccountMeta::new(reader_record_pda(&reader), false),
                AccountMeta::new_readonly(Address::default(), false),
            ],
            data: reader_ix_data(tag::GRANT_READER, reader),
        }
    }
}

pub(crate) fn reader_ix_data(instruction_tag: u8, reader: Address) -> Vec<u8> {
    let mut data = vec![instruction_tag];
    data.extend_from_slice(
        &wincode::serialize(&ReaderIxData {
            reader: reader.to_bytes(),
        })
        .expect("reader instruction data is fixed size"),
    );
    data
}
