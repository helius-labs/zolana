use custom_ring_interface::{tag, ReaderIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::{shared::ReaderKey, CustomRing};

/// Creates the ring's read access entry for `reader`, authorizing it to read
/// the ring through the ring RPC.
#[must_use]
pub struct GrantReadAccess {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub reader: ReaderKey,
}

impl GrantReadAccess {
    pub fn instruction(self) -> Result<Instruction, wincode::Error> {
        let Self {
            ring,
            payer,
            authority,
            reader,
        } = self;
        Ok(Instruction {
            program_id: ring.program_id(),
            accounts: vec![
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new_readonly(ring.config_pda(), false),
                AccountMeta::new(ring.read_access_record_pda(&reader), false),
                // The system program is the all-zero address.
                AccountMeta::new_readonly(Address::default(), false),
            ],
            data: reader_ix_data(tag::GRANT_READ_ACCESS, reader)?,
        })
    }
}

pub(crate) fn reader_ix_data(
    instruction_tag: u8,
    reader: ReaderKey,
) -> Result<Vec<u8>, wincode::Error> {
    let mut data = vec![instruction_tag];
    data.extend_from_slice(&wincode::serialize(&ReaderIxData {
        reader: reader.to_bytes(),
    })?);
    Ok(data)
}
