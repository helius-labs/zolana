use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::{instructions::grant_read_access::reader_ix_data, shared::ReaderKey, CustomRing};
use custom_ring_interface::tag;

/// Closes the read access record for `reader` and returns its rent to
/// `rent_recipient`.
#[must_use]
pub struct RevokeReadAccess {
    pub ring: CustomRing,
    pub authority: Address,
    pub reader: ReaderKey,
    pub rent_recipient: Address,
}

impl RevokeReadAccess {
    pub fn instruction(self) -> Result<Instruction, wincode::Error> {
        let Self {
            ring,
            authority,
            reader,
            rent_recipient,
        } = self;
        Ok(Instruction {
            program_id: ring.program_id(),
            accounts: vec![
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new_readonly(ring.config_pda(), false),
                AccountMeta::new(ring.read_access_record_pda(&reader), false),
                AccountMeta::new(rent_recipient, false),
            ],
            data: reader_ix_data(tag::REVOKE_READ_ACCESS, reader)?,
        })
    }
}
