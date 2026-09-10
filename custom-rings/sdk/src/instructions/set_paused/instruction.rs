use custom_ring_interface::{tag, SetPausedIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::pda;

use crate::CustomRing;

#[must_use]
pub struct SetPaused {
    pub ring: CustomRing,
    pub authority: Address,
    pub paused: bool,
}

impl SetPaused {
    pub fn instruction(self) -> Result<Instruction, wincode::Error> {
        let Self {
            ring,
            authority,
            paused,
        } = self;
        let mut data = vec![tag::SET_PAUSED];
        data.extend_from_slice(&wincode::serialize(&SetPausedIxData {
            paused: u8::from(paused),
        })?);
        Ok(Instruction {
            program_id: ring.program_id(),
            accounts: vec![
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new_readonly(ring.config_pda(), false),
                AccountMeta::new(ring.ring_auth_pda(), false),
                AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
            ],
            data,
        })
    }
}
