use custom_ring_interface::tag;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::CustomRing;

/// Both keys sign, a mistyped address cannot strand the config.
#[must_use]
pub struct SetAuthority {
    pub ring: CustomRing,
    pub authority: Address,
    pub new_authority: Address,
}

impl SetAuthority {
    pub fn instruction(self) -> Instruction {
        let Self {
            ring,
            authority,
            new_authority,
        } = self;
        Instruction {
            program_id: ring.program_id(),
            accounts: vec![
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new_readonly(new_authority, true),
                AccountMeta::new(ring.config_pda(), false),
            ],
            data: vec![tag::SET_AUTHORITY],
        }
    }
}
