use crate::{tag, CustomRing};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

/// Requires the config authority.
pub struct CreateHeadMapRoot {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
}

impl CreateHeadMapRoot {
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: self.ring.program_id(),
            accounts: vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new_readonly(self.ring.config_pda(), false),
                AccountMeta::new(self.ring.head_map_root_pda(), false),
                AccountMeta::new_readonly(Address::default(), false),
            ],
            data: vec![tag::CREATE_HEAD_MAP_ROOT],
        }
    }
}
