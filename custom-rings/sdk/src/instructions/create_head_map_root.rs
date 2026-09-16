use crate::{tag, CustomRing};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

#[must_use]
pub struct CreateHeadMapRoot {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
}

impl CreateHeadMapRoot {
    pub fn instruction(self) -> Instruction {
        CreateIndexedRoot {
            ring: self.ring,
            payer: self.payer,
            authority: self.authority,
            root: self.ring.head_map_root_pda(),
            tag: tag::CREATE_HEAD_MAP_ROOT,
        }
        .instruction()
    }
}

/// Both indexed roots share one account layout under the config authority.
pub(super) struct CreateIndexedRoot {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub root: Address,
    pub tag: u8,
}

impl CreateIndexedRoot {
    pub(super) fn instruction(self) -> Instruction {
        Instruction {
            program_id: self.ring.program_id(),
            accounts: vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new_readonly(self.ring.config_pda(), false),
                AccountMeta::new(self.root, false),
                AccountMeta::new_readonly(Address::default(), false),
            ],
            data: vec![self.tag],
        }
    }
}
