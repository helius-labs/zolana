use crate::{instructions::create_head_map_root::CreateIndexedRoot, tag, CustomRing};
use solana_address::Address;
use solana_instruction::Instruction;

#[must_use]
pub struct CreateKeyRegistryRoot {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
}

impl CreateKeyRegistryRoot {
    pub fn instruction(self) -> Instruction {
        CreateIndexedRoot {
            ring: self.ring,
            payer: self.payer,
            authority: self.authority,
            root: self.ring.key_registry_root_pda(),
            tag: tag::CREATE_KEY_REGISTRY_ROOT,
        }
        .instruction()
    }
}
