use crate::{tag, CustomRing};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

#[must_use]
pub struct CreateKeyRegistryRoot {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
}

impl CreateKeyRegistryRoot {
    pub fn instruction(self) -> Instruction {
        Instruction {
            program_id: self.ring.program_id(),
            accounts: vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new_readonly(self.ring.config_pda(), false),
                AccountMeta::new(self.ring.key_registry_root_pda(), false),
                AccountMeta::new_readonly(Address::default(), false),
            ],
            data: vec![tag::CREATE_KEY_REGISTRY_ROOT],
        }
    }
}
