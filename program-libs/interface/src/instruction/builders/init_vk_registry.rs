use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::tag, verifying_keys::registry::VK_REGISTRY_SPECS,
    verifying_keys::registry_spec::vk_registry_account_len, PROGRAM_ID_PUBKEY,
};

/// Permissionless registry creation for `VK_CATALOG[vk_index]`. The account
/// exceeds the per-transaction allocation cap, so creation is a step machine.
/// Send [`Self::instruction`] repeatedly (create, then one resize per
/// transaction, then finalize). [`Self::transaction_count`] says how many
/// sends reach the finalized state.
pub struct InitVkRegistry {
    pub payer: Pubkey,
    pub vk_index: u8,
}

impl InitVkRegistry {
    pub fn registry_address(&self) -> Pubkey {
        Pubkey::new_from_array(VK_REGISTRY_SPECS[self.vk_index as usize].address)
    }

    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new(self.registry_address(), false),
                AccountMeta::new_readonly(Pubkey::default(), false),
            ],
            data: vec![tag::INIT_VK_REGISTRY, self.vk_index],
        }
    }

    /// create + per-transaction resizes up to the target length + finalize.
    pub fn transaction_count(&self) -> usize {
        const MAX_PERMITTED_DATA_INCREASE: usize = 10_240;
        let target =
            vk_registry_account_len(VK_REGISTRY_SPECS[self.vk_index as usize].g2_count as usize);
        1 + target
            .saturating_sub(MAX_PERMITTED_DATA_INCREASE)
            .div_ceil(MAX_PERMITTED_DATA_INCREASE)
            + 1
    }
}

/// Append the optional trailing VK-registry account to a transact-family
/// instruction built by the existing builders. Read-only by requirement.
pub fn append_vk_registry(instruction: &mut Instruction, registry: Pubkey) {
    instruction
        .accounts
        .push(AccountMeta::new_readonly(registry, false));
}
