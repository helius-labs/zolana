use custom_ring_interface::{tag, SetPolicySourceIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_ring_policy::ListId;

use crate::{instructions::entry::EntryError, CustomRing};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceOwner {
    Own,
    Shared(CustomRing),
}

#[must_use]
pub struct SetSourceOwner {
    pub ring: CustomRing,
    pub authority: Address,
    pub list_id: ListId,
    pub source: SourceOwner,
}

impl SetSourceOwner {
    pub fn instruction(self) -> Result<Instruction, EntryError> {
        let Self {
            ring,
            authority,
            list_id,
            source,
        } = self;
        let mut accounts = vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(ring.config_pda(), false),
            AccountMeta::new(ring.policy_config_pda(), false),
        ];
        let source = match source {
            SourceOwner::Own => 0,
            SourceOwner::Shared(curator) => {
                accounts.push(AccountMeta::new_readonly(
                    curator.policy_config_pda(),
                    false,
                ));
                1
            }
        };
        let mut instruction_data = vec![tag::SET_POLICY_SOURCE];
        instruction_data.extend_from_slice(&wincode::serialize(&SetPolicySourceIxData {
            list_id: list_id as u8,
            source,
        })?);
        Ok(Instruction {
            program_id: ring.program_id(),
            accounts,
            data: instruction_data,
        })
    }
}
