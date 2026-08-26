use custom_ring_interface::{tag, SetPolicySourceIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_ring_policy::RecordKind;

use crate::{instructions::record::RecordError, CustomRing};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicySource {
    Own,
    Shared(CustomRing),
}

#[must_use]
pub struct SetPolicySource {
    pub ring: CustomRing,
    pub authority: Address,
    pub kind: RecordKind,
    pub source: PolicySource,
}

impl SetPolicySource {
    pub fn instruction(self) -> Result<Instruction, RecordError> {
        let Self {
            ring,
            authority,
            kind,
            source,
        } = self;
        let mut accounts = vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(ring.config_pda(), false),
            AccountMeta::new(ring.policy_config_pda(), false),
        ];
        let source = match source {
            PolicySource::Own => 0,
            PolicySource::Shared(curator) => {
                accounts.push(AccountMeta::new_readonly(
                    curator.policy_config_pda(),
                    false,
                ));
                1
            }
        };
        let mut instruction_data = vec![tag::SET_POLICY_SOURCE];
        instruction_data.extend_from_slice(&wincode::serialize(&SetPolicySourceIxData {
            kind: kind as u8,
            source,
        })?);
        Ok(Instruction {
            program_id: ring.program_id(),
            accounts,
            data: instruction_data,
        })
    }
}
