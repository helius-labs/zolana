use custom_ring_interface::{tag, SET_POLICY_RULES_COMPUTE_UNIT_LIMIT};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_ring_policy::{ListId, RuleTable};

use crate::{
    instructions::{
        entry::EntryError,
        policy_table::{LegacyPacket, PolicyTable},
    },
    CustomRing,
};

/// Replaces the pinned table and its source map, signed by the upgrade authority.
#[must_use]
pub struct SetPolicyRules<'a> {
    pub ring: CustomRing,
    pub authority: Address,
    pub rules: &'a RuleTable,
    /// The complete map, a referenced list left out reads the ring's own
    /// entries again.
    pub shared_sources: Vec<(ListId, CustomRing)>,
}

impl SetPolicyRules<'_> {
    pub fn instruction(self) -> Result<Instruction, EntryError> {
        let Self {
            ring,
            authority,
            rules,
            shared_sources,
        } = self;
        let body = PolicyTable {
            rules,
            shared_sources: &shared_sources,
        }
        .body()?;
        let mut accounts = vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(ring.policy_config_pda(), false),
            AccountMeta::new_readonly(ring.program_id(), false),
            AccountMeta::new_readonly(ring.program_data_pda(), false),
        ];
        accounts.extend(body.curator_accounts());
        LegacyPacket {
            payer: authority,
            compute_unit_limit: SET_POLICY_RULES_COMPUTE_UNIT_LIMIT,
            instruction: Instruction {
                program_id: ring.program_id(),
                accounts,
                data: body.instruction_data(tag::SET_POLICY_RULES)?,
            },
        }
        .fit()
    }
}
