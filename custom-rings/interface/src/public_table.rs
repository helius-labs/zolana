//! Public policy fields for the fixed 2x3 proof. The program must build these
//! from its authenticated PolicyConfig account, never from instruction data.

use zolana_hasher::primitives::right_align;
use zolana_ring_policy::{EncodedRuleTable, SourceMap};

use crate::{CustomRingError, PolicyConfig};

pub const POLICY_2X3_PUBLIC_INPUTS: usize = 78;
pub type PolicyTableInputs = [[u8; 32]; POLICY_2X3_PUBLIC_INPUTS];

/// Schema order of policy.PublicTableTwoByThreeCircuit in Go.
/// The table hash remains part of the original statement hash. Its equality
/// to these fields relies on PolicyConfig's validated write-and-repin path.
pub fn policy_table_inputs(
    statement: [u8; 32],
    policy_hash: [u8; 32],
    sources: &SourceMap,
    table: &EncodedRuleTable,
    tree_hash: [u8; 32],
) -> Box<PolicyTableInputs> {
    let mut inputs = Box::new([[0; 32]; POLICY_2X3_PUBLIC_INPUTS]);
    inputs[0] = statement;
    inputs[1] = policy_hash;
    for (i, source) in sources.slots().iter().enumerate() {
        inputs[2 + 2 * i] = right_align(&[source.list_id]);
        inputs[3 + 2 * i] = source.registry;
    }
    inputs[18..34].copy_from_slice(&table.rules);
    inputs[34] = right_align(&[table.rule_count]);
    inputs[35..43].copy_from_slice(&table.inline_assets);
    for (i, limit) in table.inline_limits.iter().enumerate() {
        inputs[43 + i] = right_align(limit);
    }
    inputs[51] = right_align(&[table.inline_count]);
    for i in 0..table.limit_assets.len() {
        inputs[52 + 3 * i] = table.limit_assets[i];
        inputs[53 + 3 * i] = right_align(&table.limit_caps[i]);
        inputs[54 + 3 * i] = right_align(&table.limit_cosign[i]);
    }
    inputs[76] = right_align(&[table.limit_count]);
    inputs[77] = tree_hash;
    inputs
}

impl PolicyConfig {
    pub fn public_table_inputs(
        &self,
        statement: [u8; 32],
        tree_hash: [u8; 32],
    ) -> Result<Box<PolicyTableInputs>, CustomRingError> {
        Ok(policy_table_inputs(
            statement,
            self.policy_hash,
            &self.source_map()?,
            &self.rules,
            tree_hash,
        ))
    }
}
