//! Public policy fields for the shaped policy proofs. The program must build these
//! from its authenticated PolicyConfig account, never from instruction data.

use zolana_hasher::primitives::right_align;
use zolana_ring_policy::{EncodedRuleTable, SourceMap};

use crate::{CustomRingError, PolicyConfig};

pub const POLICY_2X3_PUBLIC_INPUTS: usize = 78;
pub type PolicyTableInputs = [[u8; 32]; POLICY_2X3_PUBLIC_INPUTS];

/// Schema order of the public-table policy circuits in Go.
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

/// Shipped policy capacities that can carry an ordinary minimal v1 transaction.
/// Every actual payload still needs a byte and address limit check.
pub const fn policy_shape_supported(
    inputs: usize,
    outputs: usize,
    anonymous: bool,
    delegate: bool,
) -> bool {
    if anonymous && delegate {
        return false;
    }
    if anonymous {
        matches!(
            (inputs, outputs),
            (1, 2)
                | (1, 4)
                | (2, 2)
                | (2, 4)
                | (3, 2)
                | (3, 4)
                | (4, 2)
                | (4, 4)
                | (5, 2)
                | (5, 4)
                | (6, 2)
                | (6, 4)
                | (8, 2)
                | (12, 2)
        )
    } else if delegate {
        matches!((inputs, outputs), (2, 2) | (4, 4))
    } else {
        (matches!(inputs, 1 | 2 | 3 | 4 | 5 | 6 | 8 | 12 | 16) && matches!(outputs, 2 | 4))
            || (inputs == 24 && outputs == 2)
    }
}

#[cfg(test)]
mod tests {
    use super::policy_shape_supported;

    #[test]
    fn policy_shape_catalog_matches_the_shared_prover_manifest() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../policy-shapes.json")).unwrap();
        let shapes = manifest.as_array().unwrap();
        assert_eq!(shapes.len(), 70);
        for entry in shapes {
            assert!(policy_shape_supported(
                entry["inputs"].as_u64().unwrap() as usize,
                entry["outputs"].as_u64().unwrap() as usize,
                entry["anonymous"].as_bool().unwrap(),
                entry["delegate"].as_bool().unwrap()
            ));
        }
    }

    #[test]
    fn shipped_policy_shapes_exclude_oversized_and_wrong_rail_capacities() {
        assert_eq!(
            zolana_interface::shape::SPP_SUPPORTED_SHAPES
                .into_iter()
                .filter(|s| policy_shape_supported(s.n_inputs(), s.n_outputs(), false, false))
                .count(),
            19
        );
        for (n, m) in [(1, 8), (2, 16), (32, 2), (49, 2), (7, 2)] {
            assert!(!policy_shape_supported(n, m, false, false));
        }
        assert!(policy_shape_supported(1, 2, true, false));
        assert!(!policy_shape_supported(2, 4, false, true));
        assert!(!policy_shape_supported(2, 2, true, true));
    }
}
