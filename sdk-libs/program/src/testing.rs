pub use zolana_zk_dsl::testing::*;

/// Inspect carried metadata in SDK tests. These values are not authorization
/// inputs for an application circuit; the SPP proof validates the transaction.
pub fn utxo_metadata(
    utxo: &crate::circuit::Utxo,
) -> (
    crate::circuit::CircuitVar,
    crate::circuit::CircuitVar,
    crate::circuit::Bool,
) {
    (
        utxo.meta.nullifier.clone(),
        utxo.meta.latest_tree_id.clone(),
        utxo.meta.has_latest_tree_id.clone(),
    )
}
