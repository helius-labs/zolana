use std::collections::BTreeSet;

use super::common::{
    get_tree_info, hash_from_vec, non_inclusion_proof_from_context, validate_proof_leaves,
};
use super::types::{GetNonInclusionProofsRequest, GetNonInclusionProofsResponse};
use crate::api::error::PhotonApiError;
use crate::common::rings_tree::RingsTreeKind;
use crate::common::typedefs::context::extract as extract_context;
use crate::common::typedefs::hash::Hash;
use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
use crate::dao::generated::rings_tx_nullifiers;
use crate::ingester::persist::indexed_merkle_tree::{
    get_multiple_indexed_exclusion_ranges_with_custom_empty_proofs,
    get_zeroeth_nullifier_exclusion_range,
};
use sea_orm::{
    ColumnTrait, DatabaseConnection, DatabaseTransaction, EntityTrait, QueryFilter,
    TransactionTrait,
};

pub async fn get_non_inclusion_proofs(
    conn: &DatabaseConnection,
    request: GetNonInclusionProofsRequest,
) -> Result<GetNonInclusionProofsResponse, PhotonApiError> {
    validate_proof_leaves(&request.leaves)?;

    let context = extract_context(conn).await?;
    let tx = conn.begin().await?;
    crate::api::set_transaction_isolation_if_needed(&tx).await?;

    let tree_info = get_tree_info(&tx, request.tree_account).await?;
    let tree_bytes = request.tree_account.to_bytes_vec();
    let leaves = request.leaves.iter().map(Hash::to_vec).collect::<Vec<_>>();
    reject_known_nullifiers(&tx, request.tree_account, &request.leaves).await?;
    let proof_map = get_multiple_indexed_exclusion_ranges_with_custom_empty_proofs(
        &tx,
        tree_bytes.clone(),
        RingsTreeKind::Nullifier.tree_height() + 1,
        leaves,
        RingsTreeKind::Nullifier,
        Some(get_zeroeth_nullifier_exclusion_range(tree_bytes)),
    )
    .await?;

    let proofs = request
        .leaves
        .into_iter()
        .map(|leaf| {
            let leaf_bytes = leaf.to_vec();
            let (range, proof) = proof_map.get(&leaf_bytes).ok_or_else(|| {
                PhotonApiError::RecordNotFound(format!(
                    "No non-inclusion proof found for leaf {}",
                    leaf
                ))
            })?;
            non_inclusion_proof_from_context(
                leaf,
                range,
                proof,
                &tree_info,
                RingsTreeKind::Nullifier,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    tx.commit().await?;

    Ok(GetNonInclusionProofsResponse { context, proofs })
}

async fn reject_known_nullifiers(
    tx: &DatabaseTransaction,
    tree_account: SerializablePubkey,
    leaves: &[Hash],
) -> Result<(), PhotonApiError> {
    let unique_leaves = leaves.iter().map(Hash::to_vec).collect::<BTreeSet<_>>();
    let row = rings_tx_nullifiers::Entity::find()
        .filter(rings_tx_nullifiers::Column::NullifierTree.eq(tree_account.to_bytes_vec()))
        .filter(
            rings_tx_nullifiers::Column::Nullifier
                .is_in(unique_leaves.into_iter().collect::<Vec<_>>()),
        )
        .one(tx)
        .await?;

    if let Some(row) = row {
        let leaf = hash_from_vec(row.nullifier)?;
        return Err(PhotonApiError::ValidationError(format!(
            "Nullifier leaf {} is already used or queued for tree {}",
            leaf, tree_account
        )));
    }

    Ok(())
}
