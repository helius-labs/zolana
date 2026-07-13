use std::collections::{BTreeMap, BTreeSet};

use super::common::{
    get_tree_info, merkle_proof_from_context, rings_output_leaf_indices, validate_proof_leaves,
};
use crate::api::error::PhotonApiError;
use crate::common::indexer_context::extract as extract_context;
use crate::common::rings_tree::RingsTreeKind;
use crate::ingester::persist::get_multiple_compressed_leaf_proofs_by_indices_with_height;
use sea_orm::{DatabaseConnection, TransactionTrait};
use zolana_indexer_api::{GetMerkleProofsRequest, GetMerkleProofsResponse};

pub async fn get_merkle_proofs(
    conn: &DatabaseConnection,
    request: GetMerkleProofsRequest,
) -> Result<GetMerkleProofsResponse, PhotonApiError> {
    validate_proof_leaves(&request.leaves)?;

    let context = extract_context(conn).await?;
    let tx = conn.begin().await?;
    crate::api::set_transaction_isolation_if_needed(&tx).await?;

    let tree_account = request.tree_account;
    let tree_info = get_tree_info(&tx, tree_account).await?;
    let leaf_indices = rings_output_leaf_indices(&tx, tree_account, &request.leaves).await?;

    let unique_indices = leaf_indices.iter().copied().collect::<BTreeSet<_>>();
    let proof_rows = get_multiple_compressed_leaf_proofs_by_indices_with_height(
        &tx,
        tree_account,
        RingsTreeKind::State,
        unique_indices.into_iter().collect(),
        RingsTreeKind::State.tree_height() + 1,
    )
    .await?;
    let proofs_by_index = proof_rows
        .into_iter()
        .map(|proof| (proof.leaf_index, proof))
        .collect::<BTreeMap<_, _>>();
    let proofs = request
        .leaves
        .into_iter()
        .zip(leaf_indices)
        .map(|(leaf, leaf_index)| {
            let proof = proofs_by_index.get(&leaf_index).ok_or_else(|| {
                PhotonApiError::RecordNotFound(format!(
                    "No proof found for leaf index {}",
                    leaf_index
                ))
            })?;
            merkle_proof_from_context(proof.clone(), &tree_info, RingsTreeKind::State, &leaf)
        })
        .collect::<Result<Vec<_>, _>>()?;

    tx.commit().await?;

    Ok(GetMerkleProofsResponse { context, proofs })
}
