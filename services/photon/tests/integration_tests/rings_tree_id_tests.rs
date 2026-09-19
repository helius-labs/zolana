//! What the two read methods say about trees: the id each output landed in,
//! and the id a client should append its next output to.

use photon_indexer::{
    api::{
        error::PhotonApiError,
        method::rings::{get_encrypted_utxos_by_tags, get_shielded_transactions_by_tags},
    },
    dao::generated::tree_metadata,
};
use sea_orm::{sea_query::Expr, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use solana_pubkey::Pubkey;
use zolana_indexer_api::{GetRingsByTagsRequest, Hash, Limit, SerializablePubkey};

use crate::rings_fixtures::{
    fixture_tree, fresh_rings_database, seed_tagged_transaction_history, seed_tree_metadata,
    FIXTURE_TREE_ID, VIEW_TAG,
};

async fn seeded_database() -> DatabaseConnection {
    let db = fresh_rings_database().await;
    seed_tagged_transaction_history(&db, VIEW_TAG, 0..3).await;
    db
}

fn request(view_tag: [u8; 32]) -> GetRingsByTagsRequest {
    GetRingsByTagsRequest {
        tags: vec![Hash::from(view_tag)],
        cursor: None,
        limit: Some(Limit::new(10).expect("limit is within the shared bounds")),
        ring_program_id: None,
    }
}

/// The id comes from the tree's metadata row, not from the output row, so it
/// has to survive the join rather than be read back off `output_tree`.
#[tokio::test]
async fn an_output_reports_the_id_of_the_tree_it_landed_in() {
    let db = seeded_database().await;

    let transactions = get_shielded_transactions_by_tags(&db, request(VIEW_TAG))
        .await
        .expect("tags lookup")
        .transactions;
    let matches = get_encrypted_utxos_by_tags(&db, request(VIEW_TAG))
        .await
        .expect("utxo lookup")
        .matches;

    let expected_tree = SerializablePubkey::from(fixture_tree());
    for transaction in &transactions {
        for slot in &transaction.output_slots {
            assert_eq!(slot.output_context.tree_id, FIXTURE_TREE_ID);
            assert_eq!(slot.output_context.tree, expected_tree);
        }
    }
    // Both read methods build their output context through the same helper, so
    // the second endpoint is what proves that helper is actually shared.
    for encrypted in &matches {
        assert_eq!(
            encrypted.output_slot.output_context.tree_id,
            FIXTURE_TREE_ID
        );
        assert_eq!(encrypted.output_slot.output_context.tree, expected_tree);
    }
}

/// An output whose tree row predates the id column is a named error, never a
/// dropped note and never a guessed id. The join is a `LEFT JOIN` precisely so
/// the row survives far enough to be reported as an error.
#[tokio::test]
async fn an_unsynced_tree_is_an_error_rather_than_a_missing_output() {
    let db = seeded_database().await;
    tree_metadata::Entity::update_many()
        .col_expr(
            tree_metadata::Column::TreeId,
            Expr::value(Option::<i32>::None),
        )
        .exec(&db)
        .await
        .expect("clear the tree id");

    let error = get_shielded_transactions_by_tags(&db, request(VIEW_TAG))
        .await
        .expect_err("an unsynced tree has no id to report");

    assert!(
        matches!(&error, PhotonApiError::UnexpectedError(message) if message.contains("tree id")),
        "unexpected error: {error:?}"
    );
}

/// The append target is a property of the pool, not of any returned note, so a
/// wallet that matched nothing still learns it without a second call.
#[tokio::test]
async fn the_append_target_is_reported_on_a_page_that_matched_nothing() {
    let db = seeded_database().await;

    let response = get_shielded_transactions_by_tags(&db, request([1u8; 32]))
        .await
        .expect("tags lookup");

    assert!(response.transactions.is_empty());
    assert_eq!(response.output_tree_id, Some(FIXTURE_TREE_ID));
}

/// The newest tree is not always a usable one: a paused tree rejects every
/// append, so naming it would send every wallet at a tree that cannot take
/// their outputs.
#[tokio::test]
async fn a_paused_newest_tree_is_skipped_for_the_newest_unpaused_one() {
    let db = seeded_database().await;
    let newest = FIXTURE_TREE_ID + 1;
    seed_tree_metadata(&db, Pubkey::new_unique(), newest, true).await;

    let response = get_shielded_transactions_by_tags(&db, request(VIEW_TAG))
        .await
        .expect("tags lookup");
    assert_eq!(response.output_tree_id, Some(FIXTURE_TREE_ID));

    // Unpausing it makes it the answer, so the previous assertion is about the
    // state and not about the row being invisible.
    seed_tree_metadata(&db, Pubkey::new_unique(), newest, false).await;
    let response = get_shielded_transactions_by_tags(&db, request(VIEW_TAG))
        .await
        .expect("tags lookup");
    assert_eq!(response.output_tree_id, Some(newest));
}

/// A pool whose every tree is paused has no append target, and saying so is
/// more useful than handing back an id that cannot work.
#[tokio::test]
async fn a_pool_with_no_usable_tree_reports_no_append_target() {
    let db = seeded_database().await;
    tree_metadata::Entity::update_many()
        .col_expr(tree_metadata::Column::Paused, Expr::value(true))
        .exec(&db)
        .await
        .expect("pause every tree");

    let response = get_encrypted_utxos_by_tags(&db, request(VIEW_TAG))
        .await
        .expect("utxo lookup");

    assert_eq!(response.output_tree_id, None);
}

/// A row the metadata sync has not reached yet is not a known-unpaused tree,
/// so it is not an append target either.
#[tokio::test]
async fn an_unsynced_tree_state_is_not_an_append_target() {
    let db = seeded_database().await;
    tree_metadata::Entity::update_many()
        .col_expr(
            tree_metadata::Column::Paused,
            Expr::value(Option::<bool>::None),
        )
        .filter(tree_metadata::Column::TreeId.eq(i32::from(FIXTURE_TREE_ID)))
        .exec(&db)
        .await
        .expect("clear the tree state");

    let response = get_shielded_transactions_by_tags(&db, request(VIEW_TAG))
        .await
        .expect("tags lookup");

    assert_eq!(response.output_tree_id, None);
}
