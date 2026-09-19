//! Which types tolerate a field they have never heard of, and which refuse it.
//!
//! The split is deliberate and load-bearing, so it is pinned rather than left
//! to whoever next edits a `#[serde(..)]` attribute.

use zolana_indexer_api::{
    GetEncryptedUtxosByTagsResponse, GetMerkleProofsRequest, GetShieldedTransactionsByTagsResponse,
    SerializablePubkey,
};

/// A read response must survive a field it has never heard of, so adding one to
/// Photon does not break clients built before it.
#[test]
fn a_read_response_tolerates_a_field_it_does_not_know() {
    let page = serde_json::json!({
        "context": { "blockTime": 3, "slot": 1, "somethingLater": 9 },
        "matches": [],
        "nextCursor": null,
        "aFieldFromAFutureRelease": { "nested": true },
    });
    let response: GetEncryptedUtxosByTagsResponse =
        serde_json::from_value(page).expect("an unknown field is not an error");
    assert_eq!(response.context.slot, 1);
}

/// The other direction of the same window: a reader built against this release
/// still reads an older Photon that reports no append target.
#[test]
fn a_read_response_survives_an_indexer_that_omits_the_append_target() {
    let page = serde_json::json!({
        "context": { "blockTime": 3, "slot": 1 },
        "transactions": [],
        "nextCursor": null,
    });
    let response: GetShieldedTransactionsByTagsResponse =
        serde_json::from_value(page).expect("an absent append target is readable");
    assert_eq!(response.output_tree_id, None);
}

/// Requests keep refusing unknown fields: a misspelled parameter there is a
/// caller bug, and silently ignoring it would answer a different question.
#[test]
fn a_request_still_refuses_a_field_it_does_not_know() {
    let request = serde_json::json!({
        "treeAccount": SerializablePubkey::from([3; 32]).to_string(),
        "leaves": [],
        "treeAcount": "typo",
    });
    assert!(serde_json::from_value::<GetMerkleProofsRequest>(request).is_err());
}
