//! The unknown-field rule of the wire contract, shared with the TS codec: every
//! response tolerates a field it has never heard of, every request refuses one.
//!
//! The split is deliberate and load-bearing, so it is pinned rather than left
//! to whoever next edits a `#[serde(..)]` attribute.

use spr_indexer_api::{
    GetEncryptedUtxosByTagsResponse, GetMerkleProofsRequest, GetMerkleProofsResponse,
    GetNonInclusionProofsResponse, GetShieldedTransactionsBySignatureResponse,
    GetShieldedTransactionsByTagsResponse, GetUserRecordsResponse, Hash, SerializablePubkey,
};

/// A read response must survive a field it has never heard of, so adding one to
/// Photon does not break clients built before it.
#[test]
fn a_read_response_tolerates_a_field_it_does_not_know() {
    let page = serde_json::json!({
        "context": { "blockTime": 3, "slot": 1, "somethingLater": 9 },
        "data": [],
        "paginationToken": null,
        "aFieldFromAFutureRelease": { "nested": true },
    });
    let response: GetEncryptedUtxosByTagsResponse =
        serde_json::from_value(page).expect("an unknown field is not an error");
    assert_eq!(response.context.slot, 1);
}

/// The rule holds at every depth of every response, not only on the page.
#[test]
fn every_response_object_tolerates_a_field_it_does_not_know() {
    let hash = Hash::from([1; 32]).to_string();
    let pubkey = SerializablePubkey::from([3; 32]).to_string();
    let signature = "1".repeat(64);
    let context = serde_json::json!({ "blockTime": 3, "slot": 7, "later": 1 });
    let output_slot = serde_json::json!({
        "viewTag": hash,
        "outputContext": { "hash": hash, "treeId": 2, "leafIndex": 0, "later": 1 },
        "payload": "",
        "later": 1,
    });
    let event = serde_json::json!({
        "slot": 7,
        "txSignature": signature,
        "eventIndex": 0,
        "txViewingPk": null,
        "salt": null,
        "outputSlots": [output_slot],
        "messages": [{ "viewTag": hash, "payload": "", "later": 1 }],
        "nullifiers": [],
        "proofless": false,
        "later": 1,
    });
    let events: GetShieldedTransactionsByTagsResponse = serde_json::from_value(serde_json::json!({
        "context": context,
        "data": [{ "slot": 7, "signature": signature, "events": [event], "later": 1 }],
        "paginationToken": null,
    }))
    .expect("an events page with unknown fields");
    assert_eq!(
        events.data[0].events[0].output_slots[0]
            .output_context
            .tree_id,
        2
    );

    let outputs: GetEncryptedUtxosByTagsResponse = serde_json::from_value(serde_json::json!({
        "context": context,
        "data": [{
            "slot": 7,
            "signature": signature,
            "outputs": [{
                "slot": 7,
                "txSignature": signature,
                "outputSlot": output_slot,
                "txViewingPk": null,
                "salt": null,
                "later": 1,
            }],
            "later": 1,
        }],
        "paginationToken": null,
    }))
    .expect("an outputs page with unknown fields");
    assert_eq!(outputs.data[0].outputs.len(), 1);

    let by_signature: GetShieldedTransactionsBySignatureResponse =
        serde_json::from_value(serde_json::json!({
            "context": context,
            "transactions": [{ "eventIndex": 0, "transaction": event, "later": 1 }],
            "later": 1,
        }))
        .expect("a by-signature response with unknown fields");
    assert_eq!(by_signature.transactions.len(), 1);

    let merkle_context = serde_json::json!({ "treeType": 0, "tree": pubkey, "later": 1 });
    let merkle: GetMerkleProofsResponse = serde_json::from_value(serde_json::json!({
        "context": context,
        "proofs": [{
            "leaf": hash,
            "merkleContext": merkle_context,
            "path": [hash],
            "leafIndex": 0,
            "root": hash,
            "rootSeq": 0,
            "rootIndex": 0,
            "later": 1,
        }],
        "later": 1,
    }))
    .expect("merkle proofs with unknown fields");
    assert_eq!(merkle.proofs.len(), 1);

    let non_inclusion: GetNonInclusionProofsResponse = serde_json::from_value(serde_json::json!({
        "context": context,
        "proofs": [{
            "leaf": hash,
            "merkleContext": merkle_context,
            "path": [hash],
            "lowElement": hash,
            "lowElementIndex": 0,
            "highElement": hash,
            "highElementIndex": 1,
            "root": hash,
            "rootSeq": 0,
            "rootIndex": 0,
            "later": 1,
        }],
        "later": 1,
    }))
    .expect("non-inclusion proofs with unknown fields");
    assert_eq!(non_inclusion.proofs.len(), 1);

    let records: GetUserRecordsResponse = serde_json::from_value(serde_json::json!({
        "context": context,
        "records": [{
            "owner": pubkey,
            "nullifierPubkey": hash,
            "viewingPubkey": "",
            "mergeEncryption": 1,
            "later": 1,
        }, null],
        "later": 1,
    }))
    .expect("user records with unknown fields");
    assert_eq!(records.records.len(), 2);
}

/// The deprecated output `tree` account is optional: a reader takes the tree
/// from `treeId`, so Photon can stop sending it without breaking this release.
#[test]
fn an_output_context_reads_without_the_deprecated_tree() {
    let hash = Hash::from([1; 32]).to_string();
    let page = |output_context: serde_json::Value| {
        serde_json::json!({
            "context": { "blockTime": 3, "slot": 7 },
            "data": [{
                "slot": 7,
                "signature": "1".repeat(64),
                "outputs": [{
                    "slot": 7,
                    "txSignature": "1".repeat(64),
                    "outputSlot": { "viewTag": hash, "outputContext": output_context, "payload": "" },
                    "txViewingPk": null,
                    "salt": null,
                }],
            }],
            "paginationToken": null,
        })
    };
    let context = |page: serde_json::Value| {
        let response: GetEncryptedUtxosByTagsResponse =
            serde_json::from_value(page).expect("an output without its tree account");
        response.data[0].outputs[0]
            .output_slot
            .output_context
            .clone()
    };

    let without = context(page(
        serde_json::json!({ "hash": hash, "treeId": 2, "leafIndex": 0 }),
    ));
    assert_eq!(without.tree_id, 2);
    assert_eq!(without.tree, None);

    let tree = SerializablePubkey::from([3; 32]);
    let with = context(page(serde_json::json!({
        "hash": hash,
        "tree": tree.to_string(),
        "treeId": 2,
        "leafIndex": 0,
    })));
    assert_eq!(with.tree, Some(tree));
    assert!(
        serde_json::to_value(&with)
            .expect("serializes")
            .get("tree")
            .is_some(),
        "Photon keeps sending the account it was given"
    );
}

/// The other direction of the same window: a reader built against this release
/// still reads an older Photon that reports no append target.
#[test]
fn a_read_response_survives_an_indexer_that_omits_the_append_target() {
    let page = serde_json::json!({
        "context": { "blockTime": 3, "slot": 1 },
        "data": [],
        "paginationToken": null,
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
