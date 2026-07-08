//! Account view-tag derivation for indexer queries.
//!
//! Every zone output an account can decrypt -- a deposit into it, a transfer to
//! it, or its own change -- is tagged with that account's shared viewing key
//! X coordinate (`fixture.rs` `view_tag`; the prover takes `sender_view_tag` /
//! `recipient_view_tag` as inputs the caller derives this way). So a single tag
//! per account suffices to fetch all of its ciphertexts.

use zolana_squads_interface::state::ViewingKeyAccount;

/// The 32-byte X coordinate of a SEC1-compressed P-256 shared viewing key.
pub fn view_tag_from_shared_viewing_key(shared_viewing_key: &[u8; 33]) -> [u8; 32] {
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&shared_viewing_key[1..33]);
    tag
}

/// The view tag under which the account's outputs are indexed.
pub fn account_view_tag(account: &ViewingKeyAccount) -> [u8; 32] {
    view_tag_from_shared_viewing_key(&account.shared_viewing_key)
}

/// All view tags to query for an account's UTXOs.
pub fn account_query_tags(account: &ViewingKeyAccount) -> Vec<[u8; 32]> {
    vec![account_view_tag(account)]
}
