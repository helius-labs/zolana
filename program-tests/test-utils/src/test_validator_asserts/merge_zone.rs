use solana_account::Account;
use solana_pubkey::Pubkey;
use zolana_client::{ClientError, Rpc};

use super::{
    state_root_from, to_address, wait_for_merkle_proof, wait_for_nullifier_present,
};

/// Inputs for [`assert_merge_zone`]. The merge consolidates the 8-input shape
/// into the single `output_hash`; `input_nullifiers` are the nullifiers the merge
/// proof spent (real and dummy slots).
pub struct MergeZoneAssertArgs<'a> {
    pub tree: &'a Pubkey,
    pub output_hash: [u8; 32],
    pub input_nullifiers: &'a [[u8; 32]],
    pub tree_before: &'a Account,
}

/// Functional assert for the `merge_zone` consolidated output. Mirrors the
/// `spp merge` inclusion-proof check (`steps/merge.rs::assert_merged`) but as a
/// reusable function: given the appended output hash and the spent input
/// nullifiers, verify
///
/// - the tree root advanced (the output was appended),
/// - photon serves a merkle inclusion proof for the consolidated output, tracking
///   the on-chain root,
/// - every spent input nullifier is now present in the nullifier tree (its
///   non-inclusion proof is no longer served).
///
/// Callers must pass the `tree` account state captured before the transaction
/// (`tree_before`) so the root advance can be checked.
#[track_caller]
pub fn assert_merge_zone<R: Rpc, I: Rpc>(
    rpc: &R,
    indexer: &I,
    args: MergeZoneAssertArgs,
) -> Result<(), ClientError> {
    let MergeZoneAssertArgs {
        tree,
        output_hash,
        input_nullifiers,
        tree_before,
    } = args;

    let root_before = state_root_from(tree_before);
    let root_after = state_root_from(&super::fetch_account(rpc, tree)?);
    assert_ne!(root_after, root_before, "consolidated output must be appended");

    let proof = wait_for_merkle_proof(indexer, to_address(tree), output_hash);
    assert_eq!(
        proof.root, root_after,
        "photon merkle root tracks the on-chain root"
    );

    for nullifier in input_nullifiers {
        wait_for_nullifier_present(indexer, to_address(tree), *nullifier);
    }

    Ok(())
}
