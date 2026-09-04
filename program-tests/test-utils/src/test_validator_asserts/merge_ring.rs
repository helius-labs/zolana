use solana_account::Account;
use solana_pubkey::Pubkey;
use zolana_client::{ClientError, Rpc};

use super::{state_root_from, to_address, wait_for_merkle_proof, wait_for_nullifier_present};
use crate::nullifier_pda::{assert_nullifier_pdas, assert_tree_lamports_after_spend};

/// Inputs for [`assert_merge_ring`]. The merge consolidates the 8-input shape
/// into the single `output_hash`; `input_nullifiers` are the nullifiers the merge
/// proof spent (real and dummy slots).
pub struct MergeRingAssertArgs<'a> {
    pub tree: &'a Pubkey,
    pub output_hash: [u8; 32],
    pub input_nullifiers: &'a [[u8; 32]],
    pub tree_before: &'a Account,
}

/// Functional assert for the `merge_ring` consolidated output. Mirrors the
/// `spp merge` inclusion-proof check (`steps/merge.rs::assert_merged`) but as a
/// reusable function: given the appended output hash and the spent input
/// nullifiers, verify
///
/// - the tree root advanced (the output was appended),
/// - the tree collected the forester fee and funded exactly one nullifier
///   nullifier PDA per input; every nullifier PDA exists with its rent, owner, size and bump,
/// - photon serves a merkle inclusion proof for the consolidated output, tracking
///   the on-chain root,
/// - every spent input nullifier is now present in the nullifier tree (its
///   non-inclusion proof is no longer served).
///
/// Callers must pass the `tree` account state captured before the transaction
/// (`tree_before`) so the root advance can be checked.
#[track_caller]
pub fn assert_merge_ring<R: Rpc, I: Rpc>(
    rpc: &R,
    indexer: &I,
    args: MergeRingAssertArgs,
) -> Result<(), ClientError> {
    let MergeRingAssertArgs {
        tree,
        output_hash,
        input_nullifiers,
        tree_before,
    } = args;

    let root_before = state_root_from(tree_before);
    let tree_after =
        assert_tree_lamports_after_spend(rpc, tree, tree_before, input_nullifiers.len() as u64)?;
    let root_after = state_root_from(&tree_after);
    assert_ne!(
        root_after, root_before,
        "consolidated output must be appended"
    );
    assert_nullifier_pdas(rpc, tree, input_nullifiers)?;

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
