use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_client::{ClientError, Rpc};
use zolana_interface::instruction::TransactIxData;

use super::{
    state_root_from, to_address, wait_for_indexed_transaction, wait_for_merkle_proof,
    wait_for_nullifier_present,
};

/// Inputs for [`assert_zone_transact`]. The view tags identify which indexed
/// transaction photon must serve: a `zone_transact` output is indexed by the
/// recipient's confidential view tag, or by the sender change tag for a
/// change-only transfer with no recipient slot.
pub struct ZoneTransactAssertArgs<'a> {
    pub tree: &'a Pubkey,
    pub data: &'a TransactIxData,
    pub signature: Signature,
    /// Tag the indexed transaction is located by (recipient tag for a transfer,
    /// or the sender change tag for a change-only consolidation).
    pub fetch_view_tag: [u8; 32],
    pub tree_before: &'a Account,
}

/// Functional assert for `zone_transact` (and the shared `transact` flow).
///
/// Verifies the full state transition without re-deriving the emitted event from
/// scratch (event re-derivation is coupled to the bundle/ciphertext slot mapping,
/// done inline in the step files via `Wallet::sync`). Instead it cross-checks the
/// instruction against what photon indexed:
///
/// - the indexed transaction is served by photon under `fetch_view_tag`,
/// - the tree root advanced (the outputs were appended),
/// - the indexed transaction's `nullifiers` equal the instruction's
///   `inputs[].nullifier_hash`, and its output-slot hashes equal the
///   instruction's `output_utxo_hashes` (so the emitted event matched the data),
/// - photon serves a merkle inclusion proof for every appended output, each
///   tracking the on-chain root,
/// - every spent nullifier is now present in the nullifier tree (its
///   non-inclusion proof is no longer served).
///
/// Callers must pass the `tree` account state captured before the transaction
/// (`tree_before`) so the root advance can be checked.
#[track_caller]
pub fn assert_zone_transact<R: Rpc, I: Rpc>(
    rpc: &R,
    indexer: &I,
    args: ZoneTransactAssertArgs,
) -> Result<(), ClientError> {
    let ZoneTransactAssertArgs {
        tree,
        data,
        signature,
        fetch_view_tag,
        tree_before,
    } = args;

    let root_before = state_root_from(tree_before);
    let root_after = state_root_from(&super::fetch_account(rpc, tree)?);
    assert_ne!(root_after, root_before, "outputs must be appended");

    let indexed = wait_for_indexed_transaction(indexer, fetch_view_tag, signature);
    assert_eq!(indexed.tx_signature, signature, "indexed signature");

    let expected_nullifiers: Vec<[u8; 32]> =
        data.inputs.iter().map(|input| input.nullifier_hash).collect();
    assert_eq!(
        indexed.nullifiers, expected_nullifiers,
        "indexed nullifiers must match the instruction inputs"
    );

    let indexed_output_hashes: Vec<[u8; 32]> = indexed
        .output_slots
        .iter()
        .map(|slot| slot.output_context.hash)
        .collect();
    assert_eq!(
        indexed_output_hashes, data.output_utxo_hashes,
        "indexed output hashes must match the instruction output commitments"
    );

    for output_hash in &data.output_utxo_hashes {
        let proof = wait_for_merkle_proof(indexer, to_address(tree), *output_hash);
        assert_eq!(
            proof.root, root_after,
            "photon merkle root tracks the on-chain root"
        );
    }

    for nullifier in &expected_nullifiers {
        wait_for_nullifier_present(indexer, to_address(tree), *nullifier);
    }

    Ok(())
}
