//! Assert for a Squads zone `transact` / `execute_proposal` withdrawal: a
//! zone-proof-gated spend that forwards a real SPP zone-rail proof and settles a
//! negative public amount OUT of the pool. Unlike the proofless deposit, real
//! funds LEAVE the SPP: the external recipient's balance rises by the withdrawn
//! amount and the pool's SOL interface (or SPL vault) falls by it.
//!
//! Verifies the full state transition directly: the settled fund movement, the
//! appended change leaf (tree root + next index advance), the spent input's
//! nullifier now present in the nullifier tree, and Photon indexing of both the
//! transaction (by the sender view tag) and the change UTXO's merkle proof.

use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_client::{ClientError, Rpc};

use super::{
    fetch_account, state_root_from, to_address, token_amount, tree_next_index,
    wait_for_indexed_transaction, wait_for_merkle_proof, wait_for_nullifier_present,
};

/// Settlement rail the withdrawal took, with the pre-withdrawal snapshots the
/// fund-movement assert compares against.
pub enum SquadsWithdrawalSettlement<'a> {
    Sol {
        sol_interface: &'a Pubkey,
        sol_interface_before: &'a Account,
        recipient: &'a Pubkey,
        recipient_before: &'a Account,
    },
    Spl {
        vault: &'a Pubkey,
        vault_before: &'a Account,
        recipient_token: &'a Pubkey,
        recipient_token_before: &'a Account,
    },
}

pub struct SquadsWithdrawalAssertArgs<'a> {
    pub tree: &'a Pubkey,
    pub withdrawn: u64,
    pub change_utxo_hash: [u8; 32],
    pub nullifier: [u8; 32],
    /// The sender-change output ciphertext view tag Photon indexes the
    /// transaction and change UTXO under.
    pub sender_view_tag: [u8; 32],
    pub signature: Signature,
    pub tree_before: &'a Account,
    pub settlement: SquadsWithdrawalSettlement<'a>,
}

#[track_caller]
pub fn assert_squads_withdrawal<R: Rpc, I: Rpc>(
    rpc: &R,
    indexer: &I,
    args: SquadsWithdrawalAssertArgs,
) -> Result<(), ClientError> {
    let SquadsWithdrawalAssertArgs {
        tree,
        withdrawn,
        change_utxo_hash,
        nullifier,
        sender_view_tag,
        signature,
        tree_before,
        settlement,
    } = args;

    // Real funds left the pool: the recipient rose by `withdrawn`, the pool's
    // interface/vault fell by it.
    match settlement {
        SquadsWithdrawalSettlement::Sol {
            sol_interface,
            sol_interface_before,
            recipient,
            recipient_before,
        } => {
            let interface_after = fetch_account(rpc, sol_interface)?;
            assert_eq!(
                interface_after.lamports + withdrawn,
                sol_interface_before.lamports,
                "sol interface falls by the withdrawn amount"
            );
            let recipient_after = fetch_account(rpc, recipient)?;
            assert_eq!(
                recipient_after.lamports,
                recipient_before.lamports + withdrawn,
                "external recipient rises by the withdrawn amount"
            );
        }
        SquadsWithdrawalSettlement::Spl {
            vault,
            vault_before,
            recipient_token,
            recipient_token_before,
        } => {
            assert_eq!(
                token_amount(&fetch_account(rpc, vault)?) + withdrawn,
                token_amount(vault_before),
                "vault falls by the withdrawn amount"
            );
            assert_eq!(
                token_amount(&fetch_account(rpc, recipient_token)?),
                token_amount(recipient_token_before) + withdrawn,
                "recipient token account rises by the withdrawn amount"
            );
        }
    }

    // The change leaf was appended: the root advanced and next_index grew by one.
    let tree_after = fetch_account(rpc, tree)?;
    let root_before = state_root_from(tree_before);
    let root_after = state_root_from(&tree_after);
    assert_ne!(root_after, root_before, "change leaf must be appended");
    assert_eq!(
        tree_next_index(&tree_after),
        tree_next_index(tree_before) + 1,
        "tree next index advances by one change output"
    );

    // Photon indexed the transaction (by the sender view tag), and its nullifiers
    // and output hashes match what the withdrawal spent and appended.
    let indexed = wait_for_indexed_transaction(indexer, sender_view_tag, signature);
    assert_eq!(indexed.tx_signature, signature, "indexed signature");
    assert_eq!(
        indexed.nullifiers,
        vec![nullifier],
        "indexed nullifier matches the spent input"
    );
    let indexed_output_hashes: Vec<[u8; 32]> = indexed
        .output_slots
        .iter()
        .map(|slot| slot.output_context.hash)
        .collect();
    assert_eq!(
        indexed_output_hashes,
        vec![change_utxo_hash],
        "indexed output hash matches the change commitment"
    );

    // Photon serves a merkle inclusion proof for the change UTXO, tracking the
    // on-chain root.
    let proof = wait_for_merkle_proof(indexer, to_address(tree), change_utxo_hash);
    assert_eq!(
        proof.root, root_after,
        "photon merkle root tracks the on-chain root"
    );

    // The spent input's nullifier is now present in the nullifier tree.
    wait_for_nullifier_present(indexer, to_address(tree), nullifier);
    Ok(())
}
