//! Assert for a Squads ring withdrawal (`transact` or a settled withdrawal
//! proposal): a `(1, 1)` spend that settles the public amount out of SPP and
//! appends one change output. The change is identified by the UTXO the backend
//! decrypts for the sender afterwards, so the assert ties the indexed
//! transaction, the appended leaf, and the decrypted change together.

use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_client::{ClientError, Rpc};
use zolana_test_utils::test_validator_asserts::{
    fetch_account, state_root_from, to_address, token_amount, utxo_next_index_from,
    wait_for_indexed_transaction, wait_for_merkle_proof, wait_for_nullifier_present,
};

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
    /// The sender's change UTXO as the backend decrypts it after settlement.
    pub change_utxo_hash: [u8; 32],
    /// The spent input's nullifier.
    pub nullifier: [u8; 32],
    /// The sender view tag the change output is indexed under.
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

    match settlement {
        SquadsWithdrawalSettlement::Sol {
            sol_interface,
            sol_interface_before,
            recipient,
            recipient_before,
        } => {
            assert_eq!(
                fetch_account(rpc, sol_interface)?.lamports + withdrawn,
                sol_interface_before.lamports,
                "sol interface falls by the withdrawn amount"
            );
            assert_eq!(
                fetch_account(rpc, recipient)?.lamports,
                recipient_before.lamports + withdrawn,
                "recipient rises by the withdrawn amount"
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
                "spl interface falls by the withdrawn amount"
            );
            assert_eq!(
                token_amount(&fetch_account(rpc, recipient_token)?),
                token_amount(recipient_token_before) + withdrawn,
                "recipient token account rises by the withdrawn amount"
            );
        }
    }

    let tree_after = fetch_account(rpc, tree)?;
    let root_after = state_root_from(&tree_after);
    assert_ne!(
        root_after,
        state_root_from(tree_before),
        "change leaf must be appended"
    );
    assert_eq!(
        utxo_next_index_from(tree, &tree_after),
        utxo_next_index_from(tree, tree_before) + 1,
        "tree next index advances by one change output"
    );

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
        "the only output is the decrypted change"
    );

    let proof = wait_for_merkle_proof(indexer, to_address(tree), change_utxo_hash);
    assert_eq!(
        proof.root, root_after,
        "photon merkle root tracks the on-chain root"
    );
    wait_for_nullifier_present(indexer, to_address(tree), nullifier);
    Ok(())
}
