//! Assert for the Squads zone `deposit` (tag 1): a proofless deposit that CPIs
//! into SPP's `zone_deposit`, creating a zone-owned UTXO whose recipient `owner`
//! is derived on-chain from a `ViewingKeyAccount` as
//! `Poseidon(vka.owner, vka.nullifier_pubkey)`.
//!
//! Unlike a direct SPP deposit, the created UTXO carries the zone program id, and
//! its owner is not a standard shielded-keypair owner hash, so a generic
//! `Wallet::sync` cannot rediscover it. This assert therefore verifies the full
//! state transition directly: the emitted event, an independently recomputed leaf
//! hash, the settled fund movement, the appended tree leaf, and Photon indexing.

use solana_account::Account;
use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_client::{ClientError, Rpc};
use zolana_program_test::DepositOutput;
use zolana_transaction::{owner_utxo_hash, utxo_hash};

use super::{
    assert_indexed_deposit_utxo, fetch_account, state_root_from, to_address, token_amount,
    tree_next_index, wait_for_indexed_utxo, wait_for_merkle_proof,
};

const ZERO32: [u8; 32] = [0u8; 32];

/// Settlement rail the deposit took, with the pre-deposit snapshots the fund
/// movement assert compares against.
pub enum SquadsDepositSettlement<'a> {
    Sol {
        sol_interface: &'a Pubkey,
        sol_interface_before: &'a Account,
    },
    Spl {
        vault: &'a Pubkey,
        user_token: &'a Pubkey,
        vault_before: &'a Account,
        user_token_before: &'a Account,
    },
}

pub struct SquadsDepositAssertArgs<'a> {
    pub tree: &'a Pubkey,
    pub event: &'a DepositOutput,
    /// The deposit's `view_tag`, equal to the recipient VKA's shared viewing key
    /// bytes `[1..33]`.
    pub view_tag: [u8; 32],
    pub blinding: [u8; 31],
    /// The recipient VKA's `owner` field element.
    pub vka_owner: [u8; 32],
    /// The recipient VKA's `nullifier_pubkey` field element.
    pub vka_nullifier_pubkey: [u8; 32],
    pub expected_amount: u64,
    pub expected_asset: Address,
    pub expected_zone_program_id: [u8; 32],
    pub signature: Signature,
    pub tree_before: &'a Account,
    pub settlement: SquadsDepositSettlement<'a>,
}

#[track_caller]
pub fn assert_squads_deposit<R: Rpc, I: Rpc>(
    rpc: &R,
    indexer: &I,
    args: SquadsDepositAssertArgs,
) -> Result<(), ClientError> {
    let SquadsDepositAssertArgs {
        tree,
        event,
        view_tag,
        blinding,
        vka_owner,
        vka_nullifier_pubkey,
        expected_amount,
        expected_asset,
        expected_zone_program_id,
        signature,
        tree_before,
        settlement,
    } = args;

    // Owner hash the program derived on-chain from the recipient viewing key
    // account (`Poseidon(vka.owner, vka.nullifier_pubkey)`).
    let owner = zolana_keypair::hash::poseidon(&[&vka_owner, &vka_nullifier_pubkey])
        .expect("owner poseidon");

    let expected = DepositOutput {
        view_tag,
        utxo_hash: event.utxo_hash,
        output_tree: event.output_tree,
        leaf_index: event.leaf_index,
        output: zolana_event::ProoflessOutput {
            owner,
            blinding,
            asset: expected_asset.to_bytes(),
            amount: expected_amount,
            data_hash: None,
            utxo_data: None,
            zone_program_id: Some(expected_zone_program_id),
            zone_data_hash: Some(ZERO32),
            zone_data: Some(Vec::new()),
        },
    };
    assert_eq!(*event, expected, "squads deposit event");

    // Independently recompute the appended leaf: the zone deposit carries no
    // application/zone data, so `data_hash` and `zone_data_hash` are zero and the
    // `zone_hash` binds only the squads program id.
    let zone_program_id = Address::new_from_array(expected_zone_program_id);
    let owner_leaf = owner_utxo_hash(&owner, &blinding).expect("owner utxo hash");
    let recomputed = utxo_hash(
        expected_asset,
        expected_amount,
        &ZERO32,
        &ZERO32,
        Some(zone_program_id),
        &owner_leaf,
    )
    .expect("utxo hash");
    assert_eq!(recomputed, event.utxo_hash, "recomputed zone UTXO hash");

    match settlement {
        SquadsDepositSettlement::Sol {
            sol_interface,
            sol_interface_before,
        } => {
            let after = fetch_account(rpc, sol_interface)?;
            assert_eq!(
                after.lamports,
                sol_interface_before.lamports + expected_amount,
                "sol interface grows by the deposit"
            );
        }
        SquadsDepositSettlement::Spl {
            vault,
            user_token,
            vault_before,
            user_token_before,
        } => {
            assert_eq!(
                token_amount(&fetch_account(rpc, vault)?),
                token_amount(vault_before) + expected_amount,
                "vault grows by the deposit"
            );
            assert_eq!(
                token_amount(&fetch_account(rpc, user_token)?),
                token_amount(user_token_before) - expected_amount,
                "user token account shrinks by the deposit"
            );
        }
    }

    let tree_after = fetch_account(rpc, tree)?;
    assert_ne!(
        state_root_from(&tree_after),
        state_root_from(tree_before),
        "leaf must be appended"
    );
    assert_eq!(
        tree_next_index(&tree_after),
        tree_next_index(tree_before) + 1,
        "tree next index advances by one"
    );

    let indexed = wait_for_indexed_utxo(indexer, view_tag, signature);
    assert_indexed_deposit_utxo(&indexed, view_tag, signature, tree, event);

    let proof = wait_for_merkle_proof(indexer, to_address(tree), event.utxo_hash);
    assert_eq!(
        proof.root,
        state_root_from(&tree_after),
        "photon merkle root tracks the on-chain root"
    );
    Ok(())
}
