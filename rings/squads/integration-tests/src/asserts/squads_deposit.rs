//! Assert for the Squads ring `deposit` (tag 1): a proofless deposit the ring
//! forwards to SPP `ring_deposit`. The ring commits the output to the recipient
//! viewing key account's owner and publishes the blinding in the clear as the
//! deposit record, so the leaf is recomputed here from the account and the
//! recorded blinding rather than rediscovered by a wallet sync.

use solana_account::Account;
use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_client::{ClientError, EncryptedUtxoMatch, Rpc};
use zolana_interface::state::read_tree_id;
use zolana_keypair::PublicKey;
use zolana_program_test::RingDepositOutput;
use zolana_test_utils::test_validator_asserts::{
    fetch_account, state_root_from, to_address, token_amount, utxo_next_index_from,
    wait_for_indexed_utxo, wait_for_merkle_proof,
};
use zolana_transaction::{owner_utxo_hash, Data, Mint, OutputContext, OutputSlot, Utxo};

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
    pub event: &'a RingDepositOutput,
    pub view_tag: [u8; 32],
    pub blinding: [u8; 32],
    /// The recipient viewing key account's owner identity.
    pub vka_owner: [u8; 32],
    pub vka_nullifier_pubkey: [u8; 32],
    pub expected_amount: u64,
    /// The mint, `SOL_MINT` for SOL.
    pub expected_asset: Address,
    pub expected_ring_program_id: [u8; 32],
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
        expected_ring_program_id,
        signature,
        tree_before,
        settlement,
    } = args;

    let tree_id = read_tree_id(&tree_before.data).expect("tree id");
    let owner = PublicKey::from_owner_identity(vka_owner);
    let owner_hash =
        zolana_keypair::hash::owner_hash(&owner, &vka_nullifier_pubkey).expect("owner hash");
    let expected = RingDepositOutput {
        view_tag,
        utxo_hash: Utxo {
            owner,
            asset: Mint::new(expected_asset, 0),
            amount: expected_amount,
            blinding,
            ring_program_id: Some(Address::new_from_array(expected_ring_program_id)),
            data: Data::default(),
        }
        .hash(&vka_nullifier_pubkey, &[0u8; 32], &[0u8; 32], tree_id)
        .expect("ring UTXO hash"),
        output_tree: tree.to_bytes(),
        leaf_index: utxo_next_index_from(tree, tree_before),
        output: zolana_event::EncryptedRingDepositOutput {
            owner_utxo_hash: owner_utxo_hash(&owner_hash, &blinding).expect("owner utxo hash"),
            asset: expected_asset.to_bytes(),
            amount: expected_amount,
            data_hash: None,
            ring_program_id: expected_ring_program_id,
            ring_data_hash: [0u8; 32],
            encrypted: zolana_event::EncryptedRingDepositData {
                tx_viewing_pk: [0u8; 33],
                salt: [0u8; 16],
                ciphertext: blinding.to_vec(),
            },
        },
    };
    assert_eq!(*event, expected, "squads deposit event");

    match settlement {
        SquadsDepositSettlement::Sol {
            sol_interface,
            sol_interface_before,
        } => {
            assert_eq!(
                fetch_account(rpc, sol_interface)?.lamports,
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
                "spl interface grows by the deposit"
            );
            assert_eq!(
                token_amount(&fetch_account(rpc, user_token)?),
                token_amount(user_token_before) - expected_amount,
                "depositor token account shrinks by the deposit"
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
        utxo_next_index_from(tree, &tree_after),
        expected.leaf_index + 1,
        "tree next index advances by one"
    );

    let indexed = wait_for_indexed_utxo(indexer, view_tag, signature);
    assert_eq!(
        indexed,
        EncryptedUtxoMatch {
            slot: indexed.slot,
            tx_signature: signature,
            output_slot: OutputSlot {
                view_tag,
                output_context: OutputContext {
                    hash: expected.utxo_hash,
                    tree_id,
                    leaf_index: expected.leaf_index,
                },
                payload: zolana_event::encode_encrypted_ring_deposit_output(expected.output),
            },
            tx_viewing_pk: None,
            salt: None,
        },
        "indexed squads deposit"
    );

    let proof = wait_for_merkle_proof(indexer, to_address(tree), expected.utxo_hash);
    assert_eq!(
        proof.root,
        state_root_from(&tree_after),
        "photon merkle root tracks the on-chain root"
    );
    Ok(())
}
