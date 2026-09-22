use solana_account::Account;
use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_client::{ClientError, Rpc};
use zolana_interface::{instruction::RingAssetDeposit, state::read_tree_id};
use zolana_program_test::RingDepositOutput;
use zolana_transaction::{OutputContext, OutputSlot};
use zolana_wallet::{SyncWalletAuthority, Wallet, DEFAULT_TAG_WINDOW};

use super::{
    fetch_account, state_root_from, to_address, wait_for_indexed_utxo, wait_for_merkle_proof,
};

pub struct RingDepositAssertArgs<'a> {
    pub tree: &'a Pubkey,
    pub event: &'a RingDepositOutput,
    pub data: &'a RingAssetDeposit,
    pub expected_amount: u64,
    pub expected_asset: Address,
    pub expected_ring_program_id: [u8; 32],
    pub signature: Signature,
    pub tree_before: &'a Account,
}

#[track_caller]
pub fn assert_ring_deposit<R: Rpc, I: Rpc, A: SyncWalletAuthority + ?Sized>(
    rpc: &R,
    indexer: &I,
    args: RingDepositAssertArgs,
    authority: &A,
    recipient: &mut Wallet,
) -> Result<(), ClientError> {
    let RingDepositAssertArgs {
        tree,
        event,
        data,
        expected_amount,
        expected_asset,
        expected_ring_program_id,
        signature,
        tree_before,
    } = args;

    let expected = RingDepositOutput {
        view_tag: data.view_tag,
        utxo_hash: event.utxo_hash,
        output_tree: event.output_tree,
        leaf_index: event.leaf_index,
        output: zolana_event::EncryptedRingDepositOutput {
            owner_utxo_hash: data.owner_utxo_hash,
            asset: expected_asset.to_bytes(),
            amount: expected_amount,
            data_hash: data.data_hash,
            ring_program_id: expected_ring_program_id,
            ring_data_hash: data.ring_data_hash,
            encrypted: zolana_event::EncryptedRingDepositData {
                tx_viewing_pk: data.encrypted.tx_viewing_pk,
                salt: data.encrypted.salt,
                ciphertext: data.encrypted.ciphertext.clone(),
            },
        },
    };
    assert_eq!(*event, expected, "ring deposit event");

    let root_before = state_root_from(tree_before);
    let tree_account = fetch_account(rpc, tree)?;
    let root_after = state_root_from(&tree_account);
    assert_ne!(root_after, root_before, "leaf must be appended");
    // The commitment folds the tree's raw id in, and the id lives in the tree
    // account, so the assert reads it there rather than restating it.
    let tree_id = read_tree_id(&tree_account.data).expect("tree id");

    let indexed = wait_for_indexed_utxo(indexer, data.view_tag, signature);
    assert_eq!(
        indexed,
        zolana_client::EncryptedUtxoMatch {
            slot: indexed.slot,
            tx_signature: signature,
            output_slot: OutputSlot {
                view_tag: data.view_tag,
                output_context: OutputContext {
                    hash: event.utxo_hash,
                    tree_id,
                    leaf_index: event.leaf_index,
                },
                payload: zolana_event::encode_encrypted_ring_deposit_output(
                    expected.output.clone(),
                ),
            },
            tx_viewing_pk: None,
            salt: None,
        },
        "indexed ring deposit"
    );

    let proof = wait_for_merkle_proof(indexer, to_address(tree), event.utxo_hash);
    assert_eq!(
        proof.root, root_after,
        "photon merkle root tracks the on-chain root"
    );

    let before = recipient.utxos.len();
    recipient
        .sync(
            authority,
            &[event.to_shielded_transaction(signature, tree_id)],
            0,
            DEFAULT_TAG_WINDOW,
        )
        .expect("wallet discovery");
    assert_eq!(
        recipient.utxos.len(),
        before + 1,
        "recipient wallet must discover the ring deposit"
    );
    let utxo = recipient.utxos.last().expect("discovered UTXO");
    assert_eq!(utxo.utxo_hash, event.utxo_hash, "wallet UTXO hash");
    assert_eq!(
        utxo.utxo.ring_program_id.map(|id| id.to_bytes()),
        Some(expected_ring_program_id),
        "wallet UTXO is owned by the ring program"
    );
    Ok(())
}
