use solana_account::Account;
use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_client::{ClientError, Rpc};
use zolana_interface::instruction::ZoneAssetDeposit;
use zolana_program_test::ZoneDepositOutput;
use zolana_transaction::{
    OutputContext, OutputSlot, SyncWalletAuthority, Wallet, DEFAULT_TAG_WINDOW,
};

use super::{
    fetch_account, state_root_from, to_address, wait_for_indexed_utxo, wait_for_merkle_proof,
};

pub struct ZoneDepositAssertArgs<'a> {
    pub tree: &'a Pubkey,
    pub event: &'a ZoneDepositOutput,
    pub data: &'a ZoneAssetDeposit,
    pub expected_amount: u64,
    pub expected_asset: Address,
    pub expected_zone_program_id: [u8; 32],
    pub signature: Signature,
    pub tree_before: &'a Account,
}

#[track_caller]
pub fn assert_zone_deposit<R: Rpc, I: Rpc, A: SyncWalletAuthority + ?Sized>(
    rpc: &R,
    indexer: &I,
    args: ZoneDepositAssertArgs,
    authority: &A,
    recipient: &mut Wallet,
) -> Result<(), ClientError> {
    let ZoneDepositAssertArgs {
        tree,
        event,
        data,
        expected_amount,
        expected_asset,
        expected_zone_program_id,
        signature,
        tree_before,
    } = args;

    let expected = ZoneDepositOutput {
        view_tag: data.view_tag,
        utxo_hash: event.utxo_hash,
        output_tree: event.output_tree,
        leaf_index: event.leaf_index,
        output: zolana_event::EncryptedZoneDepositOutput {
            owner_utxo_hash: data.owner_utxo_hash,
            asset: expected_asset.to_bytes(),
            amount: expected_amount,
            data_hash: data.data_hash,
            zone_program_id: expected_zone_program_id,
            zone_data_hash: data.zone_data_hash,
            encrypted: zolana_event::EncryptedZoneDepositData {
                tx_viewing_pk: data.encrypted.tx_viewing_pk,
                salt: data.encrypted.salt,
                ciphertext: data.encrypted.ciphertext.clone(),
            },
        },
    };
    assert_eq!(*event, expected, "zone deposit event");

    let root_before = state_root_from(tree_before);
    let root_after = state_root_from(&fetch_account(rpc, tree)?);
    assert_ne!(root_after, root_before, "leaf must be appended");

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
                    tree: to_address(tree),
                    leaf_index: event.leaf_index,
                },
                payload: zolana_event::encode_encrypted_zone_deposit_output(
                    expected.output.clone(),
                ),
            },
            tx_viewing_pk: None,
            salt: None,
        },
        "indexed zone deposit"
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
            &[event.to_shielded_transaction(signature)],
            0,
            DEFAULT_TAG_WINDOW,
        )
        .expect("wallet discovery");
    assert_eq!(
        recipient.utxos.len(),
        before + 1,
        "recipient wallet must discover the zone deposit"
    );
    let utxo = recipient.utxos.last().expect("discovered UTXO");
    assert_eq!(
        utxo.output_context.hash, event.utxo_hash,
        "wallet UTXO hash"
    );
    assert_eq!(
        utxo.utxo.zone_program_id.map(|id| id.to_bytes()),
        Some(expected_zone_program_id),
        "wallet UTXO is owned by the zone program"
    );
    Ok(())
}
