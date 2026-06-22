use solana_account::Account;
use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_client::{ClientError, Rpc};
use zolana_event::DepositView;
use zolana_interface::instruction::DepositIxData;
use zolana_transaction::{AssetRegistry, Wallet, DEFAULT_TAG_WINDOW};

use super::{
    expected_deposit_view, fetch_account, state_root_from, to_address, wait_for_indexed_utxo,
    wait_for_merkle_proof,
};

pub struct DepositAssertArgs<'a> {
    pub tree: &'a Pubkey,
    pub event: &'a DepositView,
    pub data: &'a DepositIxData,
    pub expected_amount: u64,
    pub expected_asset: Address,
    pub signature: Signature,
    pub tree_before: &'a Account,
}

#[track_caller]
pub fn assert_deposit<R: Rpc, I: Rpc>(
    rpc: &R,
    indexer: &I,
    args: DepositAssertArgs,
    recipient: &mut Wallet,
) -> Result<(), ClientError> {
    let DepositAssertArgs {
        tree,
        event,
        data,
        expected_amount,
        expected_asset,
        signature,
        tree_before,
    } = args;

    assert_eq!(
        *event,
        expected_deposit_view(data, expected_amount, expected_asset, event),
        "deposit event"
    );

    let root_before = state_root_from(tree_before);
    let root_after = state_root_from(&fetch_account(rpc, tree)?);
    assert_ne!(root_after, root_before, "leaf must be appended");

    let indexed = wait_for_indexed_utxo(indexer, data.view_tag, signature);
    assert_eq!(indexed.view_tag, data.view_tag, "indexed view tag");
    assert_eq!(indexed.tx_signature, signature, "indexed signature");
    assert_eq!(indexed.utxo_hash, event.utxo_hash, "indexed UTXO hash");
    assert_eq!(indexed.output_tree, to_address(tree), "indexed output tree");
    assert_eq!(indexed.leaf_index, event.leaf_index, "indexed leaf index");

    let proof = wait_for_merkle_proof(indexer, to_address(tree), event.utxo_hash);
    assert_eq!(
        proof.root, root_after,
        "photon merkle root tracks the on-chain root"
    );

    let before = recipient.utxos.len();
    recipient
        .sync(
            &[],
            std::slice::from_ref(event),
            &AssetRegistry::default(),
            0,
            DEFAULT_TAG_WINDOW,
        )
        .expect("wallet discovery");
    assert_eq!(
        recipient.utxos.len(),
        before + 1,
        "recipient wallet must discover the deposit"
    );
    let utxo = recipient.utxos.last().expect("discovered UTXO");
    assert_eq!(utxo.hash, event.utxo_hash, "wallet UTXO hash");
    assert_eq!(utxo.utxo.amount, event.amount, "wallet UTXO amount");
    Ok(())
}
