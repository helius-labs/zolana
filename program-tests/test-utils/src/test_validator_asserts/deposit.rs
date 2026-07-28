use solana_account::Account;
use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_client::{ClientError, Rpc};
use zolana_interface::instruction::AssetDeposit;
use zolana_program_test::DepositOutput;
use zolana_transaction::{SyncWalletAuthority, Wallet};

use super::{
    assert_indexed_deposit_utxo, expected_deposit_view, fetch_account, state_root_from, to_address,
    wait_for_indexed_utxo, wait_for_merkle_proof,
};

pub struct DepositAssertArgs<'a> {
    pub tree: &'a Pubkey,
    pub event: &'a DepositOutput,
    pub data: &'a AssetDeposit,
    pub expected_amount: u64,
    pub expected_asset: Address,
    pub signature: Signature,
    pub tree_before: &'a Account,
}

#[track_caller]
pub fn assert_deposit<R: Rpc, I: Rpc, A: SyncWalletAuthority + ?Sized>(
    rpc: &R,
    indexer: &I,
    args: DepositAssertArgs,
    authority: &A,
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
    assert_indexed_deposit_utxo(&indexed, data.view_tag, signature, tree, event);

    let proof = wait_for_merkle_proof(indexer, to_address(tree), event.utxo_hash);
    assert_eq!(
        proof.root, root_after,
        "photon merkle root tracks the on-chain root"
    );

    super::assert_wallet_discovers(recipient, authority, event, signature, None, "deposit");
    Ok(())
}
