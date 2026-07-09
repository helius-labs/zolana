use rings_client::{ClientError, Rpc};
use rings_interface::instruction::DepositIxData;
use rings_program_test::DepositOutput;
use rings_transaction::{Wallet, DEFAULT_TAG_WINDOW};
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_signature::Signature;

use super::{
    assert_indexed_deposit_utxo, expected_deposit_view, fetch_account, state_root_from, to_address,
    token_amount, wait_for_indexed_utxo, wait_for_merkle_proof,
};

pub struct SplDepositAssertArgs<'a> {
    pub tree: &'a Pubkey,
    pub mint: &'a Pubkey,
    pub vault: &'a Pubkey,
    pub user_token: &'a Pubkey,
    pub event: &'a DepositOutput,
    pub data: &'a DepositIxData,
    pub expected_amount: u64,
    pub signature: Signature,
    pub tree_before: &'a Account,
    pub vault_before: &'a Account,
    pub user_token_before: &'a Account,
}

#[track_caller]
pub fn assert_spl_deposit<R: Rpc, I: Rpc>(
    rpc: &R,
    indexer: &I,
    args: SplDepositAssertArgs,
    recipient: &mut Wallet,
) -> Result<(), ClientError> {
    let SplDepositAssertArgs {
        tree,
        mint,
        vault,
        user_token,
        event,
        data,
        expected_amount,
        signature,
        tree_before,
        vault_before,
        user_token_before,
    } = args;

    assert_eq!(
        *event,
        expected_deposit_view(data, expected_amount, to_address(mint), event),
        "deposit event"
    );

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

    let before = recipient.utxos.len();
    recipient
        .sync(
            &[event.to_shielded_transaction(signature)],
            0,
            DEFAULT_TAG_WINDOW,
        )
        .expect("wallet discovery");
    assert_eq!(
        recipient.utxos.len(),
        before + 1,
        "recipient wallet must discover the SPL deposit"
    );
    let utxo = recipient.utxos.last().expect("discovered UTXO");
    assert_eq!(
        utxo.output_context.hash, event.utxo_hash,
        "wallet UTXO hash"
    );
    assert_eq!(
        utxo.utxo.asset.to_bytes(),
        mint.to_bytes(),
        "wallet UTXO asset is the mint"
    );
    Ok(())
}
