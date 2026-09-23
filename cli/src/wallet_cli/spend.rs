//! Default-ring spends, built from `zolana-transaction` and `zolana-client`.
//!
//! The CLI holds the whole keypair, so a spend is: pick notes from the synced
//! wallet, add the outputs to a `ConfidentialTransaction`, encrypt it with the
//! keypair, let the client fetch the input proofs and prove, then sign with the
//! funding key and send.

use anyhow::{bail, Result};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    sign_transaction, Rpc, RpcSendTransactionConfig, SignedPrivateTransaction, SolanaRpc,
    ZolanaClient,
};
use zolana_interface::pda;
use zolana_program::instruction::{
    TransactInterfaceTransferAccounts, TransactSolTransferAccounts, TransactSplWithdrawalAccounts,
};
use zolana_transaction::{
    instructions::transact::{auto_shapes, ConfidentialTransaction},
    Address, Wallet, WalletUtxo, SOL_MINT,
};

use super::sync::SyncContext;

/// A ring-bound note's commitment covers its ring; the default-ring circuit
/// does not.
pub(super) fn is_default_ring_spendable(entry: &WalletUtxo) -> bool {
    entry.utxo.ring_program_id.is_none() && entry.ring_data_hash.is_none()
}

/// No ring binding and no attached data: the only notes a split or a merge
/// takes, since their spend input drops the committed data hashes.
pub(super) fn is_plain_utxo(entry: &WalletUtxo) -> bool {
    is_default_ring_spendable(entry) && entry.data_hash.is_none() && entry.utxo.data.is_empty()
}

/// The single tree holding the eligible notes of `asset`. A transact binds one
/// input tree, so notes spread over several trees are merged per tree first.
pub(super) fn spend_tree(
    wallet: &Wallet,
    asset: Address,
    eligible: impl Fn(&WalletUtxo) -> bool,
) -> Result<Address> {
    let mut trees: Vec<Address> = wallet
        .unspent()
        .filter(|entry| entry.utxo.asset.asset == asset && eligible(entry))
        .map(|entry| pda::tree(entry.tree_id()))
        .collect();
    trees.sort();
    trees.dedup();
    match trees.as_slice() {
        [tree] => Ok(*tree),
        [] => bail!("no spendable balance"),
        _ => bail!(
            "balance is spread over {} trees; merge each tree first",
            trees.len()
        ),
    }
}

/// Largest notes first, so a fragmented balance is covered with the fewest
/// inputs, bounded by the widest supported shape.
pub(super) fn select_notes(
    wallet: &Wallet,
    asset: Address,
    amount: u64,
) -> Result<Vec<WalletUtxo>> {
    let tree = spend_tree(wallet, asset, is_default_ring_spendable)?;
    let max_inputs = auto_shapes()
        .map(|shape| shape.n_inputs())
        .max()
        .unwrap_or(0);
    let mut candidates: Vec<&WalletUtxo> = wallet
        .unspent()
        .filter(|entry| {
            entry.utxo.asset.asset == asset
                && pda::tree(entry.tree_id()) == tree
                && is_default_ring_spendable(entry)
        })
        .collect();
    candidates.sort_by_key(|entry| std::cmp::Reverse(entry.utxo.amount));
    let total: u64 = candidates.iter().map(|entry| entry.utxo.amount).sum();
    let mut selected = Vec::new();
    let mut covered = 0u64;
    for entry in candidates.into_iter().take(max_inputs) {
        covered += entry.utxo.amount;
        selected.push(entry.clone());
        if covered >= amount {
            return Ok(selected);
        }
    }
    if total >= amount {
        bail!("{amount} needs more than {max_inputs} notes; merge first");
    }
    bail!("insufficient balance: requested {amount}, available {total}")
}

/// Where a withdrawal settles: the recipient itself for SOL, its associated
/// token account for SPL.
pub(super) fn withdraw_to(
    transaction: &mut ConfidentialTransaction,
    recipient: Pubkey,
    asset: Address,
    amount: u64,
    spl_token_program: Option<Pubkey>,
) -> Result<TransactInterfaceTransferAccounts> {
    if asset == SOL_MINT {
        transaction.withdraw_sol(amount, recipient)?;
        return Ok(TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts { recipient },
        ));
    }
    let Some(token_program) = spl_token_program else {
        bail!("SPL withdrawal needs the mint's token program");
    };
    let mint = Pubkey::new_from_array(asset.to_bytes());
    let user_token_account =
        pda::associated_token_address_with_program(&recipient, &mint, &token_program);
    transaction.withdraw(asset, amount, user_token_account)?;
    Ok(TransactInterfaceTransferAccounts::SplWithdrawal(
        TransactSplWithdrawalAccounts {
            mint,
            spl_interface: pda::spl_interface(&mint),
            user_token_account,
            token_program,
        },
    ))
}

/// How a spend is sent.
pub(super) enum Send {
    /// Skip preflight: the CLI confirms right after, so a simulation first
    /// would only add a round trip.
    Fast,
    /// Simulate before sending.
    Checked,
}

/// Encrypt, prove, sign with the funding key, send and wait for the indexer.
pub(super) fn send_private(
    ctx: &SyncContext,
    client: &ZolanaClient<SolanaRpc>,
    transaction: ConfidentialTransaction,
    settlement_transfers: Vec<TransactInterfaceTransferAccounts>,
    send: Send,
) -> Result<Signature> {
    let keypair = &ctx.material.keypair;
    let signed = SignedPrivateTransaction {
        transaction: transaction.encrypt(keypair)?,
        settlement_transfers,
    };
    let message =
        client.finish_submission_unsigned_sync(&signed, ctx.material.funding.pubkey(), keypair)?;
    let transaction = sign_transaction(message, &[&ctx.material.funding])?;
    let signature = match send {
        Send::Fast => client.rpc().send_transaction_with_config(
            &transaction,
            RpcSendTransactionConfig {
                skip_preflight: true,
                ..RpcSendTransactionConfig::default()
            },
        )?,
        Send::Checked => client.rpc().process_transaction(transaction)?,
    };
    client.confirm_private_transaction_sync(signature)?;
    Ok(signature)
}
