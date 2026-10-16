//! Default-ring spends, built from `zolana-transaction` and `zolana-client`.
//!
//! The CLI holds the whole keypair, so a spend is: pick notes from the
//! wallet's spendable UTXOs, add the outputs to a `ConfidentialTransaction`, encrypt it with the
//! keypair, let the client fetch the input proofs and prove, then sign with the
//! owner and fee payer and send.

use anyhow::Result;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    sign_transaction, Rpc, RpcSendTransactionConfig, SignedPrivateTransaction, SolanaRpc,
    Submission, ZolanaClient,
};
use zolana_program::instruction::TransactInterfaceTransferAccounts;
use zolana_transaction::instructions::transact::ConfidentialTransaction;

use super::sync::SyncContext;

/// How a spend is sent.
pub(super) enum Send {
    /// Skip preflight: the CLI confirms right after, so a simulation first
    /// would only add a round trip.
    Fast,
    /// Simulate before sending.
    Checked,
}

/// Encrypt, prove, sign with the owner and fee payer, send and wait for the indexer.
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
    let unsigned = Submission::new(&signed, ctx.material.fee_payer.pubkey(), keypair)
        .finish_unsigned_sync(client)?;
    let transaction = sign_transaction(unsigned.message, &[&ctx.material.fee_payer, keypair])?;
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
