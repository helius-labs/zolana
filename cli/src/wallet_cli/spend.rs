//! Default-ring spends, built from `spr-transaction` and `spr-client`.
//!
//! The CLI holds the whole keypair, so a spend is: pick notes from the
//! wallet's spendable UTXOs, add the outputs to a `ConfidentialTransaction`, encrypt it with the
//! keypair, let the client fetch the input proofs and prove, then sign with the
//! funding key and send.

use anyhow::Result;
use solana_signature::Signature;
use spr_client::{
    sign_transaction, Rpc, RpcSendTransactionConfig, SolanaRpc, SprClient, TransactionProofRequest,
};
use spr_transaction::instructions::transact::ConfidentialTransaction;

use super::sync::SyncContext;

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
    client: &SprClient<SolanaRpc>,
    transaction: ConfidentialTransaction,
    send: Send,
) -> Result<Signature> {
    let keypair = &ctx.material.keypair;
    let signed = transaction.encrypt(keypair)?;
    let unsigned =
        TransactionProofRequest::new(signed, &[keypair])?.fetch_and_prove_sync(client)?;
    let transaction = sign_transaction(unsigned.message, &[&ctx.material.funding])?;
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
