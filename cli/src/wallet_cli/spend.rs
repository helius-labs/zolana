//! Default-ring spends, built from `zolana-transaction` and `zolana-client`.
//!
//! The CLI holds the whole keypair, so a spend is: pick notes from the
//! wallet's spendable UTXOs, add the outputs to a `ConfidentialTransaction`, encrypt it with the
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
use zolana_transaction::{instructions::transact::ConfidentialTransaction, Address, SOL_MINT};

use super::sync::SyncContext;

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
