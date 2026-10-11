use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction_status_client_types::EncodedTransaction;
use zolana_client::{ComputeBudgetConfig, Rpc, SolanaRpc};
use zolana_interface::pda;

use k_lend_rfq_sdk::pair::Pair;

use crate::kvault;

const COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

pub fn blocking<R>(work: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current() {
        Ok(_) => tokio::task::block_in_place(work),
        Err(_) => work(),
    }
}

pub fn send(
    rpc: &SolanaRpc,
    instructions: &[Instruction],
    payer: &dyn Signer,
    signers: &[&dyn Signer],
) -> Result<Signature> {
    Ok(rpc.create_and_send_transaction(
        instructions,
        payer.pubkey(),
        signers,
        ComputeBudgetConfig::new(COMPUTE_UNIT_LIMIT),
    )?)
}

pub fn compute_units(rpc: &SolanaRpc, signature: &Signature) -> Result<u64> {
    let confirmed = rpc.fetch_confirmed_transaction(signature)?;
    let meta = confirmed
        .transaction
        .meta
        .ok_or_else(|| anyhow!("transaction {signature} has no metadata"))?;
    Option::<u64>::from(meta.compute_units_consumed)
        .ok_or_else(|| anyhow!("transaction {signature} reports no compute units"))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Landed {
    pub signatures: usize,
    pub programs: Vec<Address>,
}

pub fn landed(rpc: &SolanaRpc, signature: &Signature) -> Result<Landed> {
    let signatures = match rpc
        .fetch_confirmed_transaction(signature)?
        .transaction
        .transaction
    {
        EncodedTransaction::Json(transaction) => transaction.signatures.len(),
        other => return Err(anyhow!("transaction {signature} came back as {other:?}")),
    };
    let programs = rpc
        .fetch_confirmed_instruction_groups(signature)?
        .groups
        .into_iter()
        .map(|group| group.outer.program_id)
        .collect();
    Ok(Landed {
        signatures,
        programs,
    })
}

pub fn public_balances(rpc: &SolanaRpc, owner: &Address, pair: &Pair) -> Result<Vec<u64>> {
    [pair.token_mint, pair.shares_mint]
        .iter()
        .map(|mint| kvault::token_balance(rpc, &pda::associated_token_address(owner, mint)))
        .collect()
}
