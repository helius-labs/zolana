//! Localnet orchestration and proof helpers shared by the Harness. Indexer polling
//! lives in `zolana_test_utils::test_validator_asserts`.

use anyhow::Result;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;
use zolana_client::{ClientError, Proof, ProofCompressed, Rpc, SolanaRpc};
use zolana_interface::instruction::instruction_data::{
    merge_transact::MergeProof, transact::TransactProof,
};
use zolana_test_utils::localnet::start_shielded_pool_localnet;

pub(crate) const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
pub(crate) const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:8784";
pub(crate) const ZERO: [u8; 32] = [0u8; 32];
// Blinding positions in the fixed-position output layout
// `[spl_change, sol_change, recipients...]`.
pub(crate) const SPL_CHANGE_POSITION: u8 = 0;
pub(crate) const SOL_CHANGE_POSITION: u8 = 1;
pub(crate) const RECIPIENT_POSITION_BASE: u8 = 2;

/// The P256-rail merge proof (always BSB22-committed), via the shared
/// `ProofCompressed::to_merge_proof` conversion.
pub(crate) fn pack_proof(proof: &Proof) -> Result<MergeProof> {
    Ok(ProofCompressed::try_from(*proof)?.to_merge_proof()?)
}

/// Build the compressed proof carried by a `transact` instruction.
pub(crate) fn transact_proof(proof: &Proof) -> Result<TransactProof> {
    Ok(ProofCompressed::try_from(*proof)?.to_transact_proof())
}

/// Restart a fresh validator + Photon via the `zolana` CLI (the single source of
/// truth for localnet orchestration and readiness). `--skip-prover` leaves the
/// persistent prover server untouched so its proving keys stay loaded.
pub(crate) fn restart_localnet() {
    start_shielded_pool_localnet("zolana-spp", &[]);
}

pub(crate) fn send_transaction(
    rpc: &mut SolanaRpc,
    ixs: &[Instruction],
    payer: &Pubkey,
    signers: &[&Keypair],
) -> std::result::Result<Signature, ClientError> {
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = Message::new(ixs, Some(payer));
    let transaction = Transaction::new(signers, message, blockhash);
    rpc.send_transaction(&transaction)
}
