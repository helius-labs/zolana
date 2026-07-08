//! One-call private-transaction submit.
//!
//! Absorbs the fetch → assemble → prove → build → send → wait-for-index plumbing
//! a caller would otherwise hand-roll for a shielded transfer or withdrawal,
//! exposing it as the single [`Submit`] action.
//!
//! A private submit needs two backends, not one: spend proofs come from the
//! Photon indexer ([`ZolanaIndexer`]) and the transaction is sent through a
//! Solana RPC ([`Rpc`]). [`Submit`] takes them separately so the indexer
//! dependency is explicit rather than hidden behind a single "rpc".

use std::{
    thread::sleep,
    time::{Duration, Instant},
};

use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_interface::instruction::{Transact, TransactWithdrawal};
use zolana_transaction::instructions::{transact::SignedTransaction, types::InputCommitment};

use crate::{
    error::ClientError,
    indexer::ZolanaIndexer,
    prover::{
        transact::witness::{assemble, AssembledTransfer, ProverInputs, SpendProof},
        ProofCompressed, ProverClient,
    },
    rpc::Rpc,
};

/// Compute-unit ceiling a private transaction is submitted with unless the
/// caller overrides it. Benchmarked transfers and withdrawals run ~148k-152k CU
/// (`program-tests/shielded-pool/CU_BENCHMARK.md`).
pub const DEFAULT_TRANSACT_CU_LIMIT: u32 = 200_000;

/// How long [`Submit::execute`] waits for the indexer to pick up the sent
/// transaction before giving up.
const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
/// Delay between indexer polls.
const INDEXER_POLL: Duration = Duration::from_millis(500);

/// One-call submit for a signed private transaction.
///
/// Holds the two backends a submit needs plus the fixed parameters: the
/// [`ZolanaIndexer`] answers spend-proof lookups, the [`Rpc`] sends the
/// transaction. [`Submit::execute`] then fetches proofs, proves, sends, and
/// waits for the transaction to be indexed.
///
/// The three per-transaction pieces (`signed`, `withdrawal`, `wait_tag`) are
/// passed to [`Submit::execute`]; a caller holds them on the `CreatedTransfer` /
/// `CreatedWithdrawal` returned by `create_transfer` / `create_withdrawal`.
pub struct Submit<'a, R: Rpc> {
    /// Answers spend-proof lookups (Photon).
    pub indexer: &'a ZolanaIndexer,
    /// Sends the transaction (a Solana RPC).
    pub rpc: &'a R,
    pub prover: &'a ProverClient,
    pub payer: &'a dyn Signer,
    pub tree: Pubkey,
    /// Compute-unit limit; `None` uses [`DEFAULT_TRANSACT_CU_LIMIT`].
    pub cu_limit: Option<u32>,
}

impl<R: Rpc> Submit<'_, R> {
    /// Fetch the input spend proofs for `tree` and assemble the prover witness:
    /// the network-bound, prover-free prefix of [`Submit::execute`].
    fn prepare(&self, signed: SignedTransaction) -> Result<AssembledTransfer, ClientError> {
        let commitments = signed.input_commitments()?;
        let tree = Address::new_from_array(self.tree.to_bytes());
        let spend_proofs = fetch_spend_proofs(self.indexer, tree, &commitments)?;
        assemble(signed, &spend_proofs)
    }

    /// Prove and submit the transaction, then wait for it to be indexed.
    ///
    /// Fetches the input proofs, assembles, proves on the matching rail,
    /// compresses, builds the `Transact` instruction, sends it under a
    /// compute-unit ceiling, and polls the indexer until the transaction is
    /// visible. Returning after indexing means a caller can `sync_wallet`
    /// immediately without racing Photon. `wait_tag` is the transfer's
    /// confidential view tag (on `CreatedTransfer` / `CreatedWithdrawal`).
    pub fn execute(
        self,
        signed: SignedTransaction,
        withdrawal: Option<TransactWithdrawal>,
        wait_tag: [u8; 32],
    ) -> Result<Signature, ClientError> {
        let assembled = self.prepare(signed)?;

        let proof = match &assembled.prover_inputs {
            ProverInputs::P256(inputs) => self.prover.prove_transfer_p256(inputs)?,
            ProverInputs::Eddsa(inputs) => self.prover.prove_transfer(inputs)?,
        };
        let proof = ProofCompressed::try_from(proof)?.to_transact_proof();
        let data = assembled.with_proof(proof);

        let transact_ix = Transact {
            payer: self.payer.pubkey(),
            tree: self.tree,
            withdrawal,
            data,
        }
        .instruction();
        let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(
            self.cu_limit.unwrap_or(DEFAULT_TRANSACT_CU_LIMIT),
        );

        let payer_address = Address::new_from_array(self.payer.pubkey().to_bytes());
        let signature = self.rpc.create_and_send_transaction(
            &[cu_ix, transact_ix],
            payer_address,
            &[self.payer],
        )?;

        wait_for_indexed_transaction(self.indexer, wait_tag, signature)?;
        Ok(signature)
    }
}

/// Resolve the spend proof (state inclusion + nullifier non-inclusion) for each
/// input commitment on `tree`, in commitment order. Batches both indexer lookups
/// so a multi-input spend costs two round trips, not two per input.
fn fetch_spend_proofs(
    indexer: &ZolanaIndexer,
    tree: Address,
    commitments: &[InputCommitment],
) -> Result<Vec<SpendProof>, ClientError> {
    let leaves = commitments
        .iter()
        .map(|commitment| commitment.utxo_hash)
        .collect::<Vec<_>>();
    let nullifiers = commitments
        .iter()
        .map(|commitment| commitment.nullifier)
        .collect::<Vec<_>>();
    let state_proofs = indexer.get_merkle_proofs(tree, leaves)?.proofs;
    let nullifier_proofs = indexer.get_non_inclusion_proofs(tree, nullifiers)?.proofs;
    if state_proofs.len() != commitments.len() || nullifier_proofs.len() != commitments.len() {
        return Err(ClientError::Rpc(
            "indexer returned incomplete input proofs".to_string(),
        ));
    }
    // The merkle / non-inclusion proofs carry the tree root indices the witness
    // build resolves placement against; `SpendProof` wraps them directly.
    Ok(state_proofs
        .into_iter()
        .zip(nullifier_proofs)
        .map(|(state, nullifier)| SpendProof { state, nullifier })
        .collect())
}

/// Poll the indexer until the sent transaction is visible under `tag`, or
/// [`INDEXER_TIMEOUT`] elapses. The indexer lags the chain, so a plain on-chain
/// confirmation is not enough for a caller that reads state back immediately.
fn wait_for_indexed_transaction(
    indexer: &ZolanaIndexer,
    tag: [u8; 32],
    signature: Signature,
) -> Result<(), ClientError> {
    let started = Instant::now();
    loop {
        let response = indexer.get_shielded_transactions_by_tags(vec![tag], None, Some(50))?;
        if response
            .transactions
            .iter()
            .any(|item| item.tx_signature == signature)
        {
            return Ok(());
        }
        if started.elapsed() >= INDEXER_TIMEOUT {
            return Err(ClientError::Rpc(format!(
                "timed out after {INDEXER_TIMEOUT:?} waiting for the indexer to pick up {signature}"
            )));
        }
        sleep(INDEXER_POLL);
    }
}
