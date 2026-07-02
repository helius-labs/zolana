//! One-call private-transaction submit.
//!
//! Absorbs the fetch → assemble → prove → build → send plumbing a caller would
//! otherwise hand-roll for a shielded transfer or withdrawal, exposing it as the
//! single [`Submit`] action.

use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_interface::instruction::{Transact, TransactWithdrawal};
use zolana_transaction::instructions::transact::SignedTransaction;

use crate::{
    error::ClientError,
    prover::{
        transact::witness::{assemble, AssembledTransfer, ProverInputs},
        ProofCompressed, ProverClient,
    },
    rpc::Rpc,
};

/// Compute-unit ceiling a private transaction is submitted with unless the
/// caller overrides it. A shielded `Transact` verifies a Groth16 proof on-chain,
/// which does not fit inside the default per-instruction budget.
pub const DEFAULT_TRANSACT_CU_LIMIT: u32 = 1_400_000;

/// A signed private transaction ready to prove and submit.
///
/// Mirrors the `create_*` → send split: hold the [`SignedTransaction`] (from
/// `create_transfer_sync` / `create_withdrawal_sync` or a hand-built `Transaction`),
/// then [`Submit::execute`] fetches the input proofs, proves, and sends in one call.
///
/// `execute` returns once the transaction is confirmed; it does **not** wait for
/// the indexer to catch up. Reading the result back (e.g. `sync_wallet`) is the
/// caller's next step, and — because the wallet sync races the indexer — a caller
/// that immediately reads should first wait for the transaction to be indexed
/// (see the deposit examples' `wait_for_indexed_transaction`).
pub struct Submit {
    pub signed: SignedTransaction,
    /// `None` for a shielded-to-shielded transfer; `Some(..)` when the transaction
    /// settles publicly (a withdrawal or a public-withdrawal transfer fallback).
    pub withdrawal: Option<TransactWithdrawal>,
    /// Compute-unit limit; `None` uses [`DEFAULT_TRANSACT_CU_LIMIT`].
    pub cu_limit: Option<u32>,
}

impl Submit {
    /// A submit for a shielded-to-shielded transfer (no public settlement, default
    /// compute-unit limit). Set [`Submit::withdrawal`] / [`Submit::cu_limit`]
    /// afterwards for a withdrawal or a custom budget.
    pub fn new(signed: SignedTransaction) -> Self {
        Self {
            signed,
            withdrawal: None,
            cu_limit: None,
        }
    }

    /// Fetch the input spend proofs for `tree` and assemble the prover witness.
    ///
    /// This is the network-bound-but-prover-free prefix of [`Submit::execute`],
    /// split out so it is testable without a running prover server.
    pub(crate) fn prepare<R: Rpc>(
        &self,
        rpc: &R,
        tree: Pubkey,
    ) -> Result<AssembledTransfer, ClientError> {
        let commitments = self.signed.input_commitments()?;
        let tree_address = Address::new_from_array(tree.to_bytes());
        let spend_proofs = rpc.get_spend_proofs(tree_address, &commitments)?;
        assemble(self.signed.clone(), &spend_proofs)
    }

    /// Prove and submit the transaction: fetch proofs, assemble, prove on the
    /// matching rail, compress, build the `Transact` instruction, and send it
    /// under a compute-unit ceiling. Returns the confirmed transaction signature.
    pub fn execute<R: Rpc>(
        self,
        rpc: &R,
        prover: &ProverClient,
        payer: &Keypair,
        tree: Pubkey,
    ) -> Result<Signature, ClientError> {
        let assembled = self.prepare(rpc, tree)?;

        let proof = match &assembled.prover_inputs {
            ProverInputs::P256(inputs) => prover.prove_transfer_p256(inputs)?,
            ProverInputs::Eddsa(inputs) => prover.prove_transfer(inputs)?,
        };
        let proof = ProofCompressed::try_from(proof)?.to_transact_proof();
        let data = assembled.with_proof(proof);

        let transact_ix = Transact {
            payer: payer.pubkey(),
            tree,
            withdrawal: self.withdrawal,
            data,
        }
        .instruction();
        let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(
            self.cu_limit.unwrap_or(DEFAULT_TRANSACT_CU_LIMIT),
        );

        let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
        rpc.create_and_send_transaction(&[cu_ix, transact_ix], payer_address, &[payer])
    }
}
