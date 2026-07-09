//! One-call private-transaction submit.
//!
//! Absorbs the fetch → assemble → prove → build → send → wait-for-index plumbing
//! a caller would otherwise hand-roll for a shielded transfer or withdrawal,
//! exposing it as the single [`Submit`] action.
//!
//! A private submit needs two backends, not one: spend proofs come from the
//! Photon indexer and the transaction is sent through a Solana RPC. [`Submit`]
//! takes them as two [`Rpc`] values so the indexer dependency is explicit
//! rather than hidden behind a single "rpc"; a combined backend (such as
//! `ZolanaClient`) can fill both fields.

use std::{
    thread::sleep,
    time::{Duration, Instant},
};

use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_interface::instruction::{
    instruction_data::transact::TransactIxData, Transact, TransactWithdrawal,
};
use zolana_transaction::instructions::{transact::SignedTransaction, types::InputCommitment};

use crate::{
    actions::transaction::{CreatedTransfer, CreatedWithdrawal},
    error::ClientError,
    prover::{
        transact::witness::{assemble, AssembledTransfer, ProverInputs, SpendProof},
        ProofCompressed, ProverClient,
    },
    rpc::Rpc,
};

/// Compute-unit ceiling a private transaction is submitted with unless the
/// caller overrides it. The mollusk benchmark reports ~148k-152k CU
/// (`program-tests/shielded-pool/CU_BENCHMARK.md`), but live localnet
/// transfers and withdrawals consume ~290k-296k; 600k leaves headroom.
pub const DEFAULT_TRANSACT_CU_LIMIT: u32 = 600_000;

/// How long [`Submit::execute`] waits for the indexer to pick up the sent
/// transaction before giving up.
const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
/// Delay between indexer polls.
const INDEXER_POLL: Duration = Duration::from_millis(500);

/// One-call submit for a signed private transaction.
///
/// Holds the two backends a submit needs plus the fixed parameters: `indexer`
/// answers spend-proof lookups (Photon), `rpc` sends the transaction (a Solana
/// RPC). [`Submit::execute`] then fetches proofs, proves, sends, and waits for
/// the transaction to be indexed.
///
/// [`Submit::execute`] takes the created transaction directly: any
/// [`Sendable`], which [`CreatedTransfer`] and [`CreatedWithdrawal`] implement.
pub struct Submit<'a, R: Rpc, I: Rpc> {
    /// Answers spend-proof lookups (Photon).
    pub indexer: &'a I,
    /// Sends the transaction (a Solana RPC).
    pub rpc: &'a R,
    pub prover: &'a ProverClient,
    pub payer: &'a dyn Signer,
    pub tree: Pubkey,
    /// Compute-unit limit; `None` uses [`DEFAULT_TRANSACT_CU_LIMIT`].
    pub cu_limit: Option<u32>,
}

impl<R: Rpc, I: Rpc> Submit<'_, R, I> {
    /// Fetch the input spend proofs for `tree` and assemble the prover witness:
    /// the network-bound, prover-free prefix of [`Submit::execute`].
    fn prepare(&self, signed: SignedTransaction) -> Result<AssembledTransfer, ClientError> {
        let commitments = signed.input_commitments()?;
        let tree = Address::new_from_array(self.tree.to_bytes());
        let spend_proofs = fetch_spend_proofs(self.indexer, tree, &commitments)?;
        assemble(signed, &spend_proofs)
    }

    /// Prove and submit the created transaction, then wait for it to be
    /// indexed.
    ///
    /// Fetches the input proofs, assembles, proves on the matching rail,
    /// compresses, builds the `Transact` instruction, sends it under a
    /// compute-unit ceiling, and polls the indexer until the transaction is
    /// visible. Returning after indexing means a caller can `sync_wallet`
    /// immediately without racing Photon.
    pub fn execute<T: Sendable>(self, tx: &T) -> Result<Signature, ClientError> {
        self.execute_inner(tx, &[])
    }

    /// [`Submit::execute`] with extra instructions spliced into the same
    /// transaction, atomically: all land or none do. The extras run after the
    /// `Transact` instruction, and the payer signs everything — spend
    /// authorization travels inside the proof, so no other signature is
    /// needed.
    ///
    /// Two shared budgets to keep in mind: the extras count against the same
    /// compute-unit ceiling (override `cu_limit` if they are heavy), and the
    /// `Transact` instruction is large, so the 1232-byte transaction packet
    /// leaves limited room for extras.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use solana_compute_budget_interface::ComputeBudgetInstruction;
    /// use solana_signature::Signature;
    /// use zolana_client::{ClientError, CreatedTransfer, Rpc, Submit};
    ///
    /// fn send_with_priority_fee<R: Rpc, I: Rpc>(
    ///     submit: Submit<'_, R, I>, // e.g. rpc.send(&payer) on ZolanaClient
    ///     transfer: &CreatedTransfer,
    /// ) -> Result<Signature, ClientError> {
    ///     // A public instruction settled atomically with the private
    ///     // transfer: here, a priority fee.
    ///     let priority_fee_ix = ComputeBudgetInstruction::set_compute_unit_price(10_000);
    ///     submit.execute_with(transfer, &[priority_fee_ix])
    /// }
    /// ```
    pub fn execute_with<T: Sendable>(
        self,
        tx: &T,
        instructions: &[Instruction],
    ) -> Result<Signature, ClientError> {
        self.execute_inner(tx, instructions)
    }

    fn execute_inner<T: Sendable>(
        self,
        tx: &T,
        extra_instructions: &[Instruction],
    ) -> Result<Signature, ClientError> {
        let signed = tx.signed().clone();
        let withdrawal = tx.withdrawal().cloned();
        let wait_tag = tx.wait_tag();
        let assembled = self.prepare(signed)?;
        let data = prove_assembled(self.prover, assembled)?.data;

        let transact_ix = Transact {
            payer: self.payer.pubkey(),
            tree: self.tree,
            withdrawal,
            data,
        }
        .instruction();
        let instructions = build_instructions(self.cu_limit, transact_ix, extra_instructions);

        let payer_address = Address::new_from_array(self.payer.pubkey().to_bytes());
        let signature =
            self.rpc
                .create_and_send_transaction(&instructions, payer_address, &[self.payer])?;

        wait_for_indexed_transaction(self.indexer, wait_tag, signature)?;
        Ok(signature)
    }
}

/// Assemble the instruction list a submit sends: the compute-budget ceiling,
/// the `Transact` instruction, then any caller extras in order.
fn build_instructions(
    cu_limit: Option<u32>,
    transact_ix: Instruction,
    extras: &[Instruction],
) -> Vec<Instruction> {
    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(
        cu_limit.unwrap_or(DEFAULT_TRANSACT_CU_LIMIT),
    );
    let mut instructions = vec![cu_ix, transact_ix];
    instructions.extend_from_slice(extras);
    instructions
}

/// A created private transaction [`Submit::execute`] can prove and send: the
/// signed payload, its optional public-withdrawal routing, and the view tag
/// to wait for in the indexer. Implemented by [`CreatedTransfer`] and
/// [`CreatedWithdrawal`].
pub trait Sendable {
    fn signed(&self) -> &SignedTransaction;
    fn withdrawal(&self) -> Option<&TransactWithdrawal>;
    fn wait_tag(&self) -> [u8; 32];
}

impl Sendable for CreatedTransfer {
    fn signed(&self) -> &SignedTransaction {
        &self.signed
    }

    fn withdrawal(&self) -> Option<&TransactWithdrawal> {
        self.withdrawal.as_ref()
    }

    fn wait_tag(&self) -> [u8; 32] {
        self.wait_tag
    }
}

impl Sendable for CreatedWithdrawal {
    fn signed(&self) -> &SignedTransaction {
        &self.signed
    }

    fn withdrawal(&self) -> Option<&TransactWithdrawal> {
        Some(&self.withdrawal)
    }

    fn wait_tag(&self) -> [u8; 32] {
        self.wait_tag
    }
}

/// A proven transaction: the ready-to-send `Transact` instruction data plus the
/// pieces a caller reporting a bare proof needs (compressed proof, public input
/// hash, circuit id).
pub(crate) struct ProvenTransact {
    pub data: TransactIxData,
    pub proof: ProofCompressed,
    pub public_input_hash: [u8; 32],
    pub circuit_id: u16,
}

/// Prove an assembled witness on the matching rail and compress the proof:
/// the prover-bound suffix shared by [`Submit::execute`] and the client-side
/// [`Rpc::prove`] implementation.
pub(crate) fn prove_assembled(
    prover: &ProverClient,
    assembled: AssembledTransfer,
) -> Result<ProvenTransact, ClientError> {
    // circuit_id has no formal registry yet: 1 = P256 rail, 0 = eddsa rail.
    let (proof, circuit_id) = match &assembled.prover_inputs {
        ProverInputs::P256(inputs) => (prover.prove_transfer_p256(inputs)?, 1),
        ProverInputs::Eddsa(inputs) => (prover.prove_transfer(inputs)?, 0),
    };
    let proof = ProofCompressed::try_from(proof)?;
    let public_input_hash = assembled.public_input_hash;
    let data = assembled.with_proof(proof.to_transact_proof());
    Ok(ProvenTransact {
        data,
        proof,
        public_input_hash,
        circuit_id,
    })
}

/// Assemble the witness from the fetched spend proofs, then prove and compress:
/// the full proving pipeline minus the proof fetch.
pub(crate) fn prove_transact(
    prover: &ProverClient,
    signed: SignedTransaction,
    spend_proofs: &[SpendProof],
) -> Result<ProvenTransact, ClientError> {
    prove_assembled(prover, assemble(signed, spend_proofs)?)
}

/// Resolve the spend proof (state inclusion + nullifier non-inclusion) for each
/// input commitment on `tree`, in commitment order. Batches both indexer lookups
/// so a multi-input spend costs two round trips, not two per input.
pub(crate) fn fetch_spend_proofs(
    indexer: &impl Rpc,
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
    indexer: &impl Rpc,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_ix(marker: u8) -> Instruction {
        Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![],
            data: vec![marker],
        }
    }

    #[test]
    fn execute_orders_cu_transact_then_extras() {
        let transact_ix = dummy_ix(1);
        let extras = [dummy_ix(2), dummy_ix(3)];

        let instructions = build_instructions(None, transact_ix.clone(), &extras);

        let cu_expected =
            ComputeBudgetInstruction::set_compute_unit_limit(DEFAULT_TRANSACT_CU_LIMIT);
        assert_eq!(instructions.len(), 4);
        assert_eq!(instructions[0].data, cu_expected.data);
        assert_eq!(instructions[1], transact_ix);
        assert_eq!(instructions[2..], extras);
    }

    #[test]
    fn execute_without_extras_keeps_the_two_instruction_shape() {
        let transact_ix = dummy_ix(1);

        let instructions = build_instructions(Some(700_000), transact_ix.clone(), &[]);

        let cu_expected = ComputeBudgetInstruction::set_compute_unit_limit(700_000);
        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0].data, cu_expected.data);
        assert_eq!(instructions[1], transact_ix);
    }
}
