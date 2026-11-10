use std::{
    cmp::Reverse,
    collections::HashSet,
    thread::sleep,
    time::{Duration, Instant},
};

use solana_commitment_config::CommitmentConfig;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{
    prover::tee::SignedTeePolicy, sign_transaction, ClientError,
    GetShieldedTransactionsBySignatureResponse, IndexerPollConfig, IndexerRpcConfig, ProverClient,
    Rpc, RpcSendTransactionConfig, SignedPrivateTransaction, SolanaRpc, SprClient, SprIndexer,
    Submission, UtxoScan,
};
use spr_keypair::{shielded::ShieldedAddress, KeypairError, ShieldedKeypair};
use spr_transaction::{
    decrypt_spendable, instructions::transact::ConfidentialTransaction, select_spend, Address,
    AssetRegistry, TransactionError, WalletUtxo, SOL_MINT,
};

use crate::{
    classify::{classify, names_insufficient_funds, ErrorClass, Phase},
    config::Config,
    metrics::{Record, Timings},
    redact::Redactor,
};

/// Below this the payer cannot cover many more transfer fees.
pub const MIN_PAYER_LAMPORTS: u64 = 100_000;
/// Consecutive failures after which the in-memory notes are no longer trusted.
const RESYNC_AFTER_FAILURES: u32 = 3;
const POLL: Duration = Duration::from_millis(500);

/// A sent transaction whose outcome is not known yet.
struct Pending {
    signature: Signature,
    last_valid_block_height: u64,
    inputs: Vec<WalletUtxo>,
}

struct Failure {
    class: ErrorClass,
    message: String,
}

impl Failure {
    fn new(class: ErrorClass, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
        }
    }

    fn client(phase: Phase, error: ClientError) -> Self {
        Self::new(classify(phase, &error), error.to_string())
    }
}

/// What one attempt produced.
pub struct Outcome {
    pub record: Record,
    pub detail: String,
}

/// One wallet sending itself a private transfer per attempt, holding its notes in memory between attempts.
pub struct Canary {
    client: SprClient<SolanaRpc>,
    funding: Keypair,
    keys: ShieldedKeypair,
    address: ShieldedAddress,
    amount: u64,
    timeout: Duration,
    redactor: Redactor,
    notes: Option<Vec<WalletUtxo>>,
    pending: Option<Pending>,
    consecutive_failures: u32,
}

impl Canary {
    pub fn new(config: &Config) -> Result<Self, KeypairError> {
        let funding = config.keypair.insecure_clone();
        // The canonical wallet derivation, as the CLI does it for `wallet new --funding-keypair`.
        let keys = ShieldedKeypair::from_keypair(&funding)?;
        let address = keys.shielded_address()?;
        let gateway = config.gateway_url();
        let prover = ProverClient::new(gateway.clone())
            .with_signed_tee(SignedTeePolicy::for_network(config.tee_network))
            .with_proof_timeout(config.timeout);
        let client = SprClient::new(
            SolanaRpc::new(config.rpc_url.clone()),
            SprIndexer::new(&gateway),
            prover,
        );
        Ok(Self {
            client,
            funding,
            keys,
            address,
            amount: config.amount,
            timeout: config.timeout,
            redactor: Redactor::new(config.secrets()),
            notes: None,
            pending: None,
            consecutive_failures: 0,
        })
    }

    pub fn wallet(&self) -> String {
        self.funding.pubkey().to_string()
    }

    /// Run one attempt; never panics on a service failure and never leaves a secret in its output.
    pub fn attempt(&mut self, timestamp_ms: u64) -> Outcome {
        let started = Instant::now();
        let mut timings = Timings::default();
        let mut signature = None;
        let result = self.run(&mut timings, &mut signature);
        let total_ms = millis(started.elapsed());
        let (error_class, detail) = match result {
            Ok(detail) => {
                self.consecutive_failures = 0;
                (None, detail)
            }
            Err(failure) => {
                self.consecutive_failures += 1;
                if self.consecutive_failures >= RESYNC_AFTER_FAILURES {
                    self.notes = None;
                }
                (Some(failure.class), failure.message)
            }
        };
        Outcome {
            record: Record {
                timestamp_ms,
                total_ms,
                timings,
                error_class,
                signature: signature.map(|signature: Signature| signature.to_string()),
            },
            detail: self.redactor.apply(&detail),
        }
    }

    fn run(
        &mut self,
        timings: &mut Timings,
        signature: &mut Option<Signature>,
    ) -> Result<String, Failure> {
        self.resolve_pending()?;
        if self.notes.is_none() {
            let mark = Instant::now();
            self.notes = Some(self.full_sync()?);
            timings.sync_ms = Some(millis(mark.elapsed()));
        }
        let payer = Address::new_from_array(self.funding.pubkey().to_bytes());
        let balance = self
            .client
            .rpc()
            .get_balance(payer)
            .map_err(|error| Failure::client(Phase::Send, error))?;
        if balance < MIN_PAYER_LAMPORTS {
            return Err(Failure::new(
                ErrorClass::InsufficientBalance,
                format!("payer holds {balance} lamports, below {MIN_PAYER_LAMPORTS}"),
            ));
        }
        let inputs = select_inputs(self.notes.as_deref().unwrap_or_default(), self.amount)
            .map_err(|error| Failure::client(Phase::Prove, error.into()))?;

        let transfer_started = Instant::now();
        let deadline = transfer_started + self.timeout;
        let (transaction, last_valid_block_height) = self
            .prove(inputs.clone(), payer)
            .map_err(|error| Failure::client(Phase::Prove, error))?;
        timings.prove_ms = Some(millis(transfer_started.elapsed()));

        let sent = *transaction.signatures.first().ok_or_else(|| {
            Failure::new(ErrorClass::Prover, "signed transaction has no signature")
        })?;
        *signature = Some(sent);
        self.pending = Some(Pending {
            signature: sent,
            last_valid_block_height,
            inputs,
        });
        let mark = Instant::now();
        self.client
            .rpc()
            .send_transaction_with_config(
                &transaction,
                RpcSendTransactionConfig {
                    skip_preflight: true,
                    ..RpcSendTransactionConfig::default()
                },
            )
            .map_err(|error| Failure::client(Phase::Send, error))?;
        timings.send_ms = Some(millis(mark.elapsed()));

        let mark = Instant::now();
        self.wait_confirmed(sent, deadline)?;
        let chain_ms = millis(mark.elapsed());
        let indexed = self.wait_indexed(sent, deadline)?;
        timings.confirm_ms = Some(millis(mark.elapsed()));
        let notes = self.adopt(indexed)?;
        Ok(format!(
            "chain={chain_ms}ms index={}ms notes={notes}",
            timings.confirm_ms.unwrap_or_default() - chain_ms
        ))
    }

    /// The wallet's spendable SOL notes, read from an indexer caught up with the RPC.
    fn full_sync(&self) -> Result<Vec<WalletUtxo>, Failure> {
        let slot = self
            .client
            .rpc()
            .get_slot()
            .map_err(|error| Failure::client(Phase::Sync, error))?;
        let retries = (self.timeout.as_millis() / POLL.as_millis()) as u32;
        let delay = POLL.as_millis() as u64;
        let assets = AssetRegistry::default();
        let scan = UtxoScan::new(&self.keys, &assets)
            .with_indexer_config(IndexerRpcConfig {
                poll: IndexerPollConfig::new(retries, delay, delay),
                require_slot: Some(slot),
            })
            .fetch(self.client.indexer())
            .map_err(|error| Failure::client(Phase::Sync, error))?;
        Ok(scan
            .spendable
            .utxos()
            .filter(|note| is_candidate(note))
            .cloned()
            .collect())
    }

    /// Prove and sign a self-transfer of the configured amount from `inputs`.
    fn prove(
        &self,
        inputs: Vec<WalletUtxo>,
        payer: Address,
    ) -> Result<(solana_transaction::versioned::VersionedTransaction, u64), ClientError> {
        let mut transaction = ConfidentialTransaction::new(inputs, payer)?;
        transaction.transfer_sol(&self.address, self.amount)?;
        let signed = SignedPrivateTransaction {
            transaction: transaction.encrypt(&self.keys)?,
            settlement_transfers: Vec::new(),
        };
        let unsigned = Submission::new(&signed, self.funding.pubkey(), &self.keys)
            .finish_unsigned_sync(&self.client)?;
        let transaction = sign_transaction(unsigned.message, &[&self.funding])?;
        Ok((transaction, unsigned.last_valid_block_height))
    }

    /// Poll the chain until `signature` is confirmed, failed, or `deadline` passes.
    fn wait_confirmed(&mut self, signature: Signature, deadline: Instant) -> Result<(), Failure> {
        loop {
            let last_error = match self.chain_status(signature) {
                Ok(ChainStatus::Confirmed) => return Ok(()),
                Ok(ChainStatus::Failed(error)) => {
                    self.forget_state();
                    let class = if names_insufficient_funds(&error) {
                        ErrorClass::InsufficientBalance
                    } else {
                        ErrorClass::Rpc
                    };
                    return Err(Failure::new(
                        class,
                        format!("transaction failed on chain: {error}"),
                    ));
                }
                Ok(ChainStatus::Unknown) => None,
                Err(error) => Some(error),
            };
            if Instant::now() >= deadline {
                return Err(match last_error {
                    Some(error) => Failure::client(Phase::Send, error),
                    None => Failure::new(
                        ErrorClass::ConfirmTimeout,
                        format!("not confirmed within {}s", self.timeout.as_secs()),
                    ),
                });
            }
            sleep(POLL);
        }
    }

    /// Poll the indexer through the gatekeeper until it returns `signature`, or `deadline` passes.
    fn wait_indexed(
        &self,
        signature: Signature,
        deadline: Instant,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, Failure> {
        loop {
            let last_error = match self
                .client
                .indexer()
                .get_shielded_transactions_by_signature(signature, None)
            {
                Ok(response) if !response.transactions.is_empty() => return Ok(response),
                Ok(_) => None,
                Err(error) => Some(error),
            };
            if Instant::now() >= deadline {
                return Err(match last_error {
                    Some(error) => Failure::client(Phase::Sync, error),
                    None => Failure::new(
                        ErrorClass::ConfirmTimeout,
                        format!(
                            "confirmed but not indexed within {}s",
                            self.timeout.as_secs()
                        ),
                    ),
                });
            }
            sleep(POLL);
        }
    }

    /// Replace the pending transaction's inputs with the outputs the indexer returned; returns the note count.
    fn adopt(
        &mut self,
        indexed: GetShieldedTransactionsBySignatureResponse,
    ) -> Result<usize, Failure> {
        let Some(pending) = self.pending.take() else {
            return Ok(self.notes.as_ref().map_or(0, Vec::len));
        };
        let transactions: Vec<_> = indexed
            .transactions
            .into_iter()
            .map(|indexed| indexed.transaction)
            .collect();
        let outputs = decrypt_spendable(&self.keys, &transactions, &AssetRegistry::default())
            .map(|spendable| spendable.with_latest_tree_id(indexed.output_tree_id))
            .and_then(|spendable| spendable.with_transaction_keys(&self.keys))
            .map_err(|error| {
                self.notes = None;
                Failure::client(Phase::Sync, error.into())
            })?;
        let outputs: Vec<WalletUtxo> = outputs
            .utxos()
            .filter(|note| is_candidate(note))
            .cloned()
            .collect();
        let spent: u64 = pending.inputs.iter().map(|note| note.utxo.amount).sum();
        let created: u64 = outputs.iter().map(|note| note.utxo.amount).sum();
        if outputs.is_empty() || created != spent {
            self.notes = None;
            return Err(Failure::new(
                ErrorClass::Indexer,
                format!("indexed outputs hold {created} lamports for inputs of {spent}"),
            ));
        }
        let spent: HashSet<[u8; 32]> = pending.inputs.iter().map(|note| note.nullifier).collect();
        // With no notes in memory a full sync follows, which reads these outputs itself.
        let Some(notes) = self.notes.as_mut() else {
            return Ok(0);
        };
        notes.retain(|note| !spent.contains(&note.nullifier));
        notes.extend(outputs);
        Ok(notes.len())
    }

    /// Settle a transaction a previous attempt sent but could not confirm.
    fn resolve_pending(&mut self) -> Result<(), Failure> {
        let Some(pending) = &self.pending else {
            return Ok(());
        };
        let (signature, last_valid) = (pending.signature, pending.last_valid_block_height);
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.chain_status(signature) {
                Ok(ChainStatus::Confirmed) => {
                    match self.wait_indexed(signature, deadline) {
                        Ok(indexed) => {
                            self.adopt(indexed)?;
                        }
                        Err(_) => self.forget_state(),
                    }
                    return Ok(());
                }
                Ok(ChainStatus::Failed(_)) => {
                    self.forget_state();
                    return Ok(());
                }
                Ok(ChainStatus::Unknown) => {
                    let expired = self
                        .client
                        .rpc()
                        .get_block_height()
                        .is_ok_and(|height| height > last_valid);
                    if expired {
                        // Never landed: the inputs are unspent unless the indexer says otherwise.
                        match self
                            .client
                            .indexer()
                            .get_shielded_transactions_by_signature(signature, None)
                        {
                            Ok(indexed) if !indexed.transactions.is_empty() => {
                                self.adopt(indexed)?;
                            }
                            Ok(_) => self.pending = None,
                            Err(_) => self.forget_state(),
                        }
                        return Ok(());
                    }
                }
                Err(_) => {}
            }
            if Instant::now() >= deadline {
                return Err(Failure::new(
                    ErrorClass::ConfirmTimeout,
                    format!("previous transaction {signature} is still unresolved"),
                ));
            }
            sleep(POLL);
        }
    }

    /// The chain's view of `signature`, searching history so an old landing is not mistaken for a drop.
    fn chain_status(&self, signature: Signature) -> Result<ChainStatus, ClientError> {
        let statuses = self
            .client
            .rpc()
            .client()
            .get_signature_statuses_with_history(&[signature])
            .map_err(|error| ClientError::Rpc(format!("get_signature_statuses: {error}")))?;
        Ok(match statuses.value.into_iter().next().flatten() {
            Some(status) if status.err.is_some() => ChainStatus::Failed(
                status
                    .err
                    .map(|error| error.to_string())
                    .unwrap_or_default(),
            ),
            Some(status) if status.satisfies_commitment(CommitmentConfig::confirmed()) => {
                ChainStatus::Confirmed
            }
            _ => ChainStatus::Unknown,
        })
    }

    /// Drop everything held in memory so the next attempt starts from a full sync.
    fn forget_state(&mut self) {
        self.notes = None;
        self.pending = None;
    }
}

enum ChainStatus {
    Confirmed,
    Failed(String),
    Unknown,
}

fn is_candidate(note: &WalletUtxo) -> bool {
    note.utxo.asset.asset == SOL_MINT && note.utxo.amount > 0 && note.is_plain()
}

/// The largest note that covers `amount`, plus the smallest other note so dust folds back in and the note count stays flat.
pub fn select_inputs(
    notes: &[WalletUtxo],
    amount: u64,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    let mut candidates: Vec<&WalletUtxo> = notes.iter().filter(|note| is_candidate(note)).collect();
    candidates.sort_by_key(|note| Reverse(note.utxo.amount));
    match candidates.as_slice() {
        [largest, .., smallest] if largest.utxo.amount >= amount => {
            Ok(vec![(*largest).clone(), (*smallest).clone()])
        }
        [only] if only.utxo.amount >= amount => Ok(vec![(*only).clone()]),
        _ => select_spend(candidates, SOL_MINT, amount),
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(amount: u64, tag: u8) -> WalletUtxo {
        let mut note = WalletUtxo::dummy(0).unwrap();
        note.utxo.amount = amount;
        note.nullifier = [tag; 32];
        note
    }

    fn amounts(notes: &[WalletUtxo]) -> Vec<u64> {
        notes.iter().map(|note| note.utxo.amount).collect()
    }

    #[test]
    fn steady_state_spends_both_notes() {
        let notes = [note(1_000, 1), note(5_000_000, 2)];
        assert_eq!(
            amounts(&select_inputs(&notes, 1_000).unwrap()),
            [5_000_000, 1_000]
        );
    }

    #[test]
    fn extra_notes_fold_in_smallest_first() {
        let notes = [note(300, 1), note(9_000, 2), note(1_000, 3), note(0, 4)];
        assert_eq!(
            amounts(&select_inputs(&notes, 1_000).unwrap()),
            [9_000, 300]
        );
    }

    #[test]
    fn a_single_note_is_spent_alone() {
        assert_eq!(
            amounts(&select_inputs(&[note(2_000, 1)], 1_000).unwrap()),
            [2_000]
        );
    }

    #[test]
    fn small_notes_combine_when_none_covers_the_amount() {
        let notes = [note(600, 1), note(700, 2)];
        assert_eq!(amounts(&select_inputs(&notes, 1_000).unwrap()), [700, 600]);
    }

    #[test]
    fn a_short_wallet_is_insufficient() {
        let error = select_inputs(&[note(10, 1)], 1_000).unwrap_err();
        assert_eq!(
            classify(Phase::Prove, &error.into()),
            ErrorClass::InsufficientBalance
        );
        let error = select_inputs(&[], 1_000).unwrap_err();
        assert_eq!(
            classify(Phase::Prove, &error.into()),
            ErrorClass::InsufficientBalance
        );
    }
}
