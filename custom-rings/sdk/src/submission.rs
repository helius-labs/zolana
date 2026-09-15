use solana_instruction_error::InstructionError;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;
use solana_transaction_status_client_types::TransactionConfirmationStatus;
use thiserror::Error;
use zolana_client::{
    compile_message, sign_transaction, ClientError, ComputeBudgetConfig, ProverClient, Rpc,
    SolanaRpc,
};

use crate::{
    budget::TRANSACT_COMPUTE_UNIT_LIMIT, instructions::transact::ProvedWindow, CustomRingTransfer,
    TransferError, TransferProofEnvironment,
};

const MAX_ATTEMPTS: u8 = 3;
const STALE_HEAD_ROOT: u32 = 8166;
const POLICY_PROOF_FAILED: u32 = 8101;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmissionStatus {
    Confirmed {
        signature: Signature,
        slot: u64,
    },
    Failed {
        signature: Signature,
        error: TransactionError,
    },
    Pending {
        signature: Signature,
    },
}

#[derive(Debug, Error)]
pub enum SubmissionError {
    #[error(transparent)]
    Prove(#[from] TransferError),
    #[error(transparent)]
    Client(#[from] ClientError),
}

pub struct SubmissionEnvironment<'a, I: Rpc> {
    pub indexer: &'a I,
    pub rpc: &'a SolanaRpc,
    pub prover: &'a ProverClient,
    pub payer: &'a dyn Signer,
    pub signers: &'a [&'a dyn Signer],
}

struct Attempt {
    transaction: VersionedTransaction,
    window: Option<ProvedWindow>,
    last_valid_block_height: u64,
}

#[derive(Clone, Copy)]
struct Broadcast {
    signature: Signature,
    window: Option<ProvedWindow>,
    last_valid_block_height: u64,
}

impl Attempt {
    fn broadcast(&self) -> Broadcast {
        Broadcast {
            signature: self.transaction.signatures[0],
            window: self.window,
            last_valid_block_height: self.last_valid_block_height,
        }
    }
}

enum Outcome {
    Unknown,
    Confirmed { slot: u64 },
    Failed(TransactionError),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WindowState {
    Same,
    Advanced,
}

#[must_use]
pub struct RingTransferSubmission<'a> {
    transfer: CustomRingTransfer<'a>,
    pending: Option<Attempt>,
    attempts: u8,
    terminal: Option<SubmissionStatus>,
}

impl<'a> RingTransferSubmission<'a> {
    pub fn new(transfer: CustomRingTransfer<'a>) -> Self {
        Self {
            transfer,
            pending: None,
            attempts: 0,
            terminal: None,
        }
    }

    pub fn pending_transaction(&self) -> Option<&VersionedTransaction> {
        self.pending.as_ref().map(|attempt| &attempt.transaction)
    }

    pub fn attempts(&self) -> u8 {
        self.attempts
    }

    /// The caller keeps the input notes reserved until a terminal result.
    pub fn send<I: Rpc>(
        &mut self,
        env: SubmissionEnvironment<'_, I>,
    ) -> Result<SubmissionStatus, SubmissionError> {
        if let Some(terminal) = &self.terminal {
            return Ok(terminal.clone());
        }
        loop {
            let mut failure = None;
            let broadcast = match &self.pending {
                Some(attempt) => attempt.broadcast(),
                None => {
                    let attempt = self.attempt(&env)?;
                    self.attempts += 1;
                    if let Err(error) = env.rpc.client().send_transaction(&attempt.transaction) {
                        // A transport error says nothing about whether the node accepted the bytes.
                        failure = error.get_transaction_error();
                    }
                    self.pending.insert(attempt).broadcast()
                }
            };
            let signature = broadcast.signature;
            let error = match failure {
                Some(error) => error,
                None => match outcome(env.rpc, broadcast)? {
                    Outcome::Unknown => return Ok(SubmissionStatus::Pending { signature }),
                    Outcome::Confirmed { slot } => {
                        let terminal = SubmissionStatus::Confirmed { signature, slot };
                        self.pending = None;
                        self.terminal = Some(terminal.clone());
                        return Ok(terminal);
                    }
                    Outcome::Failed(error) => error,
                },
            };
            let window = match broadcast.window {
                Some(window) if ring_error(&error) == Some(POLICY_PROOF_FAILED) => {
                    if env.rpc.get_slot()? / window.slots == window.index {
                        WindowState::Same
                    } else {
                        WindowState::Advanced
                    }
                }
                _ => WindowState::Same,
            };
            let retry = retryable(&error, window) && self.attempts < MAX_ATTEMPTS;
            self.pending = None;
            if !retry {
                let terminal = SubmissionStatus::Failed { signature, error };
                self.terminal = Some(terminal.clone());
                return Ok(terminal);
            }
        }
    }

    fn attempt<I: Rpc>(
        &self,
        env: &SubmissionEnvironment<'_, I>,
    ) -> Result<Attempt, SubmissionError> {
        let proven = self.transfer.clone().prove(TransferProofEnvironment {
            indexer: env.indexer,
            rpc: env.rpc,
            prover: env.prover,
        })?;
        let window = proven.window;
        let instruction = proven.instruction()?;
        let (blockhash, last_valid_block_height) = env.rpc.get_latest_blockhash()?;
        let message = compile_message(
            &env.payer.pubkey(),
            core::slice::from_ref(&instruction),
            blockhash,
            ComputeBudgetConfig::new(TRANSACT_COMPUTE_UNIT_LIMIT),
        )?;
        let mut signers: Vec<&dyn Signer> = vec![env.payer];
        signers.extend(env.signers.iter().copied());
        Ok(Attempt {
            transaction: sign_transaction(message, &signers)?,
            window,
            last_valid_block_height,
        })
    }
}

/// An unknown status past the blockhash's last valid height is a dropped broadcast.
fn outcome(rpc: &SolanaRpc, broadcast: Broadcast) -> Result<Outcome, SubmissionError> {
    let status = rpc
        .client()
        .get_signature_statuses_with_history(&[broadcast.signature])
        .ok()
        .and_then(|response| response.value.into_iter().next().flatten());
    let Some(status) = status else {
        return Ok(
            if rpc.get_block_height()? > broadcast.last_valid_block_height {
                Outcome::Failed(TransactionError::BlockhashNotFound)
            } else {
                Outcome::Unknown
            },
        );
    };
    if !matches!(
        status.confirmation_status,
        Some(TransactionConfirmationStatus::Confirmed | TransactionConfirmationStatus::Finalized)
    ) {
        return Ok(Outcome::Unknown);
    }
    Ok(match status.err {
        None => Outcome::Confirmed { slot: status.slot },
        Some(error) => Outcome::Failed(error),
    })
}

// The attempt compiles a one-instruction message.
fn ring_error(error: &TransactionError) -> Option<u32> {
    match error {
        TransactionError::InstructionError(0, InstructionError::Custom(code)) => Some(*code),
        _ => None,
    }
}

fn retryable(error: &TransactionError, window: WindowState) -> bool {
    matches!(error, TransactionError::BlockhashNotFound)
        || matches!(ring_error(error), Some(STALE_HEAD_ROOT))
        || (ring_error(error) == Some(POLICY_PROOF_FAILED) && window == WindowState::Advanced)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CustomRing, CustomRingTransferInput};
    use serde_json::{json, Value};
    use solana_address::Address;
    use solana_rpc_client::rpc_client::RpcClient;
    use solana_rpc_client_api::request::RpcRequest;
    use zolana_keypair::{random_blinding, ShieldedKeypair};
    use zolana_transaction::{
        instructions::{transact::ConfidentialTransfer, types::SppProofInputUtxo},
        Data, Utxo, SOL_MINT,
    };

    fn pending(sender: &ShieldedKeypair, attempts: u8) -> RingTransferSubmission<'_> {
        let ring = CustomRing::new(Address::new_from_array([5; 32]));
        let input = SppProofInputUtxo::new(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: SOL_MINT,
                amount: 10,
                blinding: random_blinding(),
                ring_program_id: Some(ring.program_id()),
                data: Data::default(),
            },
            sender,
        );
        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address().unwrap(),
            vec![input],
            sender.pubkey(),
        );
        transfer
            .send(&sender.shielded_address().unwrap(), SOL_MINT, 4)
            .unwrap();
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender,
            prepared: transfer.prepare().unwrap(),
        });
        let message = compile_message(
            &sender.pubkey(),
            &[],
            Default::default(),
            ComputeBudgetConfig::new(1_400_000),
        )
        .unwrap();
        let transaction = sign_transaction(message, &[sender]).unwrap();
        let mut submission = RingTransferSubmission::new(transfer);
        submission.pending = Some(Attempt {
            transaction,
            window: None,
            last_valid_block_height: 20,
        });
        submission.attempts = attempts;
        submission
    }

    fn rpc(status: Value, block_height: u64) -> SolanaRpc {
        SolanaRpc::with_client(RpcClient::new_mock_with_mocks(
            "succeeds",
            [
                (
                    RpcRequest::GetSignatureStatuses,
                    json!({"context": {"slot": 9}, "value": [status]}),
                ),
                (RpcRequest::GetBlockHeight, json!(block_height)),
            ]
            .into_iter()
            .collect(),
        ))
    }

    fn failed(index: u8, code: u32) -> Value {
        let error = json!({"InstructionError": [index, {"Custom": code}]});
        json!({"slot": 9, "confirmations": 1, "confirmationStatus": "confirmed", "err": error, "status": {"Err": error}})
    }

    fn send(
        submission: &mut RingTransferSubmission<'_>,
        rpc: &SolanaRpc,
        payer: &ShieldedKeypair,
    ) -> SubmissionStatus {
        submission
            .send(SubmissionEnvironment {
                indexer: rpc,
                rpc,
                prover: &ProverClient::local(),
                payer,
                signers: &[],
            })
            .unwrap()
    }

    #[test]
    fn unknown_outcome_only_polls_the_original_signature() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let mut submission = pending(&sender, 1);
        let transaction = submission.pending_transaction().unwrap().clone();
        for _ in 0..2 {
            let rpc = rpc(Value::Null, 10);
            assert_eq!(
                send(&mut submission, &rpc, &sender),
                SubmissionStatus::Pending {
                    signature: transaction.signatures[0]
                }
            );
            assert_eq!(submission.attempts(), 1);
            assert_eq!(submission.pending_transaction(), Some(&transaction));
        }
    }

    #[test]
    fn an_expired_blockhash_fails_the_last_attempt() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let mut submission = pending(&sender, MAX_ATTEMPTS);
        let signature = submission.pending_transaction().unwrap().signatures[0];
        let rpc = rpc(Value::Null, 21);
        assert_eq!(
            send(&mut submission, &rpc, &sender),
            SubmissionStatus::Failed {
                signature,
                error: TransactionError::BlockhashNotFound
            }
        );
        assert!(submission.pending_transaction().is_none());
    }

    #[test]
    fn confirmation_finishes_once_and_releases_the_pending_attempt() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let mut submission = pending(&sender, 1);
        let signature = submission.pending_transaction().unwrap().signatures[0];
        let rpc = rpc(
            json!({"slot": 9, "confirmations": 1, "confirmationStatus": "confirmed", "err": null, "status": {"Ok": null}}),
            10,
        );
        for _ in 0..2 {
            assert_eq!(
                send(&mut submission, &rpc, &sender),
                SubmissionStatus::Confirmed { signature, slot: 9 }
            );
            assert_eq!(submission.attempts(), 1);
            assert!(submission.pending_transaction().is_none());
        }
    }

    #[test]
    fn unrelated_errors_and_the_third_failed_attempt_never_reprove() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        for (attempts, index, code) in [
            (1, 1, STALE_HEAD_ROOT),
            (1, 0, 8145),
            (3, 0, STALE_HEAD_ROOT),
        ] {
            let mut submission = pending(&sender, attempts);
            let signature = submission.pending_transaction().unwrap().signatures[0];
            let rpc = rpc(failed(index, code), 10);
            assert_eq!(
                send(&mut submission, &rpc, &sender),
                SubmissionStatus::Failed {
                    signature,
                    error: TransactionError::InstructionError(
                        index,
                        InstructionError::Custom(code)
                    )
                }
            );
            assert_eq!(submission.attempts(), attempts);
            assert!(submission.pending_transaction().is_none());
        }
    }

    #[test]
    fn only_the_bound_ring_failure_can_retry() {
        let error =
            |index, code| TransactionError::InstructionError(index, InstructionError::Custom(code));
        assert!(retryable(&error(0, STALE_HEAD_ROOT), WindowState::Same));
        assert!(!retryable(&error(1, STALE_HEAD_ROOT), WindowState::Same));
        assert!(!retryable(
            &error(0, POLICY_PROOF_FAILED),
            WindowState::Same
        ));
        assert!(retryable(
            &error(0, POLICY_PROOF_FAILED),
            WindowState::Advanced
        ));
        assert!(!retryable(&error(0, 8145), WindowState::Advanced));
        assert!(!retryable(
            &TransactionError::AccountInUse,
            WindowState::Advanced
        ));
        assert!(retryable(
            &TransactionError::BlockhashNotFound,
            WindowState::Same
        ));
    }
}
