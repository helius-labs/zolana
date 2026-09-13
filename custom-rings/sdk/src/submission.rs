use solana_instruction_error::InstructionError;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;
use solana_transaction_status_client_types::TransactionConfirmationStatus;
use thiserror::Error;
use zolana_client::{ClientError, ProverClient, Rpc, SolanaRpc};

use crate::{CustomRingTransfer, SendError, TransactSend, TransferError, TransferProofEnvironment};

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
    Build(#[from] SendError),
    #[error(transparent)]
    Read(#[from] ClientError),
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
    window: Option<(u64, u64)>,
}

/// Reserve input notes until a terminal result.
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

    /// Unknown outcomes retain the original signature.
    pub fn send<I: Rpc>(
        &mut self,
        env: SubmissionEnvironment<'_, I>,
    ) -> Result<SubmissionStatus, SubmissionError> {
        let SubmissionEnvironment {
            indexer,
            rpc,
            prover,
            payer,
            signers,
        } = env;
        if let Some(terminal) = &self.terminal {
            return Ok(terminal.clone());
        }
        loop {
            let mut failure = None;
            if self.pending.is_none() {
                let proven = self.transfer.clone().prove(TransferProofEnvironment {
                    indexer,
                    rpc,
                    prover,
                })?;
                let window = proven.window;
                let transaction = TransactSend {
                    payer,
                    signers,
                    instruction: proven.instruction()?,
                }
                .build(rpc)?;
                self.pending = Some(Attempt {
                    transaction,
                    window,
                });
                self.attempts += 1;
                let attempt = self.pending.as_ref().expect("stored before send");
                if let Err(error) = rpc.client().send_transaction(&attempt.transaction) {
                    failure = error.get_transaction_error();
                    // A transport error says nothing about whether the node accepted the bytes.
                }
            }
            let attempt = self.pending.as_ref().expect("pending attempt");
            let signature = attempt.transaction.signatures[0];
            if failure.is_none() {
                let status = rpc
                    .client()
                    .get_signature_statuses_with_history(&[signature]);
                let Some(status) = status
                    .ok()
                    .and_then(|response| response.value.into_iter().next().flatten())
                else {
                    return Ok(SubmissionStatus::Pending { signature });
                };
                if !matches!(
                    status.confirmation_status,
                    Some(
                        TransactionConfirmationStatus::Confirmed
                            | TransactionConfirmationStatus::Finalized
                    )
                ) {
                    return Ok(SubmissionStatus::Pending { signature });
                }
                match status.err {
                    None => {
                        let terminal = SubmissionStatus::Confirmed {
                            signature,
                            slot: status.slot,
                        };
                        self.pending = None;
                        self.terminal = Some(terminal.clone());
                        return Ok(terminal);
                    }
                    Some(error) => failure = Some(error),
                }
            }
            let error = failure.expect("failed status");
            let window_changed = match attempt.window {
                Some((slots, index)) if ring_error(&error) == Some(POLICY_PROOF_FAILED) => {
                    rpc.get_slot()? / slots != index
                }
                _ => false,
            };
            let retry = retryable(&error, window_changed) && self.attempts < MAX_ATTEMPTS;
            self.pending = None;
            if !retry {
                let terminal = SubmissionStatus::Failed { signature, error };
                self.terminal = Some(terminal.clone());
                return Ok(terminal);
            }
        }
    }
}

fn ring_error(error: &TransactionError) -> Option<u32> {
    match error {
        TransactionError::InstructionError(0, InstructionError::Custom(code)) => Some(*code),
        _ => None,
    }
}

fn retryable(error: &TransactionError, window_changed: bool) -> bool {
    matches!(ring_error(error), Some(STALE_HEAD_ROOT))
        || (ring_error(error) == Some(POLICY_PROOF_FAILED) && window_changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CustomRing, CustomRingTransferInput};
    use serde_json::{json, Value};
    use solana_address::Address;
    use solana_rpc_client::rpc_client::RpcClient;
    use solana_rpc_client_api::request::RpcRequest;
    use zolana_client::{compile_message, sign_transaction, ComputeBudgetConfig};
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
        });
        submission.attempts = attempts;
        submission
    }

    fn rpc(status: Value) -> SolanaRpc {
        SolanaRpc::with_client(RpcClient::new_mock_with_mocks(
            "succeeds",
            [(
                RpcRequest::GetSignatureStatuses,
                json!({"context": {"slot": 9}, "value": [status]}),
            )]
            .into_iter()
            .collect(),
        ))
    }

    fn failed(index: u8, code: u32) -> Value {
        let error = json!({"InstructionError": [index, {"Custom": code}]});
        json!({"slot": 9, "confirmations": 1, "confirmationStatus": "confirmed", "err": error, "status": {"Err": error}})
    }

    #[test]
    fn unknown_outcome_only_polls_the_original_signature() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let mut submission = pending(&sender, 1);
        let transaction = submission.pending_transaction().unwrap().clone();
        for _ in 0..2 {
            let rpc = rpc(Value::Null);
            let result = submission
                .send(SubmissionEnvironment {
                    indexer: &rpc,
                    rpc: &rpc,
                    prover: &ProverClient::local(),
                    payer: &sender,
                    signers: &[],
                })
                .unwrap();
            assert_eq!(
                result,
                SubmissionStatus::Pending {
                    signature: transaction.signatures[0]
                }
            );
            assert_eq!(submission.attempts(), 1);
            assert_eq!(submission.pending_transaction(), Some(&transaction));
        }
    }

    #[test]
    fn confirmation_finishes_once_and_releases_the_pending_attempt() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let mut submission = pending(&sender, 1);
        let signature = submission.pending_transaction().unwrap().signatures[0];
        let rpc = rpc(
            json!({"slot": 9, "confirmations": 1, "confirmationStatus": "confirmed", "err": null, "status": {"Ok": null}}),
        );
        for _ in 0..2 {
            assert_eq!(
                submission
                    .send(SubmissionEnvironment {
                        indexer: &rpc,
                        rpc: &rpc,
                        prover: &ProverClient::local(),
                        payer: &sender,
                        signers: &[],
                    })
                    .unwrap(),
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
            let rpc = rpc(failed(index, code));
            let result = submission
                .send(SubmissionEnvironment {
                    indexer: &rpc,
                    rpc: &rpc,
                    prover: &ProverClient::local(),
                    payer: &sender,
                    signers: &[],
                })
                .unwrap();
            assert_eq!(
                result,
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
        assert!(retryable(&error(0, STALE_HEAD_ROOT), false));
        assert!(!retryable(&error(1, STALE_HEAD_ROOT), false));
        assert!(!retryable(&error(0, POLICY_PROOF_FAILED), false));
        assert!(retryable(&error(0, POLICY_PROOF_FAILED), true));
        assert!(!retryable(&error(0, 8145), true));
        assert!(!retryable(&TransactionError::AccountInUse, true));
    }
}
