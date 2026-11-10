use spr_client::ClientError;
use spr_transaction::TransactionError;

/// Where an attempt was when it failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Sync,
    Prove,
    Send,
    Confirm,
}

/// The failure classes the canary reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    Indexer,
    Prover,
    Rpc,
    ConfirmTimeout,
    InsufficientBalance,
}

impl ErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Indexer => "indexer",
            Self::Prover => "prover",
            Self::Rpc => "rpc",
            Self::ConfirmTimeout => "confirm_timeout",
            Self::InsufficientBalance => "insufficient_balance",
        }
    }

    /// The class of an error with no more specific variant.
    fn of_phase(phase: Phase) -> Self {
        match phase {
            Phase::Sync => Self::Indexer,
            Phase::Prove => Self::Prover,
            Phase::Send => Self::Rpc,
            Phase::Confirm => Self::ConfirmTimeout,
        }
    }
}

/// The class of a client error raised during `phase`, by variant first, by phase otherwise.
pub fn classify(phase: Phase, error: &ClientError) -> ErrorClass {
    use ClientError as E;
    match error {
        E::InsufficientBalance { .. }
        | E::Transaction(
            TransactionError::InsufficientBalance { .. }
            | TransactionError::NoSpendableBalance { .. }
            | TransactionError::SpendNeedsMerge { .. },
        ) => ErrorClass::InsufficientBalance,
        E::Indexer(_)
        | E::IndexerUnavailable(_)
        | E::IndexerTimeout
        | E::IndexerCursorNotAdvanced
        | E::IndexerMinimumContextSlot { .. }
        | E::IndexerNotCaughtUp { .. }
        | E::IndexerProofDataNotReady
        | E::IncompleteInputProofs { .. }
        | E::IncompleteTransactionProofs { .. } => ErrorClass::Indexer,
        E::PollTimedOut { .. } if phase == Phase::Confirm => ErrorClass::ConfirmTimeout,
        E::PollTimedOut { .. } => ErrorClass::Indexer,
        E::ProverServer(_)
        | E::ProverRejected { .. }
        | E::ProverFailed(_)
        | E::Prover(_)
        | E::ProverIndexerUnconfigured
        | E::InvalidIndexedRequest
        | E::ProofParse(_)
        | E::ProofVerification(_)
        | E::ProvingKeyMismatch { .. }
        | E::MissingProvingKeySha256 { .. }
        | E::ProverProvingKeysMismatch { .. }
        | E::ProvingKeySet(_)
        | E::Tee(_) => ErrorClass::Prover,
        E::Rpc(message) | E::TransactionFailed(message) if names_insufficient_funds(message) => {
            ErrorClass::InsufficientBalance
        }
        E::SolanaRpcTransaction { source, .. } if names_insufficient_funds(&source.to_string()) => {
            ErrorClass::InsufficientBalance
        }
        E::Rpc(_) | E::TransactionFailed(_) | E::SolanaRpcTransaction { .. } => ErrorClass::Rpc,
        _ => ErrorClass::of_phase(phase),
    }
}

/// Whether a Solana error says the fee payer cannot pay.
pub fn names_insufficient_funds(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("insufficient funds") || message.contains("insufficient lamports")
}

#[cfg(test)]
mod tests {
    use spr_transaction::SOL_MINT;

    use super::*;

    #[test]
    fn wallet_shortfalls_are_insufficient_balance() {
        let cases = [
            ClientError::InsufficientBalance {
                requested: 2,
                available: 1,
            },
            ClientError::Transaction(TransactionError::InsufficientBalance {
                requested: 2,
                available: 1,
            }),
            ClientError::Transaction(TransactionError::NoSpendableBalance { asset: SOL_MINT }),
            ClientError::Rpc("Transaction simulation failed: insufficient funds for fee".into()),
            ClientError::TransactionFailed("custom program error: insufficient lamports".into()),
        ];
        for error in &cases {
            assert_eq!(
                classify(Phase::Prove, error),
                ErrorClass::InsufficientBalance,
                "{error}"
            );
        }
    }

    #[test]
    fn variants_win_over_the_phase() {
        assert_eq!(
            classify(Phase::Prove, &ClientError::IndexerProofDataNotReady),
            ErrorClass::Indexer
        );
        assert_eq!(
            classify(Phase::Sync, &ClientError::ProverServer("status 503".into())),
            ErrorClass::Prover
        );
        assert_eq!(
            classify(Phase::Prove, &ClientError::Rpc("blockhash".into())),
            ErrorClass::Rpc
        );
        assert_eq!(
            classify(Phase::Confirm, &ClientError::Indexer("502".into())),
            ErrorClass::Indexer
        );
    }

    #[test]
    fn poll_timeouts_depend_on_the_phase() {
        let timeout = || ClientError::PollTimedOut {
            attempts: 3,
            last_error: None,
        };
        assert_eq!(
            classify(Phase::Confirm, &timeout()),
            ErrorClass::ConfirmTimeout
        );
        assert_eq!(classify(Phase::Sync, &timeout()), ErrorClass::Indexer);
    }

    #[test]
    fn other_errors_fall_back_to_the_phase() {
        let error = || ClientError::MissingOutput;
        assert_eq!(classify(Phase::Sync, &error()), ErrorClass::Indexer);
        assert_eq!(classify(Phase::Prove, &error()), ErrorClass::Prover);
        assert_eq!(classify(Phase::Send, &error()), ErrorClass::Rpc);
        assert_eq!(
            classify(Phase::Confirm, &error()),
            ErrorClass::ConfirmTimeout
        );
    }

    #[test]
    fn class_names_are_stable() {
        assert_eq!(
            [
                ErrorClass::Indexer,
                ErrorClass::Prover,
                ErrorClass::Rpc,
                ErrorClass::ConfirmTimeout,
                ErrorClass::InsufficientBalance,
            ]
            .map(ErrorClass::as_str),
            [
                "indexer",
                "prover",
                "rpc",
                "confirm_timeout",
                "insufficient_balance"
            ]
        );
    }
}
