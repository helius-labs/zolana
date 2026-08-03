//! One vocabulary for asserting rejected instructions across test backends.

use litesvm::types::FailedTransactionMetadata;
use solana_instruction::error::InstructionError;
use solana_transaction_error::TransactionError;
use zolana_client::ClientError;
use zolana_interface::error::ShieldedPoolError;

use crate::ProgramTestError;

/// The expected shape of a rejected instruction: which instruction failed and
/// with what error. Tests build one `Rejection` and assert it against
/// whichever backend produced the failure, so error expectations read
/// identically across [`crate::ZolanaProgramTest`], raw LiteSVM, and
/// RPC-client tests, and are always typed (never matched on error text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub instruction_index: u8,
    pub error: InstructionError,
}

impl Rejection {
    pub fn new(error: InstructionError) -> Self {
        Self {
            instruction_index: 0,
            error,
        }
    }

    pub fn custom(code: u32) -> Self {
        Self::new(InstructionError::Custom(code))
    }

    pub fn pool(error: ShieldedPoolError) -> Self {
        Self::custom(error as u32)
    }

    /// Pin the failing instruction's index (defaults to 0) for transactions
    /// that carry wrapper or budget instructions before the one under test.
    pub fn at(mut self, instruction_index: u8) -> Self {
        self.instruction_index = instruction_index;
        self
    }

    fn expected(&self) -> TransactionError {
        TransactionError::InstructionError(self.instruction_index, self.error.clone())
    }

    /// Assert a [`crate::ZolanaProgramTest`] submission failed as expected.
    #[track_caller]
    pub fn assert_litesvm(&self, err: ProgramTestError) {
        let ProgramTestError::TransactionFailure(failure) = err else {
            panic!("expected {:?}, got {err:?}", self.expected());
        };
        self.assert_failed_meta(&failure);
    }

    /// Assert a raw LiteSVM failure matches, printing the program logs on
    /// mismatch.
    #[track_caller]
    pub fn assert_failed_meta(&self, failure: &FailedTransactionMetadata) {
        assert_eq!(
            failure.err,
            self.expected(),
            "unexpected transaction failure; logs:\n{}",
            failure.meta.pretty_logs(),
        );
    }

    /// Assert an RPC-client submission surfaced the expected typed failure.
    #[track_caller]
    pub fn assert_client(&self, error: &ClientError) {
        let ClientError::SolanaRpcTransaction { source, .. } = error else {
            panic!("expected {:?}, got {error:?}", self.expected());
        };
        let transaction_error = source
            .get_transaction_error()
            .unwrap_or_else(|| panic!("expected a typed transaction error, got {error:?}"));
        assert_eq!(transaction_error, self.expected());
    }
}
