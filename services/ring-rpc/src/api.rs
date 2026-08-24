pub use zolana_ring_client::rpc::{
    auditor_key_attestation, cursor_in_bounds, limit_in_bounds, unix_now, AuditorPubkey,
    CreateAuditorKeyRequest, CreateAuditorKeyResponse, DecryptedOutput, DecryptedTransaction,
    DecryptedTransactionsPage, DecryptedWithdrawal, DepositRecord, GetDecryptedTransactionsRequest,
    GetDecryptedTransactionsResponse, HealthResponse, ReadAttestation, ReadAuth, ReadBuildError,
    ReadRequest, ReadSignature, ReadSigner, RingDepositsRequest, RingDepositsResponse, RingState,
    RingStatusRequest, RingStatusResponse, SkippedReason, SkippedTransaction, WebAuthnAssertion,
    AUDIT_PAGE_LIMIT, CREATE_AUDITOR_KEY, GET_DECRYPTED_TRANSACTIONS, HEALTH, RING_DEPOSITS,
    RING_STATUS,
};

use crate::upstream::DepositHistory;

impl From<DepositHistory> for RingDepositsResponse {
    fn from(history: DepositHistory) -> Self {
        Self {
            deposits: history.deposits,
            cursor: history
                .cursor
                .map(|signature| signature.as_ref().to_vec().into()),
            oldest_slot: history.oldest_slot,
        }
    }
}
