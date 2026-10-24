#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("prover server error: {0}")]
    ProverServer(String),
    #[error("prover error: {0}")]
    Prover(String),
    #[error("prover indexer is not ready")]
    IndexerProofDataNotReady,
    #[error("prover has no indexer configured")]
    ProverIndexerUnconfigured,
    #[error("prover proving keys do not match: {mismatches:?}")]
    ProverProvingKeysMismatch { mismatches: Vec<String> },
    #[error("proving key {key} mismatch: expected {expected}, reported {reported}")]
    ProvingKeyMismatch {
        key: String,
        expected: String,
        reported: String,
    },
    #[error("proof parse: {0}")]
    ProofParse(String),
    #[error("proof verification: {0}")]
    ProofVerification(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hasher(#[from] zolana_hasher::HasherError),
}
pub(crate) type Result<T> = std::result::Result<T, Error>;
