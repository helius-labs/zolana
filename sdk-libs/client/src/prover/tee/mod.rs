use thiserror::Error;

#[derive(Debug, Error)]
pub enum TeeError {
    #[error("the SDK release pins no TEE prover deployment")]
    NoPinnedDeployment,
    #[error("prover client has no TEE policy")]
    NoPolicy,
    #[error("TEE policy is malformed, {0}")]
    Policy(String),
    #[error("attestation evidence is malformed, {0}")]
    Evidence(String),
    #[error("TDX quote verification failed, {0}")]
    Quote(String),
    #[error("TCB status {status} is not allowed")]
    TcbStatus { status: String },
    #[error("MRTD and RTMR0 to RTMR2 match no pinned OS measurement")]
    MeasurementNotAllowed,
    #[error("RTMR3 event log does not replay to the quoted RTMR3")]
    EventLogMismatch,
    #[error("runtime event {0} is missing or repeated")]
    RuntimeEvent(&'static str),
    #[error("app id {0} is not the pinned app")]
    AppIdNotPinned(String),
    #[error("compose hash {0} is not allowed")]
    ComposeHashNotAllowed(String),
    #[error("OS image hash {0} is not allowed")]
    OsImageNotAllowed(String),
    #[error("key provider is not the pinned KMS")]
    KeyProviderNotPinned,
    #[error("prover HPKE key is not the pinned key")]
    HpkeKeyNotPinned,
    #[error("quote report_data does not match the session nonce and key")]
    ReportDataMismatch,
    #[error("policy requires GPU evidence and the prover sent none")]
    GpuEvidenceMissing,
    #[error("sealed exchange failed, {0}")]
    Sealing(&'static str),
    #[error("prover answered {status} without sealing")]
    UnsealedResponse { status: u16 },
}
