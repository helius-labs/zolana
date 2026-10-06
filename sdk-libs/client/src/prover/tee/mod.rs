use thiserror::Error;

#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum TeeError {
    #[error("the SDK release has no default TEE prover deployment")]
    NoDefaultDeployment,
    #[error("prover client has no TEE policy")]
    NoPolicy,
    #[error("TEE policy is malformed, {0}")]
    Policy(String),
    #[error("attestation is malformed, {0}")]
    MalformedAttestation(String),
    #[error("TDX quote verification failed, {0}")]
    Quote(String),
    #[error("Nitro attestation document verification failed, {0}")]
    NitroDocument(String),
    #[error("prover attests as {got}, the policy requires {expected}")]
    PlatformMismatch { expected: String, got: String },
    #[error("TCB status {status} is not allowed")]
    TcbStatus { status: String },
    #[error("MRTD and RTMR0 to RTMR2 match no allowed OS measurement")]
    MeasurementNotAllowed,
    #[error("PCR0 to PCR2 match no allowed enclave image")]
    EnclaveMeasurementNotAllowed,
    #[error("RTMR3 event log does not replay to the quoted RTMR3")]
    EventLogMismatch,
    #[error("runtime event {0} is missing or repeated")]
    RuntimeEvent(&'static str),
    #[error("app id {0} does not match the policy")]
    AppIdMismatch(String),
    #[error("compose hash {0} is not allowed")]
    ComposeHashNotAllowed(String),
    #[error("OS image hash {0} is not allowed")]
    OsImageNotAllowed(String),
    #[error("key provider does not match the policy KMS")]
    KeyProviderMismatch,
    #[error("prover HPKE key does not match the policy")]
    HpkeKeyMismatch,
    #[error("quote report_data does not match the session nonce and key")]
    ReportDataMismatch,
    #[error("policy requires GPU evidence and the prover sent none")]
    GpuEvidenceMissing,
    #[error("encrypted exchange failed, {0}")]
    Encryption(&'static str),
    #[error("prover answered {status} without encryption")]
    UnencryptedResponse { status: u16 },
}
