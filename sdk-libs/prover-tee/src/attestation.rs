use serde::Deserialize;

use super::{platform::Evidence, Platform};

/// The body of `GET /tee/v1/attestation`.
#[derive(Clone, Debug, Deserialize)]
pub struct Attestation {
    #[serde(with = "hex")]
    pub(super) hpke_public_key: [u8; 32],
    /// The raw NRAS response the prover verified inside the TEE, required even when null.
    #[serde(deserialize_with = "Option::deserialize")]
    pub(super) gpu: Option<String>,
    #[serde(flatten)]
    pub(super) evidence: Evidence,
}

impl Attestation {
    pub fn platform(&self) -> Platform {
        self.evidence.platform()
    }
}
