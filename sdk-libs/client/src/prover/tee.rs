//! Encrypts every prover call to the HPKE key verified TEE evidence binds.
//! The wire contract is `spr-prover-tee`; this module adds the session
//! that attests once and reuses the key across a client's calls.

mod session;

pub use spr_prover_tee::{
    inspect, verify, verify_with, Anchors, Attestation, AttestedIdentity, AttestedProver,
    DstackIdentity, DstackPolicy, EncryptedRequest, GpuRequirement, KeyProvider, NitroIdentity,
    NitroMeasurement, NitroPolicy, Platform, PlatformIdentity, PlatformPolicy, TdxMeasurement,
    TeeError, TeePolicy, TeePolicyFile, ATTESTATION_PATH, DEFAULT_PROVER_URL, HEADER_CIPHERTEXT,
    HEADER_ENC, HEADER_VERSION, MAINNET_PROVER_URL, MAX_ATTESTATION_BYTES, NONCE_SIZE, VERSION,
};

pub(crate) use session::TeeSession;
#[cfg(test)]
pub(crate) use spr_prover_tee::NitroFixture;

#[cfg(test)]
pub(crate) trait FixtureSession {
    /// A session trusting the fixture root in place of the AWS root.
    fn session(&self) -> TeeSession;
}

#[cfg(test)]
impl FixtureSession for NitroFixture {
    fn session(&self) -> TeeSession {
        TeeSession::trusting(self.policy().clone(), self.anchors())
    }
}
