use std::fmt;

use sha2::{Digest, Sha256, Sha512};

use super::{
    platform::{mismatch, Anchors},
    Attestation, GpuRequirement, Platform, PlatformIdentity, TeeError, TeePolicy, NONCE_SIZE,
    REPORT_DOMAIN,
};

/// A prover that passed [`verify`] for one session nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AttestedProver {
    pub platform: Platform,
    pub hpke_public_key: [u8; 32],
    /// The dstack compose hash or the Nitro PCR0.
    pub image_id: Vec<u8>,
    pub tcb_status: Option<String>,
    pub gpu_verified: bool,
}

/// What verified evidence proves about the prover, before any policy applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedIdentity {
    pub hpke_public_key: [u8; 32],
    pub report_data: [u8; 64],
    /// The raw NRAS response the prover verified inside the TEE.
    pub gpu: Option<String>,
    pub platform: PlatformIdentity,
}

/// Binds the session nonce, the encryption key and the NRAS digest into the evidence, zeros without a GPU.
pub fn report_data(
    nonce: &[u8; NONCE_SIZE],
    hpke_public_key: &[u8; 32],
    gpu_token: Option<&[u8]>,
) -> [u8; 64] {
    let gpu_digest: [u8; 32] = gpu_token.map_or([0; 32], |token| Sha256::digest(token).into());
    Sha512::new()
        .chain_update(REPORT_DOMAIN)
        .chain_update(nonce)
        .chain_update(hpke_public_key)
        .chain_update(gpu_digest)
        .finalize()
        .into()
}

/// Checks only what the platform vendor proves at `now_secs`, before any pin applies.
pub fn inspect(attestation: Attestation, now_secs: u64) -> Result<AttestedIdentity, TeeError> {
    Trust::at(now_secs).inspect(attestation)
}

/// Accepts the attestation only if its platform evidence, pins and report_data
/// all match `policy` and `nonce` at `now_secs`.
pub fn verify(
    attestation: Attestation,
    policy: &TeePolicy,
    nonce: &[u8; NONCE_SIZE],
    now_secs: u64,
) -> Result<AttestedProver, TeeError> {
    Trust::at(now_secs).verify(attestation, Session { policy, nonce })
}

impl fmt::Display for AttestedProver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}, image {}",
            self.platform,
            hex::encode(&self.image_id)
        )?;
        if let Some(status) = &self.tcb_status {
            write!(f, ", TCB {status}")?;
        }
        let gpu = if self.gpu_verified {
            "verified"
        } else {
            "absent"
        };
        write!(f, ", GPU {gpu}")
    }
}

#[derive(Clone, Copy)]
pub(super) struct Trust<'a> {
    pub now_secs: u64,
    pub anchors: &'a Anchors,
}

pub(super) struct Session<'a> {
    pub policy: &'a TeePolicy,
    pub nonce: &'a [u8; NONCE_SIZE],
}

pub struct Claims<'a> {
    pub hpke_public_key: &'a [u8; 32],
    pub gpu: Option<&'a str>,
    pub nonce: &'a [u8; NONCE_SIZE],
}

pub struct Measured<I> {
    pub identity: I,
    pub report_data: [u8; 64],
}

impl Trust<'static> {
    fn at(now_secs: u64) -> Self {
        Self {
            now_secs,
            anchors: &Anchors::PRODUCTION,
        }
    }
}

impl Trust<'_> {
    pub(super) fn inspect(self, attestation: Attestation) -> Result<AttestedIdentity, TeeError> {
        let Attestation {
            hpke_public_key,
            gpu,
            evidence,
        } = attestation;
        let platform = evidence.platform();
        if gpu.is_some() && !platform.hosts_gpu() {
            return Err(TeeError::MalformedAttestation(format!(
                "{platform} hosts no GPU, gpu must be null"
            )));
        }
        let measured = evidence.inspect(self)?;
        Ok(AttestedIdentity {
            hpke_public_key,
            report_data: measured.report_data,
            gpu,
            platform: measured.identity,
        })
    }

    pub(super) fn verify(
        self,
        attestation: Attestation,
        session: Session<'_>,
    ) -> Result<AttestedProver, TeeError> {
        let Session { policy, nonce } = session;
        if attestation.platform() != policy.platform() {
            return Err(mismatch(policy.platform(), attestation.platform()));
        }
        let identity = self.inspect(attestation)?;
        let platform = identity.platform.platform();
        let claims = Claims {
            hpke_public_key: &identity.hpke_public_key,
            gpu: identity.gpu.as_deref(),
            nonce,
        };
        identity.platform.check(policy.pins(), &claims)?;
        let gpu_token = claims.gpu.map(str::as_bytes);
        if identity.report_data != report_data(nonce, &identity.hpke_public_key, gpu_token) {
            return Err(TeeError::ReportDataMismatch);
        }
        if policy.gpu() == GpuRequirement::Required && gpu_token.is_none() {
            return Err(TeeError::GpuEvidenceMissing);
        }
        Ok(AttestedProver {
            platform,
            hpke_public_key: identity.hpke_public_key,
            image_id: identity.platform.image_id(),
            tcb_status: identity.platform.tcb_status(),
            gpu_verified: gpu_token.is_some(),
        })
    }
}

impl<I> Measured<I> {
    pub(super) fn map<J>(self, wrap: impl FnOnce(I) -> J) -> Measured<J> {
        Measured {
            identity: wrap(self.identity),
            report_data: self.report_data,
        }
    }
}
