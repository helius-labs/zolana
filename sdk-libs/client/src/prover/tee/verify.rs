use serde::Deserialize;
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::{
    EventLogEntry, Evidence, GpuRequirement, Measurement, TeeError, TeePolicy, REPORT_DOMAIN,
};

/// TCG event type of every dstack runtime event in RTMR3.
const RUNTIME_EVENT_TYPE: u32 = 0x0800_0001;

/// A prover that passed [`verify`] for one session nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedProver {
    pub hpke_public_key: [u8; 32],
    pub tcb_status: String,
    pub compose_hash: [u8; 32],
    pub gpu_verified: bool,
}

/// Binds the session nonce, the sealing key and the NRAS digest into the quote, zeros without a GPU.
pub fn report_data(
    nonce: &[u8; 32],
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

/// What a verified quote proves about the prover, before any policy applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedIdentity {
    pub tcb_status: String,
    pub measurement: Measurement,
    pub app_id: [u8; 20],
    pub compose_hash: [u8; 32],
    pub os_image_hash: [u8; 32],
    pub key_provider: KeyProvider,
    pub hpke_public_key: [u8; 32],
    pub report_data: [u8; 64],
    /// The raw NRAS response the prover verified inside the TEE.
    pub gpu: Option<String>,
}

/// The key-provider runtime event, the source of the app's derived keys.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct KeyProvider {
    pub name: String,
    #[serde(with = "hex")]
    pub id: Vec<u8>,
}

/// Checks only what Intel and the event log prove, the quote signature at
/// `now_secs`, the RTMR3 replay and the identity events it carries.
pub fn inspect(evidence: Evidence, now_secs: u64) -> Result<AttestedIdentity, TeeError> {
    let verified = dcap_qvl::verify::verify(&evidence.quote, &evidence.collateral.into(), now_secs)
        .map_err(|e| TeeError::Quote(format!("{e:#}")))?;
    let report = verified
        .report
        .as_td10()
        .ok_or_else(|| TeeError::Quote("not a TDX quote".into()))?;
    let events = runtime_events(&evidence.event_log, &report.rt_mr3)?;
    let key_provider = serde_json::from_slice(single(&events, "key-provider")?)
        .map_err(|_| TeeError::RuntimeEvent("key-provider"))?;
    Ok(AttestedIdentity {
        tcb_status: verified.status.clone(),
        measurement: Measurement {
            mrtd: report.mr_td,
            rtmr0: report.rt_mr0,
            rtmr1: report.rt_mr1,
            rtmr2: report.rt_mr2,
        },
        app_id: fixed(&events, "app-id")?,
        compose_hash: fixed(&events, "compose-hash")?,
        os_image_hash: fixed(&events, "os-image-hash")?,
        key_provider,
        hpke_public_key: evidence.hpke_public_key,
        report_data: report.report_data,
        gpu: evidence.gpu,
    })
}

/// Accepts the evidence only if Intel signed a TDX quote whose measurements,
/// app identity and report_data all match `policy` and `nonce` at `now_secs`.
pub fn verify(
    evidence: Evidence,
    policy: &TeePolicy,
    nonce: &[u8; 32],
    now_secs: u64,
) -> Result<AttestedProver, TeeError> {
    let identity = inspect(evidence, now_secs)?;
    if !policy.tcb_statuses.contains(&identity.tcb_status) {
        return Err(TeeError::TcbStatus {
            status: identity.tcb_status,
        });
    }
    if !policy.measurements.contains(&identity.measurement) {
        return Err(TeeError::MeasurementNotAllowed);
    }
    if identity.app_id != policy.app_id {
        return Err(TeeError::AppIdNotPinned(hex::encode(identity.app_id)));
    }
    if !policy.compose_hashes.contains(&identity.compose_hash) {
        return Err(TeeError::ComposeHashNotAllowed(hex::encode(
            identity.compose_hash,
        )));
    }
    if !policy.os_image_hashes.contains(&identity.os_image_hash) {
        return Err(TeeError::OsImageNotAllowed(hex::encode(
            identity.os_image_hash,
        )));
    }
    if identity.key_provider.name != "kms" || identity.key_provider.id != policy.key_provider_id {
        return Err(TeeError::KeyProviderNotPinned);
    }
    if identity.hpke_public_key != policy.hpke_public_key {
        return Err(TeeError::HpkeKeyNotPinned);
    }
    let gpu_token = identity.gpu.as_deref().map(str::as_bytes);
    if identity.report_data != report_data(nonce, &identity.hpke_public_key, gpu_token) {
        return Err(TeeError::ReportDataMismatch);
    }
    if policy.gpu == GpuRequirement::Required && gpu_token.is_none() {
        return Err(TeeError::GpuEvidenceMissing);
    }
    Ok(AttestedProver {
        hpke_public_key: identity.hpke_public_key,
        tcb_status: identity.tcb_status,
        compose_hash: identity.compose_hash,
        gpu_verified: gpu_token.is_some(),
    })
}

/// Recomputes every RTMR3 digest from its `event_payload` before replaying to
/// `rtmr3`, so swapped event content fails even when the digests replay.
fn runtime_events<'a>(
    log: &'a [EventLogEntry],
    rtmr3: &[u8; 48],
) -> Result<Vec<&'a EventLogEntry>, TeeError> {
    let mut replayed = [0u8; 48];
    let mut events = Vec::new();
    for entry in log.iter().filter(|entry| entry.imr == 3) {
        if entry.event_type != RUNTIME_EVENT_TYPE {
            return Err(TeeError::EventLogMismatch);
        }
        let digest = Sha384::new()
            .chain_update(RUNTIME_EVENT_TYPE.to_le_bytes())
            .chain_update(b":")
            .chain_update(entry.event.as_bytes())
            .chain_update(b":")
            .chain_update(&entry.event_payload)
            .finalize();
        if digest.as_slice() != entry.digest {
            return Err(TeeError::EventLogMismatch);
        }
        replayed = Sha384::new()
            .chain_update(replayed)
            .chain_update(digest)
            .finalize()
            .into();
        events.push(entry);
    }
    if &replayed != rtmr3 {
        return Err(TeeError::EventLogMismatch);
    }
    Ok(events)
}

fn fixed<const N: usize>(
    events: &[&EventLogEntry],
    name: &'static str,
) -> Result<[u8; N], TeeError> {
    single(events, name)?
        .try_into()
        .map_err(|_| TeeError::RuntimeEvent(name))
}

fn single<'a>(events: &[&'a EventLogEntry], name: &'static str) -> Result<&'a [u8], TeeError> {
    let mut matching = events.iter().filter(|event| event.event == name);
    match (matching.next(), matching.next()) {
        (Some(event), None) => Ok(&event.event_payload),
        _ => Err(TeeError::RuntimeEvent(name)),
    }
}
