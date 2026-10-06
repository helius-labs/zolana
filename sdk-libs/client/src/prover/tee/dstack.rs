use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

use super::{
    platform::TeePlatform,
    policy::hex_list,
    verify::{Claims, Measured},
    TeeError,
};

/// TCG event type of every dstack runtime event in RTMR3.
const RUNTIME_EVENT_TYPE: u32 = 0x0800_0001;

pub struct Dstack;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DstackPolicy {
    #[serde(with = "hex")]
    pub app_id: [u8; 20],
    #[serde(with = "hex")]
    pub hpke_public_key: [u8; 32],
    /// The `id` the key-provider event names, the KMS root the app keys derive from.
    #[serde(with = "hex")]
    pub key_provider_id: Vec<u8>,
    #[serde(with = "hex_list")]
    pub os_image_hashes: Vec<[u8; 32]>,
    pub measurements: Vec<TdxMeasurement>,
    #[serde(with = "hex_list")]
    pub compose_hashes: Vec<[u8; 32]>,
    pub tcb_statuses: Vec<String>,
}

/// The boot measurements of one OS image on one VM shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TdxMeasurement {
    #[serde(with = "hex")]
    pub mrtd: [u8; 48],
    #[serde(with = "hex")]
    pub rtmr0: [u8; 48],
    #[serde(with = "hex")]
    pub rtmr1: [u8; 48],
    #[serde(with = "hex")]
    pub rtmr2: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DstackIdentity {
    pub tcb_status: String,
    pub measurement: TdxMeasurement,
    pub app_id: [u8; 20],
    pub compose_hash: [u8; 32],
    pub os_image_hash: [u8; 32],
    pub key_provider: KeyProvider,
}

/// The key-provider runtime event, the source of the app's derived keys.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct KeyProvider {
    pub name: String,
    #[serde(with = "hex")]
    pub id: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DstackEvidence {
    #[serde(with = "hex")]
    pub(super) quote: Vec<u8>,
    pub(super) event_log: Vec<EventLogEntry>,
    pub(super) collateral: Collateral,
}

/// One dstack event log entry, with an empty `event_payload` for boot events.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct EventLogEntry {
    imr: u32,
    event_type: u32,
    #[serde(default, with = "hex")]
    digest: Vec<u8>,
    pub(super) event: String,
    #[serde(with = "hex")]
    pub(super) event_payload: Vec<u8>,
}

/// dcap-qvl `QuoteCollateralV3` in hex, Intel signed so the prover may relay it.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct Collateral {
    pck_crl_issuer_chain: String,
    #[serde(with = "hex")]
    root_ca_crl: Vec<u8>,
    #[serde(with = "hex")]
    pck_crl: Vec<u8>,
    tcb_info_issuer_chain: String,
    tcb_info: String,
    #[serde(with = "hex")]
    tcb_info_signature: Vec<u8>,
    qe_identity_issuer_chain: String,
    qe_identity: String,
    #[serde(with = "hex")]
    qe_identity_signature: Vec<u8>,
}

impl TeePlatform for Dstack {
    const HOSTS_GPU: bool = true;
    const ROTATES_KEY_PER_BOOT: bool = false;
    const ANCHORS: Self::Anchors = ();
    type Evidence = Box<DstackEvidence>;
    type Policy = DstackPolicy;
    type Identity = DstackIdentity;
    /// dcap-qvl holds the Intel root.
    type Anchors = ();

    /// Checks the quote signature at `now_secs`, the RTMR3 replay and the identity events it carries.
    fn inspect(
        evidence: Box<DstackEvidence>,
        (): &(),
        now_secs: u64,
    ) -> Result<Measured<DstackIdentity>, TeeError> {
        let verified =
            dcap_qvl::verify::verify(&evidence.quote, &evidence.collateral.into(), now_secs)
                .map_err(|e| TeeError::Quote(format!("{e:#}")))?;
        let report = verified
            .report
            .as_td10()
            .ok_or_else(|| TeeError::Quote("not a TDX quote".into()))?;
        let events = runtime_events(&evidence.event_log, &report.rt_mr3)?;
        let key_provider = serde_json::from_slice(single(&events, "key-provider")?)
            .map_err(|_| TeeError::RuntimeEvent("key-provider"))?;
        Ok(Measured {
            identity: DstackIdentity {
                tcb_status: verified.status.clone(),
                measurement: TdxMeasurement {
                    mrtd: report.mr_td,
                    rtmr0: report.rt_mr0,
                    rtmr1: report.rt_mr1,
                    rtmr2: report.rt_mr2,
                },
                app_id: fixed(&events, "app-id")?,
                compose_hash: fixed(&events, "compose-hash")?,
                os_image_hash: fixed(&events, "os-image-hash")?,
                key_provider,
            },
            report_data: report.report_data,
        })
    }

    fn check(
        identity: &DstackIdentity,
        pins: &DstackPolicy,
        claims: &Claims<'_>,
    ) -> Result<(), TeeError> {
        if !pins.tcb_statuses.contains(&identity.tcb_status) {
            return Err(TeeError::TcbStatus {
                status: identity.tcb_status.clone(),
            });
        }
        if !pins.measurements.contains(&identity.measurement) {
            return Err(TeeError::MeasurementNotAllowed);
        }
        if identity.app_id != pins.app_id {
            return Err(TeeError::AppIdMismatch(hex::encode(identity.app_id)));
        }
        if !pins.compose_hashes.contains(&identity.compose_hash) {
            return Err(TeeError::ComposeHashNotAllowed(hex::encode(
                identity.compose_hash,
            )));
        }
        if !pins.os_image_hashes.contains(&identity.os_image_hash) {
            return Err(TeeError::OsImageNotAllowed(hex::encode(
                identity.os_image_hash,
            )));
        }
        if identity.key_provider.name != "kms" || identity.key_provider.id != pins.key_provider_id {
            return Err(TeeError::KeyProviderMismatch);
        }
        if claims.hpke_public_key != &pins.hpke_public_key {
            return Err(TeeError::HpkeKeyMismatch);
        }
        Ok(())
    }

    fn image_id(identity: &DstackIdentity) -> Vec<u8> {
        identity.compose_hash.to_vec()
    }

    fn tcb_status(identity: &DstackIdentity) -> Option<String> {
        Some(identity.tcb_status.clone())
    }
}

impl From<Collateral> for dcap_qvl::QuoteCollateralV3 {
    fn from(c: Collateral) -> Self {
        Self {
            pck_crl_issuer_chain: c.pck_crl_issuer_chain,
            root_ca_crl: c.root_ca_crl,
            pck_crl: c.pck_crl,
            tcb_info_issuer_chain: c.tcb_info_issuer_chain,
            tcb_info: c.tcb_info,
            tcb_info_signature: c.tcb_info_signature,
            qe_identity_issuer_chain: c.qe_identity_issuer_chain,
            qe_identity: c.qe_identity,
            qe_identity_signature: c.qe_identity_signature,
            pck_certificate_chain: None,
        }
    }
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
        // The guest agent's GetQuote leaves RTMR3 digests empty, a stated one must still match.
        if !entry.digest.is_empty() && digest.as_slice() != entry.digest {
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
