use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeR,
    Serializable,
};
use serde::Deserialize;

use super::{
    seal::{open_response, request_aad},
    verify,
    verify::report_data,
    Evidence, SealedRequest, TeeError, TeePolicy, HPKE_INFO, RESPONSE_EXPORT,
};

const PROBE_ATTESTATION: &str =
    include_str!("../../../../../prover/tee/testdata/probe_attestation.json");
const PROBE_POLICY: &str = include_str!("../../../../../prover/tee/testdata/probe_policy.json");
const VECTORS: &str = include_str!("../../../../../prover/tee/testdata/vectors.json");
const LIVE_ATTESTATION: &str =
    include_str!("../../../../../prover/tee/testdata/live_attestation.json");

#[derive(Deserialize)]
struct ProbeFixture {
    captured_at: u64,
    attestation: serde_json::Value,
}

/// A real dstack-nvidia-0.5.9 attestation whose report_data binds a dstack
/// app certificate, not a prover session.
fn probe() -> (Evidence, TeePolicy, u64) {
    let fixture: ProbeFixture = serde_json::from_str(PROBE_ATTESTATION).unwrap();
    let evidence = serde_json::from_value(fixture.attestation).unwrap();
    (
        evidence,
        TeePolicy::from_json(PROBE_POLICY).unwrap(),
        fixture.captured_at,
    )
}

#[test]
fn a_real_quote_passes_every_check_before_report_data() {
    let (evidence, policy, now) = probe();
    assert!(matches!(
        verify(evidence, &policy, &[0x22; 32], now),
        Err(TeeError::ReportDataMismatch)
    ));
}

#[test]
fn each_policy_check_refuses_with_its_own_error() {
    type Edit = fn(&mut Evidence, &mut TeePolicy, &mut u64);
    type Expected = fn(&TeeError) -> bool;
    let cases: [(&str, Edit, Expected); 10] = [
        (
            "quote signature",
            |e, _, _| e.quote[700] ^= 1,
            |e| matches!(e, TeeError::Quote(_)),
        ),
        (
            "collateral expired",
            |_, _, now| *now += 400 * 86_400,
            |e| matches!(e, TeeError::Quote(_)),
        ),
        (
            "tcb status",
            |_, p, _| p.tcb_statuses.clear(),
            |e| matches!(e, TeeError::TcbStatus { .. }),
        ),
        (
            "os measurement",
            |_, p, _| p.measurements[0].rtmr1[0] ^= 1,
            |e| matches!(e, TeeError::MeasurementNotAllowed),
        ),
        (
            "swapped event payload",
            |e, _, _| {
                let event = e
                    .event_log
                    .iter_mut()
                    .find(|ev| ev.event == "compose-hash")
                    .unwrap();
                event.event_payload[0] ^= 1;
            },
            |e| matches!(e, TeeError::EventLogMismatch),
        ),
        (
            "app id",
            |_, p, _| p.app_id[0] ^= 1,
            |e| matches!(e, TeeError::AppIdNotPinned(_)),
        ),
        (
            "compose hash",
            |_, p, _| p.compose_hashes.clear(),
            |e| matches!(e, TeeError::ComposeHashNotAllowed(_)),
        ),
        (
            "os image",
            |_, p, _| p.os_image_hashes.clear(),
            |e| matches!(e, TeeError::OsImageNotAllowed(_)),
        ),
        (
            "key provider",
            |_, p, _| p.key_provider_id.clear(),
            |e| matches!(e, TeeError::KeyProviderNotPinned),
        ),
        (
            "hpke key",
            |_, p, _| p.hpke_public_key[0] ^= 1,
            |e| matches!(e, TeeError::HpkeKeyNotPinned),
        ),
    ];
    for (name, edit, expected) in cases {
        let (mut evidence, mut policy, mut now) = probe();
        edit(&mut evidence, &mut policy, &mut now);
        let error = verify(evidence, &policy, &[0x22; 32], now).unwrap_err();
        assert!(expected(&error), "{name}: {error}");
    }
}

#[derive(Deserialize)]
struct LiveFixture {
    captured_at: u64,
    nonce: String,
    attestation: serde_json::Value,
}

/// A live H200 prover's answer to a recorded nonce, quote and GPU verdict included.
#[test]
fn the_archived_deployment_accepts_its_attestation() {
    let fixture: LiveFixture = serde_json::from_str(LIVE_ATTESTATION).unwrap();
    let nonce = bytes::<32>(&fixture.nonce);
    let evidence = || serde_json::from_value::<Evidence>(fixture.attestation.clone()).unwrap();
    let file: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../prover/tee/testdata/live_policy.json"
    ))
    .unwrap();
    let policy: TeePolicy = serde_json::from_value(file["deployment"].clone()).unwrap();
    let prover = verify(evidence(), &policy, &nonce, fixture.captured_at).unwrap();
    assert!(prover.gpu_verified);
    assert!(matches!(
        verify(evidence(), &policy, &[0; 32], fixture.captured_at),
        Err(TeeError::ReportDataMismatch)
    ));
}

#[derive(Deserialize)]
struct Vectors {
    ikm: String,
    hpke_public_key: String,
    nonce: String,
    gpu_token: String,
    report_data: String,
    report_data_no_gpu: String,
    method: String,
    request_uri: String,
    enc: String,
    ciphertext: String,
    plaintext: String,
    response_key: String,
    response_status: u16,
    response_body: String,
    sealed_response: String,
    aad_cases: Vec<AadCase>,
}

#[derive(Deserialize)]
struct AadCase {
    method: String,
    request_target: String,
    aad: String,
}

#[test]
fn the_aad_drops_every_credential_as_the_go_prover_does() {
    let v: Vectors = serde_json::from_str(VECTORS).unwrap();
    assert!(!v.aad_cases.is_empty());
    for case in v.aad_cases {
        assert_eq!(
            request_aad(&case.method, &case.request_target),
            case.aad,
            "{}",
            case.request_target
        );
    }
}

fn bytes<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value).unwrap().try_into().unwrap()
}

#[test]
fn report_data_matches_the_go_prover() {
    let v: Vectors = serde_json::from_str(VECTORS).unwrap();
    let nonce = bytes::<32>(&v.nonce);
    let key = bytes::<32>(&v.hpke_public_key);
    assert_eq!(
        hex::encode(report_data(&nonce, &key, Some(v.gpu_token.as_bytes()))),
        v.report_data
    );
    assert_eq!(
        hex::encode(report_data(&nonce, &key, None)),
        v.report_data_no_gpu
    );
}

/// Opens what the Go prover's own client half sealed, so suite, info, AAD,
/// exporter label and response framing agree across the two implementations.
#[test]
fn sealing_interoperates_with_the_go_prover() {
    let v: Vectors = serde_json::from_str(VECTORS).unwrap();
    let (private_key, public_key) = X25519HkdfSha256::derive_keypair(&hex::decode(&v.ikm).unwrap());
    assert_eq!(hex::encode(public_key.to_bytes()), v.hpke_public_key);

    let encapped =
        <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&hex::decode(&v.enc).unwrap()).unwrap();
    let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &private_key,
        &encapped,
        HPKE_INFO,
    )
    .unwrap();
    let aad = request_aad(&v.method, &v.request_uri);
    let plaintext = receiver
        .open(&hex::decode(&v.ciphertext).unwrap(), aad.as_bytes())
        .unwrap();
    assert_eq!(plaintext, v.plaintext.as_bytes());
    let mut response_key = [0u8; 32];
    receiver.export(RESPONSE_EXPORT, &mut response_key).unwrap();
    assert_eq!(hex::encode(response_key), v.response_key);

    let (status, body) =
        open_response(&response_key, &hex::decode(&v.sealed_response).unwrap()).unwrap();
    assert_eq!(
        (status, body.as_slice()),
        (v.response_status, v.response_body.as_bytes())
    );
}

#[test]
fn a_sealed_request_opens_only_on_its_route() {
    let v: Vectors = serde_json::from_str(VECTORS).unwrap();
    let (private_key, public_key) = X25519HkdfSha256::derive_keypair(&hex::decode(&v.ikm).unwrap());
    let sealed = SealedRequest::seal(
        &public_key.to_bytes().into(),
        "GET",
        "/prove/merge/status?jobId=a",
        b"",
    )
    .unwrap();
    let open_on = |uri: &str| {
        let encapped =
            <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&hex::decode(&sealed.enc).unwrap())
                .unwrap();
        let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &private_key,
            &encapped,
            HPKE_INFO,
        )
        .unwrap();
        receiver
            .open(&sealed.body, format!("GET {uri}").as_bytes())
            .is_ok()
    };
    assert!(open_on("/prove/merge/status?jobId=a"));
    assert!(!open_on("/prove/merge/status?jobId=b"));
}

#[test]
fn sealed_responses_reject_tampering_and_truncation() {
    let v: Vectors = serde_json::from_str(VECTORS).unwrap();
    let key = bytes::<32>(&v.response_key);
    let sealed = hex::decode(&v.sealed_response).unwrap();
    assert_eq!(sealed.len(), 12 + 2 + v.response_body.len() + 16);
    for offset in [0, 12, sealed.len() - 1] {
        let mut tampered = sealed.clone();
        tampered[offset] ^= 1;
        assert!(open_response(&key, &tampered).is_err());
    }
    for end in 0..sealed.len() {
        assert!(open_response(&key, &sealed[..end]).is_err());
    }
    assert!(open_response(&key, &sealed[12..]).is_err());
    let mut wrong_key = key;
    wrong_key[0] ^= 1;
    assert!(open_response(&wrong_key, &sealed).is_err());
}

#[test]
fn the_release_policy_matches_its_pin_file() {
    let file: serde_json::Value = serde_json::from_str(include_str!("policy.json")).unwrap();
    if file["deployment"].is_null() {
        assert!(matches!(
            TeePolicy::pinned(),
            Err(TeeError::NoPinnedDeployment)
        ));
    } else {
        let expected: TeePolicy = serde_json::from_value(file["deployment"].clone()).unwrap();
        assert_eq!(TeePolicy::pinned().unwrap(), expected);
    }
}
