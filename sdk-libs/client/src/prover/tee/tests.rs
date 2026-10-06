use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeR,
    Serializable,
};
use serde::Deserialize;

use super::{
    dstack::{DstackEvidence, DstackPolicy},
    encryption::{decrypt_response, request_aad},
    platform::Evidence,
    verify,
    verify::report_data,
    Attestation, EncryptedRequest, Platform, PlatformPolicy, TeeError, TeePolicy, TeePolicyFile,
    HPKE_INFO, RESPONSE_EXPORT,
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
fn probe() -> (Attestation, TeePolicy, u64) {
    let fixture: ProbeFixture = serde_json::from_str(PROBE_ATTESTATION).unwrap();
    let attestation = serde_json::from_value(fixture.attestation).unwrap();
    (
        attestation,
        TeePolicy::from_json(PROBE_POLICY).unwrap(),
        fixture.captured_at,
    )
}

fn nitro_policy() -> serde_json::Value {
    serde_json::json!({
        "platform": "aws-nitro",
        "measurements": [{"pcr0": "01".repeat(48), "pcr1": "02".repeat(48), "pcr2": "03".repeat(48)}],
        "gpu": "optional",
        "max_age_secs": 60,
    })
}

fn dstack_pins(policy: &mut TeePolicy) -> &mut DstackPolicy {
    match &mut policy.pins {
        PlatformPolicy::DstackTdx(pins) => pins,
        pins => panic!("{} policy", pins.platform()),
    }
}

fn dstack_evidence(attestation: &mut Attestation) -> &mut DstackEvidence {
    match &mut attestation.evidence {
        Evidence::DstackTdx(evidence) => evidence,
        Evidence::AwsNitro(_) => panic!("Nitro evidence"),
    }
}

#[test]
fn a_real_quote_passes_every_check_before_report_data() {
    let (attestation, policy, now) = probe();
    assert!(matches!(
        verify(attestation, &policy, &[0x22; 32], now),
        Err(TeeError::ReportDataMismatch)
    ));
}

#[test]
fn each_policy_check_refuses_with_its_own_error() {
    type Edit = fn(&mut Attestation, &mut TeePolicy, &mut u64);
    type Expected = fn(&TeeError) -> bool;
    let cases: [(&str, Edit, Expected); 11] = [
        (
            "quote signature",
            |e, _, _| dstack_evidence(e).quote[700] ^= 1,
            |e| matches!(e, TeeError::Quote(_)),
        ),
        (
            "collateral expired",
            |_, _, now| *now += 400 * 86_400,
            |e| matches!(e, TeeError::Quote(_)),
        ),
        (
            "tcb status",
            |_, p, _| dstack_pins(p).tcb_statuses.clear(),
            |e| matches!(e, TeeError::TcbStatus { .. }),
        ),
        (
            "os measurement",
            |_, p, _| dstack_pins(p).measurements[0].rtmr1[0] ^= 1,
            |e| matches!(e, TeeError::MeasurementNotAllowed),
        ),
        (
            "swapped event payload",
            |e, _, _| {
                let event = dstack_evidence(e)
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
            |_, p, _| dstack_pins(p).app_id[0] ^= 1,
            |e| matches!(e, TeeError::AppIdMismatch(_)),
        ),
        (
            "compose hash",
            |_, p, _| dstack_pins(p).compose_hashes.clear(),
            |e| matches!(e, TeeError::ComposeHashNotAllowed(_)),
        ),
        (
            "os image",
            |_, p, _| dstack_pins(p).os_image_hashes.clear(),
            |e| matches!(e, TeeError::OsImageNotAllowed(_)),
        ),
        (
            "key provider",
            |_, p, _| dstack_pins(p).key_provider_id.clear(),
            |e| matches!(e, TeeError::KeyProviderMismatch),
        ),
        (
            "hpke key",
            |_, p, _| dstack_pins(p).hpke_public_key[0] ^= 1,
            |e| matches!(e, TeeError::HpkeKeyMismatch),
        ),
        (
            "platform",
            |_, p, _| *p = TeePolicy::from_json(&nitro_policy().to_string()).unwrap(),
            |e| matches!(e, TeeError::PlatformMismatch { .. }),
        ),
    ];
    for (name, edit, expected) in cases {
        let (mut attestation, mut policy, mut now) = probe();
        edit(&mut attestation, &mut policy, &mut now);
        let error = verify(attestation, &policy, &[0x22; 32], now).unwrap_err();
        assert!(expected(&error), "{name}: {error}");
    }
}

#[derive(Deserialize)]
struct LiveFixture {
    captured_at: u64,
    nonce: String,
    attestation: serde_json::Value,
}

/// A live Nitro enclave's answer, signed by the real AWS chain.
#[test]
fn the_live_nitro_enclave_passes_the_aws_chain_and_its_pinned_image() {
    let fixture: LiveFixture = serde_json::from_str(include_str!(
        "../../../../../prover/tee/testdata/nitro_live_attestation.json"
    ))
    .unwrap();
    let nonce = bytes::<32>(&fixture.nonce);
    let attestation =
        || serde_json::from_value::<Attestation>(fixture.attestation.clone()).unwrap();
    let file: TeePolicyFile = serde_json::from_str(include_str!(
        "../../../../../prover/tee/testdata/nitro_live_policy.json"
    ))
    .unwrap();
    let policy = file.deployment.unwrap();
    let prover = verify(attestation(), &policy, &nonce, fixture.captured_at).unwrap();
    assert_eq!(prover.platform, Platform::AwsNitro);
    assert!(!prover.gpu_verified);
    assert!(verify(attestation(), &policy, &[0; 32], fixture.captured_at).is_err());
}

/// A live H200 prover's answer to a recorded nonce, quote and GPU verdict included.
#[test]
fn the_archived_deployment_accepts_its_attestation() {
    let fixture: LiveFixture = serde_json::from_str(LIVE_ATTESTATION).unwrap();
    let nonce = bytes::<32>(&fixture.nonce);
    let attestation =
        || serde_json::from_value::<Attestation>(fixture.attestation.clone()).unwrap();
    let file: TeePolicyFile = serde_json::from_str(include_str!(
        "../../../../../prover/tee/testdata/live_policy.json"
    ))
    .unwrap();
    let policy = file.deployment.unwrap();
    let prover = verify(attestation(), &policy, &nonce, fixture.captured_at).unwrap();
    assert!(prover.gpu_verified);
    assert_eq!(prover.platform, Platform::DstackTdx);
    assert_eq!(prover.tcb_status.as_deref(), Some("UpToDate"));
    let PlatformPolicy::DstackTdx(pins) = policy.pins() else {
        panic!("not a dstack policy");
    };
    assert!(pins
        .compose_hashes
        .iter()
        .any(|hash| hash[..] == prover.image_id));
    assert!(matches!(
        verify(attestation(), &policy, &[0; 32], fixture.captured_at),
        Err(TeeError::ReportDataMismatch)
    ));
}

#[test]
fn a_policy_names_its_platform_and_only_that_platforms_pins() {
    let probe: serde_json::Value = serde_json::from_str(PROBE_POLICY).unwrap();
    let nitro = nitro_policy();
    for policy in [&probe, &nitro] {
        let parsed = TeePolicy::from_json(&policy.to_string()).unwrap();
        assert_eq!(policy["platform"], parsed.platform().as_str());
    }
    let refused = |base: &serde_json::Value, key: &str, value: serde_json::Value| {
        let mut edited = base.clone();
        match value {
            serde_json::Value::Null => edited.as_object_mut().unwrap().remove(key),
            value => edited.as_object_mut().unwrap().insert(key.into(), value),
        };
        assert!(
            matches!(
                TeePolicy::from_json(&edited.to_string()),
                Err(TeeError::Policy(_))
            ),
            "{key}"
        );
    };
    refused(&probe, "pcr0", nitro["measurements"][0]["pcr0"].clone());
    refused(&nitro, "app_id", probe["app_id"].clone());
    refused(&nitro, "measurements", probe["measurements"].clone());
    refused(&probe, "platform", "aws-nitro".into());
    refused(&probe, "platform", "amd-sev-snp".into());
    refused(&probe, "platform", serde_json::Value::Null);
    refused(&nitro, "unknown", true.into());
}

#[test]
fn every_parse_path_refuses_a_gpu_the_platform_cannot_attest() {
    let mut policy = nitro_policy();
    policy["gpu"] = "required".into();
    assert!(matches!(
        TeePolicy::from_json(&policy.to_string()),
        Err(TeeError::Policy(_))
    ));
    assert!(serde_json::from_value::<TeePolicy>(policy.clone()).is_err());
    let file = serde_json::json!({ "deployment": policy });
    assert!(serde_json::from_value::<TeePolicyFile>(file).is_err());
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
    encrypted_response: String,
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

/// Decrypts what the Go prover's own client half encrypted, so suite, info, AAD,
/// exporter label and response framing agree across the two implementations.
#[test]
fn encryption_interoperates_with_the_go_prover() {
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
        decrypt_response(&response_key, &hex::decode(&v.encrypted_response).unwrap()).unwrap();
    assert_eq!(
        (status, body.as_slice()),
        (v.response_status, v.response_body.as_bytes())
    );
}

#[test]
fn an_encrypted_request_decrypts_only_on_its_route() {
    let v: Vectors = serde_json::from_str(VECTORS).unwrap();
    let (private_key, public_key) = X25519HkdfSha256::derive_keypair(&hex::decode(&v.ikm).unwrap());
    let encrypted = EncryptedRequest::encrypt(
        &public_key.to_bytes().into(),
        "GET",
        "/prove/merge/status?jobId=a",
        b"",
    )
    .unwrap();
    let open_on = |uri: &str| {
        let encapped = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(
            &hex::decode(&encrypted.enc).unwrap(),
        )
        .unwrap();
        let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &private_key,
            &encapped,
            HPKE_INFO,
        )
        .unwrap();
        receiver
            .open(&encrypted.body, format!("GET {uri}").as_bytes())
            .is_ok()
    };
    assert!(open_on("/prove/merge/status?jobId=a"));
    assert!(!open_on("/prove/merge/status?jobId=b"));
}

#[test]
fn encrypted_responses_reject_tampering_and_truncation() {
    let v: Vectors = serde_json::from_str(VECTORS).unwrap();
    let key = bytes::<32>(&v.response_key);
    let encrypted = hex::decode(&v.encrypted_response).unwrap();
    assert_eq!(encrypted.len(), 12 + 2 + v.response_body.len() + 16);
    for offset in [0, 12, encrypted.len() - 1] {
        let mut tampered = encrypted.clone();
        tampered[offset] ^= 1;
        assert!(decrypt_response(&key, &tampered).is_err());
    }
    for end in 0..encrypted.len() {
        assert!(decrypt_response(&key, &encrypted[..end]).is_err());
    }
    assert!(decrypt_response(&key, &encrypted[12..]).is_err());
    let mut wrong_key = key;
    wrong_key[0] ^= 1;
    assert!(decrypt_response(&wrong_key, &encrypted).is_err());
}

#[test]
fn the_release_policy_matches_its_pin_file() {
    let file: TeePolicyFile = serde_json::from_str(include_str!("policy.json")).unwrap();
    match file.deployment {
        None => assert!(matches!(
            TeePolicy::default_deployment(),
            Err(TeeError::NoDefaultDeployment)
        )),
        Some(expected) => assert_eq!(TeePolicy::default_deployment().unwrap(), expected),
    }
}
