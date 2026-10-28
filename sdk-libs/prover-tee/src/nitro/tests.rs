use ciborium::Value;
use coset::{iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use p384::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use x509_cert::ext::pkix::KeyUsages;

use super::fixture::{text, Fixture, HPKE_PUBLIC_KEY, NONCE, NOW};
use super::{NitroPolicy, AWS_NITRO_ROOT_G1, NOT_BEFORE_SKEW_SECS};
use crate::{
    platform::Anchors,
    verify,
    verify::{Session, Trust},
    Attestation, GpuRequirement, PlatformPolicy, TeeError, TeePolicy,
};

fn set(fields: &mut [(Value, Value)], name: &str, value: Value) {
    fields
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some(name))
        .unwrap()
        .1 = value;
}

fn remove(fields: &mut Vec<(Value, Value)>, name: &str) {
    fields.retain(|(key, _)| key.as_text() != Some(name));
}

fn pcrs(fields: &mut [(Value, Value)]) -> &mut Vec<(Value, Value)> {
    fields
        .iter_mut()
        .find_map(|(key, pcrs)| (key.as_text() == Some("pcrs")).then_some(pcrs))
        .and_then(Value::as_map_mut)
        .unwrap()
}

fn says(error: &TeeError, reason: &str) -> bool {
    matches!(error, TeeError::NitroDocument(message) if message.contains(reason))
}

fn trailing(mut encoded: Vec<u8>) -> Vec<u8> {
    encoded.push(0);
    encoded
}

#[test]
fn the_embedded_root_is_aws_nitro_enclaves_root_g1() {
    assert_eq!(
        hex::encode(Sha256::digest(AWS_NITRO_ROOT_G1)),
        "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
    );
}

#[test]
fn a_valid_document_passes_tagged_or_not() {
    for tagged in [true, false] {
        let prover = Fixture {
            tagged,
            ..Fixture::default()
        }
        .verify()
        .unwrap();
        assert_eq!(prover.hpke_public_key, HPKE_PUBLIC_KEY);
        assert_eq!(prover.image_id, [1; 48]);
        assert_eq!(prover.tcb_status, None);
        assert!(!prover.gpu_verified);
    }
}

#[test]
fn production_verification_trusts_only_the_aws_root() {
    let fixture = Fixture::default();
    assert!(matches!(
        verify(fixture.attestation(), &fixture.policy, &NONCE, NOW),
        Err(TeeError::NitroDocument(_))
    ));
}

#[test]
fn each_nitro_check_refuses_with_its_own_error() {
    type Edit = fn(&mut Fixture);
    type Expected = fn(&TeeError) -> bool;
    let document = |e: &TeeError| matches!(e, TeeError::NitroDocument(_));
    let cases: &[(&str, Edit, Expected)] = &[
        ("tampered signature", |f| f.flip_signature = true, document),
        (
            "leaf may not sign",
            |f| f.leaf_usage = Some(KeyUsages::KeyCertSign),
            document,
        ),
        (
            "leaf notBefore beyond the skew",
            |f| f.leaf_not_before = NOW + NOT_BEFORE_SKEW_SECS + 1,
            document,
        ),
        (
            "module_id missing",
            |f| f.edit_document = |d| remove(d, "module_id"),
            document,
        ),
        (
            "module_id empty",
            |f| f.edit_document = |d| set(d, "module_id", Value::Text(String::new())),
            document,
        ),
        (
            "module_id not text",
            |f| f.edit_document = |d| set(d, "module_id", Value::Integer(7.into())),
            document,
        ),
        (
            "timestamp missing",
            |f| f.edit_document = |d| remove(d, "timestamp"),
            document,
        ),
        (
            "timestamp negative",
            |f| f.edit_document = |d| set(d, "timestamp", Value::Integer((-1).into())),
            document,
        ),
        (
            "timestamp not an integer",
            |f| f.edit_document = |d| set(d, "timestamp", Value::Float(1.0)),
            |e| says(e, "a float"),
        ),
        (
            "repeated document key",
            |f| {
                f.edit_document =
                    |d| d.extend([text("extra", Value::Null), text("extra", Value::Null)])
            },
            document,
        ),
        (
            "repeated user_data",
            |f| f.edit_document = |d| d.push(text("user_data", Value::Bytes(vec![0; 64]))),
            document,
        ),
        (
            "repeated pcr index",
            |f| f.edit_document = |d| pcrs(d).push((0.into(), Value::Bytes(vec![9; 48]))),
            |e| says(e, "pcrs repeats"),
        ),
        (
            "pcr index 32",
            |f| f.edit_document = |d| pcrs(d).push((32.into(), Value::Bytes(vec![9; 48]))),
            |e| says(e, "below 32"),
        ),
        (
            "over 32 pcrs",
            |f| {
                f.edit_document = |d| {
                    pcrs(d).extend((4..=32).map(|index| (index.into(), Value::Bytes(vec![0; 48]))))
                }
            },
            |e| says(e, "pcrs has over 32"),
        ),
        (
            "over 16 document entries",
            |f| f.edit_document = |d| d.extend((0..8).map(|index| (index.into(), Value::Null))),
            |e| says(e, "the document has over 16"),
        ),
        (
            "over 8 cabundle certificates",
            |f| {
                f.edit_document = |d| {
                    let Some(Value::Array(bundle)) = d.iter_mut().find_map(|(key, bundle)| {
                        (key.as_text() == Some("cabundle")).then_some(bundle)
                    }) else {
                        unreachable!()
                    };
                    bundle.extend(vec![Value::Bytes(vec![0; 8]); 7]);
                }
            },
            |e| says(e, "cabundle has over 8"),
        ),
        (
            "byte string key",
            |f| f.edit_document = |d| d.push((Value::Bytes(vec![1]), Value::Null)),
            |e| says(e, "not text or integer"),
        ),
        (
            "nested repeated key",
            |f| {
                f.edit_document = |d| {
                    d.push(text(
                        "extra",
                        Value::Map(vec![text("a", Value::Null), text("a", Value::Null)]),
                    ))
                }
            },
            |e| says(e, "repeats a key"),
        ),
        (
            "nested float",
            |f| f.edit_document = |d| d.push(text("extra", Value::Array(vec![Value::Float(1.0)]))),
            |e| says(e, "a float"),
        ),
        (
            "nested tag",
            |f| {
                f.edit_document = |d| {
                    d.push(text(
                        "extra",
                        Value::Tag(1, Box::new(Value::Integer(1.into()))),
                    ))
                }
            },
            |e| says(e, "a tag"),
        ),
        (
            "tagged timestamp",
            |f| {
                f.edit_document = |d| {
                    set(
                        d,
                        "timestamp",
                        Value::Tag(1, Box::new(Value::Integer(1.into()))),
                    )
                }
            },
            |e| says(e, "a tag"),
        ),
        (
            "timestamp 2^53",
            |f| f.edit_document = |d| set(d, "timestamp", Value::Integer((1u64 << 53).into())),
            |e| says(e, "beyond 2^53"),
        ),
        (
            "certificate as text",
            |f| f.edit_document = |d| set(d, "certificate", Value::Text("00".into())),
            |e| says(e, "certificate is not a byte string"),
        ),
        (
            "user_data as an array of bytes",
            |f| {
                f.edit_document = |d| {
                    set(
                        d,
                        "user_data",
                        Value::Array(vec![Value::Integer(0.into()); 64]),
                    )
                }
            },
            |e| says(e, "user_data is not a byte string"),
        ),
        (
            "module_id as bytes",
            |f| f.edit_document = |d| set(d, "module_id", Value::Bytes(b"i-0123".to_vec())),
            |e| says(e, "module_id is not a text string"),
        ),
        (
            "digest as bytes",
            |f| f.edit_document = |d| set(d, "digest", Value::Bytes(b"SHA384".to_vec())),
            |e| says(e, "digest is not a text string"),
        ),
        (
            "trailing bytes after the document",
            |f| f.edit_encoding = trailing,
            |e| says(e, "trailing bytes"),
        ),
        (
            "trailing bytes after the tagged COSE_Sign1",
            |f| f.edit_cose = trailing,
            |e| says(e, "trailing bytes"),
        ),
        (
            "trailing bytes after the untagged COSE_Sign1",
            |f| {
                f.tagged = false;
                f.edit_cose = trailing;
            },
            |e| says(e, "trailing bytes"),
        ),
        ("wrong root", |f| f.trusted_root_seed = 4, document),
        (
            "intermediate not a CA",
            |f| f.intermediate_is_ca = false,
            document,
        ),
        ("expired leaf", |f| f.leaf_not_after = NOW - 1, document),
        (
            "unknown critical extension",
            |f| f.leaf_critical_extension = true,
            document,
        ),
        ("wrong alg", |f| f.alg = iana::Algorithm::ES256, document),
        (
            "pcr not allowed",
            |f| f.measurement.pcr2[0] ^= 1,
            |e| matches!(e, TeeError::EnclaveMeasurementNotAllowed),
        ),
        (
            "zero pcr0",
            |f| {
                f.measurement.pcr0 = [0; 48];
                f.policy = TeePolicy::new(PlatformPolicy::AwsNitro(NitroPolicy {
                    measurements: vec![f.measurement.clone()],
                    hpke_public_key: None,
                }));
            },
            document,
        ),
        ("nonce", |f| f.document_nonce[0] ^= 1, |e| says(e, "nonce")),
        (
            "user_data",
            |f| f.user_data[0] ^= 1,
            |e| matches!(e, TeeError::ReportDataMismatch),
        ),
        ("public_key", |f| f.public_key[0] ^= 1, document),
        (
            "gpu",
            |f| f.gpu = Some("nras".into()),
            |e| matches!(e, TeeError::MalformedAttestation(m) if m.contains("gpu must be null")),
        ),
        (
            "gpu with an unpinned image",
            |f| {
                f.gpu = Some("nras".into());
                f.measurement.pcr2[0] ^= 1;
            },
            |e| matches!(e, TeeError::MalformedAttestation(m) if m.contains("gpu must be null")),
        ),
        (
            "platform",
            |f| {
                f.policy = TeePolicy::from_json(include_str!(
                    "../../../../prover/tee/testdata/probe_policy.json"
                ))
                .unwrap();
            },
            |e| matches!(e, TeeError::PlatformMismatch { .. }),
        ),
        (
            "measurement allowlist empty",
            |f| f.policy = TeePolicy::new(PlatformPolicy::AwsNitro(NitroPolicy::default())),
            |e| matches!(e, TeeError::EnclaveMeasurementNotAllowed),
        ),
    ];
    for (name, edit, expected) in cases {
        let mut fixture = Fixture::default();
        edit(&mut fixture);
        let error = fixture.verify().unwrap_err();
        assert!(expected(&error), "{name}: {error}");
    }
}

#[test]
fn a_document_passes_at_each_tolerated_edge() {
    type Edit = fn(&mut Fixture);
    let cases: [(&str, Edit); 7] = [
        ("leaf notBefore at the skew", |f| {
            f.leaf_not_before = NOW + NOT_BEFORE_SKEW_SECS;
        }),
        ("leaf notAfter now", |f| f.leaf_not_after = NOW),
        ("leaf without key usage", |f| f.leaf_usage = None),
        ("pcr index 31", |f| {
            f.edit_document = |d| pcrs(d).push((31.into(), Value::Bytes(vec![0; 48])));
        }),
        ("timestamp 2^53 minus 1", |f| {
            f.edit_document = |d| set(d, "timestamp", Value::Integer(((1u64 << 53) - 1).into()));
        }),
        ("unknown integer keyed entry", |f| {
            f.edit_document = |d| d.push((7.into(), Value::Text("extra".into())));
        }),
        ("non-minimal map length", |f| {
            f.edit_encoding = |encoded| {
                let (&header, rest) = encoded.split_first().unwrap();
                assert_eq!(header, 0xa9);
                [&[0xb8, 0x09], rest].concat()
            };
        }),
    ];
    for (name, edit) in cases {
        let mut fixture = Fixture::default();
        edit(&mut fixture);
        assert!(fixture.verify().is_ok(), "{name}");
    }
}

#[test]
fn a_key_pin_admits_only_the_pinned_key() {
    let prover = Fixture::default().pinning_key().verify().unwrap();
    assert_eq!(prover.hpke_public_key, HPKE_PUBLIC_KEY);
    assert!(Fixture::default().rebooted().verify().is_ok());
    assert!(matches!(
        Fixture::default().pinning_key().rebooted().verify(),
        Err(TeeError::HpkeKeyMismatch)
    ));
}

#[test]
fn a_nitro_policy_cannot_require_a_gpu() {
    let fixture = Fixture::default();
    assert!(matches!(
        fixture.policy.clone().with_gpu(GpuRequirement::Required),
        Err(TeeError::Policy(_))
    ));
}

#[test]
fn inspect_refuses_gpu_evidence_from_a_platform_without_a_gpu() {
    let fixture = Fixture {
        gpu: Some("nras".into()),
        ..Fixture::default()
    };
    let trust = Trust {
        now_secs: NOW,
        anchors: &fixture.anchors(),
    };
    assert!(matches!(
        trust.inspect(fixture.attestation()),
        Err(TeeError::MalformedAttestation(m)) if m.contains("gpu must be null")
    ));
}

#[test]
fn an_attestation_without_a_gpu_field_is_refused() {
    let mut attestation = Fixture::default().attestation_json();
    attestation.as_object_mut().unwrap().remove("gpu");
    assert!(serde_json::from_value::<Attestation>(attestation).is_err());
}

#[derive(Deserialize)]
struct SharedCases {
    now: u64,
    #[serde(with = "hex")]
    nonce: [u8; 32],
    #[serde(with = "hex")]
    hpke_public_key: [u8; 32],
    policy: TeePolicy,
    #[serde(with = "hex")]
    root: Vec<u8>,
    #[serde(with = "hex")]
    leaf_key: Vec<u8>,
    cases: Vec<SharedCase>,
}

#[derive(Deserialize)]
struct SharedCase {
    name: String,
    #[serde(flatten)]
    bytes: CaseBytes,
    expect: Expect,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum CaseBytes {
    /// Signed by `leaf_key` into a tagged COSE_Sign1.
    Payload(#[serde(with = "hex")] Vec<u8>),
    Cose(#[serde(with = "hex")] Vec<u8>),
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
enum Expect {
    Accept,
    Reject,
}

#[test]
fn the_shared_cbor_cases_pass_or_fail_as_pinned() {
    let shared: SharedCases = serde_json::from_str(include_str!(
        "../../../../prover/tee/testdata/nitro_cbor_cases.json"
    ))
    .unwrap();
    let leaf = SigningKey::from_slice(&shared.leaf_key).unwrap();
    let anchors = Anchors {
        nitro: Box::leak(shared.root.into_boxed_slice()),
        ..Anchors::PRODUCTION
    };
    let trust = Trust {
        now_secs: shared.now,
        anchors: &anchors,
    };
    for case in shared.cases {
        let document = match case.bytes {
            CaseBytes::Cose(document) => document,
            CaseBytes::Payload(payload) => CoseSign1Builder::new()
                .protected(
                    HeaderBuilder::new()
                        .algorithm(iana::Algorithm::ES384)
                        .build(),
                )
                .payload(payload)
                .create_signature(b"", |signed| {
                    let signature: Signature = leaf.sign(signed);
                    signature.to_bytes().to_vec()
                })
                .build()
                .to_tagged_vec()
                .unwrap(),
        };
        let attestation = serde_json::from_value(serde_json::json!({
            "platform": "aws-nitro",
            "hpke_public_key": hex::encode(shared.hpke_public_key),
            "gpu": null,
            "evidence": { "document": hex::encode(document) },
        }))
        .unwrap();
        let verdict = trust.verify(
            attestation,
            Session {
                policy: &shared.policy,
                nonce: &shared.nonce,
            },
        );
        match (case.expect, verdict) {
            (Expect::Accept, Ok(_)) | (Expect::Reject, Err(TeeError::NitroDocument(_))) => {}
            (expect, verdict) => panic!("{}, expected {expect:?}, got {verdict:?}", case.name),
        }
    }
}

#[test]
fn rotation_preserves_image_and_key_pairs_across_languages() {
    let live: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../prover/tee/testdata/nitro_live_attestation.json"
    ))
    .unwrap();
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../prover/tee/testdata/nitro_rotation_cases.json"
    ))
    .unwrap();
    let nonce: [u8; 32] = hex::decode(live["nonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    for case in cases.as_array().unwrap() {
        let policy = TeePolicy::from_json(&case["policy"].to_string()).unwrap();
        let attestation = serde_json::from_value(live["attestation"].clone()).unwrap();
        let verdict = verify(
            attestation,
            &policy,
            &nonce,
            live["captured_at"].as_u64().unwrap(),
        );
        assert_eq!(
            verdict.is_ok(),
            case["accept"].as_bool().unwrap(),
            "{}: {verdict:?}",
            case["name"]
        );
    }
}
