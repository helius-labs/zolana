use std::{str::FromStr, time::Duration};

use ciborium::Value;
use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use p384::ecdsa::{
    signature::{self, Keypair, Signer},
    DerSignature, Signature, SigningKey, VerifyingKey,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use x509_cert::{
    builder::{profile::BuilderProfile, Builder, CertificateBuilder},
    certificate::TbsCertificate,
    der::{
        asn1::{OctetString, UtcTime},
        oid::db::rfc5912::ECDSA_WITH_SHA_384,
        Encode,
    },
    ext::{
        pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier},
        Extension,
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{
        self, AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, SubjectPublicKeyInfoOwned,
        SubjectPublicKeyInfoRef,
    },
    time::{Time, Validity},
};

use super::{NitroMeasurement, NitroPolicy, AWS_NITRO_ROOT_G1, NOT_BEFORE_SKEW_SECS};
use crate::prover::tee::{
    platform::Anchors,
    verify,
    verify::{report_data, Session, Trust},
    AttestedProver, GpuRequirement, PlatformPolicy, TeeError, TeePolicy, TeeSession,
};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const NONCE: [u8; 32] = [0x11; 32];
const HPKE_PUBLIC_KEY: [u8; 32] = [0x22; 32];
const REBOOTED_HPKE_PUBLIC_KEY: [u8; 32] = [0x44; 32];
const ROOT: &str = "CN=root";
const INTERMEDIATE: &str = "CN=intermediate";

/// One synthetic enclave answer, valid until a case edits it.
pub(crate) struct Fixture {
    now: u64,
    nonce: [u8; 32],
    measurement: NitroMeasurement,
    trusted_root_seed: u8,
    intermediate_is_ca: bool,
    leaf_not_before: u64,
    leaf_not_after: u64,
    leaf_usage: Option<KeyUsages>,
    leaf_critical_extension: bool,
    alg: iana::Algorithm,
    tagged: bool,
    flip_signature: bool,
    document_nonce: [u8; 32],
    hpke_public_key: [u8; 32],
    public_key: [u8; 32],
    user_data: [u8; 64],
    edit_document: fn(&mut Vec<(Value, Value)>),
    edit_encoding: fn(Vec<u8>) -> Vec<u8>,
    edit_cose: fn(Vec<u8>) -> Vec<u8>,
    gpu: Option<String>,
    policy: TeePolicy,
}

impl Default for Fixture {
    fn default() -> Self {
        Self::at(NONCE, NOW)
    }
}

impl Fixture {
    /// An answer to `nonce` whose certificates are valid around `now`.
    pub(crate) fn at(nonce: [u8; 32], now: u64) -> Self {
        let measurement = NitroMeasurement {
            pcr0: [1; 48],
            pcr1: [2; 48],
            pcr2: [3; 48],
        };
        Self {
            now,
            nonce,
            policy: TeePolicy::new(PlatformPolicy::AwsNitro(NitroPolicy {
                measurements: vec![measurement.clone()],
                hpke_public_key: None,
            })),
            measurement,
            trusted_root_seed: 1,
            intermediate_is_ca: true,
            leaf_not_before: now - DAY,
            leaf_not_after: now + DAY,
            leaf_usage: Some(KeyUsages::DigitalSignature),
            leaf_critical_extension: false,
            alg: iana::Algorithm::ES384,
            tagged: true,
            flip_signature: false,
            document_nonce: nonce,
            hpke_public_key: HPKE_PUBLIC_KEY,
            public_key: HPKE_PUBLIC_KEY,
            user_data: report_data(&nonce, &HPKE_PUBLIC_KEY, None),
            edit_document: |_| {},
            edit_encoding: |encoded| encoded,
            edit_cose: |encoded| encoded,
            gpu: None,
        }
    }

    pub(crate) fn pinning_key(mut self) -> Self {
        let PlatformPolicy::AwsNitro(pins) = &mut self.policy.pins else {
            unreachable!()
        };
        pins.hpke_public_key = Some(HPKE_PUBLIC_KEY);
        self
    }

    pub(crate) fn rebooted(mut self) -> Self {
        self.hpke_public_key = REBOOTED_HPKE_PUBLIC_KEY;
        self.public_key = REBOOTED_HPKE_PUBLIC_KEY;
        self.user_data = report_data(&self.nonce, &REBOOTED_HPKE_PUBLIC_KEY, None);
        self
    }

    /// A session trusting the fixture root in place of the AWS root.
    pub(crate) fn session(&self) -> TeeSession {
        TeeSession::trusting(self.policy.clone(), self.anchors())
    }

    pub(crate) fn attestation_json(&self) -> serde_json::Value {
        serde_json::json!({
            "platform": "aws-nitro",
            "hpke_public_key": hex::encode(self.hpke_public_key),
            "gpu": self.gpu,
            "evidence": { "document": hex::encode(self.document()) },
        })
    }

    fn anchors(&self) -> Anchors {
        let root = issue(Issue {
            subject: ROOT,
            key: &key(self.trusted_root_seed),
            parent: None,
            ca: true,
            not_before: self.now - DAY,
            not_after: self.now + DAY,
            usage: Some(KeyUsages::KeyCertSign),
            critical_extension: false,
        });
        Anchors {
            nitro: Box::leak(root.into_boxed_slice()),
            ..Anchors::PRODUCTION
        }
    }

    fn verify(&self) -> Result<AttestedProver, TeeError> {
        Trust {
            now_secs: self.now,
            anchors: &self.anchors(),
        }
        .verify(
            self.attestation(),
            Session {
                policy: &self.policy,
                nonce: &self.nonce,
            },
        )
    }

    fn attestation(&self) -> crate::prover::tee::Attestation {
        serde_json::from_value(self.attestation_json()).unwrap()
    }

    fn document(&self) -> Vec<u8> {
        let (root_key, intermediate_key, leaf_key) = (key(1), key(2), key(3));
        let root = issue(Issue {
            subject: ROOT,
            key: &root_key,
            parent: None,
            ca: true,
            not_before: self.now - DAY,
            not_after: self.now + DAY,
            usage: Some(KeyUsages::KeyCertSign),
            critical_extension: false,
        });
        let intermediate = issue(Issue {
            subject: INTERMEDIATE,
            key: &intermediate_key,
            parent: Some((ROOT, &root_key)),
            ca: self.intermediate_is_ca,
            not_before: self.now - DAY,
            not_after: self.now + DAY,
            usage: Some(KeyUsages::KeyCertSign),
            critical_extension: false,
        });
        let leaf = issue(Issue {
            subject: "CN=enclave",
            key: &leaf_key,
            parent: Some((INTERMEDIATE, &intermediate_key)),
            ca: false,
            not_before: self.leaf_not_before,
            not_after: self.leaf_not_after,
            usage: self.leaf_usage,
            critical_extension: self.leaf_critical_extension,
        });
        let pcrs = [
            &self.measurement.pcr0,
            &self.measurement.pcr1,
            &self.measurement.pcr2,
            &[0; 48],
        ];
        let mut fields = vec![
            text("module_id", Value::Text("i-0123-enc0123".into())),
            text("digest", Value::Text("SHA384".into())),
            text("timestamp", Value::Integer((self.now * 1000).into())),
            text(
                "pcrs",
                Value::Map(
                    (0u8..)
                        .zip(pcrs)
                        .map(|(index, pcr)| (index.into(), Value::Bytes(pcr.to_vec())))
                        .collect(),
                ),
            ),
            text("certificate", Value::Bytes(leaf)),
            text(
                "cabundle",
                Value::Array(vec![Value::Bytes(root), Value::Bytes(intermediate)]),
            ),
            text("public_key", Value::Bytes(self.public_key.to_vec())),
            text("user_data", Value::Bytes(self.user_data.to_vec())),
            text("nonce", Value::Bytes(self.document_nonce.to_vec())),
        ];
        (self.edit_document)(&mut fields);
        let mut encoded = Vec::new();
        ciborium::into_writer(&Value::Map(fields), &mut encoded).unwrap();
        let encoded = (self.edit_encoding)(encoded);
        let mut sign1 = CoseSign1Builder::new()
            .protected(HeaderBuilder::new().algorithm(self.alg).build())
            .payload(encoded)
            .create_signature(b"", |signed| {
                let signature: Signature = leaf_key.sign(signed);
                signature.to_bytes().to_vec()
            })
            .build();
        if self.flip_signature {
            sign1.signature[0] ^= 1;
        }
        (self.edit_cose)(if self.tagged {
            sign1.to_tagged_vec().unwrap()
        } else {
            sign1.to_vec().unwrap()
        })
    }
}

struct Issue<'a> {
    subject: &'a str,
    key: &'a SigningKey,
    /// The issuer name and key, `None` for a self-signed root.
    parent: Option<(&'a str, &'a SigningKey)>,
    ca: bool,
    not_before: u64,
    not_after: u64,
    usage: Option<KeyUsages>,
    critical_extension: bool,
}

/// Names the certificate signature algorithm without the SHA-384 OID feature of sha2.
struct Es384<'a>(&'a SigningKey);

struct Names {
    subject: Name,
    issuer: Name,
}

impl BuilderProfile for Names {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(Vec::new())
    }
}

impl Keypair for Es384<'_> {
    type VerifyingKey = VerifyingKey;

    fn verifying_key(&self) -> VerifyingKey {
        *self.0.verifying_key()
    }
}

impl DynSignatureAlgorithmIdentifier for Es384<'_> {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA_384,
            parameters: None,
        })
    }
}

impl Signer<DerSignature> for Es384<'_> {
    fn try_sign(&self, signed: &[u8]) -> Result<DerSignature, signature::Error> {
        self.0.try_sign(signed)
    }
}

fn issue(issue: Issue<'_>) -> Vec<u8> {
    let (issuer, signer) = issue.parent.unwrap_or((issue.subject, issue.key));
    let validity = Validity::new(utc(issue.not_before), utc(issue.not_after));
    let mut builder = CertificateBuilder::new(
        Names {
            subject: Name::from_str(issue.subject).unwrap(),
            issuer: Name::from_str(issuer).unwrap(),
        },
        SerialNumber::new(&[1]).unwrap(),
        validity,
        SubjectPublicKeyInfoOwned::from_key(issue.key.verifying_key()).unwrap(),
    )
    .unwrap();
    builder
        .add_extension(&BasicConstraints {
            ca: issue.ca,
            path_len_constraint: None,
        })
        .unwrap();
    if let Some(usage) = issue.usage {
        builder.add_extension(&KeyUsage(usage.into())).unwrap();
    }
    if issue.critical_extension {
        let identifier = SubjectKeyIdentifier(OctetString::new(vec![7; 20]).unwrap());
        builder.add_extension((true, &identifier)).unwrap();
    }
    builder
        .build::<_, DerSignature>(&Es384(signer))
        .unwrap()
        .to_der()
        .unwrap()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 48]).unwrap()
}

fn utc(secs: u64) -> Time {
    Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(secs)).unwrap())
}

fn text(key: &str, value: Value) -> (Value, Value) {
    (Value::Text(key.into()), value)
}

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
                    "../../../../../../prover/tee/testdata/probe_policy.json"
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
    assert!(serde_json::from_value::<crate::prover::tee::Attestation>(attestation).is_err());
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
        "../../../../../../prover/tee/testdata/nitro_cbor_cases.json"
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
