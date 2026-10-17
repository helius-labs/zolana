use std::{str::FromStr, time::Duration};

use ciborium::Value;
use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use p384::ecdsa::{
    signature::{self, Keypair, Signer},
    DerSignature, Signature, SigningKey, VerifyingKey,
};
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

use super::{NitroMeasurement, NitroPolicy};
use crate::{platform::Anchors, verify::report_data, PlatformPolicy, TeePolicy};
#[cfg(test)]
use crate::{
    verify::{Session, Trust},
    Attestation, AttestedProver, TeeError,
};

pub(crate) const NOW: u64 = 1_800_000_000;
pub(crate) const DAY: u64 = 86_400;
pub(crate) const NONCE: [u8; 32] = [0x11; 32];
pub(crate) const HPKE_PUBLIC_KEY: [u8; 32] = [0x22; 32];
pub(crate) const REBOOTED_HPKE_PUBLIC_KEY: [u8; 32] = [0x44; 32];
pub(crate) const ROOT: &str = "CN=root";
pub(crate) const INTERMEDIATE: &str = "CN=intermediate";

/// One synthetic enclave answer, valid until a case edits it.
pub struct Fixture {
    pub(crate) now: u64,
    pub(crate) nonce: [u8; 32],
    pub(crate) measurement: NitroMeasurement,
    pub(crate) trusted_root_seed: u8,
    pub(crate) intermediate_is_ca: bool,
    pub(crate) leaf_not_before: u64,
    pub(crate) leaf_not_after: u64,
    pub(crate) leaf_usage: Option<KeyUsages>,
    pub(crate) leaf_critical_extension: bool,
    pub(crate) alg: iana::Algorithm,
    pub(crate) tagged: bool,
    pub(crate) flip_signature: bool,
    pub(crate) document_nonce: [u8; 32],
    pub(crate) hpke_public_key: [u8; 32],
    pub(crate) public_key: [u8; 32],
    pub(crate) user_data: [u8; 64],
    pub(crate) edit_document: fn(&mut Vec<(Value, Value)>),
    pub(crate) edit_encoding: fn(Vec<u8>) -> Vec<u8>,
    pub(crate) edit_cose: fn(Vec<u8>) -> Vec<u8>,
    pub(crate) gpu: Option<String>,
    pub(crate) policy: TeePolicy,
}

impl Default for Fixture {
    fn default() -> Self {
        Self::at(NONCE, NOW)
    }
}

impl Fixture {
    /// An answer to `nonce` whose certificates are valid around `now`.
    pub fn at(nonce: [u8; 32], now: u64) -> Self {
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

    pub fn pinning_key(mut self) -> Self {
        let PlatformPolicy::AwsNitro(pins) = &mut self.policy.pins else {
            unreachable!()
        };
        pins.hpke_public_key = Some(HPKE_PUBLIC_KEY);
        self
    }

    /// Attests `key` in place of the fixture's constant, for a prover that
    /// holds the matching secret.
    pub fn with_hpke_public_key(mut self, key: [u8; 32]) -> Self {
        self.hpke_public_key = key;
        self.public_key = key;
        self.user_data = report_data(&self.nonce, &key, None);
        self
    }

    pub fn rebooted(mut self) -> Self {
        self.hpke_public_key = REBOOTED_HPKE_PUBLIC_KEY;
        self.public_key = REBOOTED_HPKE_PUBLIC_KEY;
        self.user_data = report_data(&self.nonce, &REBOOTED_HPKE_PUBLIC_KEY, None);
        self
    }

    pub fn policy(&self) -> &TeePolicy {
        &self.policy
    }

    pub fn attestation_json(&self) -> serde_json::Value {
        serde_json::json!({
            "platform": "aws-nitro",
            "hpke_public_key": hex::encode(self.hpke_public_key),
            "gpu": self.gpu,
            "evidence": { "document": hex::encode(self.document()) },
        })
    }

    /// The fixture root in place of the AWS root.
    pub fn anchors(&self) -> Anchors {
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

    #[cfg(test)]
    pub(crate) fn verify(&self) -> Result<AttestedProver, TeeError> {
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

    #[cfg(test)]
    pub(crate) fn attestation(&self) -> Attestation {
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

pub(crate) struct Issue<'a> {
    pub(crate) subject: &'a str,
    pub(crate) key: &'a SigningKey,
    /// The issuer name and key, `None` for a self-signed root.
    pub(crate) parent: Option<(&'a str, &'a SigningKey)>,
    pub(crate) ca: bool,
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
    pub(crate) usage: Option<KeyUsages>,
    pub(crate) critical_extension: bool,
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

pub(crate) fn issue(issue: Issue<'_>) -> Vec<u8> {
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

pub(crate) fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 48]).unwrap()
}

fn utc(secs: u64) -> Time {
    Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(secs)).unwrap())
}

pub(crate) fn text(key: &str, value: Value) -> (Value, Value) {
    (Value::Text(key.into()), value)
}
