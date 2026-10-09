use std::{
    collections::{BTreeMap, HashMap, HashSet},
    iter,
    time::Duration,
};

use ciborium::{value::Integer, Value};
use ciborium_ll::{simple, Decoder, Header};
use coset::{iana, Algorithm, CborSerializable, CoseSign1, TaggedCborSerializable};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use x509_cert::{
    der::{
        oid::{
            db::rfc5912::{ECDSA_WITH_SHA_384, ID_EC_PUBLIC_KEY, SECP_384_R_1},
            AssociatedOid, ObjectIdentifier,
        },
        Decode, Encode,
    },
    ext::pkix::{BasicConstraints, KeyUsage},
    Certificate,
};

use super::{
    platform::TeePlatform,
    policy::hex_pin,
    verify::{Claims, Measured},
    TeeError,
};

/// AWS Nitro Enclaves root G1, SHA-256 of the DER pinned in a test.
const AWS_NITRO_ROOT_G1: &[u8] = include_bytes!("nitro/aws_nitro_enclaves_root_g1.der");
const NOT_BEFORE_SKEW_SECS: u64 = 300;
const MAX_DOCUMENT_FIELDS: usize = 16;
const MAX_PCRS: usize = 32;
const MAX_CABUNDLE: usize = 8;
const MAX_DEPTH: usize = 16;
const REPEATED_KEY: &str = "the document repeats a key or has one not text or integer";
const COSE_SIGN1_TAG: u64 = 18;
/// `Number.MAX_SAFE_INTEGER`, the TS client reads no larger integer exactly.
const MAX_INTEGER: u64 = (1 << 53) - 1;

pub struct Nitro;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NitroPolicy {
    pub measurements: Vec<NitroMeasurement>,
    /// Holds across reboots only on a KMS deployment.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "hex_pin")]
    pub hpke_public_key: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NitroMeasurement {
    #[serde(with = "hex")]
    pub pcr0: [u8; 48],
    #[serde(with = "hex")]
    pub pcr1: [u8; 48],
    #[serde(with = "hex")]
    pub pcr2: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NitroIdentity {
    pub measurement: NitroMeasurement,
    nonce: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NitroEvidence {
    #[serde(with = "hex")]
    pub(super) document: Vec<u8>,
}

struct AttestationDocument {
    digest: String,
    pcrs: BTreeMap<usize, Vec<u8>>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

struct Fields {
    named: HashMap<String, Value>,
    numbered: Vec<Value>,
}

#[derive(PartialEq, Eq, Hash)]
enum Key<'a> {
    Integer(Integer),
    Text(&'a str),
}

impl TeePlatform for Nitro {
    const HOSTS_GPU: bool = false;
    const ROTATES_KEY_PER_BOOT: bool = true;
    const ANCHORS: Self::Anchors = AWS_NITRO_ROOT_G1;
    type Evidence = NitroEvidence;
    type Policy = NitroPolicy;
    type Identity = NitroIdentity;
    /// DER of the certificate a `cabundle` must start at.
    type Anchors = &'static [u8];

    fn inspect(
        evidence: NitroEvidence,
        root: &&'static [u8],
        now_secs: u64,
    ) -> Result<Measured<NitroIdentity>, TeeError> {
        scan(&evidence.document, Some(COSE_SIGN1_TAG))?;
        let sign1 = CoseSign1::from_tagged_slice(&evidence.document)
            .or_else(|_| CoseSign1::from_slice(&evidence.document))
            .map_err(|e| invalid(format!("not a COSE_Sign1, {e}")))?;
        if let Some(protected) = &sign1.protected.original_data {
            scan(protected, None)?;
        }
        if sign1.protected.header.alg != Some(Algorithm::Assigned(iana::Algorithm::ES384)) {
            return Err(invalid("the protected header alg is not ES384"));
        }
        let document = AttestationDocument::decode(
            sign1
                .payload
                .as_deref()
                .ok_or_else(|| invalid("the COSE_Sign1 has no document"))?,
        )?;
        let signer = document.leaf_key(root, now_secs)?;
        let signature = Signature::from_slice(&sign1.signature)
            .map_err(|_| invalid("the COSE signature is not 96 bytes"))?;
        signer
            .verify(&sign1.tbs_data(b""), &signature)
            .map_err(|_| invalid("the COSE signature does not verify"))?;
        if document.digest != "SHA384" {
            return Err(invalid(format!("digest {} is not SHA384", document.digest)));
        }
        let measurement = NitroMeasurement {
            pcr0: document.pcr(0)?,
            pcr1: document.pcr(1)?,
            pcr2: document.pcr(2)?,
        };
        if measurement.pcr0 == [0; 48] {
            return Err(invalid("PCR0 is zero, the enclave runs in debug mode"));
        }
        let report_data = document
            .user_data
            .as_deref()
            .and_then(|user_data| user_data.try_into().ok())
            .ok_or_else(|| invalid("user_data is not 64 bytes"))?;
        Ok(Measured {
            identity: NitroIdentity {
                measurement,
                nonce: document.nonce,
                public_key: document.public_key,
            },
            report_data,
        })
    }

    fn check(
        identity: &NitroIdentity,
        pins: &NitroPolicy,
        claims: &Claims<'_>,
    ) -> Result<(), TeeError> {
        if !pins.measurements.contains(&identity.measurement) {
            return Err(TeeError::EnclaveMeasurementNotAllowed);
        }
        if identity.public_key.as_deref() != Some(claims.hpke_public_key.as_slice()) {
            return Err(invalid("public_key is not hpke_public_key"));
        }
        if identity.nonce.as_deref() != Some(claims.nonce.as_slice()) {
            return Err(invalid("nonce is not the session nonce"));
        }
        if pins
            .hpke_public_key
            .is_some_and(|pinned| &pinned != claims.hpke_public_key)
        {
            return Err(TeeError::HpkeKeyMismatch);
        }
        Ok(())
    }

    fn image_id(identity: &NitroIdentity) -> Vec<u8> {
        identity.measurement.pcr0.to_vec()
    }
}

impl AttestationDocument {
    fn decode(document: &[u8]) -> Result<Self, TeeError> {
        scan(document, None)?;
        let value: Value = ciborium::from_reader(document)
            .map_err(|e| invalid(format!("the document is not CBOR, {e}")))?;
        let Value::Map(entries) = value else {
            return Err(invalid("the document is not a map"));
        };
        let mut fields = Fields::new(entries)?;
        if fields.text("module_id")?.is_empty() {
            return Err(invalid("module_id is empty"));
        }
        match fields.take("timestamp")? {
            Value::Integer(timestamp)
                if u64::try_from(timestamp).is_ok_and(|timestamp| timestamp <= MAX_INTEGER) => {}
            _ => return Err(invalid("timestamp is not an integer up to 2^53 minus 1")),
        }
        let document = Self {
            digest: fields.text("digest")?,
            pcrs: pcrs(fields.take("pcrs")?)?,
            certificate: fields.bytes("certificate")?,
            cabundle: cabundle(fields.take("cabundle")?)?,
            public_key: fields.optional_bytes("public_key")?,
            user_data: fields.optional_bytes("user_data")?,
            nonce: fields.optional_bytes("nonce")?,
        };
        if !fields
            .named
            .values()
            .chain(&fields.numbered)
            .all(keys_unique)
        {
            return Err(invalid(REPEATED_KEY));
        }
        Ok(document)
    }

    /// The leaf key once `cabundle`, read root first, chains `certificate` to `root`.
    fn leaf_key(&self, root: &[u8], now_secs: u64) -> Result<VerifyingKey, TeeError> {
        if self.cabundle.first().map(Vec::as_slice) != Some(root) {
            return Err(invalid(
                "cabundle does not start at the AWS Nitro Enclaves root",
            ));
        }
        let leaf = certificate(&self.certificate)?;
        let bundle = self
            .cabundle
            .iter()
            .map(|der| certificate(der))
            .collect::<Result<Vec<_>, _>>()?;
        let path: Vec<&Certificate> = iter::once(&leaf).chain(bundle.iter().rev()).collect();
        for cert in &path {
            within_validity(cert, now_secs)?;
            known_critical_extensions(cert)?;
        }
        for (below, (child, parent)) in path.iter().zip(path.iter().skip(1)).enumerate() {
            verify_signed_by(child, parent)?;
            may_issue(parent, below)?;
        }
        if key_usage(&leaf)?.is_some_and(|usage| !usage.digital_signature()) {
            return Err(invalid("the document certificate may not sign"));
        }
        public_key(&leaf)
    }

    fn pcr(&self, index: usize) -> Result<[u8; 48], TeeError> {
        self.pcrs
            .get(&index)
            .and_then(|value| value.as_slice().try_into().ok())
            .ok_or_else(|| invalid(format!("PCR{index} is not a SHA384 value")))
    }
}

impl Fields {
    fn new(entries: Vec<(Value, Value)>) -> Result<Self, TeeError> {
        capped(entries.len(), MAX_DOCUMENT_FIELDS, "the document")?;
        if !unique_keys(&entries) {
            return Err(invalid(REPEATED_KEY));
        }
        let mut fields = Self {
            named: HashMap::with_capacity(entries.len()),
            numbered: Vec::new(),
        };
        for (key, value) in entries {
            match key {
                Value::Text(key) => {
                    fields.named.insert(key, value);
                }
                _ => fields.numbered.push(value),
            }
        }
        Ok(fields)
    }

    fn take(&mut self, name: &str) -> Result<Value, TeeError> {
        self.named
            .remove(name)
            .ok_or_else(|| invalid(format!("{name} is missing")))
    }

    fn text(&mut self, name: &str) -> Result<String, TeeError> {
        match self.take(name)? {
            Value::Text(text) => Ok(text),
            _ => Err(invalid(format!("{name} is not a text string"))),
        }
    }

    fn bytes(&mut self, name: &str) -> Result<Vec<u8>, TeeError> {
        bytes(self.take(name)?, name)
    }

    fn optional_bytes(&mut self, name: &str) -> Result<Option<Vec<u8>>, TeeError> {
        match self.named.remove(name) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => bytes(value, name).map(Some),
        }
    }
}

fn pcrs(value: Value) -> Result<BTreeMap<usize, Vec<u8>>, TeeError> {
    let Value::Map(entries) = value else {
        return Err(invalid("pcrs is not a map"));
    };
    capped(entries.len(), MAX_PCRS, "pcrs")?;
    let mut pcrs = BTreeMap::new();
    for (index, pcr) in entries {
        let index = match index {
            Value::Integer(index) => usize::try_from(index).ok(),
            _ => None,
        }
        .filter(|index| *index < MAX_PCRS)
        .ok_or_else(|| invalid(format!("a pcrs key is not an index below {MAX_PCRS}")))?;
        if pcrs.insert(index, bytes(pcr, "a PCR")?).is_some() {
            return Err(invalid("pcrs repeats a key"));
        }
    }
    Ok(pcrs)
}

fn cabundle(value: Value) -> Result<Vec<Vec<u8>>, TeeError> {
    let Value::Array(certificates) = value else {
        return Err(invalid("cabundle is not an array"));
    };
    capped(certificates.len(), MAX_CABUNDLE, "cabundle")?;
    certificates
        .into_iter()
        .map(|certificate| bytes(certificate, "a cabundle certificate"))
        .collect()
}

fn bytes(value: Value, name: &str) -> Result<Vec<u8>, TeeError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(invalid(format!("{name} is not a byte string"))),
    }
}

fn capped(len: usize, max: usize, name: &str) -> Result<(), TeeError> {
    if len > max {
        return Err(invalid(format!("{name} has over {max} entries")));
    }
    Ok(())
}

/// Only unique text or integer map keys at any depth.
fn keys_unique(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().all(keys_unique),
        Value::Map(entries) => {
            unique_keys(entries) && entries.iter().all(|(_, value)| keys_unique(value))
        }
        _ => true,
    }
}

fn unique_keys(entries: &[(Value, Value)]) -> bool {
    let mut seen = HashSet::with_capacity(entries.len());
    entries.iter().all(|(key, _)| {
        let key = match key {
            Value::Integer(integer) => Key::Integer(*integer),
            Value::Text(text) => Key::Text(text),
            _ => return false,
        };
        seen.insert(key)
    })
}

/// Admits one item in the CBOR subset both SDKs read alike.
fn scan(cbor: &[u8], leading_tag: Option<u64>) -> Result<(), TeeError> {
    let mut rest = cbor;
    // Items left in each open array or map, `None` while indefinite.
    let mut open: Vec<Option<usize>> = Vec::new();
    let mut tag_allowed = leading_tag;
    loop {
        let mut decoder = Decoder::from(rest);
        let header = decoder.pull().map_err(|_| malformed())?;
        rest = &rest[decoder.offset()..];
        let finished = match header {
            Header::Tag(tag) if tag_allowed.take() == Some(tag) => continue,
            Header::Tag(_) => {
                return Err(invalid(
                    "the CBOR has a tag other than one leading COSE tag",
                ))
            }
            Header::Float(_) => return Err(invalid("the CBOR has a float")),
            Header::Simple(simple::FALSE | simple::TRUE | simple::NULL)
                if decoder.offset() == 1 =>
            {
                true
            }
            Header::Simple(_) => {
                return Err(invalid(
                    "the CBOR has a simple value other than false, true or null",
                ))
            }
            Header::Positive(magnitude) if magnitude <= MAX_INTEGER => true,
            Header::Negative(below) if below < MAX_INTEGER => true,
            Header::Positive(_) | Header::Negative(_) => {
                return Err(invalid("the CBOR has an integer beyond 2^53 minus 1"))
            }
            Header::Bytes(None) | Header::Text(None) => {
                return Err(invalid("the CBOR has an indefinite length string"))
            }
            Header::Bytes(Some(len)) => {
                take(&mut rest, len)?;
                true
            }
            Header::Text(Some(len)) => {
                std::str::from_utf8(take(&mut rest, len)?)
                    .map_err(|_| invalid("the CBOR has invalid UTF-8 text"))?;
                true
            }
            Header::Array(Some(0)) | Header::Map(Some(0)) => true,
            Header::Array(items) | Header::Map(items @ None) => {
                nest(&mut open, items)?;
                false
            }
            Header::Map(Some(pairs)) => {
                nest(&mut open, Some(pairs.checked_mul(2).ok_or_else(malformed)?))?;
                false
            }
            Header::Break if open.last() == Some(&None) => {
                open.pop();
                true
            }
            Header::Break => return Err(malformed()),
        };
        tag_allowed = None;
        if finished && closes(&mut open) {
            return if rest.is_empty() {
                Ok(())
            } else {
                Err(invalid("the CBOR has trailing bytes"))
            };
        }
    }
}

fn take<'a>(rest: &mut &'a [u8], len: usize) -> Result<&'a [u8], TeeError> {
    let (taken, after) = rest.split_at_checked(len).ok_or_else(malformed)?;
    *rest = after;
    Ok(taken)
}

fn nest(open: &mut Vec<Option<usize>>, items: Option<usize>) -> Result<(), TeeError> {
    open.push(items);
    if open.len() > MAX_DEPTH {
        return Err(invalid(format!("the CBOR nests over {MAX_DEPTH} deep")));
    }
    Ok(())
}

/// True once the outermost item finishes.
fn closes(open: &mut Vec<Option<usize>>) -> bool {
    while let Some(last) = open.last_mut() {
        let Some(left) = last else {
            return false;
        };
        *left -= 1;
        if *left > 0 {
            return false;
        }
        open.pop();
    }
    true
}

fn malformed() -> TeeError {
    invalid("the CBOR is malformed")
}

fn certificate(der: &[u8]) -> Result<Certificate, TeeError> {
    Certificate::from_der(der).map_err(|e| invalid(format!("a certificate is not DER, {e}")))
}

fn within_validity(cert: &Certificate, now_secs: u64) -> Result<(), TeeError> {
    let validity = cert.tbs_certificate().validity();
    let now = Duration::from_secs(now_secs);
    let latest_start = Duration::from_secs(now_secs.saturating_add(NOT_BEFORE_SKEW_SECS));
    if latest_start < validity.not_before.to_unix_duration()
        || now > validity.not_after.to_unix_duration()
    {
        return Err(invalid("a certificate is outside its validity window"));
    }
    Ok(())
}

fn known_critical_extensions(cert: &Certificate) -> Result<(), TeeError> {
    let known = [BasicConstraints::OID, KeyUsage::OID];
    let unknown = cert
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .any(|extension| extension.critical && !known.contains(&extension.extn_id));
    if unknown {
        return Err(invalid("a certificate has an unknown critical extension"));
    }
    Ok(())
}

fn verify_signed_by(child: &Certificate, parent: &Certificate) -> Result<(), TeeError> {
    let tbs = child.tbs_certificate();
    if tbs.issuer() != parent.tbs_certificate().subject() {
        return Err(invalid("a certificate issuer does not name its parent"));
    }
    if child.signature_algorithm().oid != ECDSA_WITH_SHA_384
        || tbs.signature() != child.signature_algorithm()
    {
        return Err(invalid("a certificate is not signed with ES384"));
    }
    let signature = child
        .signature()
        .as_bytes()
        .and_then(|der| Signature::from_der(der).ok())
        .ok_or_else(|| invalid("a certificate signature is malformed"))?;
    let signed = tbs
        .to_der()
        .map_err(|e| invalid(format!("a certificate does not encode, {e}")))?;
    public_key(parent)?
        .verify(&signed, &signature)
        .map_err(|_| invalid("a certificate signature does not verify"))
}

/// `below` counts the CA certificates between `parent` and the leaf.
fn may_issue(parent: &Certificate, below: usize) -> Result<(), TeeError> {
    let constraints = parent
        .tbs_certificate()
        .get_extension::<BasicConstraints>()
        .map_err(|e| invalid(format!("basic constraints are malformed, {e}")))?;
    let is_ca = constraints.is_some_and(|(_, constraints)| {
        constraints.ca
            && constraints
                .path_len_constraint
                .is_none_or(|limit| usize::from(limit) >= below)
    });
    if !is_ca {
        return Err(invalid("a cabundle certificate may not issue at its depth"));
    }
    if key_usage(parent)?.is_some_and(|usage| !usage.key_cert_sign()) {
        return Err(invalid("a cabundle certificate may not sign certificates"));
    }
    Ok(())
}

fn key_usage(cert: &Certificate) -> Result<Option<KeyUsage>, TeeError> {
    cert.tbs_certificate()
        .get_extension::<KeyUsage>()
        .map(|usage| usage.map(|(_, usage)| usage))
        .map_err(|e| invalid(format!("key usage is malformed, {e}")))
}

fn public_key(cert: &Certificate) -> Result<VerifyingKey, TeeError> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY
        || spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|curve| curve.decode_as::<ObjectIdentifier>().ok())
            != Some(SECP_384_R_1)
    {
        return Err(invalid("a certificate key is not P384"));
    }
    spki.subject_public_key
        .as_bytes()
        .and_then(|sec1| VerifyingKey::from_sec1_bytes(sec1).ok())
        .ok_or_else(|| invalid("a certificate key is not a P384 point"))
}

fn invalid(reason: impl Into<String>) -> TeeError {
    TeeError::NitroDocument(reason.into())
}

#[cfg(test)]
pub(crate) mod tests;
