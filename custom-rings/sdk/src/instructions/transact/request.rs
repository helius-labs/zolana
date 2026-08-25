use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Serialize;
use zeroize::Zeroizing;
use zolana_client::{ClientError, Delivery, ProveRequest};
use zolana_keypair::{P256Pubkey, ViewingKey};

use super::proof::AuditProofInputError;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuditPublicInputHash([u8; 32]);

impl TryFrom<[u8; 32]> for AuditPublicInputHash {
    type Error = AuditProofInputError;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        canonical_audit_hash(value).map(Self)
    }
}

impl AsRef<[u8; 32]> for AuditPublicInputHash {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuditPrivateTxHash([u8; 32]);

impl TryFrom<[u8; 32]> for AuditPrivateTxHash {
    type Error = AuditProofInputError;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        canonical_audit_hash(value).map(Self)
    }
}

impl AsRef<[u8; 32]> for AuditPrivateTxHash {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct AuditProofRequest {
    pub public_input_hash: AuditPublicInputHash,
    pub private_tx_hash: AuditPrivateTxHash,
    pub tx_viewing_key: ViewingKey,
    pub ephemeral_key: ViewingKey,
    pub auditor_key: P256Pubkey,
}

impl ProveRequest for AuditProofRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        let tx_viewing_secret = self.tx_viewing_key.secret_bytes();
        let ephemeral_secret = self.ephemeral_key.secret_bytes();
        let auditor_key = self
            .auditor_key
            .to_p256()
            .map_err(|_| ClientError::Prover("invalid audit public key".to_string()))?;
        let auditor_pk = auditor_key.to_encoded_point(false);
        let json = AuditProofRequestJson {
            circuit_type: "custom-ring-audit",
            variant: "transfer",
            public_input_hash: bytes_to_hex(self.public_input_hash.as_ref()),
            private_tx_hash: bytes_to_hex(self.private_tx_hash.as_ref()),
            tx_viewing_sk: SecretHex(tx_viewing_secret.as_slice()),
            eph_sk: SecretHex(ephemeral_secret.as_slice()),
            auditor_pk: bytes_to_hex(auditor_pk.as_bytes()),
        };
        serde_json::to_string(&json)
            .map(Zeroizing::new)
            .map_err(|_| ClientError::Prover("audit request serialization failed".to_string()))
    }

    fn delivery(&self) -> Delivery {
        Delivery::Queued
    }
}

#[derive(Serialize)]
struct AuditProofRequestJson<'a> {
    #[serde(rename = "circuitType")]
    circuit_type: &'static str,
    variant: &'static str,
    #[serde(rename = "publicInputHash")]
    public_input_hash: String,
    #[serde(rename = "privateTxHash")]
    private_tx_hash: String,
    #[serde(rename = "txViewingSk")]
    tx_viewing_sk: SecretHex<'a>,
    #[serde(rename = "ephSk")]
    eph_sk: SecretHex<'a>,
    #[serde(rename = "auditorPk")]
    auditor_pk: String,
}

pub(crate) struct SecretHex<'a>(pub &'a [u8]);

impl Serialize for SecretHex<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = Zeroizing::new(bytes_to_hex(self.0));
        serializer.serialize_str(&encoded)
    }
}

/// A field element as the fixed-width hex the prover requires.
#[cfg(feature = "policy")]
pub(crate) fn field_hex(value: &[u8; 32]) -> String {
    bytes_to_hex(value)
}

pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::from("0x"), |mut out, byte| {
        out.push_str(&format!("{byte:02x}"));
        out
    })
}

const BN254_SCALAR_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

fn canonical_audit_hash(value: [u8; 32]) -> Result<[u8; 32], AuditProofInputError> {
    if value >= BN254_SCALAR_MODULUS {
        return Err(AuditProofInputError::GreaterThanB254FieldSize);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use zolana_client::ProveRequest;
    use zolana_keypair::ViewingKey;

    use super::*;

    #[test]
    fn rejects_noncanonical_audit_hashes() {
        assert!(matches!(
            AuditPublicInputHash::try_from(BN254_SCALAR_MODULUS),
            Err(AuditProofInputError::GreaterThanB254FieldSize)
        ));
        assert!(matches!(
            AuditPrivateTxHash::try_from(BN254_SCALAR_MODULUS),
            Err(AuditProofInputError::GreaterThanB254FieldSize)
        ));
    }

    #[test]
    fn audit_request_json_matches_the_server_wire_format() {
        let tx_viewing_key = ViewingKey::from_bytes(&[2u8; 32]).expect("valid key");
        let ephemeral_key = ViewingKey::from_bytes(&[3u8; 32]).expect("valid key");
        let auditor_key = ViewingKey::from_bytes(&[4u8; 32]).expect("valid key");
        let request = AuditProofRequest {
            public_input_hash: [0u8; 32].try_into().expect("canonical field"),
            private_tx_hash: [1u8; 32].try_into().expect("canonical field"),
            tx_viewing_key,
            ephemeral_key,
            auditor_key: auditor_key.pubkey(),
        };
        let encoded = request.body().expect("valid json");
        let value: serde_json::Value = serde_json::from_str(&encoded).expect("valid json");
        let object = value.as_object().expect("object");

        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "auditorPk",
                "circuitType",
                "ephSk",
                "privateTxHash",
                "publicInputHash",
                "txViewingSk",
                "variant",
            ]
        );
        assert_eq!(value["circuitType"], "custom-ring-audit");
        assert_eq!(value["variant"], "transfer");
        assert_eq!(value["publicInputHash"], format!("0x{}", "00".repeat(32)));
        assert_eq!(value["privateTxHash"], format!("0x{}", "01".repeat(32)));
        assert_eq!(value["txViewingSk"], format!("0x{}", "02".repeat(32)));
        assert_eq!(value["ephSk"], format!("0x{}", "03".repeat(32)));
        assert_eq!(value["auditorPk"].as_str().expect("public key").len(), 132);
    }
}
