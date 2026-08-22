use rand::RngCore;
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signer::{Signer, SignerError};
use thiserror::Error;
use zolana_indexer_api::{
    Base64String, Context, Hash, Limit, SerializablePubkey, SerializableSignature,
};
use zolana_keypair::P256Pubkey;
use zolana_ring_client::{ReaderKey, ReaderKeyError};

use crate::audit::KeyMode;

pub const HEALTH: &str = "health";
pub const CREATE_AUDITOR_KEY: &str = "createAuditorKey";
pub const RING_STATUS: &str = "ringStatus";
pub const RING_DEPOSITS: &str = "ringDeposits";
pub const GET_DECRYPTED_TRANSACTIONS: &str = "getDecryptedTransactions";
pub(crate) const AUDIT_CURSOR_LIMIT: usize = 256;
pub(crate) const AUDIT_PAGE_LIMIT: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HealthResponse {
    pub mode: KeyMode,
    pub service_pubkey: SerializablePubkey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auditor_view_tag: Option<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateAuditorKeyRequest {
    pub ring_program_id: SerializablePubkey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateAuditorKeyResponse {
    pub ring_program_id: SerializablePubkey,
    pub auditor_pubkey: AuditorPubkey,
    pub auditor_view_tag: Hash,
    pub service_pubkey: SerializablePubkey,
    pub signature: SerializableSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingDepositsRequest {
    pub ring_program_id: SerializablePubkey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Value entering the ring. A deposit publishes its asset and amount, so this
/// needs no auditor key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DepositRecord {
    pub signature: SerializableSignature,
    pub slot: u64,
    /// The owner tag of the note the deposit created.
    pub depositor: Hash,
    pub asset: SerializablePubkey,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingDepositsResponse {
    pub deposits: Vec<DepositRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingStatusRequest {
    pub ring_program_id: SerializablePubkey,
}

/// Unsigned, for diagnosis only. A ring pins its auditor from the attested
/// `createAuditorKey` response, never from this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingStatusResponse {
    pub ring_program_id: SerializablePubkey,
    pub state: RingState,
    /// The key this service holds for the ring.
    pub auditor_pubkey: AuditorPubkey,
    pub auditor_view_tag: Hash,
    /// The key the ring's config names, absent until the config exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_auditor_pubkey: Option<AuditorPubkey>,
    pub service_pubkey: SerializablePubkey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RingState {
    /// The config names this service's key, reads work.
    Served,
    /// The config names another auditor, and it cannot change, so this service
    /// can never open the ring.
    ForeignAuditor,
    /// No config yet, so `init` is free to pin this service's key.
    Uninitialized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditorPubkey(P256Pubkey);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetDecryptedTransactionsRequest {
    /// Required for derived keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_program_id: Option<SerializablePubkey>,
    /// Opaque indexer cursor.
    #[serde(default)]
    pub cursor: Option<Base64String>,
    #[serde(default)]
    pub limit: Option<Limit>,
    pub auth: ReadAuth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReadAuth {
    /// Canonical tagged reader key bytes.
    pub reader: Base64String,
    pub timestamp: u64,
    pub nonce: Base64String,
    /// DER for passkeys and raw Ed25519 otherwise.
    pub signature: Base64String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn: Option<WebAuthnAssertion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WebAuthnAssertion {
    pub authenticator_data: Base64String,
    pub client_data_json: Base64String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadSignature {
    Ed25519([u8; 64]),
    WebAuthn {
        signature_der: Vec<u8>,
        assertion: WebAuthnAssertion,
    },
}

pub trait ReadSigner {
    fn reader(&self) -> Result<ReaderKey, ReaderKeyError>;
    fn sign(&self, attestation: &[u8]) -> Result<ReadSignature, ReadBuildError>;
}

#[derive(Debug, Error)]
pub enum ReadBuildError {
    #[error(transparent)]
    Reader(#[from] ReaderKeyError),
    #[error("reader signature failed")]
    Signature(#[source] SignerError),
    #[error("audit cursor is invalid")]
    Cursor,
    #[error("audit page limit is invalid")]
    Limit,
    #[error("system clock is before the Unix epoch")]
    Clock,
}

#[must_use]
pub struct ReadRequest {
    ring: Address,
    cursor: Option<Base64String>,
    limit: Option<Limit>,
    timestamp: Option<u64>,
    nonce: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct ReadAttestation<'a> {
    pub ring: Address,
    pub timestamp: u64,
    pub nonce: &'a [u8; 32],
    pub cursor: Option<&'a [u8]>,
    pub limit: Option<Limit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetDecryptedTransactionsResponse {
    pub context: Context,
    pub value: DecryptedTransactionsPage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedTransactionsPage {
    pub items: Vec<DecryptedTransaction>,
    pub skipped: Vec<SkippedTransaction>,
    pub cursor: Option<Base64String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedTransaction {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    /// Canonical compressed P256 transaction key.
    pub tx_viewing_pk: Base64String,
    pub outputs: Vec<DecryptedOutput>,
    pub undecryptable_slots: Vec<u32>,
    pub nullifiers: Vec<Hash>,
    /// Required signers, fee payer first. The sender is the one matching an
    /// output owner tag.
    pub signers: Vec<SerializablePubkey>,
    /// Public settlement legs, where value left the ring.
    pub withdrawals: Vec<DecryptedWithdrawal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedWithdrawal {
    /// The account the lamports were settled to.
    pub recipient: SerializablePubkey,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedOutput {
    pub slot_index: u32,
    pub recipient_viewing_pk: Base64String,
    /// The output slot's owner tag. Base58 of it is the Solana address of an
    /// Ed25519 or PDA owner.
    pub owner_tag: Hash,
    pub asset: SerializablePubkey,
    pub amount: u64,
    pub ring_program_id: Option<SerializablePubkey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SkippedTransaction {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub reason: SkippedReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SkippedReason {
    MissingAuditorMessage,
    InvalidAuditData,
}

const ATTESTATION_DOMAIN: &[u8] = b"zolana/ring-auditor-key/v1";

pub fn auditor_key_attestation(ring_program_id: &Address, auditor_pubkey: &P256Pubkey) -> Vec<u8> {
    [
        ATTESTATION_DOMAIN,
        ring_program_id.as_ref(),
        auditor_pubkey.as_bytes(),
    ]
    .concat()
}

impl AuditorPubkey {
    pub fn as_key(&self) -> &P256Pubkey {
        &self.0
    }
}

impl From<P256Pubkey> for AuditorPubkey {
    fn from(value: P256Pubkey) -> Self {
        Self(value)
    }
}

impl Serialize for AuditorPubkey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Base64String(self.0.as_bytes().to_vec()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AuditorPubkey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = Base64String::deserialize(deserializer)?;
        let bytes = encoded
            .0
            .try_into()
            .map_err(|_| serde::de::Error::custom("auditor public key length is invalid"))?;
        P256Pubkey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| serde::de::Error::custom("auditor public key is invalid"))
    }
}

impl<T: Signer + ?Sized> ReadSigner for T {
    fn reader(&self) -> Result<ReaderKey, ReaderKeyError> {
        ReaderKey::ed25519(self.pubkey())
    }

    fn sign(&self, attestation: &[u8]) -> Result<ReadSignature, ReadBuildError> {
        self.try_sign_message(attestation)
            .map(|signature| ReadSignature::Ed25519(*signature.as_array()))
            .map_err(ReadBuildError::Signature)
    }
}

impl GetDecryptedTransactionsRequest {
    pub fn read(ring: Address) -> ReadRequest {
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        ReadRequest {
            ring,
            cursor: None,
            limit: None,
            timestamp: None,
            nonce,
        }
    }
}

impl ReadRequest {
    #[must_use = "use the updated request"]
    pub fn with_cursor(mut self, cursor: Base64String) -> Result<Self, ReadBuildError> {
        if cursor.0.is_empty() || cursor.0.len() > AUDIT_CURSOR_LIMIT {
            return Err(ReadBuildError::Cursor);
        }
        self.cursor = Some(cursor);
        Ok(self)
    }

    #[must_use = "use the updated request"]
    pub fn with_limit(mut self, limit: Limit) -> Result<Self, ReadBuildError> {
        if limit.value() > AUDIT_PAGE_LIMIT {
            return Err(ReadBuildError::Limit);
        }
        self.limit = Some(limit);
        Ok(self)
    }

    #[must_use = "use the updated request"]
    pub fn at(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn sign<S: ReadSigner + ?Sized>(
        self,
        signer: &S,
    ) -> Result<GetDecryptedTransactionsRequest, ReadBuildError> {
        let timestamp = match self.timestamp {
            Some(timestamp) => timestamp,
            None => unix_now()?,
        };
        let attestation = ReadAttestation {
            ring: self.ring,
            timestamp,
            nonce: &self.nonce,
            cursor: self.cursor.as_ref().map(|cursor| cursor.0.as_slice()),
            limit: self.limit.clone(),
        }
        .bytes();
        let (signature, webauthn) = match signer.sign(&attestation)? {
            ReadSignature::Ed25519(raw) => (raw.to_vec(), None),
            ReadSignature::WebAuthn {
                signature_der,
                assertion,
            } => (signature_der, Some(assertion)),
        };
        Ok(GetDecryptedTransactionsRequest {
            ring_program_id: Some(self.ring.to_bytes().into()),
            cursor: self.cursor,
            limit: self.limit,
            auth: ReadAuth {
                reader: signer.reader()?.to_bytes().to_vec().into(),
                timestamp,
                nonce: self.nonce.to_vec().into(),
                signature: signature.into(),
                webauthn,
            },
        })
    }
}

pub fn unix_now() -> Result<u64, ReadBuildError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| ReadBuildError::Clock)
}

const READ_DOMAIN: &str = "zolana/ring-rpc-read/v1";

impl ReadAttestation<'_> {
    pub fn bytes(&self) -> Vec<u8> {
        use base64::Engine;
        format!(
            "{READ_DOMAIN}\nring: {}\ntimestamp: {}\nnonce: {}\nlimit: {}\ncursor: {}",
            self.ring,
            self.timestamp,
            base64::engine::general_purpose::STANDARD.encode(self.nonce),
            self.limit.as_ref().map_or(0, Limit::value),
            base64::engine::general_purpose::STANDARD.encode(self.cursor.unwrap_or_default()),
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_attestation_is_stable() {
        let message = ReadAttestation {
            ring: Address::new_from_array([7; 32]),
            timestamp: 1_700_000_000,
            nonce: &[4; 32],
            cursor: Some(&[1, 2, 3]),
            limit: Some(Limit::new(5).expect("in range")),
        }
        .bytes();
        assert_eq!(
            String::from_utf8(message).expect("text"),
            "zolana/ring-rpc-read/v1\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1700000000\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nlimit: 5\ncursor: AQID"
        );
    }
}
