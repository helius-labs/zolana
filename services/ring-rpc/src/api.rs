use rand::RngCore;
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::{Signer, SignerError};
use thiserror::Error;
use zolana_indexer_api::{
    Base64String, Context, Hash, Limit, SerializablePubkey, SerializableSignature,
};
use zolana_keypair::P256Pubkey;
use zolana_ring_client::{ReaderKey, ReaderKeyError};

use crate::{error::RingRpcError, keys::KeyMode, upstream::DepositHistory};

pub const HEALTH: &str = "health";
pub const CREATE_AUDITOR_KEY: &str = "createAuditorKey";
pub const RING_STATUS: &str = "ringStatus";
pub const RING_DEPOSITS: &str = "ringDeposits";
pub const GET_DECRYPTED_TRANSACTIONS: &str = "getDecryptedTransactions";
pub(crate) const AUDIT_CURSOR_LIMIT: usize = 256;
pub(crate) const AUDIT_PAGE_LIMIT: u64 = 100;
pub(crate) const DEPOSITS_PAGE_LIMIT: u32 = 50;
pub(crate) const MAX_DEPOSITS_PAGE_LIMIT: u32 = 200;

/// The one cursor rule, shared by the request builder, the page options and
/// the indexer response check.
pub(crate) fn cursor_in_bounds(cursor: &[u8]) -> bool {
    !cursor.is_empty() && cursor.len() <= AUDIT_CURSOR_LIMIT
}

pub(crate) fn limit_in_bounds(limit: &Limit) -> bool {
    limit.value() <= AUDIT_PAGE_LIMIT
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HealthResponse {
    pub mode: KeyMode,
    pub service_pubkey: SerializablePubkey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateAuditorKeyRequest {
    pub ring_program_id: SerializablePubkey,
    pub auth: AuthorityAuth,
}

/// Signed by the ring's Loader v3 upgrade authority or its config authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthorityAuth {
    pub authority: SerializablePubkey,
    pub genesis_hash: Hash,
    pub timestamp: u64,
    pub nonce: Base64String,
    /// Raw Ed25519 over `AuditorKeyAttestation::bytes`.
    pub signature: Base64String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct AuditorKeyAttestation<'a> {
    pub genesis_hash: &'a [u8; 32],
    pub ring: Address,
    pub timestamp: u64,
    pub nonce: &'a [u8; 32],
}

#[must_use]
pub struct AuditorKeyRequest {
    ring: Address,
    genesis_hash: [u8; 32],
    timestamp: Option<u64>,
    nonce: [u8; 32],
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
    /// Signatures examined, which is not the number of deposits found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Opaque, taken from the previous page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Base64String>,
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
    /// Absent once the ring has no older history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Base64String>,
    /// Slot of the oldest signature examined, absent when the page examined
    /// nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_slot: Option<u64>,
}

impl RingDepositsRequest {
    pub fn page_limit(&self) -> usize {
        self.limit
            .unwrap_or(DEPOSITS_PAGE_LIMIT)
            .clamp(1, MAX_DEPOSITS_PAGE_LIMIT) as usize
    }

    /// The Solana `before` bound the cursor carries.
    pub fn before(&self) -> Result<Option<Signature>, RingRpcError> {
        self.cursor
            .as_ref()
            .map(|cursor| {
                <[u8; 64]>::try_from(cursor.0.as_slice())
                    .map(Signature::from)
                    .map_err(|_| RingRpcError::InvalidPage)
            })
            .transpose()
    }
}

impl From<DepositHistory> for RingDepositsResponse {
    fn from(history: DepositHistory) -> Self {
        Self {
            deposits: history.deposits,
            cursor: history
                .cursor
                .map(|signature| signature.as_ref().to_vec().into()),
            oldest_slot: history.oldest_slot,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingStatusRequest {
    pub ring_program_id: SerializablePubkey,
}

/// Unsigned, so it never carries the key this service holds, only the one the
/// chain already publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingStatusResponse {
    pub ring_program_id: SerializablePubkey,
    pub state: RingState,
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
    /// A token account for an SPL leg, a wallet for a SOL leg.
    pub recipient: SerializablePubkey,
    pub asset: SerializablePubkey,
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
const AUDITOR_KEY_REQUEST_DOMAIN: &str = "zolana/ring-rpc-auditor-key-request/v1";

impl CreateAuditorKeyRequest {
    /// `genesis_hash` names the cluster, a signature never carries over to another one.
    pub fn for_ring(ring: Address, genesis_hash: [u8; 32]) -> AuditorKeyRequest {
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        AuditorKeyRequest {
            ring,
            genesis_hash,
            timestamp: None,
            nonce,
        }
    }
}

impl AuditorKeyRequest {
    #[must_use = "use the updated request"]
    pub fn at(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn sign<S: Signer + ?Sized>(
        self,
        authority: &S,
    ) -> Result<CreateAuditorKeyRequest, ReadBuildError> {
        let timestamp = match self.timestamp {
            Some(timestamp) => timestamp,
            None => unix_now()?,
        };
        let attestation = AuditorKeyAttestation {
            genesis_hash: &self.genesis_hash,
            ring: self.ring,
            timestamp,
            nonce: &self.nonce,
        }
        .bytes();
        let signature = authority
            .try_sign_message(&attestation)
            .map_err(ReadBuildError::Signature)?;
        Ok(CreateAuditorKeyRequest {
            ring_program_id: self.ring.to_bytes().into(),
            auth: AuthorityAuth {
                authority: authority.pubkey().to_bytes().into(),
                genesis_hash: Hash(self.genesis_hash),
                timestamp,
                nonce: self.nonce.to_vec().into(),
                signature: signature.as_ref().to_vec().into(),
            },
        })
    }
}

impl AuditorKeyAttestation<'_> {
    pub fn bytes(&self) -> Vec<u8> {
        use base64::Engine;
        format!(
            "{AUDITOR_KEY_REQUEST_DOMAIN}\ngenesis: {}\nring: {}\ntimestamp: {}\nnonce: {}",
            Hash(*self.genesis_hash).to_base58(),
            self.ring,
            self.timestamp,
            base64::engine::general_purpose::STANDARD.encode(self.nonce),
        )
        .into_bytes()
    }
}

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
        if !cursor_in_bounds(&cursor.0) {
            return Err(ReadBuildError::Cursor);
        }
        self.cursor = Some(cursor);
        Ok(self)
    }

    #[must_use = "use the updated request"]
    pub fn with_limit(mut self, limit: Limit) -> Result<Self, ReadBuildError> {
        if !limit_in_bounds(&limit) {
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
    fn auditor_key_request_attestation_is_stable() {
        let attestation = AuditorKeyAttestation {
            genesis_hash: &[9; 32],
            ring: Address::new_from_array([5; 32]),
            timestamp: 1_700_000_000,
            nonce: &[7; 32],
        }
        .bytes();
        assert_eq!(
            String::from_utf8(attestation).expect("utf8"),
            "zolana/ring-rpc-auditor-key-request/v1\n\
             genesis: cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN\n\
             ring: LbUiWL3xVV8hTFYBVdbTNrpDo41NKS6o3LHHuDzjfcY\n\
             timestamp: 1700000000\n\
             nonce: BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
        );
    }

    fn deposits_request(limit: Option<u32>, cursor: Option<Vec<u8>>) -> RingDepositsRequest {
        RingDepositsRequest {
            ring_program_id: Address::new_from_array([5; 32]).to_bytes().into(),
            limit,
            cursor: cursor.map(Into::into),
        }
    }

    /// `Limit` cannot hold zero, so the smallest audit page the wire can carry
    /// is one.
    #[test]
    fn an_audit_page_holds_at_its_cursor_and_limit_bounds() {
        assert!(!cursor_in_bounds(&[]));
        assert!(cursor_in_bounds(&vec![1; AUDIT_CURSOR_LIMIT]));
        assert!(!cursor_in_bounds(&vec![1; AUDIT_CURSOR_LIMIT + 1]));

        assert!(limit_in_bounds(&Limit::new(1).expect("indexer limit")));
        assert!(limit_in_bounds(
            &Limit::new(AUDIT_PAGE_LIMIT).expect("indexer limit")
        ));
        assert!(!limit_in_bounds(
            &Limit::new(AUDIT_PAGE_LIMIT + 1).expect("indexer limit")
        ));
    }

    /// The deposits limit counts signatures examined, so it is clamped into
    /// range rather than refused.
    #[test]
    fn a_deposits_page_clamps_its_limit_into_range() {
        for (limit, expected) in [
            (None, DEPOSITS_PAGE_LIMIT),
            (Some(0), 1),
            (Some(1), 1),
            (Some(MAX_DEPOSITS_PAGE_LIMIT), MAX_DEPOSITS_PAGE_LIMIT),
            (Some(MAX_DEPOSITS_PAGE_LIMIT + 1), MAX_DEPOSITS_PAGE_LIMIT),
            (Some(u32::MAX), MAX_DEPOSITS_PAGE_LIMIT),
        ] {
            assert_eq!(
                deposits_request(limit, None).page_limit(),
                expected as usize
            );
        }
    }

    /// The deposits cursor is a Solana signature, a different rule from the
    /// opaque audit cursor.
    #[test]
    fn a_deposits_cursor_is_exactly_one_signature() {
        assert_eq!(
            deposits_request(None, Some(vec![1; 64]))
                .before()
                .expect("cursor"),
            Some(Signature::from([1; 64]))
        );
        assert_eq!(
            deposits_request(None, None).before().expect("no cursor"),
            None
        );
        for length in [0, 63, 65, AUDIT_CURSOR_LIMIT] {
            assert!(matches!(
                deposits_request(None, Some(vec![1; length])).before(),
                Err(RingRpcError::InvalidPage)
            ));
        }
    }

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
