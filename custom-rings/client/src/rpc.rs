//! The ring rpc wire: requests, responses, the signed attestations and the auditor key files.

use std::path::{Path, PathBuf};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::{Signer, SignerError};
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_indexer_api::{
    Base64String, Context, Hash, Limit, SerializablePubkey, SerializableSignature,
};
use zolana_keypair::{KeypairError, X25519Keypair, X25519Pubkey};
use zolana_secret_file::{
    create_new, create_pair, read_hex32, read_private, Access, SecretFileError, Visibility,
};

use crate::{
    AnonymousDisclosure, AuditInputOpening, AuditedTransaction, MergeAuditPage, ReaderKey,
    ReaderKeyError, RingWithdrawal,
};

pub const HEALTH: &str = "health";
pub const CREATE_AUDITOR_KEY: &str = "createAuditorKey";
pub const RING_STATUS: &str = "ringStatus";
pub const RING_DEPOSITS: &str = "ringDeposits";
pub const GET_DECRYPTED_TRANSACTIONS: &str = "getDecryptedTransactions";
pub const GET_AUDITED_MERGES: &str = "getAuditedMerges";
pub const AUDIT_CURSOR_LIMIT: usize = 256;
pub const AUDIT_PAGE_LIMIT: u64 = 100;
pub const DEPOSITS_PAGE_LIMIT: u32 = 50;
pub const MAX_DEPOSITS_PAGE_LIMIT: u32 = 200;
const KEY_HEX_LEN: u64 = 64;
const ATTESTATION_DOMAIN: &[u8] = b"zolana/ring-auditor-key/v1";
const READ_DOMAIN: &str = "zolana/ring-rpc-read/v1";
const AUDITOR_KEY_REQUEST_DOMAIN: &str = "zolana/ring-rpc-auditor-key-request/v1";

/// One cursor rule for the request builder, the page and the indexer response check.
pub fn cursor_in_bounds(cursor: &[u8]) -> bool {
    !cursor.is_empty() && cursor.len() <= AUDIT_CURSOR_LIMIT
}

pub fn limit_in_bounds(limit: &Limit) -> bool {
    limit.value() <= AUDIT_PAGE_LIMIT
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyMode {
    Local,
    Derived,
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
    /// Diagnostic only, the service signs its own cluster into the attestation.
    pub genesis_hash: Hash,
    pub timestamp: u64,
    pub nonce: Base64String,
    /// Raw Ed25519 over the `AuditorKeyAttestation` message.
    pub signature: Base64String,
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

/// A deposit publishes its asset and amount, so this needs no auditor key.
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
    /// Slot of the oldest signature examined, absent when the page examined nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_slot: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingStatusRequest {
    pub ring_program_id: SerializablePubkey,
}

/// Unsigned, so it carries only the key the chain already publishes.
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
    /// The config names another auditor for good, so this service never opens the ring.
    ForeignAuditor,
    /// No config yet, so `init` is free to pin this service's key.
    Uninitialized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Base64String", into = "Base64String")]
pub struct AuditorPubkey(X25519Pubkey);

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

/// Uses the same signed ring, cursor and limit attestation as transfer reads.
pub type GetAuditedMergesRequest = GetDecryptedTransactionsRequest;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetAuditedMergesResponse {
    pub context: Context,
    pub value: AuditedMergesPage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditedMergesPage {
    pub opened: Vec<AuditedMergeRecord>,
    pub unresolved: Vec<UnresolvedMergeRecord>,
    pub cursor: Option<Base64String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditedMergeRecord {
    pub tx_signature: SerializableSignature,
    pub event_index: u16,
    pub output_commitment: Hash,
    /// Authenticated registry member hash. The event does not reveal its public signing key.
    pub owner_member: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_pubkey: Option<SerializablePubkey>,
    pub mint: SerializablePubkey,
    pub amount: u64,
    pub blinding: Hash,
    pub ring_data_hash: Hash,
    pub input_nullifiers: Vec<Hash>,
    pub nullifier: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UnresolvedMergeRecord {
    pub tx_signature: SerializableSignature,
    pub event_index: u16,
    pub output_commitment: Hash,
}

impl From<MergeAuditPage> for GetAuditedMergesResponse {
    fn from(page: MergeAuditPage) -> Self {
        Self {
            context: page.context,
            value: AuditedMergesPage {
                opened: page
                    .result
                    .opened
                    .into_iter()
                    .map(|merge| AuditedMergeRecord {
                        tx_signature: merge.tx_signature.into(),
                        event_index: merge.event_index,
                        output_commitment: Hash(merge.output_commitment),
                        owner_member: Hash(merge.owner_member),
                        owner_pubkey: merge.owner_pubkey.map(Into::into),
                        mint: merge.mint.into(),
                        amount: merge.amount,
                        blinding: Hash(merge.blinding),
                        ring_data_hash: Hash(merge.ring_data_hash),
                        input_nullifiers: merge.input_nullifiers.into_iter().map(Hash).collect(),
                        nullifier: Hash(merge.nullifier),
                    })
                    .collect(),
                unresolved: page
                    .result
                    .unresolved
                    .into_iter()
                    .map(|merge| UnresolvedMergeRecord {
                        tx_signature: merge.tx_signature.into(),
                        event_index: merge.event_index,
                        output_commitment: Hash(merge.output_commitment),
                    })
                    .collect(),
                cursor: page.next_cursor.map(Into::into),
            },
        }
    }
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
pub enum RequestBuildError {
    #[error("request signature failed")]
    Signature(#[source] SignerError),
    #[error("system clock is before the Unix epoch")]
    Clock,
}

#[derive(Debug, Error)]
pub enum ReadBuildError {
    #[error(transparent)]
    Request(#[from] RequestBuildError),
    #[error(transparent)]
    Reader(#[from] ReaderKeyError),
    #[error("audit cursor is invalid")]
    Cursor,
    #[error("audit page limit is invalid")]
    Limit,
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
    /// The ring event within a Solana transaction. A signature can contain several events.
    pub event_index: u16,
    /// Canonical tagged X25519 transaction viewing key.
    pub tx_viewing_pk: Base64String,
    /// Optional recipient payload metadata, never the authoritative inventory of notes.
    pub outputs: Vec<DecryptedOutput>,
    /// Every verified dedicated opening and its published commitment, in slot order.
    pub output_openings: Vec<DecryptedOutputOpening>,
    /// Proven hidden sender and spent note metadata in an anonymous ring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anonymous: Option<DecryptedAnonymousTrace>,
    pub undecryptable_slots: Vec<u32>,
    pub nullifiers: Vec<Hash>,
    /// Required signers, fee payer first. The sender matches an output owner tag.
    pub signers: Vec<SerializablePubkey>,
    /// Public settlement legs, where value left the ring.
    pub withdrawals: Vec<DecryptedWithdrawal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedOutputContext {
    pub tree_id: u16,
    pub leaf_index: u64,
    pub hash: Hash,
}

/// Exact field encodings preserve unknown assets and dummy slots without trusting wallet data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedOutputOpening {
    pub output_context: DecryptedOutputContext,
    pub domain: Hash,
    pub tree_id: Hash,
    pub owner_hash: Hash,
    pub asset: Hash,
    pub amount: Hash,
    pub blinding: Hash,
    pub data_hash: Hash,
    pub ring_data_hash: Hash,
    pub ring_program_id: Hash,
}

impl
    From<(
        zolana_client::ProofInputUtxo,
        zolana_transaction::OutputContext,
    )> for DecryptedOutputOpening
{
    fn from(
        (opening, context): (
            zolana_client::ProofInputUtxo,
            zolana_transaction::OutputContext,
        ),
    ) -> Self {
        Self {
            output_context: DecryptedOutputContext {
                tree_id: context.tree_id,
                leaf_index: context.leaf_index,
                hash: context.hash.into(),
            },
            domain: opening.domain.into(),
            tree_id: opening.tree_id.into(),
            owner_hash: opening.owner_hash.into(),
            asset: opening.asset.into(),
            amount: opening.amount.into(),
            blinding: opening.blinding.into(),
            data_hash: opening.data_hash.into(),
            ring_data_hash: opening.ring_data_hash.into(),
            ring_program_id: opening.ring_program_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedAnonymousTrace {
    pub sender: SerializablePubkey,
    pub inputs: Vec<DecryptedAnonymousInput>,
    pub recipients: Vec<DecryptedAnonymousRecipient>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedAnonymousInput {
    pub tree_id: u16,
    pub amount: u64,
    pub asset: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedAnonymousRecipient {
    pub slot_index: u32,
    pub identity_tag: u8,
    pub identity_key: Hash,
    pub nullifier_pk: Hash,
    pub amount: u64,
    pub asset: Hash,
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
    /// Base58 of it is the Solana address of an Ed25519 or PDA owner.
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
    pub event_index: u16,
    pub reason: SkippedReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SkippedReason {
    MissingAuditorMessage,
    InvalidAuditData,
}

/// What a signed request covers, besides its timestamp and nonce.
pub trait Attestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadAttestation {
    pub ring: Address,
    pub cursor: Option<Base64String>,
    pub limit: Option<Limit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditorKeyAttestation {
    pub ring: Address,
    pub genesis_hash: [u8; 32],
}

#[must_use]
pub struct SignedRequest<A> {
    attestation: A,
    timestamp: Option<u64>,
    nonce: [u8; 32],
}

pub type ReadRequest = SignedRequest<ReadAttestation>;
pub type AuditorKeyRequest = SignedRequest<AuditorKeyAttestation>;

#[derive(Debug, Error)]
pub enum KeyFileError {
    #[error(transparent)]
    File(#[from] SecretFileError),
    #[error("public key file is not 66 hex characters")]
    PubkeyEncoding,
    #[error("key path must name a file")]
    InvalidPath,
    #[error("auditor key cannot be zero")]
    ZeroAuditorKey,
    #[error("auditor public key is invalid because {0}")]
    Key(#[from] KeypairError),
}

pub fn auditor_key_attestation(
    ring_program_id: &Address,
    auditor_pubkey: &X25519Pubkey,
) -> Vec<u8> {
    [
        ATTESTATION_DOMAIN,
        ring_program_id.as_ref(),
        auditor_pubkey.as_bytes(),
    ]
    .concat()
}

impl RingDepositsRequest {
    pub fn page_limit(&self) -> usize {
        self.limit
            .unwrap_or(DEPOSITS_PAGE_LIMIT)
            .clamp(1, MAX_DEPOSITS_PAGE_LIMIT) as usize
    }

    /// The Solana `before` bound the cursor carries.
    pub fn before(&self) -> Result<Option<Signature>, ReadBuildError> {
        self.cursor
            .as_ref()
            .map(|cursor| {
                <[u8; 64]>::try_from(cursor.0.as_slice())
                    .map(Signature::from)
                    .map_err(|_| ReadBuildError::Cursor)
            })
            .transpose()
    }
}

impl DecryptedTransaction {
    /// The opened values with the indexed nullifiers and the transaction's public legs.
    pub fn new(
        audited: AuditedTransaction,
        event_index: u16,
        nullifiers: Vec<[u8; 32]>,
        signers: Vec<Address>,
        withdrawals: Vec<RingWithdrawal>,
    ) -> Self {
        let outputs = audited.outputs.into_iter().map(|output| DecryptedOutput {
            slot_index: output.slot_index,
            recipient_viewing_pk: output.recipient_viewing_pk.as_bytes().to_vec().into(),
            owner_tag: output.owner_tag.into(),
            asset: output.asset.to_bytes().into(),
            amount: output.amount,
            ring_program_id: output.ring_program_id.map(|id| id.to_bytes().into()),
        });
        let withdrawals = withdrawals
            .into_iter()
            .map(|withdrawal| DecryptedWithdrawal {
                recipient: withdrawal.recipient.to_bytes().into(),
                asset: withdrawal.asset.to_bytes().into(),
                amount: withdrawal.amount,
            });
        Self {
            slot: audited.slot,
            tx_signature: audited.tx_signature.into(),
            event_index,
            tx_viewing_pk: audited.tx_viewing_pk.as_bytes().to_vec().into(),
            outputs: outputs.collect(),
            output_openings: audited
                .output_openings
                .into_iter()
                .zip(audited.output_contexts)
                .map(Into::into)
                .collect(),
            anonymous: audited.anonymous.map(DecryptedAnonymousTrace::from),
            undecryptable_slots: audited.undecryptable_slots,
            nullifiers: nullifiers.into_iter().map(Into::into).collect(),
            signers: signers
                .into_iter()
                .map(|key| key.to_bytes().into())
                .collect(),
            withdrawals: withdrawals.collect(),
        }
    }
}

/// Dummy inputs and recipients carry no note and stay out of the trace.
impl From<AnonymousDisclosure> for DecryptedAnonymousTrace {
    fn from(disclosure: AnonymousDisclosure) -> Self {
        Self {
            sender: Address::new_from_array(disclosure.sender).into(),
            inputs: disclosure
                .inputs
                .into_iter()
                .filter(|input| *input != AuditInputOpening::default())
                .map(|input| DecryptedAnonymousInput {
                    tree_id: input.tree_id,
                    amount: input.amount,
                    asset: input.asset.into(),
                })
                .collect(),
            recipients: (0u32..)
                .zip(disclosure.outputs)
                .filter(|(_, output)| output.identity_tag != 0)
                .map(|(slot_index, output)| DecryptedAnonymousRecipient {
                    slot_index,
                    identity_tag: output.identity_tag,
                    identity_key: output.identity_key.into(),
                    nullifier_pk: output.nullifier_pk.into(),
                    amount: output.amount,
                    asset: output.asset.into(),
                })
                .collect(),
        }
    }
}

impl Attestation for ReadAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        let cursor = self.cursor.as_ref().map_or(&[][..], |cursor| &cursor.0);
        format!(
            "{READ_DOMAIN}\nring: {}\ntimestamp: {timestamp}\nnonce: {}\nlimit: {}\ncursor: {}",
            self.ring,
            base64(nonce),
            self.limit.as_ref().map_or(0, Limit::value),
            base64(cursor),
        )
        .into_bytes()
    }
}

impl Attestation for AuditorKeyAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        format!(
            "{AUDITOR_KEY_REQUEST_DOMAIN}\ngenesis: {}\nring: {}\ntimestamp: {timestamp}\nnonce: {}",
            Hash(self.genesis_hash).to_base58(),
            self.ring,
            base64(nonce),
        )
        .into_bytes()
    }
}

impl<A: Attestation> SignedRequest<A> {
    pub fn new(attestation: A) -> Self {
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Self {
            attestation,
            timestamp: None,
            nonce,
        }
    }

    pub fn at(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    fn message(&self) -> Result<(u64, Vec<u8>), RequestBuildError> {
        let timestamp = self.timestamp.map_or_else(unix_now, Ok)?;
        Ok((timestamp, self.attestation.message(timestamp, &self.nonce)))
    }
}

impl ReadRequest {
    pub fn with_cursor(mut self, cursor: Base64String) -> Result<Self, ReadBuildError> {
        if !cursor_in_bounds(&cursor.0) {
            return Err(ReadBuildError::Cursor);
        }
        self.attestation.cursor = Some(cursor);
        Ok(self)
    }

    pub fn with_limit(mut self, limit: Limit) -> Result<Self, ReadBuildError> {
        if !limit_in_bounds(&limit) {
            return Err(ReadBuildError::Limit);
        }
        self.attestation.limit = Some(limit);
        Ok(self)
    }

    pub fn sign<S: ReadSigner + ?Sized>(
        self,
        signer: &S,
    ) -> Result<GetDecryptedTransactionsRequest, ReadBuildError> {
        let (timestamp, message) = self.message()?;
        let (signature, webauthn) = match signer.sign(&message)? {
            ReadSignature::Ed25519(raw) => (raw.to_vec(), None),
            ReadSignature::WebAuthn {
                signature_der,
                assertion,
            } => (signature_der, Some(assertion)),
        };
        let ReadAttestation {
            ring,
            cursor,
            limit,
        } = self.attestation;
        Ok(GetDecryptedTransactionsRequest {
            ring_program_id: Some(ring.to_bytes().into()),
            cursor,
            limit,
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

impl AuditorKeyRequest {
    pub fn sign<S: Signer + ?Sized>(
        self,
        authority: &S,
    ) -> Result<CreateAuditorKeyRequest, RequestBuildError> {
        let (timestamp, message) = self.message()?;
        let signature = authority
            .try_sign_message(&message)
            .map_err(RequestBuildError::Signature)?;
        let AuditorKeyAttestation { ring, genesis_hash } = self.attestation;
        Ok(CreateAuditorKeyRequest {
            ring_program_id: ring.to_bytes().into(),
            auth: AuthorityAuth {
                authority: authority.pubkey().to_bytes().into(),
                genesis_hash: Hash(genesis_hash),
                timestamp,
                nonce: self.nonce.to_vec().into(),
                signature: signature.as_ref().to_vec().into(),
            },
        })
    }
}

impl GetDecryptedTransactionsRequest {
    pub fn read(ring: Address) -> ReadRequest {
        SignedRequest::new(ReadAttestation {
            ring,
            cursor: None,
            limit: None,
        })
    }
}

impl CreateAuditorKeyRequest {
    /// `genesis_hash` names the cluster, a signature never carries over to another one.
    pub fn for_ring(ring: Address, genesis_hash: [u8; 32]) -> AuditorKeyRequest {
        SignedRequest::new(AuditorKeyAttestation { ring, genesis_hash })
    }
}

impl AuditorPubkey {
    pub fn as_key(&self) -> &X25519Pubkey {
        &self.0
    }
}

impl From<X25519Pubkey> for AuditorPubkey {
    fn from(value: X25519Pubkey) -> Self {
        Self(value)
    }
}

impl From<AuditorPubkey> for Base64String {
    fn from(key: AuditorPubkey) -> Self {
        Self(key.0.as_bytes().to_vec())
    }
}

impl TryFrom<Base64String> for AuditorPubkey {
    type Error = &'static str;

    fn try_from(encoded: Base64String) -> Result<Self, Self::Error> {
        let bytes = encoded
            .0
            .try_into()
            .map_err(|_| "auditor public key length is invalid")?;
        X25519Pubkey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| "auditor public key is invalid")
    }
}

impl<T: Signer + ?Sized> ReadSigner for T {
    fn reader(&self) -> Result<ReaderKey, ReaderKeyError> {
        ReaderKey::ed25519(self.pubkey())
    }

    fn sign(&self, attestation: &[u8]) -> Result<ReadSignature, ReadBuildError> {
        self.try_sign_message(attestation)
            .map(|signature| ReadSignature::Ed25519(*signature.as_array()))
            .map_err(|error| RequestBuildError::Signature(error).into())
    }
}

pub fn unix_now() -> Result<u64, RequestBuildError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| RequestBuildError::Clock)
}

/// Lowercase hex, with the public key beside it in `<file>.pub`.
pub fn read_auditor_key(path: &Path, access: Access) -> Result<X25519Keypair, KeyFileError> {
    let secret = read_hex32(&read_private(path, access, KEY_HEX_LEN)?)?;
    auditor_keypair(&secret)
}

/// Clamping keeps every scalar off the identity, the unset all-zero secret is the only refusal.
pub fn auditor_keypair(secret: &[u8; 32]) -> Result<X25519Keypair, KeyFileError> {
    if secret.iter().all(|byte| *byte == 0) {
        return Err(KeyFileError::ZeroAuditorKey);
    }
    Ok(X25519Keypair::from_bytes(secret))
}

/// Neither file remains when either cannot be written.
pub fn write_auditor_key(out: &Path) -> Result<X25519Keypair, KeyFileError> {
    let public_path = public_key_path(out)?;
    let key = X25519Keypair::new();
    let secret = Zeroizing::new(hex::encode(*key.secret_bytes()));
    let public = hex::encode(key.pubkey().as_bytes());
    create_pair((out, secret.as_bytes()), (&public_path, public.as_bytes()))?;
    Ok(key)
}

pub fn write_auditor_pubkey(path: &Path, pubkey: &X25519Pubkey) -> Result<(), KeyFileError> {
    let public = hex::encode(pubkey.as_bytes());
    Ok(create_new(path, public.as_bytes(), Visibility::Public)?)
}

pub fn read_auditor_pubkey(path: &Path) -> Result<X25519Pubkey, KeyFileError> {
    let text = std::fs::read_to_string(path).map_err(|source| SecretFileError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let bytes = hex::decode(text.trim())
        .ok()
        .and_then(|bytes| <[u8; 33]>::try_from(bytes).ok())
        .ok_or(KeyFileError::PubkeyEncoding)?;
    Ok(X25519Pubkey::from_bytes(bytes)?)
}

pub fn public_key_path(secret: &Path) -> Result<PathBuf, KeyFileError> {
    let mut name = secret
        .file_name()
        .ok_or(KeyFileError::InvalidPath)?
        .to_os_string();
    name.push(".pub");
    Ok(secret.with_file_name(name))
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests;
