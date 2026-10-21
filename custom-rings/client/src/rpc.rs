//! The ring rpc wire, its signed attestations and the auditor key files.

use std::path::{Path, PathBuf};

use custom_ring_interface::{MemberRegistry, RecordQueue, RingAccount, RootEntry};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::{Signer, SignerError};
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_client::{AsyncRpc, ClientError};
use zolana_indexer_api::{
    Base64String, Context, Hash, Limit, SerializablePubkey, SerializableSignature,
};
use zolana_interface::{state::RingConfig, RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID};
use zolana_keypair::{KeypairError, X25519Keypair, X25519Pubkey};
use zolana_secret_file::{
    create_new, create_pair, read_hex32, read_private, Access, SecretFileError, Visibility,
};

use crate::{
    AuditedInput, AuditedNote, AuditedOutput, AuditedTransaction, InputRing, KnownNote,
    MergeAuditPage, MergeKeys, OutputOpening, OutputPayloadErrorKind, ReaderKey, ReaderKeyError,
    RingWithdrawal,
};

pub const HEALTH: &str = "health";
pub const CREATE_AUDITOR_KEY: &str = "createAuditorKey";
pub const RING_STATUS: &str = "ringStatus";
pub const RING_DEPOSITS: &str = "ringDeposits";
pub const GET_DECRYPTED_TRANSACTIONS: &str = "getDecryptedTransactions";
pub const GET_AUDITED_MERGES: &str = "getAuditedMerges";
pub const GET_AUDITED_NOTES: &str = "getAuditedNotes";
/// The most UTXO hashes one `getAuditedNotes` request names.
pub const AUDITED_NOTES_LIMIT: usize = 100;
pub const AUDIT_CURSOR_LIMIT: usize = 256;
pub const AUDIT_PAGE_LIMIT: u64 = 100;
pub const DEPOSITS_PAGE_LIMIT: u32 = 50;
pub const MAX_DEPOSITS_PAGE_LIMIT: u32 = 200;
const KEY_HEX_LEN: u64 = 64;
const ATTESTATION_DOMAIN: &[u8] = b"zolana/ring-auditor-key/v1";
const READ_DOMAIN: &str = "zolana/ring-rpc-read/v1";
const AUDITOR_KEY_REQUEST_DOMAIN: &str = "zolana/ring-rpc-auditor-key-request/v1";
const AUDITED_NOTES_DOMAIN: &str = "zolana/ring-rpc-audited-notes/v1";

/// One cursor rule for the request builder, the page and the indexer response check.
pub fn cursor_in_bounds(cursor: &[u8]) -> bool {
    !cursor.is_empty() && cursor.len() <= AUDIT_CURSOR_LIMIT
}

pub fn limit_in_bounds(limit: &Limit) -> bool {
    limit.value() <= AUDIT_PAGE_LIMIT
}

/// One count rule for the note request builder and the service.
pub fn notes_in_bounds(utxo_hashes: &[Hash]) -> bool {
    (1..=AUDITED_NOTES_LIMIT).contains(&utxo_hashes.len())
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
    /// Signatures examined, not deposits found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Opaque, taken from the previous page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Base64String>,
}

/// A deposit publishes its asset and amount, reading it takes no auditor key.
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

/// Unsigned, so it carries only what the chain already publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingStatusResponse {
    pub ring_program_id: SerializablePubkey,
    pub state: RingState,
    /// The key the ring's config names, absent until the config exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_auditor_pubkey: Option<AuditorPubkey>,
    pub service_pubkey: SerializablePubkey,
    /// Absent until SPP holds a config for the ring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<RingActivation>,
    /// Absent until the ring creates its member registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<RegistryStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingActivation {
    pub activated: bool,
    pub paused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistryStatus {
    /// Entry `i` sits at history slot `i`, `null` for a slot never written.
    pub history: Vec<Option<RegistryRoot>>,
    /// The history slot of the newest root.
    pub history_cursor: u8,
    pub next_index: u32,
    /// The applied position every own-ring root must reach.
    pub floor: u64,
    pub prior_floor: u64,
    /// The slot of the last floor raise.
    pub floor_slot: u64,
    /// Queue positions `head..tail` wait for an application.
    pub queue_head: u64,
    pub queue_tail: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistryRoot {
    pub root: Hash,
    /// The queue head right after the application that pushed the root.
    pub applied: u64,
    pub slot: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RingChainStatus {
    pub activation: Option<RingActivation>,
    pub registry: Option<RegistryStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RingState {
    /// The config names the service's key, reads work.
    Served,
    /// The config names another auditor for good, the service never opens the ring.
    ForeignAuditor,
    /// No config yet, `init` is free to pin the service's key.
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
pub struct GetAuditedNotesRequest {
    /// Required for derived keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_program_id: Option<SerializablePubkey>,
    /// UTXO hashes with their tree id, `1..=AUDITED_NOTES_LIMIT` of them.
    pub utxo_hashes: Vec<Hash>,
    pub auth: ReadAuth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetAuditedNotesResponse {
    /// The backfill's newest page, a later note reads `null` until the backfill passes it.
    pub context: Context,
    pub value: AuditedNotesPage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditedNotesPage {
    /// In request order, `null` for a note the auditor has not opened.
    pub notes: Vec<Option<AuditedNoteView>>,
}

/// A note the auditor opened, with the transaction that created it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditedNoteView {
    pub utxo_hash: Hash,
    pub note: DecryptedNote,
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub event_index: u16,
    pub slot_index: u32,
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
    /// The authenticated registry member hash, the event names no signing key.
    pub owner_member: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_pubkey: Option<SerializablePubkey>,
    pub mint: SerializablePubkey,
    pub amount: u64,
    pub blinding: Hash,
    pub ring_data_hash: Hash,
    pub input_nullifiers: Vec<Hash>,
    /// Absent for an anonymous merge, whose nullifier key stays hidden.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullifier: Option<Hash>,
    /// The disclosed spent commitments of an anonymous merge, padding zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_commitments: Option<Vec<Hash>>,
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
                    .map(|merge| {
                        let (nullifier, input_commitments) = match merge.keys {
                            MergeKeys::Escrowed { nullifier } => (Some(Hash(nullifier)), None),
                            MergeKeys::Disclosed { input_commitments } => (
                                None,
                                Some(input_commitments.into_iter().map(Hash).collect()),
                            ),
                        };
                        AuditedMergeRecord {
                            tx_signature: merge.tx_signature.into(),
                            event_index: merge.event_index,
                            output_commitment: Hash(merge.output_commitment),
                            owner_member: Hash(merge.owner_member),
                            owner_pubkey: merge.owner_pubkey.map(Into::into),
                            mint: merge.mint.into(),
                            amount: merge.amount,
                            blinding: Hash(merge.blinding),
                            ring_data_hash: Hash(merge.ring_data_hash),
                            input_nullifiers: merge
                                .input_nullifiers
                                .into_iter()
                                .map(Hash)
                                .collect(),
                            nullifier,
                            input_commitments,
                        }
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
    #[error("a note read names 1 to {AUDITED_NOTES_LIMIT} UTXO hashes")]
    Notes,
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
    /// The ring event within a Solana transaction, one signature can carry several.
    pub event_index: u16,
    /// Canonical tagged X25519 transaction viewing key.
    pub tx_viewing_pk: Base64String,
    /// Every slot whose rebuilt opening reaches its published commitment, in published order.
    pub outputs: Vec<DecryptedOutput>,
    pub payload_errors: Vec<DecryptedPayloadError>,
    /// The hidden sender of an anonymous ring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<DecryptedSender>,
    /// One per published nullifier of an anonymous ring.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<DecryptedInput>,
    pub nullifiers: Vec<Hash>,
    /// Required signers, fee payer first.
    pub signers: Vec<SerializablePubkey>,
    /// Public settlement legs, where value left the ring.
    pub withdrawals: Vec<DecryptedWithdrawal>,
}

/// The public legs and nullifiers come from the confirmed transaction.
#[must_use]
pub struct ConfirmedAudit {
    pub audited: AuditedTransaction,
    pub event_index: u16,
    pub nullifiers: Vec<[u8; 32]>,
    pub signers: Vec<Address>,
    pub withdrawals: Vec<RingWithdrawal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedPayloadError {
    pub slot_index: u32,
    pub kind: OutputPayloadErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedOutputContext {
    pub tree_id: u16,
    pub leaf_index: u64,
    pub hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedOutput {
    pub slot_index: u32,
    pub output_context: DecryptedOutputContext,
    pub kind: DecryptedOutputKind,
    /// Absent for a dummy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<DecryptedNote>,
    /// The recipient's X25519 u of a ring output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_u: Option<Hash>,
    /// `0x00 || tag`, the published owner tag of an anonymous ring output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<Hash>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DecryptedOutputKind {
    Ring,
    Exit,
    Dummy,
}

/// Exact field encodings keep an unknown asset readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedNote {
    /// Base58 of it is the owner's Solana address.
    pub owner_key: SerializablePubkey,
    /// Absent for a deposit, its capsule discloses the owner hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullifier_pk: Option<Hash>,
    pub asset: Hash,
    /// Absent while the asset registry does not know the asset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint: Option<SerializablePubkey>,
    pub amount: u64,
    pub blinding: Hash,
    pub data_hash: Hash,
    pub ring_data_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedSender {
    pub owner_key: SerializablePubkey,
    /// Absent when spent note 0 is a deposit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullifier_pk: Option<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedInput {
    pub nullifier: Hash,
    /// Absent for a dummy input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opening: Option<DecryptedInputOpening>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedInputOpening {
    pub asset: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint: Option<SerializablePubkey>,
    pub amount: u64,
    pub blinding: Hash,
    /// Absent without the input's tree id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring: Option<DecryptedInputRing>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum DecryptedInputRing {
    Ring { commitment: Hash },
    Default { commitment: Hash },
    Unresolved { ring: Hash, default: Hash },
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
    /// An anonymous input names a note the service has not opened yet.
    UnseenInput,
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

/// A note read binds the hashes it names through their digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditedNotesAttestation {
    pub ring: Address,
    /// sha256 of the requested hashes, concatenated in request order.
    pub notes: [u8; 32],
}

#[must_use]
pub struct SignedRequest<A> {
    attestation: A,
    timestamp: Option<u64>,
    nonce: [u8; 32],
}

pub type ReadRequest = SignedRequest<ReadAttestation>;
pub type AuditorKeyRequest = SignedRequest<AuditorKeyAttestation>;

#[must_use]
pub struct AuditedNotesRequest {
    signed: SignedRequest<AuditedNotesAttestation>,
    utxo_hashes: Vec<Hash>,
}

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

impl From<ConfirmedAudit> for DecryptedTransaction {
    fn from(confirmed: ConfirmedAudit) -> Self {
        let ConfirmedAudit {
            audited,
            event_index,
            nullifiers,
            signers,
            withdrawals,
        } = confirmed;
        Self {
            slot: audited.slot,
            tx_signature: audited.tx_signature.into(),
            event_index,
            tx_viewing_pk: audited.tx_viewing_pk.as_bytes().to_vec().into(),
            outputs: audited.outputs.into_iter().map(Into::into).collect(),
            payload_errors: audited
                .payload_errors
                .into_iter()
                .map(|error| DecryptedPayloadError {
                    slot_index: error.slot_index,
                    kind: error.kind,
                })
                .collect(),
            sender: audited.sender.map(|sender| DecryptedSender {
                owner_key: sender.owner_key.into(),
                nullifier_pk: sender.nullifier_pk.map(Into::into),
            }),
            inputs: audited.inputs.into_iter().map(Into::into).collect(),
            nullifiers: nullifiers.into_iter().map(Into::into).collect(),
            signers: signers
                .into_iter()
                .map(|key| key.to_bytes().into())
                .collect(),
            withdrawals: withdrawals
                .into_iter()
                .map(|withdrawal| DecryptedWithdrawal {
                    recipient: withdrawal.recipient.to_bytes().into(),
                    asset: withdrawal.asset.to_bytes().into(),
                    amount: withdrawal.amount,
                })
                .collect(),
        }
    }
}

impl From<AuditedOutput> for DecryptedOutput {
    fn from(output: AuditedOutput) -> Self {
        let (kind, note, recipient_u, tag) = match output.opening {
            OutputOpening::Ring {
                note,
                recipient_u,
                tag,
            } => (
                DecryptedOutputKind::Ring,
                Some(note),
                Some(recipient_u.into()),
                tag.map(|tag| tag.field().into()),
            ),
            OutputOpening::Exit(note) => (DecryptedOutputKind::Exit, Some(note), None, None),
            OutputOpening::Dummy => (DecryptedOutputKind::Dummy, None, None, None),
        };
        Self {
            slot_index: output.slot_index,
            output_context: DecryptedOutputContext {
                tree_id: output.context.tree_id,
                leaf_index: output.context.leaf_index,
                hash: output.context.hash.into(),
            },
            kind,
            note: note.map(Into::into),
            recipient_u,
            tag,
        }
    }
}

impl From<AuditedNote> for DecryptedNote {
    fn from(note: AuditedNote) -> Self {
        KnownNote::from(note).into()
    }
}

impl From<KnownNote> for DecryptedNote {
    fn from(note: KnownNote) -> Self {
        Self {
            owner_key: note.owner_key.into(),
            nullifier_pk: note.nullifier_pk.map(Into::into),
            asset: note.asset.into(),
            mint: note.mint.map(Into::into),
            amount: note.amount,
            blinding: note.blinding.into(),
            data_hash: note.data_hash.into(),
            ring_data_hash: note.ring_data_hash.into(),
        }
    }
}

impl From<AuditedInput> for DecryptedInput {
    fn from(input: AuditedInput) -> Self {
        Self {
            nullifier: input.nullifier.into(),
            opening: input.opening.map(|opening| DecryptedInputOpening {
                asset: opening.asset.into(),
                mint: opening.mint.map(Into::into),
                amount: opening.amount,
                blinding: opening.blinding.into(),
                ring: opening.ring.map(|ring| match ring {
                    InputRing::Ring { commitment } => DecryptedInputRing::Ring {
                        commitment: commitment.into(),
                    },
                    InputRing::Default { commitment } => DecryptedInputRing::Default {
                        commitment: commitment.into(),
                    },
                    InputRing::Unresolved { ring, default } => DecryptedInputRing::Unresolved {
                        ring: ring.into(),
                        default: default.into(),
                    },
                }),
            }),
        }
    }
}

impl RegistryStatus {
    pub fn new(registry: &MemberRegistry, queue: &RecordQueue) -> Self {
        Self {
            history: registry
                .history
                .iter()
                .map(|entry| (entry.root != [0; 32]).then(|| RegistryRoot::from(entry)))
                .collect(),
            history_cursor: registry.history_cursor,
            next_index: registry.next_index(),
            floor: registry.floor(),
            prior_floor: registry.prior_floor(),
            floor_slot: registry.floor_slot(),
            queue_head: queue.head(),
            queue_tail: queue.tail(),
        }
    }
}

impl From<&RootEntry> for RegistryRoot {
    fn from(entry: &RootEntry) -> Self {
        Self {
            root: entry.root.into(),
            applied: entry.applied(),
            slot: entry.slot(),
        }
    }
}

impl RingChainStatus {
    /// An account of another owner reads as absent, a malformed one of the ring is an error.
    pub async fn read<R: AsyncRpc + ?Sized>(rpc: &R, ring: Address) -> Result<Self, ClientError> {
        let pool = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let (config, config_bump) = Address::find_program_address(&[RING_AUTH_PDA_SEED], &ring);
        let (registry, registry_bump) =
            Address::find_program_address(&[MemberRegistry::SEED], &ring);
        let (queue, queue_bump) = Address::find_program_address(&[RecordQueue::SEED], &ring);
        let accounts = rpc
            .get_multiple_accounts(vec![config, registry, queue])
            .await?;
        let [config, registry, queue] = <[_; 3]>::try_from(accounts)
            .map_err(|_| ClientError::Rpc("ring status accounts are missing".to_owned()))?;
        let invalid = |name: &str| ClientError::Rpc(format!("ring {name} account is invalid"));
        let activation = config
            .filter(|account| account.owner == pool)
            .map(|account| {
                bytemuck::try_from_bytes::<RingConfig>(&account.data)
                    .ok()
                    .filter(|config| {
                        config.has_discriminator()
                            && config.program_id == ring
                            && config.bump == config_bump
                    })
                    .map(RingActivation::from)
                    .ok_or_else(|| invalid("SPP config"))
            })
            .transpose()?;
        let registry = match (
            registry.filter(|account| account.owner == ring),
            queue.filter(|account| account.owner == ring),
        ) {
            (Some(registry), Some(queue)) => {
                let registry = MemberRegistry::decode(&registry.owner, &ring, &registry.data)
                    .filter(|registry| registry.bump == registry_bump)
                    .ok_or_else(|| invalid("member registry"))?;
                let queue = RecordQueue::decode(&queue.owner, &ring, &queue.data)
                    .filter(|queue| queue.bump == queue_bump)
                    .ok_or_else(|| invalid("record queue"))?;
                Some(RegistryStatus::new(&registry, &queue))
            }
            (None, None) => None,
            _ => return Err(invalid("member registry")),
        };
        Ok(Self {
            activation,
            registry,
        })
    }
}

impl From<&RingConfig> for RingActivation {
    fn from(config: &RingConfig) -> Self {
        Self {
            activated: config.is_activated(),
            paused: config.is_paused(),
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

impl AuditedNotesAttestation {
    pub fn new(ring: Address, utxo_hashes: &[Hash]) -> Self {
        let mut digest = Sha256::new();
        for hash in utxo_hashes {
            digest.update(hash.0);
        }
        Self {
            ring,
            notes: digest.finalize().into(),
        }
    }
}

impl Attestation for AuditedNotesAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        format!(
            "{AUDITED_NOTES_DOMAIN}\nring: {}\ntimestamp: {timestamp}\nnonce: {}\nnotes: {}",
            self.ring,
            base64(nonce),
            base64(&self.notes),
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

    /// The reader's signature over the attestation, a passkey's with its assertion.
    fn read_auth<S: ReadSigner + ?Sized>(&self, signer: &S) -> Result<ReadAuth, ReadBuildError> {
        let (timestamp, message) = self.message()?;
        let (signature, webauthn) = match signer.sign(&message)? {
            ReadSignature::Ed25519(raw) => (raw.to_vec(), None),
            ReadSignature::WebAuthn {
                signature_der,
                assertion,
            } => (signature_der, Some(assertion)),
        };
        Ok(ReadAuth {
            reader: signer.reader()?.to_bytes().to_vec().into(),
            timestamp,
            nonce: self.nonce.to_vec().into(),
            signature: signature.into(),
            webauthn,
        })
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
        let auth = self.read_auth(signer)?;
        let ReadAttestation {
            ring,
            cursor,
            limit,
        } = self.attestation;
        Ok(GetDecryptedTransactionsRequest {
            ring_program_id: Some(ring.to_bytes().into()),
            cursor,
            limit,
            auth,
        })
    }
}

impl AuditedNotesRequest {
    pub fn at(self, timestamp: u64) -> Self {
        Self {
            signed: self.signed.at(timestamp),
            ..self
        }
    }

    pub fn sign<S: ReadSigner + ?Sized>(
        self,
        signer: &S,
    ) -> Result<GetAuditedNotesRequest, ReadBuildError> {
        Ok(GetAuditedNotesRequest {
            ring_program_id: Some(self.signed.attestation.ring.to_bytes().into()),
            auth: self.signed.read_auth(signer)?,
            utxo_hashes: self.utxo_hashes,
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

impl GetAuditedNotesRequest {
    /// Refuses an empty or oversized read before it is signed.
    pub fn read(
        ring: Address,
        utxo_hashes: Vec<Hash>,
    ) -> Result<AuditedNotesRequest, ReadBuildError> {
        if !notes_in_bounds(&utxo_hashes) {
            return Err(ReadBuildError::Notes);
        }
        Ok(AuditedNotesRequest {
            signed: SignedRequest::new(AuditedNotesAttestation::new(ring, &utxo_hashes)),
            utxo_hashes,
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
