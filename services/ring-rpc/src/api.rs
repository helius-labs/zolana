//! Wire types of the Ring RPC. Scalars use the indexer's encodings (base58
//! keys and signatures, base64 bytes, hex hashes).

use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signer::Signer;
use zolana_indexer_api::{
    Base64String, Context, Hash, Limit, SerializablePubkey, SerializableSignature,
};
use zolana_keypair::{KeypairError, ViewingKey};

pub const HEALTH: &str = "health";
pub const CREATE_AUDITOR_KEY: &str = "createAuditorKey";
pub const GET_DECRYPTED_TRANSACTIONS: &str = "getDecryptedTransactions";
pub const PROVE_AUDITOR_KEY_ENCRYPTION: &str = "proveAuditorKeyEncryption";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct HealthResponse {
    /// `local` serves one key, `derived` a key per ring.
    pub mode: String,
    /// The ed25519 key this instance signs `createAuditorKey` responses with.
    pub service_pubkey: SerializablePubkey,
    /// The local key's tag, absent when keys are derived per ring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auditor_view_tag: Option<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CreateAuditorKeyRequest {
    pub ring_program_id: SerializablePubkey,
}

/// The public half of a ring's auditor key. Idempotent, the same ring gets
/// the same key back. `signature` is the instance's ed25519 signature over
/// [`auditor_key_attestation`], so a client that pins `service_pubkey` cannot
/// be handed another party's key in transit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CreateAuditorKeyResponse {
    pub ring_program_id: SerializablePubkey,
    /// SEC1 compressed, what `create_config` takes.
    pub auditor_pubkey: Base64String,
    pub auditor_view_tag: Hash,
    pub service_pubkey: SerializablePubkey,
    pub signature: SerializableSignature,
}

/// Domain of the attestation signature.
const ATTESTATION_DOMAIN: &[u8] = b"zolana/ring-auditor-key/v1";

/// The bytes the instance signs for a `createAuditorKey` response. Binds the
/// key to the ring, so a signature for one ring attests nothing for another.
pub fn auditor_key_attestation(ring_program_id: &Address, auditor_pubkey: &[u8]) -> Vec<u8> {
    [ATTESTATION_DOMAIN, ring_program_id.as_ref(), auditor_pubkey].concat()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct ProveAuditorKeyEncryptionRequest {
    /// Required when the instance derives keys per ring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_program_id: Option<SerializablePubkey>,
    pub private_tx_hash: Base64String,
    pub tx_viewing_sk: Base64String,
    pub eph_sk: Base64String,
}

/// The wincode bytes of `AuditProof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct ProveAuditorKeyEncryptionResponse {
    pub proof: Base64String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct GetDecryptedTransactionsRequest {
    /// Required when the instance derives keys per ring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_program_id: Option<SerializablePubkey>,
    /// Opaque indexer cursor from a previous page.
    #[serde(default)]
    pub cursor: Option<Base64String>,
    #[serde(default)]
    pub limit: Option<Limit>,
    pub auth: ReadAuth,
}

/// Who reads, how much, and proof of it. `signature` is `reader`'s signature
/// over [`read_attestation`] of this request, and `timestamp` (unix seconds)
/// keeps a captured request from being replayed later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct ReadAuth {
    pub scope: ReadScope,
    /// An ed25519 pubkey (32 bytes, signs ed25519) or a P-256 pubkey (33 bytes
    /// SEC1 compressed, signs ECDSA over `SHA-256(message)`, or through
    /// WebAuthn when `webauthn` is present).
    pub reader: Base64String,
    pub timestamp: u64,
    /// Raw `r || s`, or DER when `webauthn` is present.
    pub signature: Base64String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn: Option<WebAuthnAssertion>,
}

/// The authenticator output next to the signature. The challenge inside
/// `client_data_json` is `SHA-256(read_attestation)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct WebAuthnAssertion {
    pub authenticator_data: Base64String,
    pub client_data_json: Base64String,
}

/// How much of the ring a read may see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadScope {
    /// Every transaction of the ring. The reader must be the ring authority
    /// its on-chain config records.
    Ring,
    /// Only what the reader took part in: as a sender, the transactions it
    /// signed; as a recipient, the outputs encrypted to its viewing key. Any
    /// key may ask, it only ever sees its own side.
    Participant,
}

impl ReadScope {
    const fn name(self) -> &'static str {
        match self {
            Self::Ring => "ring",
            Self::Participant => "participant",
        }
    }
}

impl GetDecryptedTransactionsRequest {
    /// A read of `ring`'s page at `cursor`, to be signed by a reader.
    pub fn unsigned(ring_program_id: Address, cursor: Option<Base64String>) -> UnsignedRead {
        UnsignedRead {
            ring_program_id,
            cursor,
            limit: None,
        }
    }
}

/// A read before the reader signed it. Signing stamps the current time, so
/// sign right before sending and sign again on retry.
pub struct UnsignedRead {
    ring_program_id: Address,
    cursor: Option<Base64String>,
    limit: Option<Limit>,
}

impl UnsignedRead {
    pub fn limit(mut self, limit: Limit) -> Self {
        self.limit = Some(limit);
        self
    }

    /// The whole ring, signed by the ring authority.
    pub fn sign(self, authority: &dyn Signer) -> GetDecryptedTransactionsRequest {
        self.signed(
            ReadScope::Ring,
            authority.pubkey().to_bytes().to_vec(),
            |message| authority.sign_message(message).as_ref().to_vec(),
        )
    }

    /// The transactions `sender` signed, as the auditor sees them.
    pub fn sign_as_sender(self, sender: &dyn Signer) -> GetDecryptedTransactionsRequest {
        self.signed(
            ReadScope::Participant,
            sender.pubkey().to_bytes().to_vec(),
            |message| sender.sign_message(message).as_ref().to_vec(),
        )
    }

    /// The outputs encrypted to `recipient`'s viewing key, as the auditor sees
    /// them. ECDSA P-256 over `SHA-256(message)`, the viewing key's curve.
    pub fn sign_as_recipient(
        self,
        recipient: &ViewingKey,
    ) -> Result<GetDecryptedTransactionsRequest, KeypairError> {
        let signing = p256::ecdsa::SigningKey::from_bytes((&*recipient.secret_bytes()).into())
            .map_err(|_| KeypairError::InvalidSecretKey)?;
        Ok(self.signed(
            ReadScope::Participant,
            recipient.pubkey().as_bytes().to_vec(),
            |message| {
                use p256::ecdsa::signature::hazmat::PrehashSigner;
                let digest = <sha2::Sha256 as sha2::Digest>::digest(message);
                let signature: p256::ecdsa::Signature = signing
                    .sign_prehash(&digest)
                    .expect("P-256 prehash signing does not fail for a valid key");
                signature.to_bytes().to_vec()
            },
        ))
    }

    fn signed(
        self,
        scope: ReadScope,
        reader: Vec<u8>,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> GetDecryptedTransactionsRequest {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or_default();
        let message = read_attestation(
            scope,
            &self.ring_program_id,
            timestamp,
            self.cursor.as_ref().map(|cursor| cursor.0.as_slice()),
            self.limit.as_ref().map(Limit::value),
        );
        let signature = sign(&message);
        GetDecryptedTransactionsRequest {
            ring_program_id: Some(self.ring_program_id.to_bytes().into()),
            cursor: self.cursor,
            limit: self.limit,
            auth: ReadAuth {
                scope,
                reader: reader.into(),
                timestamp,
                signature: signature.into(),
                webauthn: None,
            },
        }
    }
}

/// Domain of the read signature.
const READ_DOMAIN: &str = "zolana/ring-rpc-read/v1";

/// The bytes a reader signs for `getDecryptedTransactions`: the scope, the
/// ring, the moment, and the page asked for, so a signature fits one request.
/// Plain text, one `name: value` line per field, because browser wallets
/// refuse to sign bytes that could be a transaction and show text as is.
pub fn read_attestation(
    scope: ReadScope,
    ring_program_id: &Address,
    timestamp: u64,
    cursor: Option<&[u8]>,
    limit: Option<u64>,
) -> Vec<u8> {
    use base64::Engine;
    format!(
        "{READ_DOMAIN}\nscope: {}\nring: {ring_program_id}\ntimestamp: {timestamp}\nlimit: {}\ncursor: {}",
        scope.name(),
        limit.unwrap_or(0),
        base64::engine::general_purpose::STANDARD.encode(cursor.unwrap_or_default()),
    )
    .into_bytes()
}

#[cfg(test)]
mod attestation_tests {
    use super::*;

    /// Pinned byte for byte with the TypeScript SDK (`ringReadAttestation`).
    #[test]
    fn read_attestation_is_the_pinned_text() {
        let message = read_attestation(
            ReadScope::Participant,
            &Address::new_from_array([7; 32]),
            1_700_000_000,
            Some(&[1, 2, 3]),
            Some(5),
        );
        assert_eq!(
            String::from_utf8(message).expect("text"),
            "zolana/ring-rpc-read/v1\nscope: participant\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1700000000\nlimit: 5\ncursor: AQID"
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct GetDecryptedTransactionsResponse {
    pub context: Context,
    pub value: DecryptedTransactionsPage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct DecryptedTransactionsPage {
    pub items: Vec<DecryptedTransaction>,
    /// Transactions tagged for this auditor that did not audit: a message
    /// encrypted to another key, a malformed message, or an asset the service
    /// cannot resolve. Reported so a gap is visible instead of silent.
    pub skipped: Vec<SkippedTransaction>,
    pub cursor: Option<Base64String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct DecryptedTransaction {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    /// Solana signers of the transaction. On the eddsa rail the spent inputs'
    /// owners sign, so this is the sender side; the fee payer is among them.
    pub signers: Vec<SerializablePubkey>,
    /// SEC1 compressed transaction viewing pubkey the recovered key matched.
    pub tx_viewing_pk: Base64String,
    pub outputs: Vec<DecryptedOutput>,
    /// Slot positions the recovered key did not open: dummies, other schemes,
    /// or ciphertexts under another transaction key.
    pub undecryptable_slots: Vec<u32>,
    pub nullifiers: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct DecryptedOutput {
    pub slot_index: u32,
    /// SEC1 compressed viewing pubkey of the output's recipient, the "to".
    /// The sender's change carries the sender's own viewing key.
    pub recipient_viewing_pk: Base64String,
    pub asset: SerializablePubkey,
    pub amount: u64,
    pub blinding: Base64String,
    pub ring_program_id: Option<SerializablePubkey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct SkippedTransaction {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub reason: String,
}
