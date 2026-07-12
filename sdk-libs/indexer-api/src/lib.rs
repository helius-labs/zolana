//! Shared wire contract for the Zolana indexer JSON-RPC API.

use std::{fmt, str::FromStr};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{
    de::{self, DeserializeOwned, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use solana_pubkey::{ParsePubkeyError, Pubkey};
use solana_signature::{ParseSignatureError, Signature};
use thiserror::Error;

pub const MIN_PAGE_LIMIT: u64 = 1;
pub const PAGE_LIMIT: u64 = 1000;
pub const GET_ENCRYPTED_UTXOS_BY_TAGS: &str = "get_encrypted_utxos_by_tags";
pub const GET_SHIELDED_TRANSACTIONS_BY_TAGS: &str = "get_shielded_transactions_by_tags";
pub const GET_MERKLE_PROOFS: &str = "get_merkle_proofs";
pub const GET_NON_INCLUSION_PROOFS: &str = "get_non_inclusion_proofs";
pub const GET_NULLIFIER_QUEUE_ELEMENTS: &str = "get_nullifier_queue_elements";

const MAX_BASE58_32_LEN: usize = 44;
const LIMIT_EXPECTATION: &str = "a value between 1 and 1000";
const LIMIT_ERROR: &str = "value must be between 1 and 1000";

/// Associates one canonical JSON-RPC method name with its parameter and result types.
pub trait RpcMethod {
    const NAME: &'static str;
    type Request: Serialize + DeserializeOwned;
    type Response: Serialize + DeserializeOwned;
}

pub mod method {
    use super::*;

    pub struct GetEncryptedUtxosByTags;
    pub struct GetShieldedTransactionsByTags;
    pub struct GetMerkleProofs;
    pub struct GetNonInclusionProofs;
    pub struct GetNullifierQueueElements;

    impl RpcMethod for GetEncryptedUtxosByTags {
        const NAME: &'static str = GET_ENCRYPTED_UTXOS_BY_TAGS;
        type Request = GetRingsByTagsRequest;
        type Response = GetEncryptedUtxosByTagsResponse;
    }

    impl RpcMethod for GetShieldedTransactionsByTags {
        const NAME: &'static str = GET_SHIELDED_TRANSACTIONS_BY_TAGS;
        type Request = GetRingsByTagsRequest;
        type Response = GetShieldedTransactionsByTagsResponse;
    }

    impl RpcMethod for GetMerkleProofs {
        const NAME: &'static str = GET_MERKLE_PROOFS;
        type Request = GetMerkleProofsRequest;
        type Response = GetMerkleProofsResponse;
    }

    impl RpcMethod for GetNonInclusionProofs {
        const NAME: &'static str = GET_NON_INCLUSION_PROOFS;
        type Request = GetNonInclusionProofsRequest;
        type Response = GetNonInclusionProofsResponse;
    }

    impl RpcMethod for GetNullifierQueueElements {
        const NAME: &'static str = GET_NULLIFIER_QUEUE_ELEMENTS;
        type Request = GetNullifierQueueElementsRequest;
        type Response = GetNullifierQueueElementsResponse;
    }
}

/// A base64-encoded byte string on the JSON wire.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(value_type = String))]
pub struct Base64String(pub Vec<u8>);

impl From<Vec<u8>> for Base64String {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<Base64String> for Vec<u8> {
    fn from(value: Base64String) -> Self {
        value.0
    }
}

impl Serialize for Base64String {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64String {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Base64Visitor;

        impl Visitor<'_> for Base64Visitor {
            type Value = Base64String;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a base64 encoded string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                STANDARD.decode(value).map(Base64String).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(Base64Visitor)
    }
}

/// A 32-byte hash represented as a base58 string.
#[derive(Default, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(value_type = String))]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn new(bytes: &[u8]) -> Result<Self, ParseHashError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| ParseHashError::WrongSize)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }

    pub fn new_unique() -> Self {
        Self(Pubkey::new_unique().to_bytes())
    }
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ParseHashError {
    #[error("string is the wrong size")]
    WrongSize,
    #[error("invalid hash input")]
    Invalid,
}

impl TryFrom<&str> for Hash {
    type Error = ParseHashError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() > MAX_BASE58_32_LEN {
            return Err(ParseHashError::WrongSize);
        }
        Self::try_from(
            bs58::decode(value)
                .into_vec()
                .map_err(|_| ParseHashError::Invalid)?,
        )
    }
}

impl TryFrom<Vec<u8>> for Hash {
    type Error = ParseHashError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        value
            .try_into()
            .map(Self)
            .map_err(|_| ParseHashError::WrongSize)
    }
}

impl From<[u8; 32]> for Hash {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<&[u8; 32]> for Hash {
    fn from(value: &[u8; 32]) -> Self {
        Self(*value)
    }
}

impl From<Hash> for [u8; 32] {
    fn from(value: Hash) -> Self {
        value.0
    }
}

impl From<Hash> for Vec<u8> {
    fn from(value: Hash) -> Self {
        value.to_vec()
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_base58())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Hash({self})")
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_base58())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HashVisitor;

        impl Visitor<'_> for HashVisitor {
            type Value = Hash;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a base58 encoded 32-byte value")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Hash::try_from(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(HashVisitor)
    }
}

/// A Solana public key represented as a base58 string.
#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(value_type = String))]
pub struct SerializablePubkey(pub Pubkey);

impl SerializablePubkey {
    pub fn to_bytes_vec(self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    pub fn new_unique() -> Self {
        Self(Pubkey::new_unique())
    }
}

impl From<Pubkey> for SerializablePubkey {
    fn from(value: Pubkey) -> Self {
        Self(value)
    }
}

impl From<&Pubkey> for SerializablePubkey {
    fn from(value: &Pubkey) -> Self {
        Self(*value)
    }
}

impl From<[u8; 32]> for SerializablePubkey {
    fn from(value: [u8; 32]) -> Self {
        Self(Pubkey::from(value))
    }
}

impl TryFrom<Vec<u8>> for SerializablePubkey {
    type Error = ParsePubkeyError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Pubkey::try_from(value)
            .map(Self)
            .map_err(|_| ParsePubkeyError::Invalid)
    }
}

impl TryFrom<&str> for SerializablePubkey {
    type Error = ParsePubkeyError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Pubkey::from_str(value).map(Self)
    }
}

impl fmt::Display for SerializablePubkey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Debug for SerializablePubkey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SerializablePubkey({})", self.0)
    }
}

impl Serialize for SerializablePubkey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for SerializablePubkey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_from_str(deserializer, "a base58 encoded Solana public key")
    }
}

/// A Solana transaction signature represented as a base58 string.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(value_type = String))]
pub struct SerializableSignature(pub Signature);

impl From<Signature> for SerializableSignature {
    fn from(value: Signature) -> Self {
        Self(value)
    }
}

impl fmt::Display for SerializableSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for SerializableSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for SerializableSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_from_str(deserializer, "a base58 encoded Solana signature")
    }
}

fn deserialize_from_str<'de, D, T, E>(
    deserializer: D,
    expectation: &'static str,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr<Err = E>,
    E: fmt::Display,
{
    struct FromStrVisitor<T, E> {
        expectation: &'static str,
        marker: std::marker::PhantomData<(T, E)>,
    }

    impl<'de, T, E> Visitor<'de> for FromStrVisitor<T, E>
    where
        T: FromStr<Err = E>,
        E: fmt::Display,
    {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.expectation)
        }

        fn visit_str<V>(self, value: &str) -> Result<Self::Value, V>
        where
            V: de::Error,
        {
            value.parse().map_err(V::custom)
        }
    }

    deserializer.deserialize_str(FromStrVisitor {
        expectation,
        marker: std::marker::PhantomData,
    })
}

impl FromStr for SerializablePubkey {
    type Err = ParsePubkeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Pubkey::from_str(value).map(Self)
    }
}

impl FromStr for SerializableSignature {
    type Err = ParseSignatureError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Signature::from_str(value).map(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Limit(u64);

impl Limit {
    pub fn new(value: u64) -> Result<Self, &'static str> {
        if (MIN_PAGE_LIMIT..=PAGE_LIMIT).contains(&value) {
            Ok(Self(value))
        } else {
            Err(LIMIT_ERROR)
        }
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

impl Default for Limit {
    fn default() -> Self {
        Self(PAGE_LIMIT)
    }
}

#[cfg(feature = "openapi")]
impl utoipa::PartialSchema for Limit {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::Schema> {
        use utoipa::openapi::{
            schema::{ObjectBuilder, Schema, Type},
            KnownFormat, RefOr, SchemaFormat,
        };

        RefOr::T(Schema::Object(
            ObjectBuilder::new()
                .schema_type(Type::Integer)
                .format(Some(SchemaFormat::KnownFormat(KnownFormat::UInt64)))
                .minimum(Some(MIN_PAGE_LIMIT))
                .maximum(Some(PAGE_LIMIT))
                .build(),
        ))
    }
}

#[cfg(feature = "openapi")]
impl utoipa::ToSchema for Limit {}

impl<'de> Deserialize<'de> for Limit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(|_| {
            de::Error::invalid_value(de::Unexpected::Unsigned(value), &LIMIT_EXPECTATION)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Context {
    pub slot: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetRingsByTagsRequest {
    pub tags: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Base64String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<Limit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EncryptedUtxoMatch {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub output_slot: RingsOutputSlot,
    pub tx_viewing_pk: Option<Base64String>,
    /// Transaction-level AES salt shared by every output ciphertext.
    pub salt: Option<Base64String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetEncryptedUtxosByTagsResponse {
    pub context: Context,
    /// Output-level matches; every returned output slot has a view tag from the request.
    pub matches: Vec<EncryptedUtxoMatch>,
    pub next_cursor: Option<Base64String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RingsOutputContext {
    pub hash: Hash,
    pub tree: SerializablePubkey,
    pub leaf_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RingsOutputSlot {
    pub view_tag: Hash,
    pub output_context: RingsOutputContext,
    pub payload: Base64String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ShieldedTransaction {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub tx_viewing_pk: Option<Base64String>,
    /// Transaction-level AES salt shared by every output ciphertext.
    pub salt: Option<Base64String>,
    pub output_slots: Vec<RingsOutputSlot>,
    pub nullifiers: Vec<Hash>,
    /// True when at least one output in this transaction is proofless.
    pub proofless: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetShieldedTransactionsByTagsResponse {
    pub context: Context,
    /// Transaction-level matches; each returned transaction has at least one requested
    /// output view tag and includes all of its output slots.
    pub transactions: Vec<ShieldedTransaction>,
    pub next_cursor: Option<Base64String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetMerkleProofsRequest {
    pub tree_account: SerializablePubkey,
    pub leaves: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetMerkleProofsResponse {
    pub context: Context,
    pub proofs: Vec<MerkleProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetNullifierQueueElementsRequest {
    pub tree_account: SerializablePubkey,
    /// Return elements with `input_queue_seq >= start_seq` (default 0).
    #[serde(default)]
    pub start_seq: u64,
    /// Maximum number of elements to return.
    pub limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetNullifierQueueElementsResponse {
    pub context: Context,
    pub elements: Vec<NullifierQueueElement>,
}

/// One queued nullifier, in on-chain input-queue order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NullifierQueueElement {
    pub seq: u64,
    pub value: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MerkleContext {
    pub tree_type: u16,
    pub tree: SerializablePubkey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MerkleProof {
    pub leaf: Hash,
    pub merkle_context: MerkleContext,
    pub path: Vec<Hash>,
    pub leaf_index: u64,
    pub root: Hash,
    pub root_seq: u64,
    pub root_index: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetNonInclusionProofsRequest {
    pub tree_account: SerializablePubkey,
    pub leaves: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetNonInclusionProofsResponse {
    pub context: Context,
    pub proofs: Vec<NonInclusionProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NonInclusionProof {
    pub leaf: Hash,
    pub merkle_context: MerkleContext,
    pub path: Vec<Hash>,
    pub low_element: Hash,
    pub low_element_index: u64,
    pub high_element: Hash,
    pub high_element_index: u64,
    pub root: Hash,
    pub root_seq: u64,
    pub root_index: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_markers_have_canonical_names() {
        assert_eq!(
            method::GetEncryptedUtxosByTags::NAME,
            "get_encrypted_utxos_by_tags"
        );
        assert_eq!(method::GetMerkleProofs::NAME, "get_merkle_proofs");
        assert_eq!(
            method::GetNullifierQueueElements::NAME,
            "get_nullifier_queue_elements"
        );
    }

    #[test]
    fn encoded_values_round_trip_and_validate() {
        let hash = Hash::from([7; 32]);
        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(serde_json::from_str::<Hash>(&json).unwrap(), hash);
        assert!(serde_json::from_str::<Hash>(r#""short""#).is_err());

        let payload = Base64String(vec![1, 2, 3]);
        let json = serde_json::to_string(&payload).unwrap();
        assert_eq!(json, r#""AQID""#);
        assert_eq!(
            serde_json::from_str::<Base64String>(&json).unwrap(),
            payload
        );
    }

    #[test]
    fn response_shape_stays_snake_case() {
        let value = serde_json::to_value(GetEncryptedUtxosByTagsResponse {
            context: Context { slot: 3 },
            matches: Vec::new(),
            next_cursor: Some(Base64String(vec![1])),
        })
        .unwrap();
        assert!(value.get("next_cursor").is_some());
        assert!(value.get("nextCursor").is_none());
    }
}
