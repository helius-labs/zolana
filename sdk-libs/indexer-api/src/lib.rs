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
pub const GET_ENCRYPTED_UTXOS_BY_TAGS: &str = "getEncryptedUtxosByTags";
pub const GET_SHIELDED_TRANSACTIONS_BY_TAGS: &str = "getShieldedTransactionsByTags";
pub const GET_SHIELDED_TRANSACTIONS_BY_SIGNATURE: &str = "getShieldedTransactionsBySignature";
pub const GET_SHIELDED_TRANSACTIONS_BY_NULLIFIERS: &str = "getShieldedTransactionsByNullifiers";
pub const GET_MERKLE_PROOFS: &str = "getMerkleProofs";
pub const GET_RING_KEY_REGISTRY_ENTRY: &str = "getRingKeyRegistryEntry";
pub const GET_RING_KEY_REGISTRY_REGISTER_PROOF: &str = "getRingKeyRegistryRegisterProof";
pub const GET_RING_SPEND_RECORD: &str = "getRingSpendRecord";
pub const GET_NON_INCLUSION_PROOFS: &str = "getNonInclusionProofs";
pub const GET_NULLIFIER_QUEUE_ELEMENTS: &str = "getNullifierQueueElements";
pub const GET_USER_RECORDS: &str = "getUserRecords";
/// The most owners one `getUserRecords` request names: the Solana RPC answers
/// `getMultipleAccounts` for at most this many accounts in one call.
pub const MAX_USER_RECORD_OWNERS: usize = 100;

const MAX_BASE58_32_LEN: usize = 44;
const LIMIT_EXPECTATION: &str = "a value between 1 and 1000";
const LIMIT_ERROR: &str = "value must be between 1 and 1000";

pub mod error_code {
    pub const RING_KEY_REGISTRY_OUT_OF_SYNC: i64 = -32070;
    pub const RING_KEY_REGISTRY_ROOT_CHANGED: i64 = -32071;
    pub const RING_KEY_REGISTRY_MEMBER_UNREGISTERED: i64 = -32072;
    pub const RING_KEY_REGISTRY_MEMBER_ALREADY_REGISTERED: i64 = -32073;
    pub const RING_SPEND_RECORD_OUT_OF_SYNC: i64 = -32074;
}

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
    pub struct GetShieldedTransactionsBySignature;
    pub struct GetShieldedTransactionsByNullifiers;
    pub struct GetMerkleProofs;
    pub struct GetRingKeyRegistryEntry;
    pub struct GetRingKeyRegistryRegisterProof;
    pub struct GetRingSpendRecord;
    pub struct GetNonInclusionProofs;
    pub struct GetNullifierQueueElements;
    pub struct GetUserRecords;

    impl RpcMethod for GetEncryptedUtxosByTags {
        const NAME: &'static str = GET_ENCRYPTED_UTXOS_BY_TAGS;
        type Request = GetRingsByTagsRequest;
        type Response = GetEncryptedUtxosByTagsResponse;
    }

    impl RpcMethod for GetShieldedTransactionsByNullifiers {
        const NAME: &'static str = GET_SHIELDED_TRANSACTIONS_BY_NULLIFIERS;
        type Request = GetRingsByNullifiersRequest;
        type Response = GetShieldedTransactionsByNullifiersResponse;
    }

    impl RpcMethod for GetShieldedTransactionsByTags {
        const NAME: &'static str = GET_SHIELDED_TRANSACTIONS_BY_TAGS;
        type Request = GetRingsByTagsRequest;
        type Response = GetShieldedTransactionsByTagsResponse;
    }

    impl RpcMethod for GetShieldedTransactionsBySignature {
        const NAME: &'static str = GET_SHIELDED_TRANSACTIONS_BY_SIGNATURE;
        type Request = GetShieldedTransactionsBySignatureRequest;
        type Response = GetShieldedTransactionsBySignatureResponse;
    }

    impl RpcMethod for GetMerkleProofs {
        const NAME: &'static str = GET_MERKLE_PROOFS;
        type Request = GetMerkleProofsRequest;
        type Response = GetMerkleProofsResponse;
    }

    impl RpcMethod for GetRingKeyRegistryEntry {
        const NAME: &'static str = GET_RING_KEY_REGISTRY_ENTRY;
        type Request = RingMemberProofRequest;
        type Response = GetRingKeyRegistryEntryResponse;
    }

    impl RpcMethod for GetRingKeyRegistryRegisterProof {
        const NAME: &'static str = GET_RING_KEY_REGISTRY_REGISTER_PROOF;
        type Request = RingMemberProofRequest;
        type Response = GetRingKeyRegistryRegisterProofResponse;
    }

    impl RpcMethod for GetRingSpendRecord {
        const NAME: &'static str = GET_RING_SPEND_RECORD;
        type Request = RingSpendRecordRequest;
        type Response = GetRingSpendRecordResponse;
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

    impl RpcMethod for GetUserRecords {
        const NAME: &'static str = GET_USER_RECORDS;
        type Request = GetUserRecordsRequest;
        type Response = GetUserRecordsResponse;
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
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
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

/// A server-issued checkpoint. Its string representation is shared by all paginated streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cursor {
    slot: u64,
    signature: Signature,
}

#[cfg(feature = "openapi")]
impl utoipa::PartialSchema for Cursor {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        <String as utoipa::PartialSchema>::schema()
    }
}
#[cfg(feature = "openapi")]
impl utoipa::ToSchema for Cursor {}

impl Cursor {
    #[doc(hidden)]
    pub const fn new(slot: u64, signature: Signature) -> Self {
        Self { slot, signature }
    }
    #[doc(hidden)]
    pub const fn slot(&self) -> u64 {
        self.slot
    }
    #[doc(hidden)]
    pub const fn signature(&self) -> Signature {
        self.signature
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "1:{}:{}", self.slot, self.signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid pagination cursor")]
pub struct ParseCursorError;

impl FromStr for Cursor {
    type Err = ParseCursorError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > 112 {
            return Err(ParseCursorError);
        }
        let mut parts = value.split(':');
        if parts.next() != Some("1") {
            return Err(ParseCursorError);
        }
        let slot = parts
            .next()
            .ok_or(ParseCursorError)?
            .parse()
            .map_err(|_| ParseCursorError)?;
        let signature = parts
            .next()
            .ok_or(ParseCursorError)?
            .parse()
            .map_err(|_| ParseCursorError)?;
        if parts.next().is_some() {
            return Err(ParseCursorError);
        }
        let cursor = Self { slot, signature };
        if cursor.to_string() != value {
            return Err(ParseCursorError);
        }
        Ok(cursor)
    }
}

impl Serialize for Cursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for Cursor {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_from_str(deserializer, "a pagination cursor")
    }
}
impl Ord for Cursor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.slot, self.signature.as_ref()).cmp(&(other.slot, other.signature.as_ref()))
    }
}
impl PartialOrd for Cursor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// One bounded page. A terminal cursor is also returned when no item matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Page<T> {
    pub context: Context,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tree_id: Option<u16>,
    pub items: Vec<T>,
    pub cursor: Option<Cursor>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid pagination response")]
pub struct InvalidPage;

#[doc(hidden)]
pub trait Positioned {
    fn position(&self) -> Cursor;
}

impl<T: Positioned> Page<T> {
    /// An indexer continuation stops at the last complete transaction returned.
    pub fn validate_indexed(
        &self,
        after: Option<Cursor>,
        limit: u64,
        minimum: Option<u64>,
    ) -> Result<(), InvalidPage> {
        self.validate(after, limit, minimum)?;
        if self.has_more && self.items.last().map(Positioned::position) != self.cursor {
            return Err(InvalidPage);
        }
        Ok(())
    }
    /// Validate ordering, completeness markers, and correlation with the requested range.
    pub fn validate(
        &self,
        after: Option<Cursor>,
        limit: u64,
        minimum: Option<u64>,
    ) -> Result<(), InvalidPage> {
        if self.items.len() as u64 > limit
            || minimum.is_some_and(|minimum| self.context.slot < minimum)
            || self
                .cursor
                .is_some_and(|cursor| cursor.slot() > self.context.slot)
        {
            return Err(InvalidPage);
        }
        let mut previous = after;
        for item in &self.items {
            let position = item.position();
            if position.slot() > self.context.slot
                || previous.is_some_and(|previous| position <= previous)
            {
                return Err(InvalidPage);
            }
            previous = Some(position);
        }
        if self.cursor < previous {
            return Err(InvalidPage);
        }
        if self.has_more && (self.cursor.is_none() || self.cursor <= after) {
            return Err(InvalidPage);
        }
        Ok(())
    }
}

/// All matching events of one Solana transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TransactionEvents<T, S = SerializableSignature> {
    pub slot: u64,
    pub signature: S,
    pub events: Vec<T>,
}

/// All matching outputs of one Solana transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TransactionOutputs<T, S = SerializableSignature> {
    pub slot: u64,
    pub signature: S,
    pub outputs: Vec<T>,
}

impl<T, S: Copy + Into<Signature>> Positioned for TransactionEvents<T, S> {
    fn position(&self) -> Cursor {
        Cursor::new(self.slot, self.signature.into())
    }
}
impl<T, S: Copy + Into<Signature>> Positioned for TransactionOutputs<T, S> {
    fn position(&self) -> Cursor {
        Cursor::new(self.slot, self.signature.into())
    }
}

impl<T, S: Copy + Into<Signature>> TransactionEvents<T, S> {
    #[doc(hidden)]
    pub fn group(events: Vec<T>, header: impl Fn(&T) -> (u64, S)) -> Vec<Self> {
        group_transactions(events, header)
            .into_iter()
            .map(|(slot, signature, events)| Self {
                slot,
                signature,
                events,
            })
            .collect()
    }
    /// Check that a transaction contains its own events in event-index order.
    pub fn validate_events(
        &self,
        position: impl Fn(&T) -> (u64, Signature, Option<u16>),
    ) -> Result<(), InvalidPage> {
        if self.events.is_empty() {
            return Err(InvalidPage);
        }
        let mut previous = None;
        for event in &self.events {
            let (slot, signature, index) = position(event);
            if slot != self.slot
                || signature != self.signature.into()
                || index.is_none()
                || previous.is_some_and(|previous| index <= Some(previous))
            {
                return Err(InvalidPage);
            }
            previous = index;
        }
        Ok(())
    }
}

impl<T, S: Copy + Into<Signature>> TransactionOutputs<T, S> {
    #[doc(hidden)]
    pub fn group(outputs: Vec<T>, header: impl Fn(&T) -> (u64, S)) -> Vec<Self> {
        group_transactions(outputs, header)
            .into_iter()
            .map(|(slot, signature, outputs)| Self {
                slot,
                signature,
                outputs,
            })
            .collect()
    }
    pub fn validate_outputs(
        &self,
        position: impl Fn(&T) -> (u64, Signature),
    ) -> Result<(), InvalidPage> {
        if self.outputs.is_empty()
            || self
                .outputs
                .iter()
                .any(|output| position(output) != (self.slot, self.signature.into()))
        {
            return Err(InvalidPage);
        }
        Ok(())
    }
}

fn group_transactions<T, S: Copy + Into<Signature>>(
    rows: Vec<T>,
    header: impl Fn(&T) -> (u64, S),
) -> Vec<(u64, S, Vec<T>)> {
    let mut groups = std::collections::BTreeMap::new();
    for row in rows {
        let (slot, signature) = header(&row);
        groups
            .entry(Cursor::new(slot, signature.into()))
            .or_insert_with(|| (slot, signature, Vec::new()))
            .2
            .push(row);
    }
    groups.into_values().collect()
}

/// A Solana transaction signature represented as a base58 string.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(value_type = String))]
pub struct SerializableSignature(pub Signature);

impl From<Signature> for SerializableSignature {
    fn from(value: Signature) -> Self {
        Self(value)
    }
}

impl From<SerializableSignature> for Signature {
    fn from(value: SerializableSignature) -> Self {
        value.0
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

#[derive(Copy, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Context {
    pub block_time: i64,
    /// Highest slot the indexer has persisted, for slot-based freshness checks.
    pub slot: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetRingsByTagsRequest {
    /// Empty tags require a ring and select its full history.
    pub tags: Vec<Hash>,
    /// Resume strictly after the given transaction. Every stream shares the
    /// order, so one recorded position serves tags, nullifiers, and encrypted
    /// UTXOs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<Limit>,
    /// Restrict the match to one ring. Its config account is derived from this
    /// program id, so the filter needs no indexed registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_program_id: Option<SerializablePubkey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_context_slot: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetRingsByNullifiersRequest {
    pub nullifiers: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<Limit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_context_slot: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EncryptedUtxoMatch {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub output_slot: RingsOutputSlot,
    pub tx_viewing_pk: Option<Base64String>,
    /// Transaction-level AES salt shared by every output ciphertext.
    pub salt: Option<Base64String>,
}

pub type GetEncryptedUtxosByTagsResponse = Page<TransactionOutputs<EncryptedUtxoMatch>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RingsOutputContext {
    pub hash: Hash,
    /// The tree account the output was appended to.
    ///
    /// Deprecated: it is `pda::tree(tree_id)` and carries nothing `tree_id`
    /// does not. Emitted for one release so readers can move over, then
    /// dropped.
    pub tree: SerializablePubkey,
    /// The raw tree id the output's commitment is hashed under.
    pub tree_id: u16,
    pub leaf_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RingsOutputSlot {
    pub view_tag: Hash,
    pub output_context: RingsOutputContext,
    pub payload: Base64String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RingsMessage {
    pub view_tag: Hash,
    pub payload: Base64String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ShieldedTransaction {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_index: Option<u16>,
    pub tx_viewing_pk: Option<Base64String>,
    /// Transaction-level AES salt shared by every output ciphertext.
    pub salt: Option<Base64String>,
    pub output_slots: Vec<RingsOutputSlot>,
    /// Published data slots bound to no output commitment, republished verbatim.
    pub messages: Vec<RingsMessage>,
    pub nullifiers: Vec<Hash>,
    /// True when at least one output in this transaction is proofless.
    pub proofless: bool,
    /// The ring's config account (its `ring_auth` PDA), or `None` when no ring
    /// authorized this transaction. Observed directly on the transaction, so it
    /// is always present for a ring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_config: Option<SerializablePubkey>,
    /// The ring's program, resolved through the indexed registrations. `None`
    /// when `ringConfig` is `None`, and also when the registration itself was
    /// never indexed -- so `ringConfig` is what distinguishes "no ring" from
    /// "ring whose program is unknown here".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_program_id: Option<SerializablePubkey>,
}

pub type GetShieldedTransactionsByTagsResponse = Page<TransactionEvents<ShieldedTransaction>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetShieldedTransactionsBySignatureRequest {
    pub tx_signature: SerializableSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IndexedShieldedTransaction {
    pub event_index: u16,
    pub transaction: ShieldedTransaction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetShieldedTransactionsBySignatureResponse {
    pub context: Context,
    /// The newest unpaused tree, as on [`GetEncryptedUtxosByTagsResponse`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tree_id: Option<u16>,
    pub transactions: Vec<IndexedShieldedTransaction>,
}

pub type GetShieldedTransactionsByNullifiersResponse = Page<TransactionEvents<ShieldedTransaction>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetMerkleProofsRequest {
    pub tree_account: SerializablePubkey,
    pub leaves: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetMerkleProofsResponse {
    pub context: Context,
    pub proofs: Vec<MerkleProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RingMemberProofRequest {
    pub ring_program_id: SerializablePubkey,
    pub member: Hash,
    pub expected_root: Hash,
    pub expected_next_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetRingKeyRegistryEntryResponse {
    pub context: Context,
    pub root: Hash,
    pub next_index: u64,
    pub member: Hash,
    pub next: Hash,
    pub index: u64,
    pub eph_pk: Base64String,
    pub ciphertext: Base64String,
    pub proof: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetRingKeyRegistryRegisterProofResponse {
    pub context: Context,
    pub root: Hash,
    pub next_index: u64,
    pub member: Hash,
    pub low_member: Hash,
    pub low_next: Hash,
    pub low_key_hash: Hash,
    pub low_index: u64,
    pub low_proof: Vec<Hash>,
    /// Computed after the predecessor update.
    pub new_proof: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RingSpendRecordRequest {
    pub ring_program_id: SerializablePubkey,
    pub member: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RingSpendRecord {
    pub transaction: ShieldedTransaction,
    pub output_index: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetRingSpendRecordResponse {
    pub context: Context,
    /// `None` until the member registers.
    pub record: Option<RingSpendRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetNullifierQueueElementsRequest {
    pub tree_account: SerializablePubkey,
    /// Return elements with `input_queue_seq >= startSeq` (default 0).
    #[serde(default)]
    pub start_seq: u64,
    /// Maximum number of elements to return.
    pub limit: Limit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetNullifierQueueElementsResponse {
    pub context: Context,
    pub elements: Vec<NullifierQueueElement>,
}

/// One queued nullifier, in on-chain input-queue order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NullifierQueueElement {
    pub seq: u64,
    pub value: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MerkleContext {
    pub tree_type: u16,
    pub tree: SerializablePubkey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MerkleProof {
    pub leaf: Hash,
    pub merkle_context: MerkleContext,
    pub path: Vec<Hash>,
    pub leaf_index: u64,
    pub root: Hash,
    /// Root ordering key: the completed Solana slot for state-tree proof
    /// freshness, or the on-chain update sequence for an indexed-tree proof.
    pub root_seq: u64,
    /// Actual on-chain history position for `root`. A state root's position is
    /// not derivable from `root_seq`: slots without updates consume no entry.
    pub root_index: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetNonInclusionProofsRequest {
    pub tree_account: SerializablePubkey,
    pub leaves: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetNonInclusionProofsResponse {
    pub context: Context,
    pub proofs: Vec<NonInclusionProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
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
    /// Root ordering key: the completed Solana slot for a state-tree proof,
    /// or the on-chain update sequence for an indexed-tree proof.
    pub root_seq: u64,
    /// On-chain history position for `root`.
    pub root_index: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetUserRecordsRequest {
    /// Solana pubkeys to look up in the user registry. At most 100.
    #[cfg_attr(feature = "openapi", schema(min_items = 1, max_items = 100))]
    pub owners: Vec<SerializablePubkey>,
}

/// A user registry record, the shielded address a Solana pubkey publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserRecord {
    pub owner: SerializablePubkey,
    /// Wallet-wide nullifier pubkey. Never rotates.
    pub nullifier_pubkey: Hash,
    /// Tagged X25519 viewing pubkey (0x04 followed by a canonical 32-byte u-coordinate).
    pub viewing_pubkey: Base64String,
    /// Merge output encryption scheme the owner accepts for `merge_transact`:
    /// 0 disables merging, 1 is PoseidonCtrV1. While a scheme is selected, any
    /// caller may merge this owner's UTXOs under that scheme.
    pub merge_encryption: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetUserRecordsResponse {
    pub context: Context,
    /// One entry per requested owner, in request order. `null` when the owner
    /// has no registry record at the slot the records were read, which is no
    /// earlier than `context.slot`.
    pub records: Vec<Option<UserRecord>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_markers_have_canonical_names() {
        assert_eq!(
            method::GetEncryptedUtxosByTags::NAME,
            "getEncryptedUtxosByTags"
        );
        assert_eq!(
            method::GetShieldedTransactionsByNullifiers::NAME,
            "getShieldedTransactionsByNullifiers"
        );
        assert_eq!(method::GetMerkleProofs::NAME, "getMerkleProofs");
        assert_eq!(
            method::GetNullifierQueueElements::NAME,
            "getNullifierQueueElements"
        );
        assert_eq!(
            method::GetShieldedTransactionsBySignature::NAME,
            "getShieldedTransactionsBySignature"
        );
        assert_eq!(method::GetUserRecords::NAME, "getUserRecords");
    }

    #[test]
    fn an_unregistered_owner_is_a_null_record_slot() {
        let page = serde_json::json!({
            "context": { "blockTime": 3, "slot": 1 },
            "records": [
                null,
                {
                    "owner": SerializablePubkey::from([5; 32]).to_string(),
                    "nullifierPubkey": Hash::from([6; 32]).to_base58(),
                    "viewingPubkey": "AQID",
                    "mergeEncryption": 1,
                },
            ],
        });
        let response: GetUserRecordsResponse = serde_json::from_value(page).unwrap();
        assert_eq!(response.records[0], None);
        let record = response.records[1].as_ref().unwrap();
        assert_eq!(record.owner, SerializablePubkey::from([5; 32]));
        assert_eq!(record.viewing_pubkey, Base64String(vec![1, 2, 3]));
        assert_eq!(record.merge_encryption, 1);

        // Unregistered slots remain explicit null values.
        let value = serde_json::to_value(&response).unwrap();
        assert!(value["records"][0].is_null());
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
    fn cursor_is_canonical_and_portable() {
        let cursor = Cursor::new(7, Signature::default());
        let encoded = format!("1:7:{}", "1".repeat(64));
        assert_eq!(cursor.to_string(), encoded);
        assert_eq!(encoded.parse::<Cursor>().unwrap(), cursor);
        assert_eq!(serde_json::to_value(cursor).unwrap(), encoded);
        for invalid in [
            format!("1:07:{}", "1".repeat(64)),
            format!("2:7:{}", "1".repeat(64)),
            format!("1:18446744073709551616:{}", "1".repeat(64)),
            "1:7:invalid".into(),
        ] {
            assert!(invalid.parse::<Cursor>().is_err());
        }
        let page = GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 3,
                slot: 7,
            },
            output_tree_id: Some(4),
            items: vec![],
            cursor: Some(cursor),
            has_more: false,
        };
        page.validate(None, 1, Some(7)).unwrap();
        let value = serde_json::to_value(page).unwrap();
        assert_eq!(value["cursor"], encoded);
        assert_eq!(value["hasMore"], false);
        assert_eq!(value["outputTreeId"], 4);
        assert_eq!(value["context"]["blockTime"], 3);
        assert!(value.get("next").is_none());
        assert!(value.get("latest").is_none());
    }

    #[test]
    fn cursors_order_by_slot_then_signature_bytes() {
        let low = Cursor::new(5, Signature::from([1; 64]));
        let same_slot = Cursor::new(5, Signature::from([2; 64]));
        assert!(low < same_slot);
        assert!(same_slot < Cursor::new(6, Signature::default()));
    }

    #[test]
    fn page_rejects_nonadvancing_and_stale_checkpoints() {
        let cursor = Cursor::new(7, Signature::default());
        let mut page = GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 7,
            },
            output_tree_id: None,
            items: vec![],
            cursor: Some(cursor),
            has_more: true,
        };
        assert!(page.validate(Some(cursor), 1, None).is_err());
        page.has_more = false;
        page.validate(Some(cursor), 1, Some(7)).unwrap();
        assert!(page.validate(None, 1, Some(8)).is_err());
        page.cursor = None;
        assert!(page.validate(Some(cursor), 1, None).is_err());
    }

    #[test]
    fn signature_lookup_contract_rejects_malformed_signatures() {
        let invalid = serde_json::json!({ "txSignature": "not-a-signature" });
        assert!(
            serde_json::from_value::<GetShieldedTransactionsBySignatureRequest>(invalid).is_err()
        );

        let signature = Signature::from([9u8; 64]);
        let request = GetShieldedTransactionsBySignatureRequest {
            tx_signature: SerializableSignature(signature),
        };
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["txSignature"], signature.to_string());
    }

    #[test]
    fn every_page_limit_uses_the_shared_bounds() {
        let tree = SerializablePubkey::from([3; 32]);
        let request = serde_json::json!({
            "treeAccount": tree.to_string(),
            "limit": PAGE_LIMIT,
        });
        let parsed = serde_json::from_value::<GetNullifierQueueElementsRequest>(request).unwrap();
        assert_eq!(parsed.limit.value(), PAGE_LIMIT);

        let invalid = serde_json::json!({
            "treeAccount": tree.to_string(),
            "limit": PAGE_LIMIT + 1,
        });
        assert!(serde_json::from_value::<GetNullifierQueueElementsRequest>(invalid).is_err());
    }
}
