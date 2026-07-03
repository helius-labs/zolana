#[allow(unused_imports)]
pub use progenitor_client::{ByteStream, ClientInfo, Error, ResponseValue};
#[allow(unused_imports)]
use progenitor_client::{encode_path, ClientHooks, OperationInfo, RequestBuilderExt};
/// Types used as operation parameters and responses.
#[allow(clippy::all)]
pub mod types {
    /// Error types.
    pub mod error {
        /// Error from a `TryFrom` or `FromStr` implementation.
        pub struct ConversionError(::std::borrow::Cow<'static, str>);
        impl ::std::error::Error for ConversionError {}
        impl ::std::fmt::Display for ConversionError {
            fn fmt(
                &self,
                f: &mut ::std::fmt::Formatter<'_>,
            ) -> Result<(), ::std::fmt::Error> {
                ::std::fmt::Display::fmt(&self.0, f)
            }
        }
        impl ::std::fmt::Debug for ConversionError {
            fn fmt(
                &self,
                f: &mut ::std::fmt::Formatter<'_>,
            ) -> Result<(), ::std::fmt::Error> {
                ::std::fmt::Debug::fmt(&self.0, f)
            }
        }
        impl From<&'static str> for ConversionError {
            fn from(value: &'static str) -> Self {
                Self(value.into())
            }
        }
        impl From<String> for ConversionError {
            fn from(value: String) -> Self {
                Self(value.into())
            }
        }
    }
    ///A base 64 encoded string.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "A base 64 encoded string.",
    ///  "default": "SGVsbG8sIFdvcmxkIQ==",
    ///  "type": "string"
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    #[serde(transparent)]
    pub struct Base64String(pub ::std::string::String);
    impl ::std::ops::Deref for Base64String {
        type Target = ::std::string::String;
        fn deref(&self) -> &::std::string::String {
            &self.0
        }
    }
    impl ::std::convert::From<Base64String> for ::std::string::String {
        fn from(value: Base64String) -> Self {
            value.0
        }
    }
    impl ::std::convert::From<::std::string::String> for Base64String {
        fn from(value: ::std::string::String) -> Self {
            Self(value)
        }
    }
    impl ::std::str::FromStr for Base64String {
        type Err = ::std::convert::Infallible;
        fn from_str(value: &str) -> ::std::result::Result<Self, Self::Err> {
            Ok(Self(value.to_string()))
        }
    }
    impl ::std::fmt::Display for Base64String {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            self.0.fmt(f)
        }
    }
    ///`Context`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "slot"
    ///  ],
    ///  "properties": {
    ///    "slot": {
    ///      "default": 100,
    ///      "type": "integer",
    ///      "format": "u-int64"
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct Context {
        pub slot: i64,
    }
    impl Context {
        pub fn builder() -> builder::Context {
            Default::default()
        }
    }
    ///`EncryptedUtxoMatch`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "output_slot",
    ///    "slot",
    ///    "tx_signature"
    ///  ],
    ///  "properties": {
    ///    "output_slot": {
    ///      "$ref": "#/components/schemas/RingsOutputSlot"
    ///    },
    ///    "salt": {
    ///      "oneOf": [
    ///        {
    ///          "type": "null"
    ///        },
    ///        {
    ///          "allOf": [
    ///            {
    ///              "$ref": "#/components/schemas/Base64String"
    ///            }
    ///          ]
    ///        }
    ///      ]
    ///    },
    ///    "slot": {
    ///      "type": "integer",
    ///      "format": "u-int64",
    ///      "minimum": 0.0
    ///    },
    ///    "tx_signature": {
    ///      "$ref": "#/components/schemas/SerializableSignature"
    ///    },
    ///    "tx_viewing_pk": {
    ///      "oneOf": [
    ///        {
    ///          "type": "null"
    ///        },
    ///        {
    ///          "allOf": [
    ///            {
    ///              "$ref": "#/components/schemas/Base64String"
    ///            }
    ///          ]
    ///        }
    ///      ]
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct EncryptedUtxoMatch {
        pub output_slot: RingsOutputSlot,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub salt: ::std::option::Option<Base64String>,
        pub slot: u64,
        pub tx_signature: SerializableSignature,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub tx_viewing_pk: ::std::option::Option<Base64String>,
    }
    impl EncryptedUtxoMatch {
        pub fn builder() -> builder::EncryptedUtxoMatch {
            Default::default()
        }
    }
    ///A 32-byte hash represented as a base58 string.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "A 32-byte hash represented as a base58 string.",
    ///  "type": "string"
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    #[serde(transparent)]
    pub struct Hash(pub ::std::string::String);
    impl ::std::ops::Deref for Hash {
        type Target = ::std::string::String;
        fn deref(&self) -> &::std::string::String {
            &self.0
        }
    }
    impl ::std::convert::From<Hash> for ::std::string::String {
        fn from(value: Hash) -> Self {
            value.0
        }
    }
    impl ::std::convert::From<::std::string::String> for Hash {
        fn from(value: ::std::string::String) -> Self {
            Self(value)
        }
    }
    impl ::std::str::FromStr for Hash {
        type Err = ::std::convert::Infallible;
        fn from_str(value: &str) -> ::std::result::Result<Self, Self::Err> {
            Ok(Self(value.to_string()))
        }
    }
    impl ::std::fmt::Display for Hash {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            self.0.fmt(f)
        }
    }
    ///`Limit`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "integer",
    ///  "format": "u-int64",
    ///  "maximum": 1000.0,
    ///  "minimum": 1.0
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(transparent)]
    pub struct Limit(pub ::std::num::NonZeroU64);
    impl ::std::ops::Deref for Limit {
        type Target = ::std::num::NonZeroU64;
        fn deref(&self) -> &::std::num::NonZeroU64 {
            &self.0
        }
    }
    impl ::std::convert::From<Limit> for ::std::num::NonZeroU64 {
        fn from(value: Limit) -> Self {
            value.0
        }
    }
    impl ::std::convert::From<::std::num::NonZeroU64> for Limit {
        fn from(value: ::std::num::NonZeroU64) -> Self {
            Self(value)
        }
    }
    impl ::std::str::FromStr for Limit {
        type Err = <::std::num::NonZeroU64 as ::std::str::FromStr>::Err;
        fn from_str(value: &str) -> ::std::result::Result<Self, Self::Err> {
            Ok(Self(value.parse()?))
        }
    }
    impl ::std::convert::TryFrom<&str> for Limit {
        type Error = <::std::num::NonZeroU64 as ::std::str::FromStr>::Err;
        fn try_from(value: &str) -> ::std::result::Result<Self, Self::Error> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<String> for Limit {
        type Error = <::std::num::NonZeroU64 as ::std::str::FromStr>::Err;
        fn try_from(value: String) -> ::std::result::Result<Self, Self::Error> {
            value.parse()
        }
    }
    impl ::std::fmt::Display for Limit {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            self.0.fmt(f)
        }
    }
    ///`MerkleContext`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "tree",
    ///    "tree_type"
    ///  ],
    ///  "properties": {
    ///    "tree": {
    ///      "$ref": "#/components/schemas/SerializablePubkey"
    ///    },
    ///    "tree_type": {
    ///      "type": "integer",
    ///      "format": "u-int16",
    ///      "minimum": 0.0
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct MerkleContext {
        pub tree: SerializablePubkey,
        pub tree_type: u64,
    }
    impl MerkleContext {
        pub fn builder() -> builder::MerkleContext {
            Default::default()
        }
    }
    ///`MerkleProof`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "leaf",
    ///    "leaf_index",
    ///    "merkle_context",
    ///    "path",
    ///    "root",
    ///    "root_index",
    ///    "root_seq"
    ///  ],
    ///  "properties": {
    ///    "leaf": {
    ///      "$ref": "#/components/schemas/Hash"
    ///    },
    ///    "leaf_index": {
    ///      "type": "integer",
    ///      "format": "u-int64",
    ///      "minimum": 0.0
    ///    },
    ///    "merkle_context": {
    ///      "$ref": "#/components/schemas/MerkleContext"
    ///    },
    ///    "path": {
    ///      "type": "array",
    ///      "items": {
    ///        "$ref": "#/components/schemas/Hash"
    ///      }
    ///    },
    ///    "root": {
    ///      "$ref": "#/components/schemas/Hash"
    ///    },
    ///    "root_index": {
    ///      "type": "integer",
    ///      "format": "u-int16",
    ///      "minimum": 0.0
    ///    },
    ///    "root_seq": {
    ///      "type": "integer",
    ///      "format": "u-int64",
    ///      "minimum": 0.0
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct MerkleProof {
        pub leaf: Hash,
        pub leaf_index: u64,
        pub merkle_context: MerkleContext,
        pub path: ::std::vec::Vec<Hash>,
        pub root: Hash,
        pub root_index: u64,
        pub root_seq: u64,
    }
    impl MerkleProof {
        pub fn builder() -> builder::MerkleProof {
            Default::default()
        }
    }
    ///`NonInclusionProof`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "high_element",
    ///    "high_element_index",
    ///    "leaf",
    ///    "low_element",
    ///    "low_element_index",
    ///    "merkle_context",
    ///    "path",
    ///    "root",
    ///    "root_index",
    ///    "root_seq"
    ///  ],
    ///  "properties": {
    ///    "high_element": {
    ///      "$ref": "#/components/schemas/Hash"
    ///    },
    ///    "high_element_index": {
    ///      "type": "integer",
    ///      "format": "u-int64",
    ///      "minimum": 0.0
    ///    },
    ///    "leaf": {
    ///      "$ref": "#/components/schemas/Hash"
    ///    },
    ///    "low_element": {
    ///      "$ref": "#/components/schemas/Hash"
    ///    },
    ///    "low_element_index": {
    ///      "type": "integer",
    ///      "format": "u-int64",
    ///      "minimum": 0.0
    ///    },
    ///    "merkle_context": {
    ///      "$ref": "#/components/schemas/MerkleContext"
    ///    },
    ///    "path": {
    ///      "type": "array",
    ///      "items": {
    ///        "$ref": "#/components/schemas/Hash"
    ///      }
    ///    },
    ///    "root": {
    ///      "$ref": "#/components/schemas/Hash"
    ///    },
    ///    "root_index": {
    ///      "type": "integer",
    ///      "format": "u-int16",
    ///      "minimum": 0.0
    ///    },
    ///    "root_seq": {
    ///      "type": "integer",
    ///      "format": "u-int64",
    ///      "minimum": 0.0
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct NonInclusionProof {
        pub high_element: Hash,
        pub high_element_index: u64,
        pub leaf: Hash,
        pub low_element: Hash,
        pub low_element_index: u64,
        pub merkle_context: MerkleContext,
        pub path: ::std::vec::Vec<Hash>,
        pub root: Hash,
        pub root_index: u64,
        pub root_seq: u64,
    }
    impl NonInclusionProof {
        pub fn builder() -> builder::NonInclusionProof {
            Default::default()
        }
    }
    ///One queued nullifier, in on-chain input-queue order.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "One queued nullifier, in on-chain input-queue order.",
    ///  "type": "object",
    ///  "required": [
    ///    "seq",
    ///    "value"
    ///  ],
    ///  "properties": {
    ///    "seq": {
    ///      "type": "integer",
    ///      "format": "u-int64",
    ///      "minimum": 0.0
    ///    },
    ///    "value": {
    ///      "$ref": "#/components/schemas/Hash"
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct NullifierQueueElement {
        pub seq: u64,
        pub value: Hash,
    }
    impl NullifierQueueElement {
        pub fn builder() -> builder::NullifierQueueElement {
            Default::default()
        }
    }
    ///`PostGetEncryptedUtxosByTagsBody`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "id",
    ///    "jsonrpc",
    ///    "method",
    ///    "params"
    ///  ],
    ///  "properties": {
    ///    "id": {
    ///      "description": "An ID to identify the request.",
    ///      "type": "string",
    ///      "enum": [
    ///        "test-account"
    ///      ]
    ///    },
    ///    "jsonrpc": {
    ///      "description": "The version of the JSON-RPC protocol.",
    ///      "type": "string",
    ///      "enum": [
    ///        "2.0"
    ///      ]
    ///    },
    ///    "method": {
    ///      "description": "The name of the method to invoke.",
    ///      "type": "string",
    ///      "enum": [
    ///        "get_encrypted_utxos_by_tags"
    ///      ]
    ///    },
    ///    "params": {
    ///      "type": "object",
    ///      "required": [
    ///        "tags"
    ///      ],
    ///      "properties": {
    ///        "cursor": {
    ///          "oneOf": [
    ///            {
    ///              "type": "null"
    ///            },
    ///            {
    ///              "allOf": [
    ///                {
    ///                  "$ref": "#/components/schemas/Base64String"
    ///                }
    ///              ]
    ///            }
    ///          ]
    ///        },
    ///        "limit": {
    ///          "oneOf": [
    ///            {
    ///              "type": "null"
    ///            },
    ///            {
    ///              "allOf": [
    ///                {
    ///                  "$ref": "#/components/schemas/Limit"
    ///                }
    ///              ]
    ///            }
    ///          ]
    ///        },
    ///        "tags": {
    ///          "type": "array",
    ///          "items": {
    ///            "$ref": "#/components/schemas/Hash"
    ///          }
    ///        }
    ///      },
    ///      "additionalProperties": false
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct PostGetEncryptedUtxosByTagsBody {
        ///An ID to identify the request.
        pub id: PostGetEncryptedUtxosByTagsBodyId,
        ///The version of the JSON-RPC protocol.
        pub jsonrpc: PostGetEncryptedUtxosByTagsBodyJsonrpc,
        ///The name of the method to invoke.
        pub method: PostGetEncryptedUtxosByTagsBodyMethod,
        pub params: PostGetEncryptedUtxosByTagsBodyParams,
    }
    impl PostGetEncryptedUtxosByTagsBody {
        pub fn builder() -> builder::PostGetEncryptedUtxosByTagsBody {
            Default::default()
        }
    }
    ///An ID to identify the request.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "An ID to identify the request.",
    ///  "type": "string",
    ///  "enum": [
    ///    "test-account"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetEncryptedUtxosByTagsBodyId {
        #[serde(rename = "test-account")]
        TestAccount,
    }
    impl ::std::fmt::Display for PostGetEncryptedUtxosByTagsBodyId {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::TestAccount => f.write_str("test-account"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetEncryptedUtxosByTagsBodyId {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "test-account" => Ok(Self::TestAccount),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetEncryptedUtxosByTagsBodyId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetEncryptedUtxosByTagsBodyId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetEncryptedUtxosByTagsBodyId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///The version of the JSON-RPC protocol.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "The version of the JSON-RPC protocol.",
    ///  "type": "string",
    ///  "enum": [
    ///    "2.0"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetEncryptedUtxosByTagsBodyJsonrpc {
        #[serde(rename = "2.0")]
        X20,
    }
    impl ::std::fmt::Display for PostGetEncryptedUtxosByTagsBodyJsonrpc {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::X20 => f.write_str("2.0"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetEncryptedUtxosByTagsBodyJsonrpc {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "2.0" => Ok(Self::X20),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetEncryptedUtxosByTagsBodyJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetEncryptedUtxosByTagsBodyJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetEncryptedUtxosByTagsBodyJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///The name of the method to invoke.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "The name of the method to invoke.",
    ///  "type": "string",
    ///  "enum": [
    ///    "get_encrypted_utxos_by_tags"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetEncryptedUtxosByTagsBodyMethod {
        #[serde(rename = "get_encrypted_utxos_by_tags")]
        GetEncryptedUtxosByTags,
    }
    impl ::std::fmt::Display for PostGetEncryptedUtxosByTagsBodyMethod {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::GetEncryptedUtxosByTags => {
                    f.write_str("get_encrypted_utxos_by_tags")
                }
            }
        }
    }
    impl ::std::str::FromStr for PostGetEncryptedUtxosByTagsBodyMethod {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "get_encrypted_utxos_by_tags" => Ok(Self::GetEncryptedUtxosByTags),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetEncryptedUtxosByTagsBodyMethod {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetEncryptedUtxosByTagsBodyMethod {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetEncryptedUtxosByTagsBodyMethod {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///`PostGetEncryptedUtxosByTagsBodyParams`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "tags"
    ///  ],
    ///  "properties": {
    ///    "cursor": {
    ///      "oneOf": [
    ///        {
    ///          "type": "null"
    ///        },
    ///        {
    ///          "allOf": [
    ///            {
    ///              "$ref": "#/components/schemas/Base64String"
    ///            }
    ///          ]
    ///        }
    ///      ]
    ///    },
    ///    "limit": {
    ///      "oneOf": [
    ///        {
    ///          "type": "null"
    ///        },
    ///        {
    ///          "allOf": [
    ///            {
    ///              "$ref": "#/components/schemas/Limit"
    ///            }
    ///          ]
    ///        }
    ///      ]
    ///    },
    ///    "tags": {
    ///      "type": "array",
    ///      "items": {
    ///        "$ref": "#/components/schemas/Hash"
    ///      }
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct PostGetEncryptedUtxosByTagsBodyParams {
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub cursor: ::std::option::Option<Base64String>,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub limit: ::std::option::Option<Limit>,
        pub tags: ::std::vec::Vec<Hash>,
    }
    impl PostGetEncryptedUtxosByTagsBodyParams {
        pub fn builder() -> builder::PostGetEncryptedUtxosByTagsBodyParams {
            Default::default()
        }
    }
    ///`PostGetEncryptedUtxosByTagsResponse`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "id",
    ///    "jsonrpc"
    ///  ],
    ///  "properties": {
    ///    "error": {
    ///      "type": "object",
    ///      "properties": {
    ///        "code": {
    ///          "type": "integer"
    ///        },
    ///        "message": {
    ///          "type": "string"
    ///        }
    ///      }
    ///    },
    ///    "id": {
    ///      "description": "An ID to identify the response.",
    ///      "type": "string",
    ///      "enum": [
    ///        "test-account"
    ///      ]
    ///    },
    ///    "jsonrpc": {
    ///      "description": "The version of the JSON-RPC protocol.",
    ///      "type": "string",
    ///      "enum": [
    ///        "2.0"
    ///      ]
    ///    },
    ///    "result": {
    ///      "type": "object",
    ///      "required": [
    ///        "context",
    ///        "matches"
    ///      ],
    ///      "properties": {
    ///        "context": {
    ///          "$ref": "#/components/schemas/Context"
    ///        },
    ///        "matches": {
    ///          "description": "Output-level matches; every returned output slot has a view tag from the request.",
    ///          "type": "array",
    ///          "items": {
    ///            "$ref": "#/components/schemas/EncryptedUtxoMatch"
    ///          }
    ///        },
    ///        "next_cursor": {
    ///          "oneOf": [
    ///            {
    ///              "type": "null"
    ///            },
    ///            {
    ///              "allOf": [
    ///                {
    ///                  "$ref": "#/components/schemas/Base64String"
    ///                }
    ///              ]
    ///            }
    ///          ]
    ///        }
    ///      },
    ///      "additionalProperties": false
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct PostGetEncryptedUtxosByTagsResponse {
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub error: ::std::option::Option<PostGetEncryptedUtxosByTagsResponseError>,
        ///An ID to identify the response.
        pub id: PostGetEncryptedUtxosByTagsResponseId,
        ///The version of the JSON-RPC protocol.
        pub jsonrpc: PostGetEncryptedUtxosByTagsResponseJsonrpc,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub result: ::std::option::Option<PostGetEncryptedUtxosByTagsResponseResult>,
    }
    impl PostGetEncryptedUtxosByTagsResponse {
        pub fn builder() -> builder::PostGetEncryptedUtxosByTagsResponse {
            Default::default()
        }
    }
    ///`PostGetEncryptedUtxosByTagsResponseError`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "properties": {
    ///    "code": {
    ///      "type": "integer"
    ///    },
    ///    "message": {
    ///      "type": "string"
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct PostGetEncryptedUtxosByTagsResponseError {
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub code: ::std::option::Option<i64>,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub message: ::std::option::Option<::std::string::String>,
    }
    impl ::std::default::Default for PostGetEncryptedUtxosByTagsResponseError {
        fn default() -> Self {
            Self {
                code: Default::default(),
                message: Default::default(),
            }
        }
    }
    impl PostGetEncryptedUtxosByTagsResponseError {
        pub fn builder() -> builder::PostGetEncryptedUtxosByTagsResponseError {
            Default::default()
        }
    }
    ///An ID to identify the response.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "An ID to identify the response.",
    ///  "type": "string",
    ///  "enum": [
    ///    "test-account"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetEncryptedUtxosByTagsResponseId {
        #[serde(rename = "test-account")]
        TestAccount,
    }
    impl ::std::fmt::Display for PostGetEncryptedUtxosByTagsResponseId {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::TestAccount => f.write_str("test-account"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetEncryptedUtxosByTagsResponseId {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "test-account" => Ok(Self::TestAccount),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetEncryptedUtxosByTagsResponseId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetEncryptedUtxosByTagsResponseId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetEncryptedUtxosByTagsResponseId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///The version of the JSON-RPC protocol.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "The version of the JSON-RPC protocol.",
    ///  "type": "string",
    ///  "enum": [
    ///    "2.0"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetEncryptedUtxosByTagsResponseJsonrpc {
        #[serde(rename = "2.0")]
        X20,
    }
    impl ::std::fmt::Display for PostGetEncryptedUtxosByTagsResponseJsonrpc {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::X20 => f.write_str("2.0"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetEncryptedUtxosByTagsResponseJsonrpc {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "2.0" => Ok(Self::X20),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetEncryptedUtxosByTagsResponseJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetEncryptedUtxosByTagsResponseJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetEncryptedUtxosByTagsResponseJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///`PostGetEncryptedUtxosByTagsResponseResult`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "context",
    ///    "matches"
    ///  ],
    ///  "properties": {
    ///    "context": {
    ///      "$ref": "#/components/schemas/Context"
    ///    },
    ///    "matches": {
    ///      "description": "Output-level matches; every returned output slot has a view tag from the request.",
    ///      "type": "array",
    ///      "items": {
    ///        "$ref": "#/components/schemas/EncryptedUtxoMatch"
    ///      }
    ///    },
    ///    "next_cursor": {
    ///      "oneOf": [
    ///        {
    ///          "type": "null"
    ///        },
    ///        {
    ///          "allOf": [
    ///            {
    ///              "$ref": "#/components/schemas/Base64String"
    ///            }
    ///          ]
    ///        }
    ///      ]
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct PostGetEncryptedUtxosByTagsResponseResult {
        pub context: Context,
        ///Output-level matches; every returned output slot has a view tag from the request.
        pub matches: ::std::vec::Vec<EncryptedUtxoMatch>,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub next_cursor: ::std::option::Option<Base64String>,
    }
    impl PostGetEncryptedUtxosByTagsResponseResult {
        pub fn builder() -> builder::PostGetEncryptedUtxosByTagsResponseResult {
            Default::default()
        }
    }
    ///`PostGetMerkleProofsBody`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "id",
    ///    "jsonrpc",
    ///    "method",
    ///    "params"
    ///  ],
    ///  "properties": {
    ///    "id": {
    ///      "description": "An ID to identify the request.",
    ///      "type": "string",
    ///      "enum": [
    ///        "test-account"
    ///      ]
    ///    },
    ///    "jsonrpc": {
    ///      "description": "The version of the JSON-RPC protocol.",
    ///      "type": "string",
    ///      "enum": [
    ///        "2.0"
    ///      ]
    ///    },
    ///    "method": {
    ///      "description": "The name of the method to invoke.",
    ///      "type": "string",
    ///      "enum": [
    ///        "get_merkle_proofs"
    ///      ]
    ///    },
    ///    "params": {
    ///      "type": "object",
    ///      "required": [
    ///        "leaves",
    ///        "tree_account"
    ///      ],
    ///      "properties": {
    ///        "leaves": {
    ///          "type": "array",
    ///          "items": {
    ///            "$ref": "#/components/schemas/Hash"
    ///          }
    ///        },
    ///        "tree_account": {
    ///          "$ref": "#/components/schemas/SerializablePubkey"
    ///        }
    ///      },
    ///      "additionalProperties": false
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct PostGetMerkleProofsBody {
        ///An ID to identify the request.
        pub id: PostGetMerkleProofsBodyId,
        ///The version of the JSON-RPC protocol.
        pub jsonrpc: PostGetMerkleProofsBodyJsonrpc,
        ///The name of the method to invoke.
        pub method: PostGetMerkleProofsBodyMethod,
        pub params: PostGetMerkleProofsBodyParams,
    }
    impl PostGetMerkleProofsBody {
        pub fn builder() -> builder::PostGetMerkleProofsBody {
            Default::default()
        }
    }
    ///An ID to identify the request.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "An ID to identify the request.",
    ///  "type": "string",
    ///  "enum": [
    ///    "test-account"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetMerkleProofsBodyId {
        #[serde(rename = "test-account")]
        TestAccount,
    }
    impl ::std::fmt::Display for PostGetMerkleProofsBodyId {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::TestAccount => f.write_str("test-account"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetMerkleProofsBodyId {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "test-account" => Ok(Self::TestAccount),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetMerkleProofsBodyId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String> for PostGetMerkleProofsBodyId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String> for PostGetMerkleProofsBodyId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///The version of the JSON-RPC protocol.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "The version of the JSON-RPC protocol.",
    ///  "type": "string",
    ///  "enum": [
    ///    "2.0"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetMerkleProofsBodyJsonrpc {
        #[serde(rename = "2.0")]
        X20,
    }
    impl ::std::fmt::Display for PostGetMerkleProofsBodyJsonrpc {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::X20 => f.write_str("2.0"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetMerkleProofsBodyJsonrpc {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "2.0" => Ok(Self::X20),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetMerkleProofsBodyJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetMerkleProofsBodyJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetMerkleProofsBodyJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///The name of the method to invoke.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "The name of the method to invoke.",
    ///  "type": "string",
    ///  "enum": [
    ///    "get_merkle_proofs"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetMerkleProofsBodyMethod {
        #[serde(rename = "get_merkle_proofs")]
        GetMerkleProofs,
    }
    impl ::std::fmt::Display for PostGetMerkleProofsBodyMethod {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::GetMerkleProofs => f.write_str("get_merkle_proofs"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetMerkleProofsBodyMethod {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "get_merkle_proofs" => Ok(Self::GetMerkleProofs),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetMerkleProofsBodyMethod {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetMerkleProofsBodyMethod {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetMerkleProofsBodyMethod {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///`PostGetMerkleProofsBodyParams`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "leaves",
    ///    "tree_account"
    ///  ],
    ///  "properties": {
    ///    "leaves": {
    ///      "type": "array",
    ///      "items": {
    ///        "$ref": "#/components/schemas/Hash"
    ///      }
    ///    },
    ///    "tree_account": {
    ///      "$ref": "#/components/schemas/SerializablePubkey"
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct PostGetMerkleProofsBodyParams {
        pub leaves: ::std::vec::Vec<Hash>,
        pub tree_account: SerializablePubkey,
    }
    impl PostGetMerkleProofsBodyParams {
        pub fn builder() -> builder::PostGetMerkleProofsBodyParams {
            Default::default()
        }
    }
    ///`PostGetMerkleProofsResponse`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "id",
    ///    "jsonrpc"
    ///  ],
    ///  "properties": {
    ///    "error": {
    ///      "type": "object",
    ///      "properties": {
    ///        "code": {
    ///          "type": "integer"
    ///        },
    ///        "message": {
    ///          "type": "string"
    ///        }
    ///      }
    ///    },
    ///    "id": {
    ///      "description": "An ID to identify the response.",
    ///      "type": "string",
    ///      "enum": [
    ///        "test-account"
    ///      ]
    ///    },
    ///    "jsonrpc": {
    ///      "description": "The version of the JSON-RPC protocol.",
    ///      "type": "string",
    ///      "enum": [
    ///        "2.0"
    ///      ]
    ///    },
    ///    "result": {
    ///      "type": "object",
    ///      "required": [
    ///        "context",
    ///        "proofs"
    ///      ],
    ///      "properties": {
    ///        "context": {
    ///          "$ref": "#/components/schemas/Context"
    ///        },
    ///        "proofs": {
    ///          "type": "array",
    ///          "items": {
    ///            "$ref": "#/components/schemas/MerkleProof"
    ///          }
    ///        }
    ///      },
    ///      "additionalProperties": false
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct PostGetMerkleProofsResponse {
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub error: ::std::option::Option<PostGetMerkleProofsResponseError>,
        ///An ID to identify the response.
        pub id: PostGetMerkleProofsResponseId,
        ///The version of the JSON-RPC protocol.
        pub jsonrpc: PostGetMerkleProofsResponseJsonrpc,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub result: ::std::option::Option<PostGetMerkleProofsResponseResult>,
    }
    impl PostGetMerkleProofsResponse {
        pub fn builder() -> builder::PostGetMerkleProofsResponse {
            Default::default()
        }
    }
    ///`PostGetMerkleProofsResponseError`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "properties": {
    ///    "code": {
    ///      "type": "integer"
    ///    },
    ///    "message": {
    ///      "type": "string"
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct PostGetMerkleProofsResponseError {
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub code: ::std::option::Option<i64>,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub message: ::std::option::Option<::std::string::String>,
    }
    impl ::std::default::Default for PostGetMerkleProofsResponseError {
        fn default() -> Self {
            Self {
                code: Default::default(),
                message: Default::default(),
            }
        }
    }
    impl PostGetMerkleProofsResponseError {
        pub fn builder() -> builder::PostGetMerkleProofsResponseError {
            Default::default()
        }
    }
    ///An ID to identify the response.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "An ID to identify the response.",
    ///  "type": "string",
    ///  "enum": [
    ///    "test-account"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetMerkleProofsResponseId {
        #[serde(rename = "test-account")]
        TestAccount,
    }
    impl ::std::fmt::Display for PostGetMerkleProofsResponseId {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::TestAccount => f.write_str("test-account"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetMerkleProofsResponseId {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "test-account" => Ok(Self::TestAccount),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetMerkleProofsResponseId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetMerkleProofsResponseId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetMerkleProofsResponseId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///The version of the JSON-RPC protocol.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "The version of the JSON-RPC protocol.",
    ///  "type": "string",
    ///  "enum": [
    ///    "2.0"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetMerkleProofsResponseJsonrpc {
        #[serde(rename = "2.0")]
        X20,
    }
    impl ::std::fmt::Display for PostGetMerkleProofsResponseJsonrpc {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::X20 => f.write_str("2.0"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetMerkleProofsResponseJsonrpc {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "2.0" => Ok(Self::X20),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetMerkleProofsResponseJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetMerkleProofsResponseJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetMerkleProofsResponseJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///`PostGetMerkleProofsResponseResult`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "context",
    ///    "proofs"
    ///  ],
    ///  "properties": {
    ///    "context": {
    ///      "$ref": "#/components/schemas/Context"
    ///    },
    ///    "proofs": {
    ///      "type": "array",
    ///      "items": {
    ///        "$ref": "#/components/schemas/MerkleProof"
    ///      }
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct PostGetMerkleProofsResponseResult {
        pub context: Context,
        pub proofs: ::std::vec::Vec<MerkleProof>,
    }
    impl PostGetMerkleProofsResponseResult {
        pub fn builder() -> builder::PostGetMerkleProofsResponseResult {
            Default::default()
        }
    }
    ///`PostGetNonInclusionProofsBody`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "id",
    ///    "jsonrpc",
    ///    "method",
    ///    "params"
    ///  ],
    ///  "properties": {
    ///    "id": {
    ///      "description": "An ID to identify the request.",
    ///      "type": "string",
    ///      "enum": [
    ///        "test-account"
    ///      ]
    ///    },
    ///    "jsonrpc": {
    ///      "description": "The version of the JSON-RPC protocol.",
    ///      "type": "string",
    ///      "enum": [
    ///        "2.0"
    ///      ]
    ///    },
    ///    "method": {
    ///      "description": "The name of the method to invoke.",
    ///      "type": "string",
    ///      "enum": [
    ///        "get_non_inclusion_proofs"
    ///      ]
    ///    },
    ///    "params": {
    ///      "type": "object",
    ///      "required": [
    ///        "leaves",
    ///        "tree_account"
    ///      ],
    ///      "properties": {
    ///        "leaves": {
    ///          "type": "array",
    ///          "items": {
    ///            "$ref": "#/components/schemas/Hash"
    ///          }
    ///        },
    ///        "tree_account": {
    ///          "$ref": "#/components/schemas/SerializablePubkey"
    ///        }
    ///      },
    ///      "additionalProperties": false
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct PostGetNonInclusionProofsBody {
        ///An ID to identify the request.
        pub id: PostGetNonInclusionProofsBodyId,
        ///The version of the JSON-RPC protocol.
        pub jsonrpc: PostGetNonInclusionProofsBodyJsonrpc,
        ///The name of the method to invoke.
        pub method: PostGetNonInclusionProofsBodyMethod,
        pub params: PostGetNonInclusionProofsBodyParams,
    }
    impl PostGetNonInclusionProofsBody {
        pub fn builder() -> builder::PostGetNonInclusionProofsBody {
            Default::default()
        }
    }
    ///An ID to identify the request.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "An ID to identify the request.",
    ///  "type": "string",
    ///  "enum": [
    ///    "test-account"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetNonInclusionProofsBodyId {
        #[serde(rename = "test-account")]
        TestAccount,
    }
    impl ::std::fmt::Display for PostGetNonInclusionProofsBodyId {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::TestAccount => f.write_str("test-account"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetNonInclusionProofsBodyId {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "test-account" => Ok(Self::TestAccount),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetNonInclusionProofsBodyId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetNonInclusionProofsBodyId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetNonInclusionProofsBodyId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///The version of the JSON-RPC protocol.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "The version of the JSON-RPC protocol.",
    ///  "type": "string",
    ///  "enum": [
    ///    "2.0"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetNonInclusionProofsBodyJsonrpc {
        #[serde(rename = "2.0")]
        X20,
    }
    impl ::std::fmt::Display for PostGetNonInclusionProofsBodyJsonrpc {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::X20 => f.write_str("2.0"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetNonInclusionProofsBodyJsonrpc {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "2.0" => Ok(Self::X20),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetNonInclusionProofsBodyJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetNonInclusionProofsBodyJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetNonInclusionProofsBodyJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///The name of the method to invoke.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "The name of the method to invoke.",
    ///  "type": "string",
    ///  "enum": [
    ///    "get_non_inclusion_proofs"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetNonInclusionProofsBodyMethod {
        #[serde(rename = "get_non_inclusion_proofs")]
        GetNonInclusionProofs,
    }
    impl ::std::fmt::Display for PostGetNonInclusionProofsBodyMethod {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::GetNonInclusionProofs => f.write_str("get_non_inclusion_proofs"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetNonInclusionProofsBodyMethod {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "get_non_inclusion_proofs" => Ok(Self::GetNonInclusionProofs),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetNonInclusionProofsBodyMethod {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetNonInclusionProofsBodyMethod {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetNonInclusionProofsBodyMethod {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///`PostGetNonInclusionProofsBodyParams`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "leaves",
    ///    "tree_account"
    ///  ],
    ///  "properties": {
    ///    "leaves": {
    ///      "type": "array",
    ///      "items": {
    ///        "$ref": "#/components/schemas/Hash"
    ///      }
    ///    },
    ///    "tree_account": {
    ///      "$ref": "#/components/schemas/SerializablePubkey"
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct PostGetNonInclusionProofsBodyParams {
        pub leaves: ::std::vec::Vec<Hash>,
        pub tree_account: SerializablePubkey,
    }
    impl PostGetNonInclusionProofsBodyParams {
        pub fn builder() -> builder::PostGetNonInclusionProofsBodyParams {
            Default::default()
        }
    }
    ///`PostGetNonInclusionProofsResponse`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "id",
    ///    "jsonrpc"
    ///  ],
    ///  "properties": {
    ///    "error": {
    ///      "type": "object",
    ///      "properties": {
    ///        "code": {
    ///          "type": "integer"
    ///        },
    ///        "message": {
    ///          "type": "string"
    ///        }
    ///      }
    ///    },
    ///    "id": {
    ///      "description": "An ID to identify the response.",
    ///      "type": "string",
    ///      "enum": [
    ///        "test-account"
    ///      ]
    ///    },
    ///    "jsonrpc": {
    ///      "description": "The version of the JSON-RPC protocol.",
    ///      "type": "string",
    ///      "enum": [
    ///        "2.0"
    ///      ]
    ///    },
    ///    "result": {
    ///      "type": "object",
    ///      "required": [
    ///        "context",
    ///        "proofs"
    ///      ],
    ///      "properties": {
    ///        "context": {
    ///          "$ref": "#/components/schemas/Context"
    ///        },
    ///        "proofs": {
    ///          "type": "array",
    ///          "items": {
    ///            "$ref": "#/components/schemas/NonInclusionProof"
    ///          }
    ///        }
    ///      },
    ///      "additionalProperties": false
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct PostGetNonInclusionProofsResponse {
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub error: ::std::option::Option<PostGetNonInclusionProofsResponseError>,
        ///An ID to identify the response.
        pub id: PostGetNonInclusionProofsResponseId,
        ///The version of the JSON-RPC protocol.
        pub jsonrpc: PostGetNonInclusionProofsResponseJsonrpc,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub result: ::std::option::Option<PostGetNonInclusionProofsResponseResult>,
    }
    impl PostGetNonInclusionProofsResponse {
        pub fn builder() -> builder::PostGetNonInclusionProofsResponse {
            Default::default()
        }
    }
    ///`PostGetNonInclusionProofsResponseError`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "properties": {
    ///    "code": {
    ///      "type": "integer"
    ///    },
    ///    "message": {
    ///      "type": "string"
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct PostGetNonInclusionProofsResponseError {
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub code: ::std::option::Option<i64>,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub message: ::std::option::Option<::std::string::String>,
    }
    impl ::std::default::Default for PostGetNonInclusionProofsResponseError {
        fn default() -> Self {
            Self {
                code: Default::default(),
                message: Default::default(),
            }
        }
    }
    impl PostGetNonInclusionProofsResponseError {
        pub fn builder() -> builder::PostGetNonInclusionProofsResponseError {
            Default::default()
        }
    }
    ///An ID to identify the response.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "An ID to identify the response.",
    ///  "type": "string",
    ///  "enum": [
    ///    "test-account"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetNonInclusionProofsResponseId {
        #[serde(rename = "test-account")]
        TestAccount,
    }
    impl ::std::fmt::Display for PostGetNonInclusionProofsResponseId {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::TestAccount => f.write_str("test-account"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetNonInclusionProofsResponseId {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "test-account" => Ok(Self::TestAccount),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetNonInclusionProofsResponseId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetNonInclusionProofsResponseId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetNonInclusionProofsResponseId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///The version of the JSON-RPC protocol.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "The version of the JSON-RPC protocol.",
    ///  "type": "string",
    ///  "enum": [
    ///    "2.0"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetNonInclusionProofsResponseJsonrpc {
        #[serde(rename = "2.0")]
        X20,
    }
    impl ::std::fmt::Display for PostGetNonInclusionProofsResponseJsonrpc {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::X20 => f.write_str("2.0"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetNonInclusionProofsResponseJsonrpc {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "2.0" => Ok(Self::X20),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetNonInclusionProofsResponseJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetNonInclusionProofsResponseJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetNonInclusionProofsResponseJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///`PostGetNonInclusionProofsResponseResult`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "context",
    ///    "proofs"
    ///  ],
    ///  "properties": {
    ///    "context": {
    ///      "$ref": "#/components/schemas/Context"
    ///    },
    ///    "proofs": {
    ///      "type": "array",
    ///      "items": {
    ///        "$ref": "#/components/schemas/NonInclusionProof"
    ///      }
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct PostGetNonInclusionProofsResponseResult {
        pub context: Context,
        pub proofs: ::std::vec::Vec<NonInclusionProof>,
    }
    impl PostGetNonInclusionProofsResponseResult {
        pub fn builder() -> builder::PostGetNonInclusionProofsResponseResult {
            Default::default()
        }
    }
    ///`PostGetNullifierQueueElementsBody`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "id",
    ///    "jsonrpc",
    ///    "method",
    ///    "params"
    ///  ],
    ///  "properties": {
    ///    "id": {
    ///      "description": "An ID to identify the request.",
    ///      "type": "string",
    ///      "enum": [
    ///        "test-account"
    ///      ]
    ///    },
    ///    "jsonrpc": {
    ///      "description": "The version of the JSON-RPC protocol.",
    ///      "type": "string",
    ///      "enum": [
    ///        "2.0"
    ///      ]
    ///    },
    ///    "method": {
    ///      "description": "The name of the method to invoke.",
    ///      "type": "string",
    ///      "enum": [
    ///        "get_nullifier_queue_elements"
    ///      ]
    ///    },
    ///    "params": {
    ///      "type": "object",
    ///      "required": [
    ///        "limit",
    ///        "tree_account"
    ///      ],
    ///      "properties": {
    ///        "limit": {
    ///          "description": "Maximum number of elements to return.",
    ///          "type": "integer",
    ///          "format": "u-int64",
    ///          "minimum": 0.0
    ///        },
    ///        "start_seq": {
    ///          "description": "Return elements with `input_queue_seq >= start_seq` (default 0).",
    ///          "type": "integer",
    ///          "format": "u-int64",
    ///          "minimum": 0.0
    ///        },
    ///        "tree_account": {
    ///          "$ref": "#/components/schemas/SerializablePubkey"
    ///        }
    ///      },
    ///      "additionalProperties": false
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct PostGetNullifierQueueElementsBody {
        ///An ID to identify the request.
        pub id: PostGetNullifierQueueElementsBodyId,
        ///The version of the JSON-RPC protocol.
        pub jsonrpc: PostGetNullifierQueueElementsBodyJsonrpc,
        ///The name of the method to invoke.
        pub method: PostGetNullifierQueueElementsBodyMethod,
        pub params: PostGetNullifierQueueElementsBodyParams,
    }
    impl PostGetNullifierQueueElementsBody {
        pub fn builder() -> builder::PostGetNullifierQueueElementsBody {
            Default::default()
        }
    }
    ///An ID to identify the request.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "An ID to identify the request.",
    ///  "type": "string",
    ///  "enum": [
    ///    "test-account"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetNullifierQueueElementsBodyId {
        #[serde(rename = "test-account")]
        TestAccount,
    }
    impl ::std::fmt::Display for PostGetNullifierQueueElementsBodyId {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::TestAccount => f.write_str("test-account"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetNullifierQueueElementsBodyId {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "test-account" => Ok(Self::TestAccount),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetNullifierQueueElementsBodyId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetNullifierQueueElementsBodyId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetNullifierQueueElementsBodyId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///The version of the JSON-RPC protocol.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "The version of the JSON-RPC protocol.",
    ///  "type": "string",
    ///  "enum": [
    ///    "2.0"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetNullifierQueueElementsBodyJsonrpc {
        #[serde(rename = "2.0")]
        X20,
    }
    impl ::std::fmt::Display for PostGetNullifierQueueElementsBodyJsonrpc {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::X20 => f.write_str("2.0"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetNullifierQueueElementsBodyJsonrpc {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "2.0" => Ok(Self::X20),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetNullifierQueueElementsBodyJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetNullifierQueueElementsBodyJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetNullifierQueueElementsBodyJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///The name of the method to invoke.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "The name of the method to invoke.",
    ///  "type": "string",
    ///  "enum": [
    ///    "get_nullifier_queue_elements"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetNullifierQueueElementsBodyMethod {
        #[serde(rename = "get_nullifier_queue_elements")]
        GetNullifierQueueElements,
    }
    impl ::std::fmt::Display for PostGetNullifierQueueElementsBodyMethod {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::GetNullifierQueueElements => {
                    f.write_str("get_nullifier_queue_elements")
                }
            }
        }
    }
    impl ::std::str::FromStr for PostGetNullifierQueueElementsBodyMethod {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "get_nullifier_queue_elements" => Ok(Self::GetNullifierQueueElements),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetNullifierQueueElementsBodyMethod {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetNullifierQueueElementsBodyMethod {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetNullifierQueueElementsBodyMethod {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///`PostGetNullifierQueueElementsBodyParams`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "limit",
    ///    "tree_account"
    ///  ],
    ///  "properties": {
    ///    "limit": {
    ///      "description": "Maximum number of elements to return.",
    ///      "type": "integer",
    ///      "format": "u-int64",
    ///      "minimum": 0.0
    ///    },
    ///    "start_seq": {
    ///      "description": "Return elements with `input_queue_seq >= start_seq` (default 0).",
    ///      "type": "integer",
    ///      "format": "u-int64",
    ///      "minimum": 0.0
    ///    },
    ///    "tree_account": {
    ///      "$ref": "#/components/schemas/SerializablePubkey"
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct PostGetNullifierQueueElementsBodyParams {
        ///Maximum number of elements to return.
        pub limit: u64,
        ///Return elements with `input_queue_seq >= start_seq` (default 0).
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub start_seq: ::std::option::Option<u64>,
        pub tree_account: SerializablePubkey,
    }
    impl PostGetNullifierQueueElementsBodyParams {
        pub fn builder() -> builder::PostGetNullifierQueueElementsBodyParams {
            Default::default()
        }
    }
    ///`PostGetNullifierQueueElementsResponse`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "id",
    ///    "jsonrpc"
    ///  ],
    ///  "properties": {
    ///    "error": {
    ///      "type": "object",
    ///      "properties": {
    ///        "code": {
    ///          "type": "integer"
    ///        },
    ///        "message": {
    ///          "type": "string"
    ///        }
    ///      }
    ///    },
    ///    "id": {
    ///      "description": "An ID to identify the response.",
    ///      "type": "string",
    ///      "enum": [
    ///        "test-account"
    ///      ]
    ///    },
    ///    "jsonrpc": {
    ///      "description": "The version of the JSON-RPC protocol.",
    ///      "type": "string",
    ///      "enum": [
    ///        "2.0"
    ///      ]
    ///    },
    ///    "result": {
    ///      "type": "object",
    ///      "required": [
    ///        "context",
    ///        "elements"
    ///      ],
    ///      "properties": {
    ///        "context": {
    ///          "$ref": "#/components/schemas/Context"
    ///        },
    ///        "elements": {
    ///          "type": "array",
    ///          "items": {
    ///            "$ref": "#/components/schemas/NullifierQueueElement"
    ///          }
    ///        }
    ///      },
    ///      "additionalProperties": false
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct PostGetNullifierQueueElementsResponse {
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub error: ::std::option::Option<PostGetNullifierQueueElementsResponseError>,
        ///An ID to identify the response.
        pub id: PostGetNullifierQueueElementsResponseId,
        ///The version of the JSON-RPC protocol.
        pub jsonrpc: PostGetNullifierQueueElementsResponseJsonrpc,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub result: ::std::option::Option<PostGetNullifierQueueElementsResponseResult>,
    }
    impl PostGetNullifierQueueElementsResponse {
        pub fn builder() -> builder::PostGetNullifierQueueElementsResponse {
            Default::default()
        }
    }
    ///`PostGetNullifierQueueElementsResponseError`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "properties": {
    ///    "code": {
    ///      "type": "integer"
    ///    },
    ///    "message": {
    ///      "type": "string"
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct PostGetNullifierQueueElementsResponseError {
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub code: ::std::option::Option<i64>,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub message: ::std::option::Option<::std::string::String>,
    }
    impl ::std::default::Default for PostGetNullifierQueueElementsResponseError {
        fn default() -> Self {
            Self {
                code: Default::default(),
                message: Default::default(),
            }
        }
    }
    impl PostGetNullifierQueueElementsResponseError {
        pub fn builder() -> builder::PostGetNullifierQueueElementsResponseError {
            Default::default()
        }
    }
    ///An ID to identify the response.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "An ID to identify the response.",
    ///  "type": "string",
    ///  "enum": [
    ///    "test-account"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetNullifierQueueElementsResponseId {
        #[serde(rename = "test-account")]
        TestAccount,
    }
    impl ::std::fmt::Display for PostGetNullifierQueueElementsResponseId {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::TestAccount => f.write_str("test-account"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetNullifierQueueElementsResponseId {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "test-account" => Ok(Self::TestAccount),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetNullifierQueueElementsResponseId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetNullifierQueueElementsResponseId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetNullifierQueueElementsResponseId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///The version of the JSON-RPC protocol.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "The version of the JSON-RPC protocol.",
    ///  "type": "string",
    ///  "enum": [
    ///    "2.0"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetNullifierQueueElementsResponseJsonrpc {
        #[serde(rename = "2.0")]
        X20,
    }
    impl ::std::fmt::Display for PostGetNullifierQueueElementsResponseJsonrpc {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::X20 => f.write_str("2.0"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetNullifierQueueElementsResponseJsonrpc {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "2.0" => Ok(Self::X20),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetNullifierQueueElementsResponseJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetNullifierQueueElementsResponseJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetNullifierQueueElementsResponseJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///`PostGetNullifierQueueElementsResponseResult`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "context",
    ///    "elements"
    ///  ],
    ///  "properties": {
    ///    "context": {
    ///      "$ref": "#/components/schemas/Context"
    ///    },
    ///    "elements": {
    ///      "type": "array",
    ///      "items": {
    ///        "$ref": "#/components/schemas/NullifierQueueElement"
    ///      }
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct PostGetNullifierQueueElementsResponseResult {
        pub context: Context,
        pub elements: ::std::vec::Vec<NullifierQueueElement>,
    }
    impl PostGetNullifierQueueElementsResponseResult {
        pub fn builder() -> builder::PostGetNullifierQueueElementsResponseResult {
            Default::default()
        }
    }
    ///`PostGetShieldedTransactionsByTagsBody`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "id",
    ///    "jsonrpc",
    ///    "method",
    ///    "params"
    ///  ],
    ///  "properties": {
    ///    "id": {
    ///      "description": "An ID to identify the request.",
    ///      "type": "string",
    ///      "enum": [
    ///        "test-account"
    ///      ]
    ///    },
    ///    "jsonrpc": {
    ///      "description": "The version of the JSON-RPC protocol.",
    ///      "type": "string",
    ///      "enum": [
    ///        "2.0"
    ///      ]
    ///    },
    ///    "method": {
    ///      "description": "The name of the method to invoke.",
    ///      "type": "string",
    ///      "enum": [
    ///        "get_shielded_transactions_by_tags"
    ///      ]
    ///    },
    ///    "params": {
    ///      "type": "object",
    ///      "required": [
    ///        "tags"
    ///      ],
    ///      "properties": {
    ///        "cursor": {
    ///          "oneOf": [
    ///            {
    ///              "type": "null"
    ///            },
    ///            {
    ///              "allOf": [
    ///                {
    ///                  "$ref": "#/components/schemas/Base64String"
    ///                }
    ///              ]
    ///            }
    ///          ]
    ///        },
    ///        "limit": {
    ///          "oneOf": [
    ///            {
    ///              "type": "null"
    ///            },
    ///            {
    ///              "allOf": [
    ///                {
    ///                  "$ref": "#/components/schemas/Limit"
    ///                }
    ///              ]
    ///            }
    ///          ]
    ///        },
    ///        "tags": {
    ///          "type": "array",
    ///          "items": {
    ///            "$ref": "#/components/schemas/Hash"
    ///          }
    ///        }
    ///      },
    ///      "additionalProperties": false
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct PostGetShieldedTransactionsByTagsBody {
        ///An ID to identify the request.
        pub id: PostGetShieldedTransactionsByTagsBodyId,
        ///The version of the JSON-RPC protocol.
        pub jsonrpc: PostGetShieldedTransactionsByTagsBodyJsonrpc,
        ///The name of the method to invoke.
        pub method: PostGetShieldedTransactionsByTagsBodyMethod,
        pub params: PostGetShieldedTransactionsByTagsBodyParams,
    }
    impl PostGetShieldedTransactionsByTagsBody {
        pub fn builder() -> builder::PostGetShieldedTransactionsByTagsBody {
            Default::default()
        }
    }
    ///An ID to identify the request.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "An ID to identify the request.",
    ///  "type": "string",
    ///  "enum": [
    ///    "test-account"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetShieldedTransactionsByTagsBodyId {
        #[serde(rename = "test-account")]
        TestAccount,
    }
    impl ::std::fmt::Display for PostGetShieldedTransactionsByTagsBodyId {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::TestAccount => f.write_str("test-account"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetShieldedTransactionsByTagsBodyId {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "test-account" => Ok(Self::TestAccount),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetShieldedTransactionsByTagsBodyId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetShieldedTransactionsByTagsBodyId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetShieldedTransactionsByTagsBodyId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///The version of the JSON-RPC protocol.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "The version of the JSON-RPC protocol.",
    ///  "type": "string",
    ///  "enum": [
    ///    "2.0"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetShieldedTransactionsByTagsBodyJsonrpc {
        #[serde(rename = "2.0")]
        X20,
    }
    impl ::std::fmt::Display for PostGetShieldedTransactionsByTagsBodyJsonrpc {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::X20 => f.write_str("2.0"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetShieldedTransactionsByTagsBodyJsonrpc {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "2.0" => Ok(Self::X20),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetShieldedTransactionsByTagsBodyJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetShieldedTransactionsByTagsBodyJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetShieldedTransactionsByTagsBodyJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///The name of the method to invoke.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "The name of the method to invoke.",
    ///  "type": "string",
    ///  "enum": [
    ///    "get_shielded_transactions_by_tags"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetShieldedTransactionsByTagsBodyMethod {
        #[serde(rename = "get_shielded_transactions_by_tags")]
        GetShieldedTransactionsByTags,
    }
    impl ::std::fmt::Display for PostGetShieldedTransactionsByTagsBodyMethod {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::GetShieldedTransactionsByTags => {
                    f.write_str("get_shielded_transactions_by_tags")
                }
            }
        }
    }
    impl ::std::str::FromStr for PostGetShieldedTransactionsByTagsBodyMethod {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "get_shielded_transactions_by_tags" => {
                    Ok(Self::GetShieldedTransactionsByTags)
                }
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetShieldedTransactionsByTagsBodyMethod {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetShieldedTransactionsByTagsBodyMethod {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetShieldedTransactionsByTagsBodyMethod {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///`PostGetShieldedTransactionsByTagsBodyParams`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "tags"
    ///  ],
    ///  "properties": {
    ///    "cursor": {
    ///      "oneOf": [
    ///        {
    ///          "type": "null"
    ///        },
    ///        {
    ///          "allOf": [
    ///            {
    ///              "$ref": "#/components/schemas/Base64String"
    ///            }
    ///          ]
    ///        }
    ///      ]
    ///    },
    ///    "limit": {
    ///      "oneOf": [
    ///        {
    ///          "type": "null"
    ///        },
    ///        {
    ///          "allOf": [
    ///            {
    ///              "$ref": "#/components/schemas/Limit"
    ///            }
    ///          ]
    ///        }
    ///      ]
    ///    },
    ///    "tags": {
    ///      "type": "array",
    ///      "items": {
    ///        "$ref": "#/components/schemas/Hash"
    ///      }
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct PostGetShieldedTransactionsByTagsBodyParams {
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub cursor: ::std::option::Option<Base64String>,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub limit: ::std::option::Option<Limit>,
        pub tags: ::std::vec::Vec<Hash>,
    }
    impl PostGetShieldedTransactionsByTagsBodyParams {
        pub fn builder() -> builder::PostGetShieldedTransactionsByTagsBodyParams {
            Default::default()
        }
    }
    ///`PostGetShieldedTransactionsByTagsResponse`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "id",
    ///    "jsonrpc"
    ///  ],
    ///  "properties": {
    ///    "error": {
    ///      "type": "object",
    ///      "properties": {
    ///        "code": {
    ///          "type": "integer"
    ///        },
    ///        "message": {
    ///          "type": "string"
    ///        }
    ///      }
    ///    },
    ///    "id": {
    ///      "description": "An ID to identify the response.",
    ///      "type": "string",
    ///      "enum": [
    ///        "test-account"
    ///      ]
    ///    },
    ///    "jsonrpc": {
    ///      "description": "The version of the JSON-RPC protocol.",
    ///      "type": "string",
    ///      "enum": [
    ///        "2.0"
    ///      ]
    ///    },
    ///    "result": {
    ///      "type": "object",
    ///      "required": [
    ///        "context",
    ///        "transactions"
    ///      ],
    ///      "properties": {
    ///        "context": {
    ///          "$ref": "#/components/schemas/Context"
    ///        },
    ///        "next_cursor": {
    ///          "oneOf": [
    ///            {
    ///              "type": "null"
    ///            },
    ///            {
    ///              "allOf": [
    ///                {
    ///                  "$ref": "#/components/schemas/Base64String"
    ///                }
    ///              ]
    ///            }
    ///          ]
    ///        },
    ///        "transactions": {
    ///          "description": "Transaction-level matches; each returned transaction has at least one requested\noutput view tag and includes all of its output slots.",
    ///          "type": "array",
    ///          "items": {
    ///            "$ref": "#/components/schemas/ShieldedTransaction"
    ///          }
    ///        }
    ///      },
    ///      "additionalProperties": false
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct PostGetShieldedTransactionsByTagsResponse {
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub error: ::std::option::Option<PostGetShieldedTransactionsByTagsResponseError>,
        ///An ID to identify the response.
        pub id: PostGetShieldedTransactionsByTagsResponseId,
        ///The version of the JSON-RPC protocol.
        pub jsonrpc: PostGetShieldedTransactionsByTagsResponseJsonrpc,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub result: ::std::option::Option<
            PostGetShieldedTransactionsByTagsResponseResult,
        >,
    }
    impl PostGetShieldedTransactionsByTagsResponse {
        pub fn builder() -> builder::PostGetShieldedTransactionsByTagsResponse {
            Default::default()
        }
    }
    ///`PostGetShieldedTransactionsByTagsResponseError`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "properties": {
    ///    "code": {
    ///      "type": "integer"
    ///    },
    ///    "message": {
    ///      "type": "string"
    ///    }
    ///  }
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    pub struct PostGetShieldedTransactionsByTagsResponseError {
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub code: ::std::option::Option<i64>,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub message: ::std::option::Option<::std::string::String>,
    }
    impl ::std::default::Default for PostGetShieldedTransactionsByTagsResponseError {
        fn default() -> Self {
            Self {
                code: Default::default(),
                message: Default::default(),
            }
        }
    }
    impl PostGetShieldedTransactionsByTagsResponseError {
        pub fn builder() -> builder::PostGetShieldedTransactionsByTagsResponseError {
            Default::default()
        }
    }
    ///An ID to identify the response.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "An ID to identify the response.",
    ///  "type": "string",
    ///  "enum": [
    ///    "test-account"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetShieldedTransactionsByTagsResponseId {
        #[serde(rename = "test-account")]
        TestAccount,
    }
    impl ::std::fmt::Display for PostGetShieldedTransactionsByTagsResponseId {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::TestAccount => f.write_str("test-account"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetShieldedTransactionsByTagsResponseId {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "test-account" => Ok(Self::TestAccount),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str> for PostGetShieldedTransactionsByTagsResponseId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetShieldedTransactionsByTagsResponseId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetShieldedTransactionsByTagsResponseId {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///The version of the JSON-RPC protocol.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "The version of the JSON-RPC protocol.",
    ///  "type": "string",
    ///  "enum": [
    ///    "2.0"
    ///  ]
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    pub enum PostGetShieldedTransactionsByTagsResponseJsonrpc {
        #[serde(rename = "2.0")]
        X20,
    }
    impl ::std::fmt::Display for PostGetShieldedTransactionsByTagsResponseJsonrpc {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match *self {
                Self::X20 => f.write_str("2.0"),
            }
        }
    }
    impl ::std::str::FromStr for PostGetShieldedTransactionsByTagsResponseJsonrpc {
        type Err = self::error::ConversionError;
        fn from_str(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            match value {
                "2.0" => Ok(Self::X20),
                _ => Err("invalid value".into()),
            }
        }
    }
    impl ::std::convert::TryFrom<&str>
    for PostGetShieldedTransactionsByTagsResponseJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &str,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&::std::string::String>
    for PostGetShieldedTransactionsByTagsResponseJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: &::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<::std::string::String>
    for PostGetShieldedTransactionsByTagsResponseJsonrpc {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::string::String,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            value.parse()
        }
    }
    ///`PostGetShieldedTransactionsByTagsResponseResult`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "context",
    ///    "transactions"
    ///  ],
    ///  "properties": {
    ///    "context": {
    ///      "$ref": "#/components/schemas/Context"
    ///    },
    ///    "next_cursor": {
    ///      "oneOf": [
    ///        {
    ///          "type": "null"
    ///        },
    ///        {
    ///          "allOf": [
    ///            {
    ///              "$ref": "#/components/schemas/Base64String"
    ///            }
    ///          ]
    ///        }
    ///      ]
    ///    },
    ///    "transactions": {
    ///      "description": "Transaction-level matches; each returned transaction has at least one requested\noutput view tag and includes all of its output slots.",
    ///      "type": "array",
    ///      "items": {
    ///        "$ref": "#/components/schemas/ShieldedTransaction"
    ///      }
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct PostGetShieldedTransactionsByTagsResponseResult {
        pub context: Context,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub next_cursor: ::std::option::Option<Base64String>,
        /**Transaction-level matches; each returned transaction has at least one requested
output view tag and includes all of its output slots.*/
        pub transactions: ::std::vec::Vec<ShieldedTransaction>,
    }
    impl PostGetShieldedTransactionsByTagsResponseResult {
        pub fn builder() -> builder::PostGetShieldedTransactionsByTagsResponseResult {
            Default::default()
        }
    }
    ///`RingsOutputContext`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "hash",
    ///    "leaf_index",
    ///    "tree"
    ///  ],
    ///  "properties": {
    ///    "hash": {
    ///      "$ref": "#/components/schemas/Hash"
    ///    },
    ///    "leaf_index": {
    ///      "type": "integer",
    ///      "format": "u-int64",
    ///      "minimum": 0.0
    ///    },
    ///    "tree": {
    ///      "$ref": "#/components/schemas/SerializablePubkey"
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct RingsOutputContext {
        pub hash: Hash,
        pub leaf_index: u64,
        pub tree: SerializablePubkey,
    }
    impl RingsOutputContext {
        pub fn builder() -> builder::RingsOutputContext {
            Default::default()
        }
    }
    ///`RingsOutputSlot`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "output_context",
    ///    "payload",
    ///    "view_tag"
    ///  ],
    ///  "properties": {
    ///    "output_context": {
    ///      "$ref": "#/components/schemas/RingsOutputContext"
    ///    },
    ///    "payload": {
    ///      "$ref": "#/components/schemas/Base64String"
    ///    },
    ///    "view_tag": {
    ///      "$ref": "#/components/schemas/Hash"
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct RingsOutputSlot {
        pub output_context: RingsOutputContext,
        pub payload: Base64String,
        pub view_tag: Hash,
    }
    impl RingsOutputSlot {
        pub fn builder() -> builder::RingsOutputSlot {
            Default::default()
        }
    }
    ///A Solana public key represented as a base58 string.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "A Solana public key represented as a base58 string.",
    ///  "default": "111gbUgQk1ZFzZAQ2u4VePsUmmbjvubFCb4fwnFfhB",
    ///  "type": "string"
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    #[serde(transparent)]
    pub struct SerializablePubkey(pub ::std::string::String);
    impl ::std::ops::Deref for SerializablePubkey {
        type Target = ::std::string::String;
        fn deref(&self) -> &::std::string::String {
            &self.0
        }
    }
    impl ::std::convert::From<SerializablePubkey> for ::std::string::String {
        fn from(value: SerializablePubkey) -> Self {
            value.0
        }
    }
    impl ::std::convert::From<::std::string::String> for SerializablePubkey {
        fn from(value: ::std::string::String) -> Self {
            Self(value)
        }
    }
    impl ::std::str::FromStr for SerializablePubkey {
        type Err = ::std::convert::Infallible;
        fn from_str(value: &str) -> ::std::result::Result<Self, Self::Err> {
            Ok(Self(value.to_string()))
        }
    }
    impl ::std::fmt::Display for SerializablePubkey {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            self.0.fmt(f)
        }
    }
    ///A Solana transaction signature.
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "description": "A Solana transaction signature.",
    ///  "default": "5J8H5sTvEhnGcB4R8K1n7mfoiWUD9RzPVGES7e3WxC7c",
    ///  "type": "string"
    ///}
    /// ```
    /// </details>
    #[derive(
        ::serde::Deserialize,
        ::serde::Serialize,
        Clone,
        Debug,
        Eq,
        Hash,
        Ord,
        PartialEq,
        PartialOrd
    )]
    #[serde(transparent)]
    pub struct SerializableSignature(pub ::std::string::String);
    impl ::std::ops::Deref for SerializableSignature {
        type Target = ::std::string::String;
        fn deref(&self) -> &::std::string::String {
            &self.0
        }
    }
    impl ::std::convert::From<SerializableSignature> for ::std::string::String {
        fn from(value: SerializableSignature) -> Self {
            value.0
        }
    }
    impl ::std::convert::From<::std::string::String> for SerializableSignature {
        fn from(value: ::std::string::String) -> Self {
            Self(value)
        }
    }
    impl ::std::str::FromStr for SerializableSignature {
        type Err = ::std::convert::Infallible;
        fn from_str(value: &str) -> ::std::result::Result<Self, Self::Err> {
            Ok(Self(value.to_string()))
        }
    }
    impl ::std::fmt::Display for SerializableSignature {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            self.0.fmt(f)
        }
    }
    ///`ShieldedTransaction`
    ///
    /// <details><summary>JSON schema</summary>
    ///
    /// ```json
    ///{
    ///  "type": "object",
    ///  "required": [
    ///    "nullifiers",
    ///    "output_slots",
    ///    "proofless",
    ///    "slot",
    ///    "tx_signature"
    ///  ],
    ///  "properties": {
    ///    "nullifiers": {
    ///      "type": "array",
    ///      "items": {
    ///        "$ref": "#/components/schemas/Hash"
    ///      }
    ///    },
    ///    "output_slots": {
    ///      "type": "array",
    ///      "items": {
    ///        "$ref": "#/components/schemas/RingsOutputSlot"
    ///      }
    ///    },
    ///    "proofless": {
    ///      "description": "True when at least one output in this transaction is proofless.",
    ///      "type": "boolean"
    ///    },
    ///    "salt": {
    ///      "oneOf": [
    ///        {
    ///          "type": "null"
    ///        },
    ///        {
    ///          "allOf": [
    ///            {
    ///              "$ref": "#/components/schemas/Base64String"
    ///            }
    ///          ]
    ///        }
    ///      ]
    ///    },
    ///    "slot": {
    ///      "type": "integer",
    ///      "format": "u-int64",
    ///      "minimum": 0.0
    ///    },
    ///    "tx_signature": {
    ///      "$ref": "#/components/schemas/SerializableSignature"
    ///    },
    ///    "tx_viewing_pk": {
    ///      "oneOf": [
    ///        {
    ///          "type": "null"
    ///        },
    ///        {
    ///          "allOf": [
    ///            {
    ///              "$ref": "#/components/schemas/Base64String"
    ///            }
    ///          ]
    ///        }
    ///      ]
    ///    }
    ///  },
    ///  "additionalProperties": false
    ///}
    /// ```
    /// </details>
    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct ShieldedTransaction {
        pub nullifiers: ::std::vec::Vec<Hash>,
        pub output_slots: ::std::vec::Vec<RingsOutputSlot>,
        ///True when at least one output in this transaction is proofless.
        pub proofless: bool,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub salt: ::std::option::Option<Base64String>,
        pub slot: u64,
        pub tx_signature: SerializableSignature,
        #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
        pub tx_viewing_pk: ::std::option::Option<Base64String>,
    }
    impl ShieldedTransaction {
        pub fn builder() -> builder::ShieldedTransaction {
            Default::default()
        }
    }
    /// Types for composing complex structures.
    pub mod builder {
        #[derive(Clone, Debug)]
        pub struct Context {
            slot: ::std::result::Result<i64, ::std::string::String>,
        }
        impl ::std::default::Default for Context {
            fn default() -> Self {
                Self {
                    slot: Err("no value supplied for slot".to_string()),
                }
            }
        }
        impl Context {
            pub fn slot<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<i64>,
                T::Error: ::std::fmt::Display,
            {
                self.slot = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for slot: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<Context> for super::Context {
            type Error = super::error::ConversionError;
            fn try_from(
                value: Context,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self { slot: value.slot? })
            }
        }
        impl ::std::convert::From<super::Context> for Context {
            fn from(value: super::Context) -> Self {
                Self { slot: Ok(value.slot) }
            }
        }
        #[derive(Clone, Debug)]
        pub struct EncryptedUtxoMatch {
            output_slot: ::std::result::Result<
                super::RingsOutputSlot,
                ::std::string::String,
            >,
            salt: ::std::result::Result<
                ::std::option::Option<super::Base64String>,
                ::std::string::String,
            >,
            slot: ::std::result::Result<u64, ::std::string::String>,
            tx_signature: ::std::result::Result<
                super::SerializableSignature,
                ::std::string::String,
            >,
            tx_viewing_pk: ::std::result::Result<
                ::std::option::Option<super::Base64String>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for EncryptedUtxoMatch {
            fn default() -> Self {
                Self {
                    output_slot: Err("no value supplied for output_slot".to_string()),
                    salt: Ok(Default::default()),
                    slot: Err("no value supplied for slot".to_string()),
                    tx_signature: Err("no value supplied for tx_signature".to_string()),
                    tx_viewing_pk: Ok(Default::default()),
                }
            }
        }
        impl EncryptedUtxoMatch {
            pub fn output_slot<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::RingsOutputSlot>,
                T::Error: ::std::fmt::Display,
            {
                self.output_slot = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for output_slot: {e}")
                    });
                self
            }
            pub fn salt<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<super::Base64String>>,
                T::Error: ::std::fmt::Display,
            {
                self.salt = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for salt: {e}")
                    });
                self
            }
            pub fn slot<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<u64>,
                T::Error: ::std::fmt::Display,
            {
                self.slot = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for slot: {e}")
                    });
                self
            }
            pub fn tx_signature<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::SerializableSignature>,
                T::Error: ::std::fmt::Display,
            {
                self.tx_signature = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for tx_signature: {e}")
                    });
                self
            }
            pub fn tx_viewing_pk<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<super::Base64String>>,
                T::Error: ::std::fmt::Display,
            {
                self.tx_viewing_pk = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for tx_viewing_pk: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<EncryptedUtxoMatch> for super::EncryptedUtxoMatch {
            type Error = super::error::ConversionError;
            fn try_from(
                value: EncryptedUtxoMatch,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    output_slot: value.output_slot?,
                    salt: value.salt?,
                    slot: value.slot?,
                    tx_signature: value.tx_signature?,
                    tx_viewing_pk: value.tx_viewing_pk?,
                })
            }
        }
        impl ::std::convert::From<super::EncryptedUtxoMatch> for EncryptedUtxoMatch {
            fn from(value: super::EncryptedUtxoMatch) -> Self {
                Self {
                    output_slot: Ok(value.output_slot),
                    salt: Ok(value.salt),
                    slot: Ok(value.slot),
                    tx_signature: Ok(value.tx_signature),
                    tx_viewing_pk: Ok(value.tx_viewing_pk),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct MerkleContext {
            tree: ::std::result::Result<
                super::SerializablePubkey,
                ::std::string::String,
            >,
            tree_type: ::std::result::Result<u64, ::std::string::String>,
        }
        impl ::std::default::Default for MerkleContext {
            fn default() -> Self {
                Self {
                    tree: Err("no value supplied for tree".to_string()),
                    tree_type: Err("no value supplied for tree_type".to_string()),
                }
            }
        }
        impl MerkleContext {
            pub fn tree<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::SerializablePubkey>,
                T::Error: ::std::fmt::Display,
            {
                self.tree = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for tree: {e}")
                    });
                self
            }
            pub fn tree_type<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<u64>,
                T::Error: ::std::fmt::Display,
            {
                self.tree_type = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for tree_type: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<MerkleContext> for super::MerkleContext {
            type Error = super::error::ConversionError;
            fn try_from(
                value: MerkleContext,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    tree: value.tree?,
                    tree_type: value.tree_type?,
                })
            }
        }
        impl ::std::convert::From<super::MerkleContext> for MerkleContext {
            fn from(value: super::MerkleContext) -> Self {
                Self {
                    tree: Ok(value.tree),
                    tree_type: Ok(value.tree_type),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct MerkleProof {
            leaf: ::std::result::Result<super::Hash, ::std::string::String>,
            leaf_index: ::std::result::Result<u64, ::std::string::String>,
            merkle_context: ::std::result::Result<
                super::MerkleContext,
                ::std::string::String,
            >,
            path: ::std::result::Result<
                ::std::vec::Vec<super::Hash>,
                ::std::string::String,
            >,
            root: ::std::result::Result<super::Hash, ::std::string::String>,
            root_index: ::std::result::Result<u64, ::std::string::String>,
            root_seq: ::std::result::Result<u64, ::std::string::String>,
        }
        impl ::std::default::Default for MerkleProof {
            fn default() -> Self {
                Self {
                    leaf: Err("no value supplied for leaf".to_string()),
                    leaf_index: Err("no value supplied for leaf_index".to_string()),
                    merkle_context: Err(
                        "no value supplied for merkle_context".to_string(),
                    ),
                    path: Err("no value supplied for path".to_string()),
                    root: Err("no value supplied for root".to_string()),
                    root_index: Err("no value supplied for root_index".to_string()),
                    root_seq: Err("no value supplied for root_seq".to_string()),
                }
            }
        }
        impl MerkleProof {
            pub fn leaf<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::Hash>,
                T::Error: ::std::fmt::Display,
            {
                self.leaf = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for leaf: {e}")
                    });
                self
            }
            pub fn leaf_index<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<u64>,
                T::Error: ::std::fmt::Display,
            {
                self.leaf_index = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for leaf_index: {e}")
                    });
                self
            }
            pub fn merkle_context<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::MerkleContext>,
                T::Error: ::std::fmt::Display,
            {
                self.merkle_context = value
                    .try_into()
                    .map_err(|e| {
                        format!(
                            "error converting supplied value for merkle_context: {e}"
                        )
                    });
                self
            }
            pub fn path<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::vec::Vec<super::Hash>>,
                T::Error: ::std::fmt::Display,
            {
                self.path = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for path: {e}")
                    });
                self
            }
            pub fn root<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::Hash>,
                T::Error: ::std::fmt::Display,
            {
                self.root = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for root: {e}")
                    });
                self
            }
            pub fn root_index<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<u64>,
                T::Error: ::std::fmt::Display,
            {
                self.root_index = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for root_index: {e}")
                    });
                self
            }
            pub fn root_seq<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<u64>,
                T::Error: ::std::fmt::Display,
            {
                self.root_seq = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for root_seq: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<MerkleProof> for super::MerkleProof {
            type Error = super::error::ConversionError;
            fn try_from(
                value: MerkleProof,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    leaf: value.leaf?,
                    leaf_index: value.leaf_index?,
                    merkle_context: value.merkle_context?,
                    path: value.path?,
                    root: value.root?,
                    root_index: value.root_index?,
                    root_seq: value.root_seq?,
                })
            }
        }
        impl ::std::convert::From<super::MerkleProof> for MerkleProof {
            fn from(value: super::MerkleProof) -> Self {
                Self {
                    leaf: Ok(value.leaf),
                    leaf_index: Ok(value.leaf_index),
                    merkle_context: Ok(value.merkle_context),
                    path: Ok(value.path),
                    root: Ok(value.root),
                    root_index: Ok(value.root_index),
                    root_seq: Ok(value.root_seq),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct NonInclusionProof {
            high_element: ::std::result::Result<super::Hash, ::std::string::String>,
            high_element_index: ::std::result::Result<u64, ::std::string::String>,
            leaf: ::std::result::Result<super::Hash, ::std::string::String>,
            low_element: ::std::result::Result<super::Hash, ::std::string::String>,
            low_element_index: ::std::result::Result<u64, ::std::string::String>,
            merkle_context: ::std::result::Result<
                super::MerkleContext,
                ::std::string::String,
            >,
            path: ::std::result::Result<
                ::std::vec::Vec<super::Hash>,
                ::std::string::String,
            >,
            root: ::std::result::Result<super::Hash, ::std::string::String>,
            root_index: ::std::result::Result<u64, ::std::string::String>,
            root_seq: ::std::result::Result<u64, ::std::string::String>,
        }
        impl ::std::default::Default for NonInclusionProof {
            fn default() -> Self {
                Self {
                    high_element: Err("no value supplied for high_element".to_string()),
                    high_element_index: Err(
                        "no value supplied for high_element_index".to_string(),
                    ),
                    leaf: Err("no value supplied for leaf".to_string()),
                    low_element: Err("no value supplied for low_element".to_string()),
                    low_element_index: Err(
                        "no value supplied for low_element_index".to_string(),
                    ),
                    merkle_context: Err(
                        "no value supplied for merkle_context".to_string(),
                    ),
                    path: Err("no value supplied for path".to_string()),
                    root: Err("no value supplied for root".to_string()),
                    root_index: Err("no value supplied for root_index".to_string()),
                    root_seq: Err("no value supplied for root_seq".to_string()),
                }
            }
        }
        impl NonInclusionProof {
            pub fn high_element<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::Hash>,
                T::Error: ::std::fmt::Display,
            {
                self.high_element = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for high_element: {e}")
                    });
                self
            }
            pub fn high_element_index<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<u64>,
                T::Error: ::std::fmt::Display,
            {
                self.high_element_index = value
                    .try_into()
                    .map_err(|e| {
                        format!(
                            "error converting supplied value for high_element_index: {e}"
                        )
                    });
                self
            }
            pub fn leaf<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::Hash>,
                T::Error: ::std::fmt::Display,
            {
                self.leaf = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for leaf: {e}")
                    });
                self
            }
            pub fn low_element<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::Hash>,
                T::Error: ::std::fmt::Display,
            {
                self.low_element = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for low_element: {e}")
                    });
                self
            }
            pub fn low_element_index<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<u64>,
                T::Error: ::std::fmt::Display,
            {
                self.low_element_index = value
                    .try_into()
                    .map_err(|e| {
                        format!(
                            "error converting supplied value for low_element_index: {e}"
                        )
                    });
                self
            }
            pub fn merkle_context<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::MerkleContext>,
                T::Error: ::std::fmt::Display,
            {
                self.merkle_context = value
                    .try_into()
                    .map_err(|e| {
                        format!(
                            "error converting supplied value for merkle_context: {e}"
                        )
                    });
                self
            }
            pub fn path<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::vec::Vec<super::Hash>>,
                T::Error: ::std::fmt::Display,
            {
                self.path = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for path: {e}")
                    });
                self
            }
            pub fn root<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::Hash>,
                T::Error: ::std::fmt::Display,
            {
                self.root = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for root: {e}")
                    });
                self
            }
            pub fn root_index<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<u64>,
                T::Error: ::std::fmt::Display,
            {
                self.root_index = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for root_index: {e}")
                    });
                self
            }
            pub fn root_seq<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<u64>,
                T::Error: ::std::fmt::Display,
            {
                self.root_seq = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for root_seq: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<NonInclusionProof> for super::NonInclusionProof {
            type Error = super::error::ConversionError;
            fn try_from(
                value: NonInclusionProof,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    high_element: value.high_element?,
                    high_element_index: value.high_element_index?,
                    leaf: value.leaf?,
                    low_element: value.low_element?,
                    low_element_index: value.low_element_index?,
                    merkle_context: value.merkle_context?,
                    path: value.path?,
                    root: value.root?,
                    root_index: value.root_index?,
                    root_seq: value.root_seq?,
                })
            }
        }
        impl ::std::convert::From<super::NonInclusionProof> for NonInclusionProof {
            fn from(value: super::NonInclusionProof) -> Self {
                Self {
                    high_element: Ok(value.high_element),
                    high_element_index: Ok(value.high_element_index),
                    leaf: Ok(value.leaf),
                    low_element: Ok(value.low_element),
                    low_element_index: Ok(value.low_element_index),
                    merkle_context: Ok(value.merkle_context),
                    path: Ok(value.path),
                    root: Ok(value.root),
                    root_index: Ok(value.root_index),
                    root_seq: Ok(value.root_seq),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct NullifierQueueElement {
            seq: ::std::result::Result<u64, ::std::string::String>,
            value: ::std::result::Result<super::Hash, ::std::string::String>,
        }
        impl ::std::default::Default for NullifierQueueElement {
            fn default() -> Self {
                Self {
                    seq: Err("no value supplied for seq".to_string()),
                    value: Err("no value supplied for value".to_string()),
                }
            }
        }
        impl NullifierQueueElement {
            pub fn seq<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<u64>,
                T::Error: ::std::fmt::Display,
            {
                self.seq = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for seq: {e}")
                    });
                self
            }
            pub fn value<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::Hash>,
                T::Error: ::std::fmt::Display,
            {
                self.value = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for value: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<NullifierQueueElement>
        for super::NullifierQueueElement {
            type Error = super::error::ConversionError;
            fn try_from(
                value: NullifierQueueElement,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    seq: value.seq?,
                    value: value.value?,
                })
            }
        }
        impl ::std::convert::From<super::NullifierQueueElement>
        for NullifierQueueElement {
            fn from(value: super::NullifierQueueElement) -> Self {
                Self {
                    seq: Ok(value.seq),
                    value: Ok(value.value),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetEncryptedUtxosByTagsBody {
            id: ::std::result::Result<
                super::PostGetEncryptedUtxosByTagsBodyId,
                ::std::string::String,
            >,
            jsonrpc: ::std::result::Result<
                super::PostGetEncryptedUtxosByTagsBodyJsonrpc,
                ::std::string::String,
            >,
            method: ::std::result::Result<
                super::PostGetEncryptedUtxosByTagsBodyMethod,
                ::std::string::String,
            >,
            params: ::std::result::Result<
                super::PostGetEncryptedUtxosByTagsBodyParams,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetEncryptedUtxosByTagsBody {
            fn default() -> Self {
                Self {
                    id: Err("no value supplied for id".to_string()),
                    jsonrpc: Err("no value supplied for jsonrpc".to_string()),
                    method: Err("no value supplied for method".to_string()),
                    params: Err("no value supplied for params".to_string()),
                }
            }
        }
        impl PostGetEncryptedUtxosByTagsBody {
            pub fn id<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetEncryptedUtxosByTagsBodyId>,
                T::Error: ::std::fmt::Display,
            {
                self.id = value
                    .try_into()
                    .map_err(|e| format!("error converting supplied value for id: {e}"));
                self
            }
            pub fn jsonrpc<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    super::PostGetEncryptedUtxosByTagsBodyJsonrpc,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.jsonrpc = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for jsonrpc: {e}")
                    });
                self
            }
            pub fn method<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetEncryptedUtxosByTagsBodyMethod>,
                T::Error: ::std::fmt::Display,
            {
                self.method = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for method: {e}")
                    });
                self
            }
            pub fn params<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetEncryptedUtxosByTagsBodyParams>,
                T::Error: ::std::fmt::Display,
            {
                self.params = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for params: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetEncryptedUtxosByTagsBody>
        for super::PostGetEncryptedUtxosByTagsBody {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetEncryptedUtxosByTagsBody,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    id: value.id?,
                    jsonrpc: value.jsonrpc?,
                    method: value.method?,
                    params: value.params?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetEncryptedUtxosByTagsBody>
        for PostGetEncryptedUtxosByTagsBody {
            fn from(value: super::PostGetEncryptedUtxosByTagsBody) -> Self {
                Self {
                    id: Ok(value.id),
                    jsonrpc: Ok(value.jsonrpc),
                    method: Ok(value.method),
                    params: Ok(value.params),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetEncryptedUtxosByTagsBodyParams {
            cursor: ::std::result::Result<
                ::std::option::Option<super::Base64String>,
                ::std::string::String,
            >,
            limit: ::std::result::Result<
                ::std::option::Option<super::Limit>,
                ::std::string::String,
            >,
            tags: ::std::result::Result<
                ::std::vec::Vec<super::Hash>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetEncryptedUtxosByTagsBodyParams {
            fn default() -> Self {
                Self {
                    cursor: Ok(Default::default()),
                    limit: Ok(Default::default()),
                    tags: Err("no value supplied for tags".to_string()),
                }
            }
        }
        impl PostGetEncryptedUtxosByTagsBodyParams {
            pub fn cursor<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<super::Base64String>>,
                T::Error: ::std::fmt::Display,
            {
                self.cursor = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for cursor: {e}")
                    });
                self
            }
            pub fn limit<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<super::Limit>>,
                T::Error: ::std::fmt::Display,
            {
                self.limit = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for limit: {e}")
                    });
                self
            }
            pub fn tags<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::vec::Vec<super::Hash>>,
                T::Error: ::std::fmt::Display,
            {
                self.tags = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for tags: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetEncryptedUtxosByTagsBodyParams>
        for super::PostGetEncryptedUtxosByTagsBodyParams {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetEncryptedUtxosByTagsBodyParams,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    cursor: value.cursor?,
                    limit: value.limit?,
                    tags: value.tags?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetEncryptedUtxosByTagsBodyParams>
        for PostGetEncryptedUtxosByTagsBodyParams {
            fn from(value: super::PostGetEncryptedUtxosByTagsBodyParams) -> Self {
                Self {
                    cursor: Ok(value.cursor),
                    limit: Ok(value.limit),
                    tags: Ok(value.tags),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetEncryptedUtxosByTagsResponse {
            error: ::std::result::Result<
                ::std::option::Option<super::PostGetEncryptedUtxosByTagsResponseError>,
                ::std::string::String,
            >,
            id: ::std::result::Result<
                super::PostGetEncryptedUtxosByTagsResponseId,
                ::std::string::String,
            >,
            jsonrpc: ::std::result::Result<
                super::PostGetEncryptedUtxosByTagsResponseJsonrpc,
                ::std::string::String,
            >,
            result: ::std::result::Result<
                ::std::option::Option<super::PostGetEncryptedUtxosByTagsResponseResult>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetEncryptedUtxosByTagsResponse {
            fn default() -> Self {
                Self {
                    error: Ok(Default::default()),
                    id: Err("no value supplied for id".to_string()),
                    jsonrpc: Err("no value supplied for jsonrpc".to_string()),
                    result: Ok(Default::default()),
                }
            }
        }
        impl PostGetEncryptedUtxosByTagsResponse {
            pub fn error<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    ::std::option::Option<
                        super::PostGetEncryptedUtxosByTagsResponseError,
                    >,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.error = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for error: {e}")
                    });
                self
            }
            pub fn id<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetEncryptedUtxosByTagsResponseId>,
                T::Error: ::std::fmt::Display,
            {
                self.id = value
                    .try_into()
                    .map_err(|e| format!("error converting supplied value for id: {e}"));
                self
            }
            pub fn jsonrpc<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    super::PostGetEncryptedUtxosByTagsResponseJsonrpc,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.jsonrpc = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for jsonrpc: {e}")
                    });
                self
            }
            pub fn result<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    ::std::option::Option<
                        super::PostGetEncryptedUtxosByTagsResponseResult,
                    >,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.result = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for result: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetEncryptedUtxosByTagsResponse>
        for super::PostGetEncryptedUtxosByTagsResponse {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetEncryptedUtxosByTagsResponse,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    error: value.error?,
                    id: value.id?,
                    jsonrpc: value.jsonrpc?,
                    result: value.result?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetEncryptedUtxosByTagsResponse>
        for PostGetEncryptedUtxosByTagsResponse {
            fn from(value: super::PostGetEncryptedUtxosByTagsResponse) -> Self {
                Self {
                    error: Ok(value.error),
                    id: Ok(value.id),
                    jsonrpc: Ok(value.jsonrpc),
                    result: Ok(value.result),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetEncryptedUtxosByTagsResponseError {
            code: ::std::result::Result<
                ::std::option::Option<i64>,
                ::std::string::String,
            >,
            message: ::std::result::Result<
                ::std::option::Option<::std::string::String>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetEncryptedUtxosByTagsResponseError {
            fn default() -> Self {
                Self {
                    code: Ok(Default::default()),
                    message: Ok(Default::default()),
                }
            }
        }
        impl PostGetEncryptedUtxosByTagsResponseError {
            pub fn code<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<i64>>,
                T::Error: ::std::fmt::Display,
            {
                self.code = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for code: {e}")
                    });
                self
            }
            pub fn message<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<::std::string::String>>,
                T::Error: ::std::fmt::Display,
            {
                self.message = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for message: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetEncryptedUtxosByTagsResponseError>
        for super::PostGetEncryptedUtxosByTagsResponseError {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetEncryptedUtxosByTagsResponseError,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    code: value.code?,
                    message: value.message?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetEncryptedUtxosByTagsResponseError>
        for PostGetEncryptedUtxosByTagsResponseError {
            fn from(value: super::PostGetEncryptedUtxosByTagsResponseError) -> Self {
                Self {
                    code: Ok(value.code),
                    message: Ok(value.message),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetEncryptedUtxosByTagsResponseResult {
            context: ::std::result::Result<super::Context, ::std::string::String>,
            matches: ::std::result::Result<
                ::std::vec::Vec<super::EncryptedUtxoMatch>,
                ::std::string::String,
            >,
            next_cursor: ::std::result::Result<
                ::std::option::Option<super::Base64String>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetEncryptedUtxosByTagsResponseResult {
            fn default() -> Self {
                Self {
                    context: Err("no value supplied for context".to_string()),
                    matches: Err("no value supplied for matches".to_string()),
                    next_cursor: Ok(Default::default()),
                }
            }
        }
        impl PostGetEncryptedUtxosByTagsResponseResult {
            pub fn context<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::Context>,
                T::Error: ::std::fmt::Display,
            {
                self.context = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for context: {e}")
                    });
                self
            }
            pub fn matches<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::vec::Vec<super::EncryptedUtxoMatch>>,
                T::Error: ::std::fmt::Display,
            {
                self.matches = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for matches: {e}")
                    });
                self
            }
            pub fn next_cursor<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<super::Base64String>>,
                T::Error: ::std::fmt::Display,
            {
                self.next_cursor = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for next_cursor: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetEncryptedUtxosByTagsResponseResult>
        for super::PostGetEncryptedUtxosByTagsResponseResult {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetEncryptedUtxosByTagsResponseResult,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    context: value.context?,
                    matches: value.matches?,
                    next_cursor: value.next_cursor?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetEncryptedUtxosByTagsResponseResult>
        for PostGetEncryptedUtxosByTagsResponseResult {
            fn from(value: super::PostGetEncryptedUtxosByTagsResponseResult) -> Self {
                Self {
                    context: Ok(value.context),
                    matches: Ok(value.matches),
                    next_cursor: Ok(value.next_cursor),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetMerkleProofsBody {
            id: ::std::result::Result<
                super::PostGetMerkleProofsBodyId,
                ::std::string::String,
            >,
            jsonrpc: ::std::result::Result<
                super::PostGetMerkleProofsBodyJsonrpc,
                ::std::string::String,
            >,
            method: ::std::result::Result<
                super::PostGetMerkleProofsBodyMethod,
                ::std::string::String,
            >,
            params: ::std::result::Result<
                super::PostGetMerkleProofsBodyParams,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetMerkleProofsBody {
            fn default() -> Self {
                Self {
                    id: Err("no value supplied for id".to_string()),
                    jsonrpc: Err("no value supplied for jsonrpc".to_string()),
                    method: Err("no value supplied for method".to_string()),
                    params: Err("no value supplied for params".to_string()),
                }
            }
        }
        impl PostGetMerkleProofsBody {
            pub fn id<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetMerkleProofsBodyId>,
                T::Error: ::std::fmt::Display,
            {
                self.id = value
                    .try_into()
                    .map_err(|e| format!("error converting supplied value for id: {e}"));
                self
            }
            pub fn jsonrpc<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetMerkleProofsBodyJsonrpc>,
                T::Error: ::std::fmt::Display,
            {
                self.jsonrpc = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for jsonrpc: {e}")
                    });
                self
            }
            pub fn method<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetMerkleProofsBodyMethod>,
                T::Error: ::std::fmt::Display,
            {
                self.method = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for method: {e}")
                    });
                self
            }
            pub fn params<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetMerkleProofsBodyParams>,
                T::Error: ::std::fmt::Display,
            {
                self.params = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for params: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetMerkleProofsBody>
        for super::PostGetMerkleProofsBody {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetMerkleProofsBody,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    id: value.id?,
                    jsonrpc: value.jsonrpc?,
                    method: value.method?,
                    params: value.params?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetMerkleProofsBody>
        for PostGetMerkleProofsBody {
            fn from(value: super::PostGetMerkleProofsBody) -> Self {
                Self {
                    id: Ok(value.id),
                    jsonrpc: Ok(value.jsonrpc),
                    method: Ok(value.method),
                    params: Ok(value.params),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetMerkleProofsBodyParams {
            leaves: ::std::result::Result<
                ::std::vec::Vec<super::Hash>,
                ::std::string::String,
            >,
            tree_account: ::std::result::Result<
                super::SerializablePubkey,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetMerkleProofsBodyParams {
            fn default() -> Self {
                Self {
                    leaves: Err("no value supplied for leaves".to_string()),
                    tree_account: Err("no value supplied for tree_account".to_string()),
                }
            }
        }
        impl PostGetMerkleProofsBodyParams {
            pub fn leaves<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::vec::Vec<super::Hash>>,
                T::Error: ::std::fmt::Display,
            {
                self.leaves = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for leaves: {e}")
                    });
                self
            }
            pub fn tree_account<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::SerializablePubkey>,
                T::Error: ::std::fmt::Display,
            {
                self.tree_account = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for tree_account: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetMerkleProofsBodyParams>
        for super::PostGetMerkleProofsBodyParams {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetMerkleProofsBodyParams,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    leaves: value.leaves?,
                    tree_account: value.tree_account?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetMerkleProofsBodyParams>
        for PostGetMerkleProofsBodyParams {
            fn from(value: super::PostGetMerkleProofsBodyParams) -> Self {
                Self {
                    leaves: Ok(value.leaves),
                    tree_account: Ok(value.tree_account),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetMerkleProofsResponse {
            error: ::std::result::Result<
                ::std::option::Option<super::PostGetMerkleProofsResponseError>,
                ::std::string::String,
            >,
            id: ::std::result::Result<
                super::PostGetMerkleProofsResponseId,
                ::std::string::String,
            >,
            jsonrpc: ::std::result::Result<
                super::PostGetMerkleProofsResponseJsonrpc,
                ::std::string::String,
            >,
            result: ::std::result::Result<
                ::std::option::Option<super::PostGetMerkleProofsResponseResult>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetMerkleProofsResponse {
            fn default() -> Self {
                Self {
                    error: Ok(Default::default()),
                    id: Err("no value supplied for id".to_string()),
                    jsonrpc: Err("no value supplied for jsonrpc".to_string()),
                    result: Ok(Default::default()),
                }
            }
        }
        impl PostGetMerkleProofsResponse {
            pub fn error<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    ::std::option::Option<super::PostGetMerkleProofsResponseError>,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.error = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for error: {e}")
                    });
                self
            }
            pub fn id<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetMerkleProofsResponseId>,
                T::Error: ::std::fmt::Display,
            {
                self.id = value
                    .try_into()
                    .map_err(|e| format!("error converting supplied value for id: {e}"));
                self
            }
            pub fn jsonrpc<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetMerkleProofsResponseJsonrpc>,
                T::Error: ::std::fmt::Display,
            {
                self.jsonrpc = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for jsonrpc: {e}")
                    });
                self
            }
            pub fn result<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    ::std::option::Option<super::PostGetMerkleProofsResponseResult>,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.result = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for result: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetMerkleProofsResponse>
        for super::PostGetMerkleProofsResponse {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetMerkleProofsResponse,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    error: value.error?,
                    id: value.id?,
                    jsonrpc: value.jsonrpc?,
                    result: value.result?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetMerkleProofsResponse>
        for PostGetMerkleProofsResponse {
            fn from(value: super::PostGetMerkleProofsResponse) -> Self {
                Self {
                    error: Ok(value.error),
                    id: Ok(value.id),
                    jsonrpc: Ok(value.jsonrpc),
                    result: Ok(value.result),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetMerkleProofsResponseError {
            code: ::std::result::Result<
                ::std::option::Option<i64>,
                ::std::string::String,
            >,
            message: ::std::result::Result<
                ::std::option::Option<::std::string::String>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetMerkleProofsResponseError {
            fn default() -> Self {
                Self {
                    code: Ok(Default::default()),
                    message: Ok(Default::default()),
                }
            }
        }
        impl PostGetMerkleProofsResponseError {
            pub fn code<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<i64>>,
                T::Error: ::std::fmt::Display,
            {
                self.code = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for code: {e}")
                    });
                self
            }
            pub fn message<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<::std::string::String>>,
                T::Error: ::std::fmt::Display,
            {
                self.message = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for message: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetMerkleProofsResponseError>
        for super::PostGetMerkleProofsResponseError {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetMerkleProofsResponseError,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    code: value.code?,
                    message: value.message?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetMerkleProofsResponseError>
        for PostGetMerkleProofsResponseError {
            fn from(value: super::PostGetMerkleProofsResponseError) -> Self {
                Self {
                    code: Ok(value.code),
                    message: Ok(value.message),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetMerkleProofsResponseResult {
            context: ::std::result::Result<super::Context, ::std::string::String>,
            proofs: ::std::result::Result<
                ::std::vec::Vec<super::MerkleProof>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetMerkleProofsResponseResult {
            fn default() -> Self {
                Self {
                    context: Err("no value supplied for context".to_string()),
                    proofs: Err("no value supplied for proofs".to_string()),
                }
            }
        }
        impl PostGetMerkleProofsResponseResult {
            pub fn context<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::Context>,
                T::Error: ::std::fmt::Display,
            {
                self.context = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for context: {e}")
                    });
                self
            }
            pub fn proofs<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::vec::Vec<super::MerkleProof>>,
                T::Error: ::std::fmt::Display,
            {
                self.proofs = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for proofs: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetMerkleProofsResponseResult>
        for super::PostGetMerkleProofsResponseResult {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetMerkleProofsResponseResult,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    context: value.context?,
                    proofs: value.proofs?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetMerkleProofsResponseResult>
        for PostGetMerkleProofsResponseResult {
            fn from(value: super::PostGetMerkleProofsResponseResult) -> Self {
                Self {
                    context: Ok(value.context),
                    proofs: Ok(value.proofs),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetNonInclusionProofsBody {
            id: ::std::result::Result<
                super::PostGetNonInclusionProofsBodyId,
                ::std::string::String,
            >,
            jsonrpc: ::std::result::Result<
                super::PostGetNonInclusionProofsBodyJsonrpc,
                ::std::string::String,
            >,
            method: ::std::result::Result<
                super::PostGetNonInclusionProofsBodyMethod,
                ::std::string::String,
            >,
            params: ::std::result::Result<
                super::PostGetNonInclusionProofsBodyParams,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetNonInclusionProofsBody {
            fn default() -> Self {
                Self {
                    id: Err("no value supplied for id".to_string()),
                    jsonrpc: Err("no value supplied for jsonrpc".to_string()),
                    method: Err("no value supplied for method".to_string()),
                    params: Err("no value supplied for params".to_string()),
                }
            }
        }
        impl PostGetNonInclusionProofsBody {
            pub fn id<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetNonInclusionProofsBodyId>,
                T::Error: ::std::fmt::Display,
            {
                self.id = value
                    .try_into()
                    .map_err(|e| format!("error converting supplied value for id: {e}"));
                self
            }
            pub fn jsonrpc<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetNonInclusionProofsBodyJsonrpc>,
                T::Error: ::std::fmt::Display,
            {
                self.jsonrpc = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for jsonrpc: {e}")
                    });
                self
            }
            pub fn method<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetNonInclusionProofsBodyMethod>,
                T::Error: ::std::fmt::Display,
            {
                self.method = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for method: {e}")
                    });
                self
            }
            pub fn params<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetNonInclusionProofsBodyParams>,
                T::Error: ::std::fmt::Display,
            {
                self.params = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for params: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetNonInclusionProofsBody>
        for super::PostGetNonInclusionProofsBody {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetNonInclusionProofsBody,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    id: value.id?,
                    jsonrpc: value.jsonrpc?,
                    method: value.method?,
                    params: value.params?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetNonInclusionProofsBody>
        for PostGetNonInclusionProofsBody {
            fn from(value: super::PostGetNonInclusionProofsBody) -> Self {
                Self {
                    id: Ok(value.id),
                    jsonrpc: Ok(value.jsonrpc),
                    method: Ok(value.method),
                    params: Ok(value.params),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetNonInclusionProofsBodyParams {
            leaves: ::std::result::Result<
                ::std::vec::Vec<super::Hash>,
                ::std::string::String,
            >,
            tree_account: ::std::result::Result<
                super::SerializablePubkey,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetNonInclusionProofsBodyParams {
            fn default() -> Self {
                Self {
                    leaves: Err("no value supplied for leaves".to_string()),
                    tree_account: Err("no value supplied for tree_account".to_string()),
                }
            }
        }
        impl PostGetNonInclusionProofsBodyParams {
            pub fn leaves<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::vec::Vec<super::Hash>>,
                T::Error: ::std::fmt::Display,
            {
                self.leaves = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for leaves: {e}")
                    });
                self
            }
            pub fn tree_account<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::SerializablePubkey>,
                T::Error: ::std::fmt::Display,
            {
                self.tree_account = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for tree_account: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetNonInclusionProofsBodyParams>
        for super::PostGetNonInclusionProofsBodyParams {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetNonInclusionProofsBodyParams,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    leaves: value.leaves?,
                    tree_account: value.tree_account?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetNonInclusionProofsBodyParams>
        for PostGetNonInclusionProofsBodyParams {
            fn from(value: super::PostGetNonInclusionProofsBodyParams) -> Self {
                Self {
                    leaves: Ok(value.leaves),
                    tree_account: Ok(value.tree_account),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetNonInclusionProofsResponse {
            error: ::std::result::Result<
                ::std::option::Option<super::PostGetNonInclusionProofsResponseError>,
                ::std::string::String,
            >,
            id: ::std::result::Result<
                super::PostGetNonInclusionProofsResponseId,
                ::std::string::String,
            >,
            jsonrpc: ::std::result::Result<
                super::PostGetNonInclusionProofsResponseJsonrpc,
                ::std::string::String,
            >,
            result: ::std::result::Result<
                ::std::option::Option<super::PostGetNonInclusionProofsResponseResult>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetNonInclusionProofsResponse {
            fn default() -> Self {
                Self {
                    error: Ok(Default::default()),
                    id: Err("no value supplied for id".to_string()),
                    jsonrpc: Err("no value supplied for jsonrpc".to_string()),
                    result: Ok(Default::default()),
                }
            }
        }
        impl PostGetNonInclusionProofsResponse {
            pub fn error<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    ::std::option::Option<super::PostGetNonInclusionProofsResponseError>,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.error = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for error: {e}")
                    });
                self
            }
            pub fn id<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetNonInclusionProofsResponseId>,
                T::Error: ::std::fmt::Display,
            {
                self.id = value
                    .try_into()
                    .map_err(|e| format!("error converting supplied value for id: {e}"));
                self
            }
            pub fn jsonrpc<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    super::PostGetNonInclusionProofsResponseJsonrpc,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.jsonrpc = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for jsonrpc: {e}")
                    });
                self
            }
            pub fn result<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    ::std::option::Option<super::PostGetNonInclusionProofsResponseResult>,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.result = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for result: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetNonInclusionProofsResponse>
        for super::PostGetNonInclusionProofsResponse {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetNonInclusionProofsResponse,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    error: value.error?,
                    id: value.id?,
                    jsonrpc: value.jsonrpc?,
                    result: value.result?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetNonInclusionProofsResponse>
        for PostGetNonInclusionProofsResponse {
            fn from(value: super::PostGetNonInclusionProofsResponse) -> Self {
                Self {
                    error: Ok(value.error),
                    id: Ok(value.id),
                    jsonrpc: Ok(value.jsonrpc),
                    result: Ok(value.result),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetNonInclusionProofsResponseError {
            code: ::std::result::Result<
                ::std::option::Option<i64>,
                ::std::string::String,
            >,
            message: ::std::result::Result<
                ::std::option::Option<::std::string::String>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetNonInclusionProofsResponseError {
            fn default() -> Self {
                Self {
                    code: Ok(Default::default()),
                    message: Ok(Default::default()),
                }
            }
        }
        impl PostGetNonInclusionProofsResponseError {
            pub fn code<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<i64>>,
                T::Error: ::std::fmt::Display,
            {
                self.code = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for code: {e}")
                    });
                self
            }
            pub fn message<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<::std::string::String>>,
                T::Error: ::std::fmt::Display,
            {
                self.message = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for message: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetNonInclusionProofsResponseError>
        for super::PostGetNonInclusionProofsResponseError {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetNonInclusionProofsResponseError,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    code: value.code?,
                    message: value.message?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetNonInclusionProofsResponseError>
        for PostGetNonInclusionProofsResponseError {
            fn from(value: super::PostGetNonInclusionProofsResponseError) -> Self {
                Self {
                    code: Ok(value.code),
                    message: Ok(value.message),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetNonInclusionProofsResponseResult {
            context: ::std::result::Result<super::Context, ::std::string::String>,
            proofs: ::std::result::Result<
                ::std::vec::Vec<super::NonInclusionProof>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetNonInclusionProofsResponseResult {
            fn default() -> Self {
                Self {
                    context: Err("no value supplied for context".to_string()),
                    proofs: Err("no value supplied for proofs".to_string()),
                }
            }
        }
        impl PostGetNonInclusionProofsResponseResult {
            pub fn context<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::Context>,
                T::Error: ::std::fmt::Display,
            {
                self.context = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for context: {e}")
                    });
                self
            }
            pub fn proofs<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::vec::Vec<super::NonInclusionProof>>,
                T::Error: ::std::fmt::Display,
            {
                self.proofs = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for proofs: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetNonInclusionProofsResponseResult>
        for super::PostGetNonInclusionProofsResponseResult {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetNonInclusionProofsResponseResult,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    context: value.context?,
                    proofs: value.proofs?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetNonInclusionProofsResponseResult>
        for PostGetNonInclusionProofsResponseResult {
            fn from(value: super::PostGetNonInclusionProofsResponseResult) -> Self {
                Self {
                    context: Ok(value.context),
                    proofs: Ok(value.proofs),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetNullifierQueueElementsBody {
            id: ::std::result::Result<
                super::PostGetNullifierQueueElementsBodyId,
                ::std::string::String,
            >,
            jsonrpc: ::std::result::Result<
                super::PostGetNullifierQueueElementsBodyJsonrpc,
                ::std::string::String,
            >,
            method: ::std::result::Result<
                super::PostGetNullifierQueueElementsBodyMethod,
                ::std::string::String,
            >,
            params: ::std::result::Result<
                super::PostGetNullifierQueueElementsBodyParams,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetNullifierQueueElementsBody {
            fn default() -> Self {
                Self {
                    id: Err("no value supplied for id".to_string()),
                    jsonrpc: Err("no value supplied for jsonrpc".to_string()),
                    method: Err("no value supplied for method".to_string()),
                    params: Err("no value supplied for params".to_string()),
                }
            }
        }
        impl PostGetNullifierQueueElementsBody {
            pub fn id<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::PostGetNullifierQueueElementsBodyId>,
                T::Error: ::std::fmt::Display,
            {
                self.id = value
                    .try_into()
                    .map_err(|e| format!("error converting supplied value for id: {e}"));
                self
            }
            pub fn jsonrpc<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    super::PostGetNullifierQueueElementsBodyJsonrpc,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.jsonrpc = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for jsonrpc: {e}")
                    });
                self
            }
            pub fn method<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    super::PostGetNullifierQueueElementsBodyMethod,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.method = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for method: {e}")
                    });
                self
            }
            pub fn params<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    super::PostGetNullifierQueueElementsBodyParams,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.params = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for params: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetNullifierQueueElementsBody>
        for super::PostGetNullifierQueueElementsBody {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetNullifierQueueElementsBody,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    id: value.id?,
                    jsonrpc: value.jsonrpc?,
                    method: value.method?,
                    params: value.params?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetNullifierQueueElementsBody>
        for PostGetNullifierQueueElementsBody {
            fn from(value: super::PostGetNullifierQueueElementsBody) -> Self {
                Self {
                    id: Ok(value.id),
                    jsonrpc: Ok(value.jsonrpc),
                    method: Ok(value.method),
                    params: Ok(value.params),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetNullifierQueueElementsBodyParams {
            limit: ::std::result::Result<u64, ::std::string::String>,
            start_seq: ::std::result::Result<
                ::std::option::Option<u64>,
                ::std::string::String,
            >,
            tree_account: ::std::result::Result<
                super::SerializablePubkey,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetNullifierQueueElementsBodyParams {
            fn default() -> Self {
                Self {
                    limit: Err("no value supplied for limit".to_string()),
                    start_seq: Ok(Default::default()),
                    tree_account: Err("no value supplied for tree_account".to_string()),
                }
            }
        }
        impl PostGetNullifierQueueElementsBodyParams {
            pub fn limit<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<u64>,
                T::Error: ::std::fmt::Display,
            {
                self.limit = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for limit: {e}")
                    });
                self
            }
            pub fn start_seq<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<u64>>,
                T::Error: ::std::fmt::Display,
            {
                self.start_seq = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for start_seq: {e}")
                    });
                self
            }
            pub fn tree_account<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::SerializablePubkey>,
                T::Error: ::std::fmt::Display,
            {
                self.tree_account = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for tree_account: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetNullifierQueueElementsBodyParams>
        for super::PostGetNullifierQueueElementsBodyParams {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetNullifierQueueElementsBodyParams,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    limit: value.limit?,
                    start_seq: value.start_seq?,
                    tree_account: value.tree_account?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetNullifierQueueElementsBodyParams>
        for PostGetNullifierQueueElementsBodyParams {
            fn from(value: super::PostGetNullifierQueueElementsBodyParams) -> Self {
                Self {
                    limit: Ok(value.limit),
                    start_seq: Ok(value.start_seq),
                    tree_account: Ok(value.tree_account),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetNullifierQueueElementsResponse {
            error: ::std::result::Result<
                ::std::option::Option<super::PostGetNullifierQueueElementsResponseError>,
                ::std::string::String,
            >,
            id: ::std::result::Result<
                super::PostGetNullifierQueueElementsResponseId,
                ::std::string::String,
            >,
            jsonrpc: ::std::result::Result<
                super::PostGetNullifierQueueElementsResponseJsonrpc,
                ::std::string::String,
            >,
            result: ::std::result::Result<
                ::std::option::Option<
                    super::PostGetNullifierQueueElementsResponseResult,
                >,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetNullifierQueueElementsResponse {
            fn default() -> Self {
                Self {
                    error: Ok(Default::default()),
                    id: Err("no value supplied for id".to_string()),
                    jsonrpc: Err("no value supplied for jsonrpc".to_string()),
                    result: Ok(Default::default()),
                }
            }
        }
        impl PostGetNullifierQueueElementsResponse {
            pub fn error<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    ::std::option::Option<
                        super::PostGetNullifierQueueElementsResponseError,
                    >,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.error = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for error: {e}")
                    });
                self
            }
            pub fn id<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    super::PostGetNullifierQueueElementsResponseId,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.id = value
                    .try_into()
                    .map_err(|e| format!("error converting supplied value for id: {e}"));
                self
            }
            pub fn jsonrpc<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    super::PostGetNullifierQueueElementsResponseJsonrpc,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.jsonrpc = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for jsonrpc: {e}")
                    });
                self
            }
            pub fn result<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    ::std::option::Option<
                        super::PostGetNullifierQueueElementsResponseResult,
                    >,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.result = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for result: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetNullifierQueueElementsResponse>
        for super::PostGetNullifierQueueElementsResponse {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetNullifierQueueElementsResponse,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    error: value.error?,
                    id: value.id?,
                    jsonrpc: value.jsonrpc?,
                    result: value.result?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetNullifierQueueElementsResponse>
        for PostGetNullifierQueueElementsResponse {
            fn from(value: super::PostGetNullifierQueueElementsResponse) -> Self {
                Self {
                    error: Ok(value.error),
                    id: Ok(value.id),
                    jsonrpc: Ok(value.jsonrpc),
                    result: Ok(value.result),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetNullifierQueueElementsResponseError {
            code: ::std::result::Result<
                ::std::option::Option<i64>,
                ::std::string::String,
            >,
            message: ::std::result::Result<
                ::std::option::Option<::std::string::String>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetNullifierQueueElementsResponseError {
            fn default() -> Self {
                Self {
                    code: Ok(Default::default()),
                    message: Ok(Default::default()),
                }
            }
        }
        impl PostGetNullifierQueueElementsResponseError {
            pub fn code<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<i64>>,
                T::Error: ::std::fmt::Display,
            {
                self.code = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for code: {e}")
                    });
                self
            }
            pub fn message<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<::std::string::String>>,
                T::Error: ::std::fmt::Display,
            {
                self.message = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for message: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetNullifierQueueElementsResponseError>
        for super::PostGetNullifierQueueElementsResponseError {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetNullifierQueueElementsResponseError,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    code: value.code?,
                    message: value.message?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetNullifierQueueElementsResponseError>
        for PostGetNullifierQueueElementsResponseError {
            fn from(value: super::PostGetNullifierQueueElementsResponseError) -> Self {
                Self {
                    code: Ok(value.code),
                    message: Ok(value.message),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetNullifierQueueElementsResponseResult {
            context: ::std::result::Result<super::Context, ::std::string::String>,
            elements: ::std::result::Result<
                ::std::vec::Vec<super::NullifierQueueElement>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetNullifierQueueElementsResponseResult {
            fn default() -> Self {
                Self {
                    context: Err("no value supplied for context".to_string()),
                    elements: Err("no value supplied for elements".to_string()),
                }
            }
        }
        impl PostGetNullifierQueueElementsResponseResult {
            pub fn context<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::Context>,
                T::Error: ::std::fmt::Display,
            {
                self.context = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for context: {e}")
                    });
                self
            }
            pub fn elements<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    ::std::vec::Vec<super::NullifierQueueElement>,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.elements = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for elements: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetNullifierQueueElementsResponseResult>
        for super::PostGetNullifierQueueElementsResponseResult {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetNullifierQueueElementsResponseResult,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    context: value.context?,
                    elements: value.elements?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetNullifierQueueElementsResponseResult>
        for PostGetNullifierQueueElementsResponseResult {
            fn from(value: super::PostGetNullifierQueueElementsResponseResult) -> Self {
                Self {
                    context: Ok(value.context),
                    elements: Ok(value.elements),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetShieldedTransactionsByTagsBody {
            id: ::std::result::Result<
                super::PostGetShieldedTransactionsByTagsBodyId,
                ::std::string::String,
            >,
            jsonrpc: ::std::result::Result<
                super::PostGetShieldedTransactionsByTagsBodyJsonrpc,
                ::std::string::String,
            >,
            method: ::std::result::Result<
                super::PostGetShieldedTransactionsByTagsBodyMethod,
                ::std::string::String,
            >,
            params: ::std::result::Result<
                super::PostGetShieldedTransactionsByTagsBodyParams,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetShieldedTransactionsByTagsBody {
            fn default() -> Self {
                Self {
                    id: Err("no value supplied for id".to_string()),
                    jsonrpc: Err("no value supplied for jsonrpc".to_string()),
                    method: Err("no value supplied for method".to_string()),
                    params: Err("no value supplied for params".to_string()),
                }
            }
        }
        impl PostGetShieldedTransactionsByTagsBody {
            pub fn id<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    super::PostGetShieldedTransactionsByTagsBodyId,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.id = value
                    .try_into()
                    .map_err(|e| format!("error converting supplied value for id: {e}"));
                self
            }
            pub fn jsonrpc<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    super::PostGetShieldedTransactionsByTagsBodyJsonrpc,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.jsonrpc = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for jsonrpc: {e}")
                    });
                self
            }
            pub fn method<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    super::PostGetShieldedTransactionsByTagsBodyMethod,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.method = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for method: {e}")
                    });
                self
            }
            pub fn params<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    super::PostGetShieldedTransactionsByTagsBodyParams,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.params = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for params: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetShieldedTransactionsByTagsBody>
        for super::PostGetShieldedTransactionsByTagsBody {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetShieldedTransactionsByTagsBody,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    id: value.id?,
                    jsonrpc: value.jsonrpc?,
                    method: value.method?,
                    params: value.params?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetShieldedTransactionsByTagsBody>
        for PostGetShieldedTransactionsByTagsBody {
            fn from(value: super::PostGetShieldedTransactionsByTagsBody) -> Self {
                Self {
                    id: Ok(value.id),
                    jsonrpc: Ok(value.jsonrpc),
                    method: Ok(value.method),
                    params: Ok(value.params),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetShieldedTransactionsByTagsBodyParams {
            cursor: ::std::result::Result<
                ::std::option::Option<super::Base64String>,
                ::std::string::String,
            >,
            limit: ::std::result::Result<
                ::std::option::Option<super::Limit>,
                ::std::string::String,
            >,
            tags: ::std::result::Result<
                ::std::vec::Vec<super::Hash>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetShieldedTransactionsByTagsBodyParams {
            fn default() -> Self {
                Self {
                    cursor: Ok(Default::default()),
                    limit: Ok(Default::default()),
                    tags: Err("no value supplied for tags".to_string()),
                }
            }
        }
        impl PostGetShieldedTransactionsByTagsBodyParams {
            pub fn cursor<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<super::Base64String>>,
                T::Error: ::std::fmt::Display,
            {
                self.cursor = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for cursor: {e}")
                    });
                self
            }
            pub fn limit<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<super::Limit>>,
                T::Error: ::std::fmt::Display,
            {
                self.limit = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for limit: {e}")
                    });
                self
            }
            pub fn tags<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::vec::Vec<super::Hash>>,
                T::Error: ::std::fmt::Display,
            {
                self.tags = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for tags: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetShieldedTransactionsByTagsBodyParams>
        for super::PostGetShieldedTransactionsByTagsBodyParams {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetShieldedTransactionsByTagsBodyParams,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    cursor: value.cursor?,
                    limit: value.limit?,
                    tags: value.tags?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetShieldedTransactionsByTagsBodyParams>
        for PostGetShieldedTransactionsByTagsBodyParams {
            fn from(value: super::PostGetShieldedTransactionsByTagsBodyParams) -> Self {
                Self {
                    cursor: Ok(value.cursor),
                    limit: Ok(value.limit),
                    tags: Ok(value.tags),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetShieldedTransactionsByTagsResponse {
            error: ::std::result::Result<
                ::std::option::Option<
                    super::PostGetShieldedTransactionsByTagsResponseError,
                >,
                ::std::string::String,
            >,
            id: ::std::result::Result<
                super::PostGetShieldedTransactionsByTagsResponseId,
                ::std::string::String,
            >,
            jsonrpc: ::std::result::Result<
                super::PostGetShieldedTransactionsByTagsResponseJsonrpc,
                ::std::string::String,
            >,
            result: ::std::result::Result<
                ::std::option::Option<
                    super::PostGetShieldedTransactionsByTagsResponseResult,
                >,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetShieldedTransactionsByTagsResponse {
            fn default() -> Self {
                Self {
                    error: Ok(Default::default()),
                    id: Err("no value supplied for id".to_string()),
                    jsonrpc: Err("no value supplied for jsonrpc".to_string()),
                    result: Ok(Default::default()),
                }
            }
        }
        impl PostGetShieldedTransactionsByTagsResponse {
            pub fn error<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    ::std::option::Option<
                        super::PostGetShieldedTransactionsByTagsResponseError,
                    >,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.error = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for error: {e}")
                    });
                self
            }
            pub fn id<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    super::PostGetShieldedTransactionsByTagsResponseId,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.id = value
                    .try_into()
                    .map_err(|e| format!("error converting supplied value for id: {e}"));
                self
            }
            pub fn jsonrpc<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    super::PostGetShieldedTransactionsByTagsResponseJsonrpc,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.jsonrpc = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for jsonrpc: {e}")
                    });
                self
            }
            pub fn result<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<
                    ::std::option::Option<
                        super::PostGetShieldedTransactionsByTagsResponseResult,
                    >,
                >,
                T::Error: ::std::fmt::Display,
            {
                self.result = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for result: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetShieldedTransactionsByTagsResponse>
        for super::PostGetShieldedTransactionsByTagsResponse {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetShieldedTransactionsByTagsResponse,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    error: value.error?,
                    id: value.id?,
                    jsonrpc: value.jsonrpc?,
                    result: value.result?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetShieldedTransactionsByTagsResponse>
        for PostGetShieldedTransactionsByTagsResponse {
            fn from(value: super::PostGetShieldedTransactionsByTagsResponse) -> Self {
                Self {
                    error: Ok(value.error),
                    id: Ok(value.id),
                    jsonrpc: Ok(value.jsonrpc),
                    result: Ok(value.result),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetShieldedTransactionsByTagsResponseError {
            code: ::std::result::Result<
                ::std::option::Option<i64>,
                ::std::string::String,
            >,
            message: ::std::result::Result<
                ::std::option::Option<::std::string::String>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for PostGetShieldedTransactionsByTagsResponseError {
            fn default() -> Self {
                Self {
                    code: Ok(Default::default()),
                    message: Ok(Default::default()),
                }
            }
        }
        impl PostGetShieldedTransactionsByTagsResponseError {
            pub fn code<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<i64>>,
                T::Error: ::std::fmt::Display,
            {
                self.code = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for code: {e}")
                    });
                self
            }
            pub fn message<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<::std::string::String>>,
                T::Error: ::std::fmt::Display,
            {
                self.message = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for message: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetShieldedTransactionsByTagsResponseError>
        for super::PostGetShieldedTransactionsByTagsResponseError {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetShieldedTransactionsByTagsResponseError,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    code: value.code?,
                    message: value.message?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetShieldedTransactionsByTagsResponseError>
        for PostGetShieldedTransactionsByTagsResponseError {
            fn from(
                value: super::PostGetShieldedTransactionsByTagsResponseError,
            ) -> Self {
                Self {
                    code: Ok(value.code),
                    message: Ok(value.message),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct PostGetShieldedTransactionsByTagsResponseResult {
            context: ::std::result::Result<super::Context, ::std::string::String>,
            next_cursor: ::std::result::Result<
                ::std::option::Option<super::Base64String>,
                ::std::string::String,
            >,
            transactions: ::std::result::Result<
                ::std::vec::Vec<super::ShieldedTransaction>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default
        for PostGetShieldedTransactionsByTagsResponseResult {
            fn default() -> Self {
                Self {
                    context: Err("no value supplied for context".to_string()),
                    next_cursor: Ok(Default::default()),
                    transactions: Err("no value supplied for transactions".to_string()),
                }
            }
        }
        impl PostGetShieldedTransactionsByTagsResponseResult {
            pub fn context<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::Context>,
                T::Error: ::std::fmt::Display,
            {
                self.context = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for context: {e}")
                    });
                self
            }
            pub fn next_cursor<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<super::Base64String>>,
                T::Error: ::std::fmt::Display,
            {
                self.next_cursor = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for next_cursor: {e}")
                    });
                self
            }
            pub fn transactions<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::vec::Vec<super::ShieldedTransaction>>,
                T::Error: ::std::fmt::Display,
            {
                self.transactions = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for transactions: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<PostGetShieldedTransactionsByTagsResponseResult>
        for super::PostGetShieldedTransactionsByTagsResponseResult {
            type Error = super::error::ConversionError;
            fn try_from(
                value: PostGetShieldedTransactionsByTagsResponseResult,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    context: value.context?,
                    next_cursor: value.next_cursor?,
                    transactions: value.transactions?,
                })
            }
        }
        impl ::std::convert::From<super::PostGetShieldedTransactionsByTagsResponseResult>
        for PostGetShieldedTransactionsByTagsResponseResult {
            fn from(
                value: super::PostGetShieldedTransactionsByTagsResponseResult,
            ) -> Self {
                Self {
                    context: Ok(value.context),
                    next_cursor: Ok(value.next_cursor),
                    transactions: Ok(value.transactions),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct RingsOutputContext {
            hash: ::std::result::Result<super::Hash, ::std::string::String>,
            leaf_index: ::std::result::Result<u64, ::std::string::String>,
            tree: ::std::result::Result<
                super::SerializablePubkey,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for RingsOutputContext {
            fn default() -> Self {
                Self {
                    hash: Err("no value supplied for hash".to_string()),
                    leaf_index: Err("no value supplied for leaf_index".to_string()),
                    tree: Err("no value supplied for tree".to_string()),
                }
            }
        }
        impl RingsOutputContext {
            pub fn hash<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::Hash>,
                T::Error: ::std::fmt::Display,
            {
                self.hash = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for hash: {e}")
                    });
                self
            }
            pub fn leaf_index<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<u64>,
                T::Error: ::std::fmt::Display,
            {
                self.leaf_index = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for leaf_index: {e}")
                    });
                self
            }
            pub fn tree<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::SerializablePubkey>,
                T::Error: ::std::fmt::Display,
            {
                self.tree = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for tree: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<RingsOutputContext> for super::RingsOutputContext {
            type Error = super::error::ConversionError;
            fn try_from(
                value: RingsOutputContext,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    hash: value.hash?,
                    leaf_index: value.leaf_index?,
                    tree: value.tree?,
                })
            }
        }
        impl ::std::convert::From<super::RingsOutputContext> for RingsOutputContext {
            fn from(value: super::RingsOutputContext) -> Self {
                Self {
                    hash: Ok(value.hash),
                    leaf_index: Ok(value.leaf_index),
                    tree: Ok(value.tree),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct RingsOutputSlot {
            output_context: ::std::result::Result<
                super::RingsOutputContext,
                ::std::string::String,
            >,
            payload: ::std::result::Result<super::Base64String, ::std::string::String>,
            view_tag: ::std::result::Result<super::Hash, ::std::string::String>,
        }
        impl ::std::default::Default for RingsOutputSlot {
            fn default() -> Self {
                Self {
                    output_context: Err(
                        "no value supplied for output_context".to_string(),
                    ),
                    payload: Err("no value supplied for payload".to_string()),
                    view_tag: Err("no value supplied for view_tag".to_string()),
                }
            }
        }
        impl RingsOutputSlot {
            pub fn output_context<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::RingsOutputContext>,
                T::Error: ::std::fmt::Display,
            {
                self.output_context = value
                    .try_into()
                    .map_err(|e| {
                        format!(
                            "error converting supplied value for output_context: {e}"
                        )
                    });
                self
            }
            pub fn payload<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::Base64String>,
                T::Error: ::std::fmt::Display,
            {
                self.payload = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for payload: {e}")
                    });
                self
            }
            pub fn view_tag<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::Hash>,
                T::Error: ::std::fmt::Display,
            {
                self.view_tag = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for view_tag: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<RingsOutputSlot> for super::RingsOutputSlot {
            type Error = super::error::ConversionError;
            fn try_from(
                value: RingsOutputSlot,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    output_context: value.output_context?,
                    payload: value.payload?,
                    view_tag: value.view_tag?,
                })
            }
        }
        impl ::std::convert::From<super::RingsOutputSlot> for RingsOutputSlot {
            fn from(value: super::RingsOutputSlot) -> Self {
                Self {
                    output_context: Ok(value.output_context),
                    payload: Ok(value.payload),
                    view_tag: Ok(value.view_tag),
                }
            }
        }
        #[derive(Clone, Debug)]
        pub struct ShieldedTransaction {
            nullifiers: ::std::result::Result<
                ::std::vec::Vec<super::Hash>,
                ::std::string::String,
            >,
            output_slots: ::std::result::Result<
                ::std::vec::Vec<super::RingsOutputSlot>,
                ::std::string::String,
            >,
            proofless: ::std::result::Result<bool, ::std::string::String>,
            salt: ::std::result::Result<
                ::std::option::Option<super::Base64String>,
                ::std::string::String,
            >,
            slot: ::std::result::Result<u64, ::std::string::String>,
            tx_signature: ::std::result::Result<
                super::SerializableSignature,
                ::std::string::String,
            >,
            tx_viewing_pk: ::std::result::Result<
                ::std::option::Option<super::Base64String>,
                ::std::string::String,
            >,
        }
        impl ::std::default::Default for ShieldedTransaction {
            fn default() -> Self {
                Self {
                    nullifiers: Err("no value supplied for nullifiers".to_string()),
                    output_slots: Err("no value supplied for output_slots".to_string()),
                    proofless: Err("no value supplied for proofless".to_string()),
                    salt: Ok(Default::default()),
                    slot: Err("no value supplied for slot".to_string()),
                    tx_signature: Err("no value supplied for tx_signature".to_string()),
                    tx_viewing_pk: Ok(Default::default()),
                }
            }
        }
        impl ShieldedTransaction {
            pub fn nullifiers<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::vec::Vec<super::Hash>>,
                T::Error: ::std::fmt::Display,
            {
                self.nullifiers = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for nullifiers: {e}")
                    });
                self
            }
            pub fn output_slots<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::vec::Vec<super::RingsOutputSlot>>,
                T::Error: ::std::fmt::Display,
            {
                self.output_slots = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for output_slots: {e}")
                    });
                self
            }
            pub fn proofless<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<bool>,
                T::Error: ::std::fmt::Display,
            {
                self.proofless = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for proofless: {e}")
                    });
                self
            }
            pub fn salt<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<super::Base64String>>,
                T::Error: ::std::fmt::Display,
            {
                self.salt = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for salt: {e}")
                    });
                self
            }
            pub fn slot<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<u64>,
                T::Error: ::std::fmt::Display,
            {
                self.slot = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for slot: {e}")
                    });
                self
            }
            pub fn tx_signature<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<super::SerializableSignature>,
                T::Error: ::std::fmt::Display,
            {
                self.tx_signature = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for tx_signature: {e}")
                    });
                self
            }
            pub fn tx_viewing_pk<T>(mut self, value: T) -> Self
            where
                T: ::std::convert::TryInto<::std::option::Option<super::Base64String>>,
                T::Error: ::std::fmt::Display,
            {
                self.tx_viewing_pk = value
                    .try_into()
                    .map_err(|e| {
                        format!("error converting supplied value for tx_viewing_pk: {e}")
                    });
                self
            }
        }
        impl ::std::convert::TryFrom<ShieldedTransaction>
        for super::ShieldedTransaction {
            type Error = super::error::ConversionError;
            fn try_from(
                value: ShieldedTransaction,
            ) -> ::std::result::Result<Self, super::error::ConversionError> {
                Ok(Self {
                    nullifiers: value.nullifiers?,
                    output_slots: value.output_slots?,
                    proofless: value.proofless?,
                    salt: value.salt?,
                    slot: value.slot?,
                    tx_signature: value.tx_signature?,
                    tx_viewing_pk: value.tx_viewing_pk?,
                })
            }
        }
        impl ::std::convert::From<super::ShieldedTransaction> for ShieldedTransaction {
            fn from(value: super::ShieldedTransaction) -> Self {
                Self {
                    nullifiers: Ok(value.nullifiers),
                    output_slots: Ok(value.output_slots),
                    proofless: Ok(value.proofless),
                    salt: Ok(value.salt),
                    slot: Ok(value.slot),
                    tx_signature: Ok(value.tx_signature),
                    tx_viewing_pk: Ok(value.tx_viewing_pk),
                }
            }
        }
    }
}
#[derive(Clone, Debug)]
/**Client for zolana-indexer-api

Zolana indexer API

Version: 0.51.2*/
pub struct Client {
    pub(crate) baseurl: String,
    pub(crate) client: reqwest::Client,
}
impl Client {
    /// Create a new client.
    ///
    /// `baseurl` is the base URL provided to the internal
    /// `reqwest::Client`, and should include a scheme and hostname,
    /// as well as port and a path stem if applicable.
    pub fn new(baseurl: &str) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let client = {
            let dur = ::std::time::Duration::from_secs(15u64);
            reqwest::ClientBuilder::new().connect_timeout(dur).timeout(dur)
        };
        #[cfg(target_arch = "wasm32")]
        let client = reqwest::ClientBuilder::new();
        Self::new_with_client(baseurl, client.build().unwrap())
    }
    /// Construct a new client with an existing `reqwest::Client`,
    /// allowing more control over its configuration.
    ///
    /// `baseurl` is the base URL provided to the internal
    /// `reqwest::Client`, and should include a scheme and hostname,
    /// as well as port and a path stem if applicable.
    pub fn new_with_client(baseurl: &str, client: reqwest::Client) -> Self {
        Self {
            baseurl: baseurl.to_string(),
            client,
        }
    }
}
impl ClientInfo<()> for Client {
    fn api_version() -> &'static str {
        "0.51.2"
    }
    fn baseurl(&self) -> &str {
        self.baseurl.as_str()
    }
    fn client(&self) -> &reqwest::Client {
        &self.client
    }
    fn inner(&self) -> &() {
        &()
    }
}
impl ClientHooks<()> for &Client {}
impl Client {
    /**Sends a `POST` request to `/get_encrypted_utxos_by_tags`

```ignore
let response = client.post_get_encrypted_utxos_by_tags()
    .body(body)
    .send()
    .await;
```*/
    pub fn post_get_encrypted_utxos_by_tags(
        &self,
    ) -> builder::PostGetEncryptedUtxosByTags<'_> {
        builder::PostGetEncryptedUtxosByTags::new(self)
    }
    /**Sends a `POST` request to `/get_merkle_proofs`

```ignore
let response = client.post_get_merkle_proofs()
    .body(body)
    .send()
    .await;
```*/
    pub fn post_get_merkle_proofs(&self) -> builder::PostGetMerkleProofs<'_> {
        builder::PostGetMerkleProofs::new(self)
    }
    /**Sends a `POST` request to `/get_non_inclusion_proofs`

```ignore
let response = client.post_get_non_inclusion_proofs()
    .body(body)
    .send()
    .await;
```*/
    pub fn post_get_non_inclusion_proofs(
        &self,
    ) -> builder::PostGetNonInclusionProofs<'_> {
        builder::PostGetNonInclusionProofs::new(self)
    }
    /**Sends a `POST` request to `/get_nullifier_queue_elements`

```ignore
let response = client.post_get_nullifier_queue_elements()
    .body(body)
    .send()
    .await;
```*/
    pub fn post_get_nullifier_queue_elements(
        &self,
    ) -> builder::PostGetNullifierQueueElements<'_> {
        builder::PostGetNullifierQueueElements::new(self)
    }
    /**Sends a `POST` request to `/get_shielded_transactions_by_tags`

```ignore
let response = client.post_get_shielded_transactions_by_tags()
    .body(body)
    .send()
    .await;
```*/
    pub fn post_get_shielded_transactions_by_tags(
        &self,
    ) -> builder::PostGetShieldedTransactionsByTags<'_> {
        builder::PostGetShieldedTransactionsByTags::new(self)
    }
}
/// Types for composing operation parameters.
#[allow(clippy::all)]
pub mod builder {
    use super::types;
    #[allow(unused_imports)]
    use super::{
        encode_path, ByteStream, ClientInfo, ClientHooks, Error, OperationInfo,
        RequestBuilderExt, ResponseValue,
    };
    /**Builder for [`Client::post_get_encrypted_utxos_by_tags`]

[`Client::post_get_encrypted_utxos_by_tags`]: super::Client::post_get_encrypted_utxos_by_tags*/
    #[derive(Debug, Clone)]
    pub struct PostGetEncryptedUtxosByTags<'a> {
        client: &'a super::Client,
        body: Result<types::builder::PostGetEncryptedUtxosByTagsBody, String>,
    }
    impl<'a> PostGetEncryptedUtxosByTags<'a> {
        pub fn new(client: &'a super::Client) -> Self {
            Self {
                client: client,
                body: Ok(::std::default::Default::default()),
            }
        }
        pub fn body<V>(mut self, value: V) -> Self
        where
            V: std::convert::TryInto<types::PostGetEncryptedUtxosByTagsBody>,
            <V as std::convert::TryInto<
                types::PostGetEncryptedUtxosByTagsBody,
            >>::Error: std::fmt::Display,
        {
            self.body = value
                .try_into()
                .map(From::from)
                .map_err(|s| {
                    format!(
                        "conversion to `PostGetEncryptedUtxosByTagsBody` for body failed: {}",
                        s
                    )
                });
            self
        }
        pub fn body_map<F>(mut self, f: F) -> Self
        where
            F: std::ops::FnOnce(
                types::builder::PostGetEncryptedUtxosByTagsBody,
            ) -> types::builder::PostGetEncryptedUtxosByTagsBody,
        {
            self.body = self.body.map(f);
            self
        }
        ///Sends a `POST` request to `/get_encrypted_utxos_by_tags`
        pub async fn send(
            self,
        ) -> Result<
            ResponseValue<types::PostGetEncryptedUtxosByTagsResponse>,
            Error<types::PostGetEncryptedUtxosByTagsResponse>,
        > {
            let Self { client, body } = self;
            let body = body
                .and_then(|v| {
                    types::PostGetEncryptedUtxosByTagsBody::try_from(v)
                        .map_err(|e| e.to_string())
                })
                .map_err(Error::InvalidRequest)?;
            let url = format!("{}/get_encrypted_utxos_by_tags", client.baseurl,);
            let mut header_map = ::reqwest::header::HeaderMap::with_capacity(1usize);
            header_map
                .append(
                    ::reqwest::header::HeaderName::from_static("api-version"),
                    ::reqwest::header::HeaderValue::from_static(
                        super::Client::api_version(),
                    ),
                );
            #[allow(unused_mut)]
            let mut request = client
                .client
                .post(url)
                .header(
                    ::reqwest::header::ACCEPT,
                    ::reqwest::header::HeaderValue::from_static("application/json"),
                )
                .json(&body)
                .headers(header_map)
                .build()?;
            let info = OperationInfo {
                operation_id: "post_get_encrypted_utxos_by_tags",
            };
            client.pre(&mut request, &info).await?;
            let result = client.exec(request, &info).await;
            client.post(&result, &info).await?;
            let response = result?;
            match response.status().as_u16() {
                200u16 => ResponseValue::from_response(response).await,
                429u16 => {
                    Err(
                        Error::ErrorResponse(
                            ResponseValue::from_response(response).await?,
                        ),
                    )
                }
                500u16 => {
                    Err(
                        Error::ErrorResponse(
                            ResponseValue::from_response(response).await?,
                        ),
                    )
                }
                _ => Err(Error::UnexpectedResponse(response)),
            }
        }
    }
    /**Builder for [`Client::post_get_merkle_proofs`]

[`Client::post_get_merkle_proofs`]: super::Client::post_get_merkle_proofs*/
    #[derive(Debug, Clone)]
    pub struct PostGetMerkleProofs<'a> {
        client: &'a super::Client,
        body: Result<types::builder::PostGetMerkleProofsBody, String>,
    }
    impl<'a> PostGetMerkleProofs<'a> {
        pub fn new(client: &'a super::Client) -> Self {
            Self {
                client: client,
                body: Ok(::std::default::Default::default()),
            }
        }
        pub fn body<V>(mut self, value: V) -> Self
        where
            V: std::convert::TryInto<types::PostGetMerkleProofsBody>,
            <V as std::convert::TryInto<
                types::PostGetMerkleProofsBody,
            >>::Error: std::fmt::Display,
        {
            self.body = value
                .try_into()
                .map(From::from)
                .map_err(|s| {
                    format!(
                        "conversion to `PostGetMerkleProofsBody` for body failed: {}", s
                    )
                });
            self
        }
        pub fn body_map<F>(mut self, f: F) -> Self
        where
            F: std::ops::FnOnce(
                types::builder::PostGetMerkleProofsBody,
            ) -> types::builder::PostGetMerkleProofsBody,
        {
            self.body = self.body.map(f);
            self
        }
        ///Sends a `POST` request to `/get_merkle_proofs`
        pub async fn send(
            self,
        ) -> Result<
            ResponseValue<types::PostGetMerkleProofsResponse>,
            Error<types::PostGetMerkleProofsResponse>,
        > {
            let Self { client, body } = self;
            let body = body
                .and_then(|v| {
                    types::PostGetMerkleProofsBody::try_from(v)
                        .map_err(|e| e.to_string())
                })
                .map_err(Error::InvalidRequest)?;
            let url = format!("{}/get_merkle_proofs", client.baseurl,);
            let mut header_map = ::reqwest::header::HeaderMap::with_capacity(1usize);
            header_map
                .append(
                    ::reqwest::header::HeaderName::from_static("api-version"),
                    ::reqwest::header::HeaderValue::from_static(
                        super::Client::api_version(),
                    ),
                );
            #[allow(unused_mut)]
            let mut request = client
                .client
                .post(url)
                .header(
                    ::reqwest::header::ACCEPT,
                    ::reqwest::header::HeaderValue::from_static("application/json"),
                )
                .json(&body)
                .headers(header_map)
                .build()?;
            let info = OperationInfo {
                operation_id: "post_get_merkle_proofs",
            };
            client.pre(&mut request, &info).await?;
            let result = client.exec(request, &info).await;
            client.post(&result, &info).await?;
            let response = result?;
            match response.status().as_u16() {
                200u16 => ResponseValue::from_response(response).await,
                429u16 => {
                    Err(
                        Error::ErrorResponse(
                            ResponseValue::from_response(response).await?,
                        ),
                    )
                }
                500u16 => {
                    Err(
                        Error::ErrorResponse(
                            ResponseValue::from_response(response).await?,
                        ),
                    )
                }
                _ => Err(Error::UnexpectedResponse(response)),
            }
        }
    }
    /**Builder for [`Client::post_get_non_inclusion_proofs`]

[`Client::post_get_non_inclusion_proofs`]: super::Client::post_get_non_inclusion_proofs*/
    #[derive(Debug, Clone)]
    pub struct PostGetNonInclusionProofs<'a> {
        client: &'a super::Client,
        body: Result<types::builder::PostGetNonInclusionProofsBody, String>,
    }
    impl<'a> PostGetNonInclusionProofs<'a> {
        pub fn new(client: &'a super::Client) -> Self {
            Self {
                client: client,
                body: Ok(::std::default::Default::default()),
            }
        }
        pub fn body<V>(mut self, value: V) -> Self
        where
            V: std::convert::TryInto<types::PostGetNonInclusionProofsBody>,
            <V as std::convert::TryInto<
                types::PostGetNonInclusionProofsBody,
            >>::Error: std::fmt::Display,
        {
            self.body = value
                .try_into()
                .map(From::from)
                .map_err(|s| {
                    format!(
                        "conversion to `PostGetNonInclusionProofsBody` for body failed: {}",
                        s
                    )
                });
            self
        }
        pub fn body_map<F>(mut self, f: F) -> Self
        where
            F: std::ops::FnOnce(
                types::builder::PostGetNonInclusionProofsBody,
            ) -> types::builder::PostGetNonInclusionProofsBody,
        {
            self.body = self.body.map(f);
            self
        }
        ///Sends a `POST` request to `/get_non_inclusion_proofs`
        pub async fn send(
            self,
        ) -> Result<
            ResponseValue<types::PostGetNonInclusionProofsResponse>,
            Error<types::PostGetNonInclusionProofsResponse>,
        > {
            let Self { client, body } = self;
            let body = body
                .and_then(|v| {
                    types::PostGetNonInclusionProofsBody::try_from(v)
                        .map_err(|e| e.to_string())
                })
                .map_err(Error::InvalidRequest)?;
            let url = format!("{}/get_non_inclusion_proofs", client.baseurl,);
            let mut header_map = ::reqwest::header::HeaderMap::with_capacity(1usize);
            header_map
                .append(
                    ::reqwest::header::HeaderName::from_static("api-version"),
                    ::reqwest::header::HeaderValue::from_static(
                        super::Client::api_version(),
                    ),
                );
            #[allow(unused_mut)]
            let mut request = client
                .client
                .post(url)
                .header(
                    ::reqwest::header::ACCEPT,
                    ::reqwest::header::HeaderValue::from_static("application/json"),
                )
                .json(&body)
                .headers(header_map)
                .build()?;
            let info = OperationInfo {
                operation_id: "post_get_non_inclusion_proofs",
            };
            client.pre(&mut request, &info).await?;
            let result = client.exec(request, &info).await;
            client.post(&result, &info).await?;
            let response = result?;
            match response.status().as_u16() {
                200u16 => ResponseValue::from_response(response).await,
                429u16 => {
                    Err(
                        Error::ErrorResponse(
                            ResponseValue::from_response(response).await?,
                        ),
                    )
                }
                500u16 => {
                    Err(
                        Error::ErrorResponse(
                            ResponseValue::from_response(response).await?,
                        ),
                    )
                }
                _ => Err(Error::UnexpectedResponse(response)),
            }
        }
    }
    /**Builder for [`Client::post_get_nullifier_queue_elements`]

[`Client::post_get_nullifier_queue_elements`]: super::Client::post_get_nullifier_queue_elements*/
    #[derive(Debug, Clone)]
    pub struct PostGetNullifierQueueElements<'a> {
        client: &'a super::Client,
        body: Result<types::builder::PostGetNullifierQueueElementsBody, String>,
    }
    impl<'a> PostGetNullifierQueueElements<'a> {
        pub fn new(client: &'a super::Client) -> Self {
            Self {
                client: client,
                body: Ok(::std::default::Default::default()),
            }
        }
        pub fn body<V>(mut self, value: V) -> Self
        where
            V: std::convert::TryInto<types::PostGetNullifierQueueElementsBody>,
            <V as std::convert::TryInto<
                types::PostGetNullifierQueueElementsBody,
            >>::Error: std::fmt::Display,
        {
            self.body = value
                .try_into()
                .map(From::from)
                .map_err(|s| {
                    format!(
                        "conversion to `PostGetNullifierQueueElementsBody` for body failed: {}",
                        s
                    )
                });
            self
        }
        pub fn body_map<F>(mut self, f: F) -> Self
        where
            F: std::ops::FnOnce(
                types::builder::PostGetNullifierQueueElementsBody,
            ) -> types::builder::PostGetNullifierQueueElementsBody,
        {
            self.body = self.body.map(f);
            self
        }
        ///Sends a `POST` request to `/get_nullifier_queue_elements`
        pub async fn send(
            self,
        ) -> Result<
            ResponseValue<types::PostGetNullifierQueueElementsResponse>,
            Error<types::PostGetNullifierQueueElementsResponse>,
        > {
            let Self { client, body } = self;
            let body = body
                .and_then(|v| {
                    types::PostGetNullifierQueueElementsBody::try_from(v)
                        .map_err(|e| e.to_string())
                })
                .map_err(Error::InvalidRequest)?;
            let url = format!("{}/get_nullifier_queue_elements", client.baseurl,);
            let mut header_map = ::reqwest::header::HeaderMap::with_capacity(1usize);
            header_map
                .append(
                    ::reqwest::header::HeaderName::from_static("api-version"),
                    ::reqwest::header::HeaderValue::from_static(
                        super::Client::api_version(),
                    ),
                );
            #[allow(unused_mut)]
            let mut request = client
                .client
                .post(url)
                .header(
                    ::reqwest::header::ACCEPT,
                    ::reqwest::header::HeaderValue::from_static("application/json"),
                )
                .json(&body)
                .headers(header_map)
                .build()?;
            let info = OperationInfo {
                operation_id: "post_get_nullifier_queue_elements",
            };
            client.pre(&mut request, &info).await?;
            let result = client.exec(request, &info).await;
            client.post(&result, &info).await?;
            let response = result?;
            match response.status().as_u16() {
                200u16 => ResponseValue::from_response(response).await,
                429u16 => {
                    Err(
                        Error::ErrorResponse(
                            ResponseValue::from_response(response).await?,
                        ),
                    )
                }
                500u16 => {
                    Err(
                        Error::ErrorResponse(
                            ResponseValue::from_response(response).await?,
                        ),
                    )
                }
                _ => Err(Error::UnexpectedResponse(response)),
            }
        }
    }
    /**Builder for [`Client::post_get_shielded_transactions_by_tags`]

[`Client::post_get_shielded_transactions_by_tags`]: super::Client::post_get_shielded_transactions_by_tags*/
    #[derive(Debug, Clone)]
    pub struct PostGetShieldedTransactionsByTags<'a> {
        client: &'a super::Client,
        body: Result<types::builder::PostGetShieldedTransactionsByTagsBody, String>,
    }
    impl<'a> PostGetShieldedTransactionsByTags<'a> {
        pub fn new(client: &'a super::Client) -> Self {
            Self {
                client: client,
                body: Ok(::std::default::Default::default()),
            }
        }
        pub fn body<V>(mut self, value: V) -> Self
        where
            V: std::convert::TryInto<types::PostGetShieldedTransactionsByTagsBody>,
            <V as std::convert::TryInto<
                types::PostGetShieldedTransactionsByTagsBody,
            >>::Error: std::fmt::Display,
        {
            self.body = value
                .try_into()
                .map(From::from)
                .map_err(|s| {
                    format!(
                        "conversion to `PostGetShieldedTransactionsByTagsBody` for body failed: {}",
                        s
                    )
                });
            self
        }
        pub fn body_map<F>(mut self, f: F) -> Self
        where
            F: std::ops::FnOnce(
                types::builder::PostGetShieldedTransactionsByTagsBody,
            ) -> types::builder::PostGetShieldedTransactionsByTagsBody,
        {
            self.body = self.body.map(f);
            self
        }
        ///Sends a `POST` request to `/get_shielded_transactions_by_tags`
        pub async fn send(
            self,
        ) -> Result<
            ResponseValue<types::PostGetShieldedTransactionsByTagsResponse>,
            Error<types::PostGetShieldedTransactionsByTagsResponse>,
        > {
            let Self { client, body } = self;
            let body = body
                .and_then(|v| {
                    types::PostGetShieldedTransactionsByTagsBody::try_from(v)
                        .map_err(|e| e.to_string())
                })
                .map_err(Error::InvalidRequest)?;
            let url = format!("{}/get_shielded_transactions_by_tags", client.baseurl,);
            let mut header_map = ::reqwest::header::HeaderMap::with_capacity(1usize);
            header_map
                .append(
                    ::reqwest::header::HeaderName::from_static("api-version"),
                    ::reqwest::header::HeaderValue::from_static(
                        super::Client::api_version(),
                    ),
                );
            #[allow(unused_mut)]
            let mut request = client
                .client
                .post(url)
                .header(
                    ::reqwest::header::ACCEPT,
                    ::reqwest::header::HeaderValue::from_static("application/json"),
                )
                .json(&body)
                .headers(header_map)
                .build()?;
            let info = OperationInfo {
                operation_id: "post_get_shielded_transactions_by_tags",
            };
            client.pre(&mut request, &info).await?;
            let result = client.exec(request, &info).await;
            client.post(&result, &info).await?;
            let response = result?;
            match response.status().as_u16() {
                200u16 => ResponseValue::from_response(response).await,
                429u16 => {
                    Err(
                        Error::ErrorResponse(
                            ResponseValue::from_response(response).await?,
                        ),
                    )
                }
                500u16 => {
                    Err(
                        Error::ErrorResponse(
                            ResponseValue::from_response(response).await?,
                        ),
                    )
                }
                _ => Err(Error::UnexpectedResponse(response)),
            }
        }
    }
}
/// Items consumers will typically use such as the Client.
pub mod prelude {
    pub use self::super::Client;
}
