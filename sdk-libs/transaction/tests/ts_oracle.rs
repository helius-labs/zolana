//! Rust-side oracle for the TypeScript `@zolana/transaction` parity tests.
//!
//! Every case here is produced by the production Rust path and written to
//! `sdk-libs/ts/transaction/test/oracles/transaction-parity-v1.json`, which
//! `sdk-libs/ts/transaction/test/vectors/rust-oracle.test.ts` reproduces by
//! running the TypeScript path over the same inputs. The file is committed, so
//! the comparison runs in both languages without a live process.
//!
//! Regenerate with
//! `ZOLANA_WRITE_TS_ORACLES=1 cargo test -p zolana-transaction --test ts_oracle`.
//! Without that variable the test verifies the committed file, so a Rust change
//! that moves any of these values fails here before it can silently drift away
//! from the TypeScript side.
//!
//! The error section is the load-bearing one: `variant_name` matches on
//! `TransactionError` exhaustively, so a new Rust variant fails to compile until
//! it is mapped to a TypeScript code (or recorded as having none).

use std::{fs, path::PathBuf};

use serde_json::{json, Map, Value};
use solana_address::Address;
use zolana_event::ProoflessOutput;
use zolana_keypair::{
    constants::{BLINDING_LEN, SALT_LEN},
    hash::hash_field,
    PublicKey, ShieldedKeypair, SigningKey, ViewingKey,
};
use zolana_transaction::{
    derive_blinding,
    instructions::{
        merge::{Merge, MERGE_INPUTS},
        merge_zone::MergeZone,
        transact::{
            canonical_shape,
            shape::resolve_shape,
            slot_ordinal,
            spp_proof_inputs::{asset_field, signed_to_field, BN254_MODULUS_DEC},
            ConfidentialSplit, ConfidentialTransfer, EncryptedTransaction, ExternalData, InputUtxo,
            PrivateTxHash, Shape, SppProofOutputUtxo, WithdrawalTarget, SENDER_SLOT_COUNT,
        },
        types::{InputUtxoContext, SppProofInputUtxo},
        zone_authority::PreparedZoneAuthority,
    },
    owner_utxo_hash,
    serialization::{
        anonymous::{
            AnonymousRecipient, AnonymousRecipientEncode, AnonymousSenderBundle,
            AnonymousSenderEncode,
        },
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        merge::{Merge as MergeSerialization, MergeEncode, MergePlaintext},
        plaintext::{PlaintextEncode, PlaintextTransfer},
        proofless::{Proofless, ProoflessEncode},
        split::{Split, SplitEncode},
        DecodeCx, OwnerCx, UtxoSerialization,
    },
    AssetRegistry, Data, DataRecord, EncryptedScheme, ProofInputUtxo, TransactionError, Utxo,
    SOL_ASSET_ID, SOL_MINT,
};

const ORACLE_PATH: &str = "../ts/transaction/test/oracles/transaction-parity-v1.json";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn address(byte: u8) -> Address {
    Address::new_from_array([byte; 32])
}

/// The TypeScript error code each Rust variant maps onto. The match is
/// exhaustive on purpose: `TRANSACTION_ERROR_CODES` in
/// `sdk-libs/ts/transaction/src/error.ts` is only meaningful as a port of this
/// enum, and the compiler is the only thing that can keep the two sets tied
/// together as the enum grows.
fn ts_code(error: &TransactionError) -> &'static str {
    match error {
        TransactionError::BadDiscriminator(_) => "TRANSACTION_BAD_DISCRIMINATOR",
        TransactionError::InvalidLength { .. } => "TRANSACTION_INVALID_LENGTH",
        TransactionError::Serialize(_) => "TRANSACTION_SERIALIZE",
        TransactionError::Deserialize(_) => "TRANSACTION_DESERIALIZE",
        TransactionError::UnknownAsset(_) => "TRANSACTION_UNKNOWN_ASSET",
        TransactionError::UnknownMint(_) => "TRANSACTION_UNKNOWN_MINT",
        TransactionError::ReservedAssetId(_) => "TRANSACTION_RESERVED_ASSET_ID",
        TransactionError::DuplicateAssetId(_) => "TRANSACTION_DUPLICATE_ASSET_ID",
        TransactionError::DuplicateMint(_) => "TRANSACTION_DUPLICATE_MINT",
        TransactionError::DataWithoutOutput => "TRANSACTION_DATA_WITHOUT_OUTPUT",
        TransactionError::TooManyOutputs => "TRANSACTION_TOO_MANY_OUTPUTS",
        TransactionError::DuplicateDataRecord => "TRANSACTION_DUPLICATE_DATA_RECORD",
        TransactionError::NonCanonicalDataOrder => "TRANSACTION_NON_CANONICAL_DATA_ORDER",
        TransactionError::MissingZoneProgramId => "TRANSACTION_MISSING_ZONE_PROGRAM_ID",
        TransactionError::UnsupportedOutputData => "TRANSACTION_UNSUPPORTED_OUTPUT_DATA",
        TransactionError::Poseidon(_) => "TRANSACTION_POSEIDON",
        TransactionError::Hash(_) => "TRANSACTION_HASH",
        TransactionError::MissingOutput => "TRANSACTION_MISSING_OUTPUT",
        TransactionError::InvalidOutputCount { .. } => "TRANSACTION_INVALID_OUTPUT_COUNT",
        TransactionError::OutputOwnerMismatch { .. } => "TRANSACTION_OUTPUT_OWNER_MISMATCH",
        TransactionError::OutputAssetMismatch { .. } => "TRANSACTION_OUTPUT_ASSET_MISMATCH",
        TransactionError::OutputAmountMismatch { .. } => "TRANSACTION_OUTPUT_AMOUNT_MISMATCH",
        TransactionError::OutputBlindingMismatch { .. } => "TRANSACTION_OUTPUT_BLINDING_MISMATCH",
        TransactionError::OutputDataMismatch { .. } => "TRANSACTION_OUTPUT_DATA_MISMATCH",
        TransactionError::OutputZoneMismatch { .. } => "TRANSACTION_OUTPUT_ZONE_MISMATCH",
        TransactionError::InvalidOutputPosition { .. } => "TRANSACTION_INVALID_OUTPUT_POSITION",
        TransactionError::UnknownAssetField(_) => "TRANSACTION_UNKNOWN_ASSET_FIELD",
        TransactionError::MissingEncryptionContext => "TRANSACTION_MISSING_ENCRYPTION_CONTEXT",
        TransactionError::NoInputs => "TRANSACTION_NO_INPUTS",
        TransactionError::NoncanonicalDummyInput { .. } => "TRANSACTION_NONCANONICAL_DUMMY_INPUT",
        TransactionError::AddressHashCountMismatch { .. } => {
            "TRANSACTION_ADDRESS_HASH_COUNT_MISMATCH"
        }
        TransactionError::WithdrawalAlreadySet => "TRANSACTION_WITHDRAWAL_ALREADY_SET",
        TransactionError::WithdrawalAssetMismatch => "TRANSACTION_WITHDRAWAL_ASSET_MISMATCH",
        TransactionError::OutputSlotOverflow { .. } => "TRANSACTION_OUTPUT_SLOT_OVERFLOW",
        TransactionError::ExcessOutputSlots { .. } => "TRANSACTION_EXCESS_OUTPUT_SLOTS",
        TransactionError::MissingZoneAuthorityProgramId => {
            "TRANSACTION_MISSING_ZONE_AUTHORITY_PROGRAM_ID"
        }
        TransactionError::ZoneAuthorityInputZoneMismatch { .. } => {
            "TRANSACTION_ZONE_AUTHORITY_INPUT_ZONE_MISMATCH"
        }
        TransactionError::ZoneAuthorityOutputZoneMismatch { .. } => {
            "TRANSACTION_ZONE_AUTHORITY_OUTPUT_ZONE_MISMATCH"
        }
        TransactionError::PublicSolAlreadySet => "TRANSACTION_PUBLIC_SOL_ALREADY_SET",
        TransactionError::PublicSplAlreadySet => "TRANSACTION_PUBLIC_SPL_ALREADY_SET",
        TransactionError::ZoneHashesAlreadySet => "TRANSACTION_ZONE_HASHES_ALREADY_SET",
        TransactionError::MultiplePublicSplAssets => "TRANSACTION_MULTIPLE_PUBLIC_SPL_ASSETS",
        TransactionError::MissingPublicSplAsset => "TRANSACTION_MISSING_PUBLIC_SPL_ASSET",
        TransactionError::SignerNotP256 => "TRANSACTION_SIGNER_NOT_P256",
        TransactionError::InsufficientBalance { .. } => "TRANSACTION_INSUFFICIENT_BALANCE",
        TransactionError::UnsupportedShape { .. } => "TRANSACTION_UNSUPPORTED_SHAPE",
        TransactionError::TooManyInputs { .. } => "TRANSACTION_TOO_MANY_INPUTS",
        TransactionError::TooManyOutputsForShape { .. } => "TRANSACTION_TOO_MANY_OUTPUTS_FOR_SHAPE",
        TransactionError::MergeInputRailMismatch { .. } => "TRANSACTION_MERGE_INPUT_RAIL_MISMATCH",
        TransactionError::MergeInputOwnerMismatch { .. } => {
            "TRANSACTION_MERGE_INPUT_OWNER_MISMATCH"
        }
        TransactionError::MergeInputNullifierKeyMismatch { .. } => {
            "TRANSACTION_MERGE_INPUT_NULLIFIER_KEY_MISMATCH"
        }
        TransactionError::MergeInputAssetMismatch { .. } => {
            "TRANSACTION_MERGE_INPUT_ASSET_MISMATCH"
        }
        TransactionError::MergeInputZoneMismatch { .. } => "TRANSACTION_MERGE_INPUT_ZONE_MISMATCH",
        TransactionError::SelectedBalanceOverflow => "TRANSACTION_SELECTED_BALANCE_OVERFLOW",
        TransactionError::WalletBalanceOverflow => "TRANSACTION_WALLET_BALANCE_OVERFLOW",
        TransactionError::InvalidTagWindow => "TRANSACTION_INVALID_TAG_WINDOW",
        TransactionError::MergeInputHasData { .. } => "TRANSACTION_MERGE_INPUT_HAS_DATA",
        TransactionError::SplitInvalidPartCount { .. } => "TRANSACTION_SPLIT_INVALID_PART_COUNT",
        TransactionError::SplitInputAssetMismatch => "TRANSACTION_SPLIT_INPUT_ASSET_MISMATCH",
        TransactionError::SplitInputHasData => "TRANSACTION_SPLIT_INPUT_HAS_DATA",
        TransactionError::SplitInputZoneMismatch => "TRANSACTION_SPLIT_INPUT_ZONE_MISMATCH",
        TransactionError::SplitInputIsDummy => "TRANSACTION_SPLIT_INPUT_IS_DUMMY",
        TransactionError::SplitInputOwnerMismatch => "TRANSACTION_SPLIT_INPUT_OWNER_MISMATCH",
        TransactionError::SplitInputNullifierKeyMismatch => {
            "TRANSACTION_SPLIT_INPUT_NULLIFIER_KEY_MISMATCH"
        }
        TransactionError::SplitAmountMismatch { .. } => "TRANSACTION_SPLIT_AMOUNT_MISMATCH",
        TransactionError::P256(_) => "TRANSACTION_P256",
        TransactionError::Keypair(_) => "TRANSACTION_KEYPAIR",
        TransactionError::WalletAuthorityMismatch => "TRANSACTION_WALLET_AUTHORITY_MISMATCH",
        TransactionError::MissingCurrentViewingKey => "TRANSACTION_MISSING_CURRENT_VIEWING_KEY",
        TransactionError::Authority(_) => "TRANSACTION_AUTHORITY",
    }
}

/// One constructed value per variant. `ts_code` is exhaustive, so this list is
/// checked against it: a variant added to the enum without a sample here fails
/// the `every_variant_has_a_sample` assertion below.
fn samples() -> Vec<(&'static str, TransactionError)> {
    vec![
        ("BadDiscriminator", TransactionError::BadDiscriminator(9)),
        (
            "InvalidLength",
            TransactionError::InvalidLength {
                expected: 32,
                actual: 31,
            },
        ),
        ("Serialize", TransactionError::Serialize("boom".into())),
        ("Deserialize", TransactionError::Deserialize("boom".into())),
        ("UnknownAsset", TransactionError::UnknownAsset(7)),
        ("UnknownMint", TransactionError::UnknownMint(address(3))),
        ("ReservedAssetId", TransactionError::ReservedAssetId(1)),
        ("DuplicateAssetId", TransactionError::DuplicateAssetId(2)),
        ("DuplicateMint", TransactionError::DuplicateMint(address(3))),
        ("DataWithoutOutput", TransactionError::DataWithoutOutput),
        ("TooManyOutputs", TransactionError::TooManyOutputs),
        ("DuplicateDataRecord", TransactionError::DuplicateDataRecord),
        (
            "NonCanonicalDataOrder",
            TransactionError::NonCanonicalDataOrder,
        ),
        (
            "MissingZoneProgramId",
            TransactionError::MissingZoneProgramId,
        ),
        (
            "UnsupportedOutputData",
            TransactionError::UnsupportedOutputData,
        ),
        ("Poseidon", TransactionError::Poseidon("boom".into())),
        ("Hash", TransactionError::Hash("boom".into())),
        ("MissingOutput", TransactionError::MissingOutput),
        (
            "InvalidOutputCount",
            TransactionError::InvalidOutputCount {
                expected: 1,
                actual: 2,
            },
        ),
        (
            "OutputOwnerMismatch",
            TransactionError::OutputOwnerMismatch { index: 1 },
        ),
        (
            "OutputAssetMismatch",
            TransactionError::OutputAssetMismatch { index: 1 },
        ),
        (
            "OutputAmountMismatch",
            TransactionError::OutputAmountMismatch { index: 1 },
        ),
        (
            "OutputBlindingMismatch",
            TransactionError::OutputBlindingMismatch { index: 1 },
        ),
        (
            "OutputDataMismatch",
            TransactionError::OutputDataMismatch { index: 1 },
        ),
        (
            "OutputZoneMismatch",
            TransactionError::OutputZoneMismatch { index: 1 },
        ),
        (
            "InvalidOutputPosition",
            TransactionError::InvalidOutputPosition { position: 3 },
        ),
        (
            "UnknownAssetField",
            TransactionError::UnknownAssetField([4u8; 32]),
        ),
        (
            "MissingEncryptionContext",
            TransactionError::MissingEncryptionContext,
        ),
        ("NoInputs", TransactionError::NoInputs),
        (
            "NoncanonicalDummyInput",
            TransactionError::NoncanonicalDummyInput { field: "amount" },
        ),
        (
            "AddressHashCountMismatch",
            TransactionError::AddressHashCountMismatch {
                expected: 2,
                actual: 1,
            },
        ),
        (
            "WithdrawalAlreadySet",
            TransactionError::WithdrawalAlreadySet,
        ),
        (
            "WithdrawalAssetMismatch",
            TransactionError::WithdrawalAssetMismatch,
        ),
        (
            "OutputSlotOverflow",
            TransactionError::OutputSlotOverflow {
                position: u32::MAX as usize + 1,
            },
        ),
        (
            "ExcessOutputSlots",
            TransactionError::ExcessOutputSlots { got: 4, outputs: 3 },
        ),
        (
            "MissingZoneAuthorityProgramId",
            TransactionError::MissingZoneAuthorityProgramId,
        ),
        (
            "ZoneAuthorityInputZoneMismatch",
            TransactionError::ZoneAuthorityInputZoneMismatch { index: 0 },
        ),
        (
            "ZoneAuthorityOutputZoneMismatch",
            TransactionError::ZoneAuthorityOutputZoneMismatch { index: 0 },
        ),
        ("PublicSolAlreadySet", TransactionError::PublicSolAlreadySet),
        ("PublicSplAlreadySet", TransactionError::PublicSplAlreadySet),
        (
            "ZoneHashesAlreadySet",
            TransactionError::ZoneHashesAlreadySet,
        ),
        (
            "MultiplePublicSplAssets",
            TransactionError::MultiplePublicSplAssets,
        ),
        (
            "MissingPublicSplAsset",
            TransactionError::MissingPublicSplAsset,
        ),
        ("SignerNotP256", TransactionError::SignerNotP256),
        (
            "InsufficientBalance",
            TransactionError::InsufficientBalance {
                requested: 5,
                available: 4,
            },
        ),
        (
            "UnsupportedShape",
            TransactionError::UnsupportedShape { n_in: 9, n_out: 9 },
        ),
        (
            "TooManyInputs",
            TransactionError::TooManyInputs { got: 3, max: 2 },
        ),
        (
            "TooManyOutputsForShape",
            TransactionError::TooManyOutputsForShape { got: 4, max: 3 },
        ),
        (
            "MergeInputRailMismatch",
            TransactionError::MergeInputRailMismatch { index: 1 },
        ),
        (
            "MergeInputOwnerMismatch",
            TransactionError::MergeInputOwnerMismatch { index: 1 },
        ),
        (
            "MergeInputNullifierKeyMismatch",
            TransactionError::MergeInputNullifierKeyMismatch { index: 1 },
        ),
        (
            "MergeInputAssetMismatch",
            TransactionError::MergeInputAssetMismatch { index: 1 },
        ),
        (
            "MergeInputZoneMismatch",
            TransactionError::MergeInputZoneMismatch { index: 1 },
        ),
        (
            "SelectedBalanceOverflow",
            TransactionError::SelectedBalanceOverflow,
        ),
        (
            "WalletBalanceOverflow",
            TransactionError::WalletBalanceOverflow,
        ),
        ("InvalidTagWindow", TransactionError::InvalidTagWindow),
        (
            "MergeInputHasData",
            TransactionError::MergeInputHasData { index: 1 },
        ),
        (
            "SplitInvalidPartCount",
            TransactionError::SplitInvalidPartCount { num_outputs: 9 },
        ),
        (
            "SplitInputAssetMismatch",
            TransactionError::SplitInputAssetMismatch,
        ),
        ("SplitInputHasData", TransactionError::SplitInputHasData),
        (
            "SplitInputZoneMismatch",
            TransactionError::SplitInputZoneMismatch,
        ),
        ("SplitInputIsDummy", TransactionError::SplitInputIsDummy),
        (
            "SplitInputOwnerMismatch",
            TransactionError::SplitInputOwnerMismatch,
        ),
        (
            "SplitInputNullifierKeyMismatch",
            TransactionError::SplitInputNullifierKeyMismatch,
        ),
        (
            "SplitAmountMismatch",
            TransactionError::SplitAmountMismatch {
                input: 10,
                num_outputs: 3,
                per_output: 3,
            },
        ),
        ("P256", TransactionError::P256("boom".into())),
        (
            "Keypair",
            TransactionError::Keypair(zolana_keypair::KeypairError::InvalidPublicKey),
        ),
        (
            "WalletAuthorityMismatch",
            TransactionError::WalletAuthorityMismatch,
        ),
        (
            "MissingCurrentViewingKey",
            TransactionError::MissingCurrentViewingKey,
        ),
        ("Authority", TransactionError::Authority("boom".into())),
    ]
}

fn errors_section() -> Value {
    let variants = samples()
        .into_iter()
        .map(|(name, error)| {
            json!({
                "variant": name,
                "display": error.to_string(),
                "tsCode": ts_code(&error),
            })
        })
        .collect::<Vec<_>>();
    json!({ "variants": variants })
}

/// `MergeSerialization::into_utxos`: the asset field is the only value the
/// plaintext cannot carry directly, so an unregistered one must be named rather
/// than resolved to a default mint.
fn merge_into_utxos_cases(registry: &AssetRegistry, spl_mint: &Address, zone: &Address) -> Value {
    let owner = owner_key(&OWNER_SECRET);
    let cases: [(&str, Address, bool); 4] = [
        ("solAsset", SOL_MINT, false),
        ("splAsset", *spl_mint, false),
        ("zoneBound", SOL_MINT, true),
        ("unregisteredAsset", address(SPL_MINT_BYTE + 1), false),
    ];

    Value::Array(
        cases
            .iter()
            .map(|(name, asset, zone_bound)| {
                let asset_field = hash_field(asset.as_array()).expect("asset field");
                let plaintext = MergePlaintext {
                    amount: 500,
                    asset_field,
                    blinding: TRANSACT_TYPES_BLINDING,
                };
                let cx = OwnerCx {
                    owner,
                    assets: registry,
                    zone_program_id: zone_bound.then_some(*zone),
                };
                let outcome = MergeSerialization::into_utxos(plaintext, &cx);
                json!({
                    "name": name,
                    "assetFieldHex": hex(&asset_field),
                    "zoneBound": zone_bound,
                    "error": outcome.as_ref().err().map(ts_code),
                    "asset": outcome
                        .as_ref()
                        .ok()
                        .and_then(|utxos| utxos.first())
                        .map(|utxo| utxo.asset.to_string()),
                    "amount": outcome
                        .as_ref()
                        .ok()
                        .and_then(|utxos| utxos.first())
                        .map(|utxo| utxo.amount.to_string()),
                    "zoneProgramId": outcome
                        .as_ref()
                        .ok()
                        .and_then(|utxos| utxos.first())
                        .and_then(|utxo| utxo.zone_program_id)
                        .map(|id| id.to_string()),
                })
            })
            .collect(),
    )
}

fn context_json(contexts: &[InputUtxoContext]) -> Value {
    Value::Array(
        contexts
            .iter()
            .map(|context| {
                json!({
                    "index": context.index,
                    "utxoHashHex": hex(&context.utxo_hash),
                    "nullifierHex": hex(&context.nullifier),
                })
            })
            .collect(),
    )
}

fn record_json(record: &DataRecord) -> Value {
    match record {
        DataRecord::ZoneData(bytes) => json!({ "kind": "zoneData", "bytesHex": hex(bytes) }),
        DataRecord::UtxoData(bytes) => json!({ "kind": "utxoData", "bytesHex": hex(bytes) }),
        DataRecord::Memo(bytes) => json!({ "kind": "memo", "bytesHex": hex(bytes) }),
    }
}

fn record(kind: &str, bytes: &[u8]) -> (DataRecord, Value) {
    let record = match kind {
        "zoneData" => DataRecord::ZoneData(bytes.to_vec()),
        "utxoData" => DataRecord::UtxoData(bytes.to_vec()),
        "memo" => DataRecord::Memo(bytes.to_vec()),
        other => panic!("unknown record kind {other}"),
    };
    (record, json!({ "kind": kind, "bytesHex": hex(bytes) }))
}

fn data_case(name: &str, kinds: &[(&str, Vec<u8>)]) -> Value {
    let mut records = Vec::new();
    let mut described = Vec::new();
    for (kind, bytes) in kinds {
        let (record, description) = record(kind, bytes);
        records.push(record);
        described.push(description);
    }
    let data = Data::new(records);
    let mut case = Map::new();
    case.insert("name".into(), json!(name));
    case.insert("records".into(), Value::Array(described));
    match data.validate() {
        Ok(()) => {
            let bytes = wincode::serialize(&data).expect("serialize data");
            let parsed: Data = wincode::deserialize_exact(&bytes).expect("round trip data");
            assert_eq!(parsed, data, "{name} does not round trip");
            case.insert("encodedHex".into(), json!(hex(&bytes)));
            case.insert("error".into(), Value::Null);
        }
        Err(error) => {
            case.insert("encodedHex".into(), Value::Null);
            case.insert("error".into(), json!(ts_code(&error)));
        }
    }
    Value::Object(case)
}

fn data_section() -> Value {
    let cases = vec![
        data_case("empty", &[]),
        data_case("zoneOnly", &[("zoneData", vec![9, 9])]),
        data_case("utxoOnly", &[("utxoData", vec![1])]),
        data_case("memoOnly", &[("memo", b"gm".to_vec())]),
        data_case(
            "canonicalOrder",
            &[
                ("zoneData", vec![9, 9]),
                ("utxoData", vec![1]),
                ("memo", b"gm".to_vec()),
            ],
        ),
        data_case("memoLongerThanAByte", &[("memo", vec![7; 300])]),
        data_case("duplicateMemo", &[("memo", vec![1]), ("memo", vec![2])]),
        data_case(
            "duplicateZone",
            &[("zoneData", vec![1]), ("zoneData", vec![2])],
        ),
        data_case(
            "utxoBeforeZone",
            &[("utxoData", vec![1]), ("zoneData", vec![2])],
        ),
        data_case("zoneAfterMemo", &[("memo", vec![0]), ("zoneData", vec![1])]),
        data_case("utxoAfterMemo", &[("memo", vec![0]), ("utxoData", vec![1])]),
        data_case("emptyRecordBytes", &[("utxoData", Vec::new())]),
    ];
    json!({ "cases": cases })
}

fn scheme_section() -> Value {
    let named = [
        ("proofless", EncryptedScheme::Proofless),
        ("anonymousRecipient", EncryptedScheme::AnonymousRecipient),
        ("anonymousSender", EncryptedScheme::AnonymousSender),
        ("confidential", EncryptedScheme::Confidential),
        ("split", EncryptedScheme::Split),
        ("merge", EncryptedScheme::Merge),
        ("plaintextTransfer", EncryptedScheme::PlaintextTransfer),
    ];
    let values = named
        .iter()
        .map(|(name, scheme)| {
            let byte = scheme.as_byte();
            assert_eq!(
                EncryptedScheme::from_byte(byte).expect("round trip scheme"),
                *scheme
            );
            json!({ "name": name, "byte": byte })
        })
        .collect::<Vec<_>>();
    let invalid = (0u16..=300)
        .filter(|byte| u8::try_from(*byte).is_ok())
        .map(|byte| byte as u8)
        .filter(|byte| EncryptedScheme::from_byte(*byte).is_err())
        .map(|byte| json!({ "byte": byte, "error": "TRANSACTION_BAD_DISCRIMINATOR" }))
        .collect::<Vec<_>>();
    json!({ "values": values, "invalid": invalid })
}

fn shape_json(shape: Shape) -> Value {
    json!({ "inputs": shape.n_inputs(), "outputs": shape.n_outputs() })
}

fn shape_case(declared: Option<Shape>, n_in: usize, n_out: usize) -> Value {
    let mut case = Map::new();
    case.insert("declared".into(), declared.map_or(Value::Null, shape_json));
    case.insert("inputs".into(), json!(n_in));
    case.insert("outputs".into(), json!(n_out));
    match resolve_shape(declared, n_in, n_out) {
        Ok(shape) => {
            case.insert("shape".into(), shape_json(shape));
            case.insert("error".into(), Value::Null);
        }
        Err(error) => {
            case.insert("shape".into(), Value::Null);
            case.insert("error".into(), json!(ts_code(&error)));
        }
    }
    Value::Object(case)
}

fn shape_section() -> Value {
    let mut cases = Vec::new();
    for n_in in 0..=6 {
        for n_out in 0..=9 {
            cases.push(shape_case(None, n_in, n_out));
        }
    }
    for declared in [
        Shape::IN1_OUT1,
        Shape::IN2_OUT3,
        Shape::IN5_OUT4,
        Shape::IN1_OUT8,
        Shape::new(7, 7),
        Shape::new(0, 0),
    ] {
        for (n_in, n_out) in [(0, 0), (1, 1), (2, 3), (5, 4), (1, 8), (6, 1), (1, 9)] {
            cases.push(shape_case(Some(declared), n_in, n_out));
        }
    }
    let canonical = (0..=6)
        .flat_map(|n_in| {
            (0..=9).map(move |n_out| {
                let mut case = Map::new();
                case.insert("inputs".into(), json!(n_in));
                case.insert("outputs".into(), json!(n_out));
                match canonical_shape(n_in, n_out) {
                    Ok(shape) => {
                        case.insert("shape".into(), shape_json(shape));
                        case.insert("error".into(), Value::Null);
                    }
                    Err(error) => {
                        case.insert("shape".into(), Value::Null);
                        case.insert("error".into(), json!(ts_code(&error)));
                    }
                }
                Value::Object(case)
            })
        })
        .collect::<Vec<_>>();
    json!({
        "supported": zolana_transaction::instructions::transact::SPP_SUPPORTED_SHAPES
            .iter()
            .map(|shape| shape_json(*shape))
            .collect::<Vec<_>>(),
        "resolve": cases,
        "canonical": canonical,
    })
}

fn asset_section() -> Value {
    let mint_a = address(3);
    let mint_b = address(4);
    let mut inserts = Vec::new();
    let mut registry = AssetRegistry::default();
    for (asset_id, mint) in [
        (0u64, mint_a),
        (SOL_ASSET_ID, mint_a),
        (2, mint_a),
        (2, mint_b),
        (3, mint_a),
        (3, mint_b),
        (4, SOL_MINT),
    ] {
        let result = registry.insert(asset_id, mint);
        inserts.push(json!({
            "assetId": asset_id.to_string(),
            "mint": mint.to_string(),
            "error": result.as_ref().err().map(ts_code),
        }));
    }

    let lookups = [0u64, 1, 2, 3, 5]
        .iter()
        .map(|asset_id| match registry.resolve(*asset_id) {
            Ok(mint) => json!({
                "assetId": asset_id.to_string(),
                "mint": mint.to_string(),
                "error": Value::Null,
            }),
            Err(error) => json!({
                "assetId": asset_id.to_string(),
                "mint": Value::Null,
                "error": ts_code(&error),
            }),
        })
        .collect::<Vec<_>>();

    let ids = [SOL_MINT, mint_a, mint_b, address(9)]
        .iter()
        .map(|mint| match registry.asset_id(mint) {
            Ok(asset_id) => json!({
                "mint": mint.to_string(),
                "assetId": asset_id.to_string(),
                "error": Value::Null,
            }),
            Err(error) => json!({
                "mint": mint.to_string(),
                "assetId": Value::Null,
                "error": ts_code(&error),
            }),
        })
        .collect::<Vec<_>>();

    let fields = [SOL_MINT, mint_a, address(9)]
        .iter()
        .map(|mint| {
            let field = zolana_keypair::hash::hash_field(mint.as_array()).expect("asset field");
            json!({
                "fieldHex": hex(&field),
                "mint": registry
                    .address_for_field(&field)
                    .expect("address for field")
                    .map(|found| found.to_string()),
            })
        })
        .collect::<Vec<_>>();

    json!({
        "solAssetId": SOL_ASSET_ID.to_string(),
        "solMint": SOL_MINT.to_string(),
        "inserts": inserts,
        "resolve": lookups,
        "assetId": ids,
        "addressForField": fields,
    })
}

struct UtxoCase {
    name: &'static str,
    owner_hash: [u8; 32],
    asset: Address,
    amount: u64,
    blinding: [u8; BLINDING_LEN],
    data_hash: Option<[u8; 32]>,
    zone_data_hash: Option<[u8; 32]>,
    zone_program_id: Option<Address>,
}

fn utxo_case(case: UtxoCase) -> Value {
    let mut json_case = Map::new();
    json_case.insert("name".into(), json!(case.name));
    json_case.insert("ownerHashHex".into(), json!(hex(&case.owner_hash)));
    json_case.insert("asset".into(), json!(case.asset.to_string()));
    json_case.insert("amount".into(), json!(case.amount.to_string()));
    json_case.insert("blindingHex".into(), json!(hex(&case.blinding)));
    json_case.insert(
        "dataHashHex".into(),
        case.data_hash.map_or(Value::Null, |hash| json!(hex(&hash))),
    );
    json_case.insert(
        "zoneDataHashHex".into(),
        case.zone_data_hash
            .map_or(Value::Null, |hash| json!(hex(&hash))),
    );
    json_case.insert(
        "zoneProgramId".into(),
        case.zone_program_id
            .map_or(Value::Null, |id| json!(id.to_string())),
    );

    let built = ProofInputUtxo::new(case.owner_hash, &case.asset, case.amount, &case.blinding)
        .map(|input| input.with_data_hash(case.data_hash.unwrap_or_default()))
        .and_then(|input| {
            input.with_zone(
                case.zone_data_hash.unwrap_or_default(),
                &case.zone_program_id,
            )
        })
        .and_then(|input| input.hash());
    match built {
        Ok(hash) => {
            json_case.insert("hashHex".into(), json!(hex(&hash)));
            json_case.insert("error".into(), Value::Null);
        }
        Err(error) => {
            json_case.insert("hashHex".into(), Value::Null);
            json_case.insert("error".into(), json!(ts_code(&error)));
        }
    }
    Value::Object(json_case)
}

fn utxo_section() -> Value {
    let blinding = [11u8; BLINDING_LEN];
    let cases = vec![
        utxo_case(UtxoCase {
            name: "bare",
            owner_hash: [1u8; 32],
            asset: SOL_MINT,
            amount: 1_000,
            blinding,
            data_hash: None,
            zone_data_hash: None,
            zone_program_id: None,
        }),
        utxo_case(UtxoCase {
            name: "zeroAmount",
            owner_hash: [1u8; 32],
            asset: SOL_MINT,
            amount: 0,
            blinding,
            data_hash: None,
            zone_data_hash: None,
            zone_program_id: None,
        }),
        utxo_case(UtxoCase {
            name: "maxAmount",
            owner_hash: [2u8; 32],
            asset: address(5),
            amount: u64::MAX,
            blinding,
            data_hash: None,
            zone_data_hash: None,
            zone_program_id: None,
        }),
        utxo_case(UtxoCase {
            name: "dataHashOnly",
            owner_hash: [1u8; 32],
            asset: SOL_MINT,
            amount: 7,
            blinding,
            data_hash: Some([6u8; 32]),
            zone_data_hash: None,
            zone_program_id: None,
        }),
        utxo_case(UtxoCase {
            name: "zoneBound",
            owner_hash: [1u8; 32],
            asset: SOL_MINT,
            amount: 7,
            blinding,
            data_hash: Some([6u8; 32]),
            zone_data_hash: Some([8u8; 32]),
            zone_program_id: Some(address(12)),
        }),
        utxo_case(UtxoCase {
            name: "zoneProgramWithoutZoneData",
            owner_hash: [1u8; 32],
            asset: SOL_MINT,
            amount: 7,
            blinding,
            data_hash: None,
            zone_data_hash: None,
            zone_program_id: Some(address(12)),
        }),
        utxo_case(UtxoCase {
            name: "zoneDataWithoutZoneProgram",
            owner_hash: [1u8; 32],
            asset: SOL_MINT,
            amount: 7,
            blinding,
            data_hash: None,
            zone_data_hash: Some([8u8; 32]),
            zone_program_id: None,
        }),
        utxo_case(UtxoCase {
            name: "canonicalDummy",
            owner_hash: [0u8; 32],
            asset: SOL_MINT,
            amount: 0,
            blinding: [7u8; BLINDING_LEN],
            data_hash: None,
            zone_data_hash: None,
            zone_program_id: None,
        }),
    ];

    let owner_hashes = [
        ([1u8; 32], blinding),
        ([0u8; 32], [0u8; BLINDING_LEN]),
        // A near-maximal owner hash that is still below the BN254 modulus, so
        // the pair exercises the wide end of the field without overflowing it.
        ([0x2au8; 32], [255u8; BLINDING_LEN]),
    ]
    .iter()
    .map(|(owner_hash, blinding)| {
        json!({
            "ownerHashHex": hex(owner_hash),
            "blindingHex": hex(blinding),
            "hashHex": hex(&owner_utxo_hash(owner_hash, blinding).expect("owner utxo hash")),
        })
    })
    .collect::<Vec<_>>();

    let blindings = [0u8, 1, 7, 128, 255]
        .iter()
        .map(|position| {
            json!({
                "seedHex": hex(&[11u8; BLINDING_LEN]),
                "position": position,
                "blindingHex": hex(&derive_blinding(&[11u8; BLINDING_LEN], *position)),
            })
        })
        .collect::<Vec<_>>();

    json!({
        "proofInputHashes": cases,
        "ownerUtxoHashes": owner_hashes,
        "deriveBlinding": blindings,
        "canonicalDummy": canonical_dummy_cases(),
    })
}

/// A zero-owner input stands for an unused slot, so every other field must be
/// zero too. The checks run in a fixed order, and each case names the field the
/// rejection must report; the multi-field cases pin that order.
fn canonical_dummy_cases() -> Value {
    let perturbations: [(&str, &[&str]); 10] = [
        ("canonical", &[]),
        ("asset", &["asset"]),
        ("amount", &["amount"]),
        ("data", &["data"]),
        ("zoneProgramId", &["zone_program_id"]),
        ("dataHash", &["data_hash"]),
        ("zoneDataHash", &["zone_data_hash"]),
        ("nullifierKey", &["nullifier_key"]),
        ("assetBeatsAmount", &["amount", "asset"]),
        ("dataBeatsZoneProgramId", &["zone_program_id", "data"]),
    ];

    Value::Array(
        perturbations
            .iter()
            .map(|(name, fields)| {
                let mut input = SppProofInputUtxo::new_dummy();
                for field in *fields {
                    match *field {
                        "asset" => input.utxo.asset = address(SPL_MINT_BYTE),
                        "amount" => input.utxo.amount = 7,
                        "data" => input.utxo.data = merge_data(&["memo"]),
                        "zone_program_id" => {
                            input.utxo.zone_program_id = Some(address(MERGE_ZONE_BYTE));
                        }
                        "data_hash" => input.data_hash = Some(MERGE_DATA_HASH),
                        "zone_data_hash" => input.zone_data_hash = Some(MERGE_ZONE_DATA_HASH),
                        "nullifier_key" => {
                            input.nullifier_key =
                                shielded_keypair(&OWNER_SECRET, &TRANSFER_VIEWING_SEED)
                                    .nullifier_key
                                    .clone();
                        }
                        other => panic!("unknown dummy field {other}"),
                    }
                }
                let outcome = input.check_canonical_dummy();
                json!({
                    "name": name,
                    "fields": fields,
                    "error": outcome.as_ref().err().map(ts_code),
                    "field": match outcome {
                        Err(TransactionError::NoncanonicalDummyInput { field }) => json!(field),
                        _ => Value::Null,
                    },
                })
            })
            .collect(),
    )
}

/// The two plaintext layouts that carry no key material, so both languages can
/// build them from the same literals. The keyed layouts (anonymous, split
/// bundle, plaintext transfer) need a shared keypair derivation and are not
/// covered here.
fn serialization_section() -> Value {
    let confidential = [
        ("bare", 1u64, 1_000u64, None, Data::default()),
        (
            "zoneBound",
            7,
            42,
            Some(address(12)),
            Data::new(vec![DataRecord::ZoneData(vec![9, 9])]),
        ),
        (
            "everyRecord",
            2,
            u64::MAX,
            Some(address(12)),
            Data::new(vec![
                DataRecord::ZoneData(vec![9, 9]),
                DataRecord::UtxoData(vec![1]),
                DataRecord::Memo(b"gm".to_vec()),
            ]),
        ),
        ("zeroAmount", 1, 0, None, Data::default()),
    ]
    .into_iter()
    .map(|(name, asset_id, amount, zone_program_id, data)| {
        let plaintext = ConfidentialOutputPlaintext {
            asset_id,
            amount,
            blinding: [11u8; BLINDING_LEN],
            zone_program_id,
            data,
        };
        let bytes = plaintext.serialize().expect("serialize confidential");
        assert_eq!(
            ConfidentialOutputPlaintext::deserialize(&bytes).expect("round trip"),
            plaintext
        );
        json!({
            "name": name,
            "assetId": asset_id.to_string(),
            "amount": amount.to_string(),
            "blindingHex": hex(&[11u8; BLINDING_LEN]),
            "zoneProgramId": zone_program_id.map(|id| id.to_string()),
            "records": plaintext
                .data
                .records
                .iter()
                .map(record_json)
                .collect::<Vec<_>>(),
            "encodedHex": hex(&bytes),
        })
    })
    .collect::<Vec<_>>();

    let merge = [("zero", 0u64, [0u8; 32]), ("max", u64::MAX, [4u8; 32])]
        .into_iter()
        .map(|(name, amount, asset_field)| {
            let plaintext = MergePlaintext {
                amount,
                asset_field,
                blinding: [11u8; BLINDING_LEN],
            };
            let bytes = plaintext.serialize().expect("serialize merge");
            let parsed = MergePlaintext::deserialize(&bytes).expect("round trip");
            assert_eq!(parsed.amount, plaintext.amount);
            assert_eq!(parsed.asset_field, plaintext.asset_field);
            assert_eq!(parsed.blinding, plaintext.blinding);
            json!({
                "name": name,
                "amount": amount.to_string(),
                "assetFieldHex": hex(&asset_field),
                "blindingHex": hex(&[11u8; BLINDING_LEN]),
                "encodedHex": hex(&bytes),
            })
        })
        .collect::<Vec<_>>();

    json!({
        "confidential": confidential,
        "merge": merge,
        "proofless": proofless_layout_cases(),
    })
}

/// The proofless note is the one plaintext with six optional fields, so the
/// TypeScript reader has to agree with Borsh on which are present and in what
/// order. Every case records both the bytes and the fields they decode to.
fn proofless_layout_cases() -> Value {
    let bare = ProoflessOutput {
        owner: [1u8; 32],
        blinding: TRANSACT_TYPES_BLINDING,
        asset: SOL_MINT.to_bytes(),
        amount: 1_000,
        data_hash: None,
        utxo_data: None,
        zone_program_id: None,
        zone_data_hash: None,
        zone_data: None,
        memo: None,
    };
    let cases = [
        ("bare", bare.clone()),
        (
            "maxAmount",
            ProoflessOutput {
                amount: u64::MAX,
                ..bare.clone()
            },
        ),
        (
            "zoneBound",
            ProoflessOutput {
                zone_program_id: Some(address(MERGE_ZONE_BYTE).to_bytes()),
                zone_data_hash: Some(MERGE_ZONE_DATA_HASH),
                zone_data: Some(vec![1, 2, 3]),
                ..bare.clone()
            },
        ),
        (
            "everyOptionalField",
            ProoflessOutput {
                data_hash: Some(MERGE_DATA_HASH),
                utxo_data: Some(vec![4, 5]),
                zone_program_id: Some(address(MERGE_ZONE_BYTE).to_bytes()),
                zone_data_hash: Some(MERGE_ZONE_DATA_HASH),
                zone_data: Some(vec![1, 2, 3]),
                memo: Some(vec![6]),
                ..bare
            },
        ),
        (
            "emptyPayloads",
            ProoflessOutput {
                utxo_data: Some(Vec::new()),
                zone_data: Some(Vec::new()),
                memo: Some(Vec::new()),
                ..bare
            },
        ),
    ];

    Value::Array(
        cases
            .iter()
            .map(|(name, output)| {
                let bytes = Proofless::serialize(output).expect("proofless bytes");
                json!({
                    "name": name,
                    "ownerHex": hex(&output.owner),
                    "blindingHex": hex(&output.blinding),
                    "asset": Address::new_from_array(output.asset).to_string(),
                    "amount": output.amount.to_string(),
                    "dataHashHex": output.data_hash.as_ref().map(|hash| hex(hash)),
                    "utxoDataHex": output.utxo_data.as_ref().map(|data| hex(data)),
                    "zoneProgramId": output
                        .zone_program_id
                        .map(|id| Address::new_from_array(id).to_string()),
                    "zoneDataHashHex": output.zone_data_hash.as_ref().map(|hash| hex(hash)),
                    "zoneDataHex": output.zone_data.as_ref().map(|data| hex(data)),
                    "memoHex": output.memo.as_ref().map(|data| hex(data)),
                    "encodedHex": hex(&bytes),
                })
            })
            .collect(),
    )
}

const OWNER_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
];
const OTHER_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12,
];
const SENDER_VIEWING_SEED: [u8; 32] = [8; 32];
const BLINDING_SEED: [u8; BLINDING_LEN] = [11; BLINDING_LEN];
const SPL_MINT_BYTE: u8 = 3;
const ZONE_BYTE: u8 = 12;

fn owner_key(secret: &[u8; 32]) -> PublicKey {
    SigningKey::from_bytes(secret)
        .expect("signing key")
        .pubkey()
}

/// A UTXO described the way both languages can rebuild it: `owner` names one of
/// the two fixed signing secrets, `position` names the blinding the shared seed
/// derives, and a `null` position carries a blinding the seed never derives.
struct UtxoSpec {
    owner: &'static str,
    asset: Address,
    amount: u64,
    position: Option<u8>,
    zone: Option<Address>,
    records: Vec<(&'static str, Vec<u8>)>,
}

fn spec_utxo(spec: &UtxoSpec) -> Utxo {
    let owner = match spec.owner {
        "owner" => owner_key(&OWNER_SECRET),
        "other" => owner_key(&OTHER_SECRET),
        other => panic!("unknown owner {other}"),
    };
    Utxo {
        owner,
        asset: spec.asset,
        amount: spec.amount,
        blinding: match spec.position {
            Some(position) => derive_blinding(&BLINDING_SEED, position),
            None => [99u8; BLINDING_LEN],
        },
        zone_program_id: spec.zone,
        data: Data::new(
            spec.records
                .iter()
                .map(|(kind, bytes)| record(kind, bytes).0)
                .collect(),
        ),
    }
}

fn spec_json(spec: &UtxoSpec) -> Value {
    json!({
        "owner": spec.owner,
        "asset": spec.asset.to_string(),
        "amount": spec.amount.to_string(),
        "position": spec.position,
        "zoneProgramId": spec.zone.map(|zone| zone.to_string()),
        "records": spec
            .records
            .iter()
            .map(|(kind, bytes)| json!({ "kind": kind, "bytesHex": hex(bytes) }))
            .collect::<Vec<_>>(),
    })
}

fn from_utxos_case(
    family: &str,
    name: &str,
    specs: Vec<UtxoSpec>,
    zone_program_id: Option<Address>,
    registry: &AssetRegistry,
) -> Value {
    let utxos = specs.iter().map(spec_utxo).collect::<Vec<_>>();
    let cx = OwnerCx {
        owner: owner_key(&OWNER_SECRET),
        assets: registry,
        zone_program_id,
    };
    let sender_viewing = ViewingKey::from_bytes(&SENDER_VIEWING_SEED).expect("viewing key");
    let encoded = match family {
        "plaintextTransfer" => PlaintextTransfer::from_utxos(
            &utxos,
            &cx,
            &PlaintextEncode {
                blinding_seed: BLINDING_SEED,
            },
        )
        .and_then(|plaintext| PlaintextTransfer::serialize(&plaintext)),
        "anonymousRecipient" => AnonymousRecipient::from_utxos(
            &utxos,
            &cx,
            &AnonymousRecipientEncode {
                tx: sender_viewing.clone(),
                recipient_pubkey: sender_viewing.pubkey(),
                sender_pubkey: sender_viewing.pubkey(),
                salt: [10u8; SALT_LEN],
                slot_index: 0,
            },
        )
        .and_then(|plaintext| AnonymousRecipient::serialize(&plaintext)),
        "anonymousSender" => AnonymousSenderBundle::from_utxos(
            &utxos,
            &cx,
            &AnonymousSenderEncode {
                tx: sender_viewing.clone(),
                self_pubkey: sender_viewing.pubkey(),
                salt: [10u8; SALT_LEN],
                slot_index: 0,
                blinding_seed: BLINDING_SEED,
                recipient_viewing_pks: vec![sender_viewing.pubkey()],
            },
        )
        .and_then(|plaintext| AnonymousSenderBundle::serialize(&plaintext)),
        "split" => Split::from_utxos(
            &utxos,
            &cx,
            &SplitEncode {
                tx: sender_viewing.clone(),
                recipient_pubkey: sender_viewing.pubkey(),
                salt: [10u8; SALT_LEN],
                slot_index: 0,
                blinding_seed: BLINDING_SEED,
            },
        )
        .and_then(|plaintext| Split::serialize(&plaintext)),
        "proofless" => Proofless::from_utxos(
            &utxos,
            &cx,
            &ProoflessEncode {
                owner_hash: [5u8; 32],
                data_hash: Some([6u8; 32]),
                zone_data_hash: None,
            },
        )
        .and_then(|plaintext| Proofless::serialize(&plaintext)),
        other => panic!("unknown family {other}"),
    };
    let mut case = Map::new();
    case.insert("name".into(), json!(name));
    case.insert(
        "utxos".into(),
        Value::Array(specs.iter().map(spec_json).collect()),
    );
    case.insert(
        "zoneProgramId".into(),
        zone_program_id.map_or(Value::Null, |zone| json!(zone.to_string())),
    );
    match encoded {
        Ok(bytes) => {
            case.insert("encodedHex".into(), json!(hex(&bytes)));
            case.insert("error".into(), Value::Null);
        }
        Err(error) => {
            case.insert("encodedHex".into(), Value::Null);
            case.insert("error".into(), json!(ts_code(&error)));
        }
    }
    Value::Object(case)
}

/// The `from_utxos` conversions: a builder turning the UTXOs it derived back
/// into the plaintext it encrypts. Both languages rebuild the inputs from the
/// two fixed signing secrets and the shared blinding seed, so a divergence in
/// key derivation shows up here as a byte mismatch rather than passing quietly.
fn from_utxos_section() -> Value {
    let spl_mint = address(SPL_MINT_BYTE);
    let zone = address(ZONE_BYTE);
    let registry = AssetRegistry::new([(2u64, spl_mint)]).expect("registry");
    let owned = |asset: Address, amount: u64, position: Option<u8>| UtxoSpec {
        owner: "owner",
        asset,
        amount,
        position,
        zone: None,
        records: Vec::new(),
    };

    let plaintext_transfer = vec![
        from_utxos_case(
            "plaintextTransfer",
            "senderSplAndSolPlusTwoRecipients",
            vec![
                owned(spl_mint, 5, Some(0)),
                owned(SOL_MINT, 7, Some(1)),
                UtxoSpec {
                    owner: "other",
                    asset: SOL_MINT,
                    amount: 11,
                    position: Some(2),
                    zone: None,
                    records: Vec::new(),
                },
                UtxoSpec {
                    owner: "other",
                    asset: spl_mint,
                    amount: 13,
                    position: Some(3),
                    zone: None,
                    records: vec![("memo", b"gm".to_vec())],
                },
            ],
            None,
            &registry,
        ),
        from_utxos_case("plaintextTransfer", "empty", Vec::new(), None, &registry),
        from_utxos_case(
            "plaintextTransfer",
            "recipientsOnly",
            vec![owned(SOL_MINT, 11, Some(2))],
            None,
            &registry,
        ),
        from_utxos_case(
            "plaintextTransfer",
            "solInTheSplSlot",
            vec![owned(SOL_MINT, 5, Some(0))],
            None,
            &registry,
        ),
        from_utxos_case(
            "plaintextTransfer",
            "splInTheSolSlot",
            vec![owned(spl_mint, 5, Some(1))],
            None,
            &registry,
        ),
        from_utxos_case(
            "plaintextTransfer",
            "foreignOwnerInTheSenderSlot",
            vec![UtxoSpec {
                owner: "other",
                asset: spl_mint,
                amount: 5,
                position: Some(0),
                zone: None,
                records: Vec::new(),
            }],
            None,
            &registry,
        ),
        from_utxos_case(
            "plaintextTransfer",
            "blindingOffTheSeed",
            vec![owned(SOL_MINT, 7, None)],
            None,
            &registry,
        ),
        from_utxos_case(
            "plaintextTransfer",
            "recipientPositionGap",
            vec![owned(SOL_MINT, 11, Some(2)), owned(SOL_MINT, 12, Some(4))],
            None,
            &registry,
        ),
        from_utxos_case(
            "plaintextTransfer",
            "zoneMismatch",
            vec![owned(SOL_MINT, 7, Some(1))],
            Some(zone),
            &registry,
        ),
        from_utxos_case(
            "plaintextTransfer",
            "unregisteredMint",
            vec![owned(address(9), 5, Some(0))],
            None,
            &registry,
        ),
    ];

    let anonymous_recipient = vec![
        from_utxos_case(
            "anonymousRecipient",
            "single",
            vec![owned(spl_mint, 5, Some(3))],
            None,
            &registry,
        ),
        from_utxos_case(
            "anonymousRecipient",
            "withMemo",
            vec![UtxoSpec {
                owner: "owner",
                asset: SOL_MINT,
                amount: 5,
                position: Some(3),
                zone: None,
                records: vec![("memo", b"gm".to_vec())],
            }],
            None,
            &registry,
        ),
        from_utxos_case(
            "anonymousRecipient",
            "zoneBound",
            vec![UtxoSpec {
                owner: "owner",
                asset: SOL_MINT,
                amount: 5,
                position: Some(3),
                zone: Some(zone),
                records: vec![("zoneData", vec![1, 2])],
            }],
            Some(zone),
            &registry,
        ),
        from_utxos_case("anonymousRecipient", "empty", Vec::new(), None, &registry),
        from_utxos_case(
            "anonymousRecipient",
            "twoUtxos",
            vec![owned(SOL_MINT, 5, Some(3)), owned(SOL_MINT, 6, Some(4))],
            None,
            &registry,
        ),
        from_utxos_case(
            "anonymousRecipient",
            "foreignOwner",
            vec![UtxoSpec {
                owner: "other",
                asset: SOL_MINT,
                amount: 5,
                position: Some(3),
                zone: None,
                records: Vec::new(),
            }],
            None,
            &registry,
        ),
    ];

    let anonymous_sender = vec![
        from_utxos_case(
            "anonymousSender",
            "splAndSol",
            vec![owned(spl_mint, 5, Some(0)), owned(SOL_MINT, 7, Some(1))],
            None,
            &registry,
        ),
        from_utxos_case(
            "anonymousSender",
            "solOnly",
            vec![owned(SOL_MINT, 7, Some(1))],
            None,
            &registry,
        ),
        from_utxos_case("anonymousSender", "empty", Vec::new(), None, &registry),
        from_utxos_case(
            "anonymousSender",
            "solAtTheSplPosition",
            vec![owned(SOL_MINT, 7, Some(0))],
            None,
            &registry,
        ),
        from_utxos_case(
            "anonymousSender",
            "twoSplLegs",
            vec![owned(spl_mint, 5, Some(0)), owned(spl_mint, 6, Some(0))],
            None,
            &registry,
        ),
    ];

    let split = vec![
        from_utxos_case(
            "split",
            "threeEqualParts",
            vec![
                owned(spl_mint, 5, Some(0)),
                owned(spl_mint, 5, Some(1)),
                owned(spl_mint, 5, Some(2)),
            ],
            None,
            &registry,
        ),
        from_utxos_case("split", "empty", Vec::new(), None, &registry),
        from_utxos_case(
            "split",
            "amountMismatch",
            vec![owned(spl_mint, 5, Some(0)), owned(spl_mint, 6, Some(1))],
            None,
            &registry,
        ),
        from_utxos_case(
            "split",
            "assetMismatch",
            vec![owned(spl_mint, 5, Some(0)), owned(SOL_MINT, 5, Some(1))],
            None,
            &registry,
        ),
        from_utxos_case(
            "split",
            "dataMismatch",
            vec![
                UtxoSpec {
                    owner: "owner",
                    asset: spl_mint,
                    amount: 5,
                    position: Some(0),
                    zone: None,
                    records: vec![("memo", b"gm".to_vec())],
                },
                owned(spl_mint, 5, Some(1)),
            ],
            None,
            &registry,
        ),
        from_utxos_case(
            "split",
            "blindingOutOfOrder",
            vec![owned(spl_mint, 5, Some(1)), owned(spl_mint, 5, Some(0))],
            None,
            &registry,
        ),
    ];

    let proofless = vec![
        from_utxos_case(
            "proofless",
            "single",
            vec![owned(SOL_MINT, 5, Some(0))],
            None,
            &registry,
        ),
        from_utxos_case(
            "proofless",
            "everyRecord",
            vec![UtxoSpec {
                owner: "owner",
                asset: SOL_MINT,
                amount: 5,
                position: Some(0),
                zone: Some(zone),
                records: vec![
                    ("zoneData", vec![9]),
                    ("utxoData", vec![1]),
                    ("memo", b"gm".to_vec()),
                ],
            }],
            Some(zone),
            &registry,
        ),
        from_utxos_case("proofless", "empty", Vec::new(), None, &registry),
        from_utxos_case(
            "proofless",
            "foreignOwner",
            vec![UtxoSpec {
                owner: "other",
                asset: SOL_MINT,
                amount: 5,
                position: Some(0),
                zone: None,
                records: Vec::new(),
            }],
            None,
            &registry,
        ),
    ];

    json!({
        "ownerPublicKeyHex": hex(owner_key(&OWNER_SECRET).as_bytes()),
        "otherPublicKeyHex": hex(owner_key(&OTHER_SECRET).as_bytes()),
        "senderViewingPublicKeyHex": hex(
            ViewingKey::from_bytes(&SENDER_VIEWING_SEED)
                .expect("viewing key")
                .pubkey()
                .as_bytes(),
        ),
        "blindingSeedHex": hex(&BLINDING_SEED),
        "splMint": address(SPL_MINT_BYTE).to_string(),
        "splAssetId": "2",
        "zoneProgramId": address(ZONE_BYTE).to_string(),
        "prooflessOwnerHashHex": hex(&[5u8; 32]),
        "prooflessDataHashHex": hex(&[6u8; 32]),
        "plaintextTransfer": plaintext_transfer,
        "anonymousRecipient": anonymous_recipient,
        "anonymousSender": anonymous_sender,
        "split": split,
        "proofless": proofless,
        "mergeIntoUtxos": merge_into_utxos_cases(&registry, &spl_mint, &zone),
    })
}

const TRANSFER_VIEWING_SEED: [u8; 32] = [21; 32];
const RECIPIENT_VIEWING_SEED: [u8; 32] = [22; 32];
const PAYER_BYTE: u8 = 15;

fn shielded_keypair(secret: &[u8; 32], viewing_seed: &[u8; 32]) -> ShieldedKeypair {
    ShieldedKeypair::from_keys(
        SigningKey::from_bytes(secret).expect("signing key"),
        ViewingKey::from_bytes(viewing_seed).expect("viewing key"),
    )
    .expect("shielded keypair")
}

/// One call on the transfer builder. Both languages replay the same list in
/// order, so a guard that fires on one side and not the other shows up as a
/// different recorded outcome rather than as a shape difference later.
enum TransferOp {
    Send {
        asset: Address,
        amount: u64,
    },
    Withdraw {
        asset: Address,
        amount: u64,
        target: &'static str,
    },
    WithShape(Shape),
}

fn transfer_op_json(op: &TransferOp) -> Value {
    match op {
        TransferOp::Send { asset, amount } => json!({
            "kind": "send",
            "asset": asset.to_string(),
            "amount": amount.to_string(),
        }),
        TransferOp::Withdraw {
            asset,
            amount,
            target,
        } => json!({
            "kind": "withdraw",
            "asset": asset.to_string(),
            "amount": amount.to_string(),
            "target": target,
        }),
        TransferOp::WithShape(shape) => json!({ "kind": "withShape", "shape": shape_json(*shape) }),
    }
}

fn withdrawal_target(target: &str) -> WithdrawalTarget {
    match target {
        "sol" => WithdrawalTarget::Sol {
            user_sol_account: address(20),
        },
        "spl" => WithdrawalTarget::Spl {
            user_spl_token: address(21),
            spl_token_interface: address(22),
        },
        other => panic!("unknown withdrawal target {other}"),
    }
}

struct TransferCase {
    name: &'static str,
    /// `(asset, amount, blinding position)` per input, all owned by the fixed
    /// transfer keypair so both languages derive the same commitments.
    inputs: Vec<(Address, u64, u8)>,
    ops: Vec<TransferOp>,
}

fn transfer_case(case: TransferCase) -> Value {
    let owner = shielded_keypair(&OWNER_SECRET, &TRANSFER_VIEWING_SEED);
    let recipient = shielded_keypair(&OTHER_SECRET, &RECIPIENT_VIEWING_SEED);
    let inputs = case
        .inputs
        .iter()
        .map(|(asset, amount, position)| {
            SppProofInputUtxo::new(
                Utxo {
                    owner: owner.signing_pubkey(),
                    asset: *asset,
                    amount: *amount,
                    blinding: derive_blinding(&BLINDING_SEED, *position),
                    zone_program_id: None,
                    data: Data::default(),
                },
                &owner,
            )
        })
        .collect::<Vec<_>>();

    let mut json_case = Map::new();
    json_case.insert("name".into(), json!(case.name));
    json_case.insert(
        "inputs".into(),
        Value::Array(
            case.inputs
                .iter()
                .map(|(asset, amount, position)| {
                    json!({
                        "asset": asset.to_string(),
                        "amount": amount.to_string(),
                        "position": position,
                    })
                })
                .collect(),
        ),
    );
    json_case.insert(
        "ops".into(),
        Value::Array(case.ops.iter().map(transfer_op_json).collect()),
    );

    let mut transfer = ConfidentialTransfer::new(
        owner.shielded_address().expect("shielded address"),
        inputs,
        address(PAYER_BYTE),
    );
    let mut failure = None;
    for op in &case.ops {
        let outcome = match op {
            TransferOp::Send { asset, amount } => transfer
                .send(
                    &recipient.shielded_address().expect("recipient address"),
                    *asset,
                    *amount,
                )
                .map(|_| ()),
            TransferOp::Withdraw {
                asset,
                amount,
                target,
            } => transfer
                .withdraw(*asset, *amount, withdrawal_target(target))
                .map(|_| ()),
            TransferOp::WithShape(shape) => {
                transfer = transfer.with_shape(*shape);
                Ok(())
            }
        };
        if let Err(error) = outcome {
            failure = Some(error);
            break;
        }
    }

    let prepared = match failure {
        Some(error) => Err(error),
        None => transfer.prepare(),
    };
    match prepared {
        Ok(prepared) => {
            json_case.insert("error".into(), Value::Null);
            // Counts before padding: Rust pads in `finalize`, so a language that
            // pads in `prepare` reports the shape's width here instead.
            json_case.insert("preparedInputs".into(), json!(prepared.inputs.len()));
            json_case.insert("preparedOutputs".into(), json!(prepared.outputs.len()));
            json_case.insert("shape".into(), shape_json(prepared.shape));
            json_case.insert(
                "publicSol".into(),
                prepared
                    .public_sol_amount
                    .map_or(Value::Null, |amount| json!(amount.to_string())),
            );
            json_case.insert(
                "publicSpl".into(),
                prepared
                    .public_spl_amount
                    .map_or(Value::Null, |amount| json!(amount.to_string())),
            );
            json_case.insert(
                "changeAmounts".into(),
                Value::Array(
                    prepared
                        .outputs
                        .iter()
                        .take(SENDER_SLOT_COUNT)
                        .map(|output| json!(output.amount.to_string()))
                        .collect(),
                ),
            );
            json_case.insert(
                "userSolAccount".into(),
                json!(prepared.user_sol_account.to_string()),
            );
            json_case.insert(
                "userSplToken".into(),
                json!(prepared.user_spl_token.to_string()),
            );
        }
        Err(error) => {
            json_case.insert("error".into(), json!(ts_code(&error)));
            for field in [
                "preparedInputs",
                "preparedOutputs",
                "shape",
                "publicSol",
                "publicSpl",
                "changeAmounts",
                "userSolAccount",
                "userSplToken",
            ] {
                json_case.insert(field.into(), Value::Null);
            }
        }
    }
    Value::Object(json_case)
}

/// The transfer builder's accept and reject set. Blindings and dummy tags are
/// randomly sampled, so this pins what the builder decides rather than the bytes
/// it produces: which inputs it takes, which shape it resolves, and how the
/// public leg and the two change slots come out.
fn transfer_section() -> Value {
    let spl_mint = address(SPL_MINT_BYTE);
    let sol_input = |amount: u64, position: u8| (SOL_MINT, amount, position);
    let cases = vec![
        transfer_case(TransferCase {
            name: "changeOnly",
            inputs: vec![sol_input(100, 0)],
            ops: Vec::new(),
        }),
        transfer_case(TransferCase {
            name: "oneRecipient",
            inputs: vec![sol_input(100, 0)],
            ops: vec![TransferOp::Send {
                asset: SOL_MINT,
                amount: 30,
            }],
        }),
        // The guard TypeScript used to apply here refused a zero amount that
        // Rust takes, so this is the case that keeps the two ends together.
        transfer_case(TransferCase {
            name: "zeroAmountRecipient",
            inputs: vec![sol_input(100, 0)],
            ops: vec![TransferOp::Send {
                asset: SOL_MINT,
                amount: 0,
            }],
        }),
        transfer_case(TransferCase {
            name: "wholeBalanceLeavesNoChange",
            inputs: vec![sol_input(100, 0)],
            ops: vec![TransferOp::Send {
                asset: SOL_MINT,
                amount: 100,
            }],
        }),
        transfer_case(TransferCase {
            name: "recipientBeyondBalance",
            inputs: vec![sol_input(100, 0)],
            ops: vec![TransferOp::Send {
                asset: SOL_MINT,
                amount: 101,
            }],
        }),
        transfer_case(TransferCase {
            name: "zeroAmountWithdrawal",
            inputs: vec![sol_input(100, 0)],
            ops: vec![TransferOp::Withdraw {
                asset: SOL_MINT,
                amount: 0,
                target: "sol",
            }],
        }),
        transfer_case(TransferCase {
            name: "solWithdrawal",
            inputs: vec![sol_input(100, 0)],
            ops: vec![TransferOp::Withdraw {
                asset: SOL_MINT,
                amount: 40,
                target: "sol",
            }],
        }),
        transfer_case(TransferCase {
            name: "splWithdrawal",
            inputs: vec![(spl_mint, 100, 0), sol_input(5, 1)],
            ops: vec![TransferOp::Withdraw {
                asset: spl_mint,
                amount: 40,
                target: "spl",
            }],
        }),
        transfer_case(TransferCase {
            name: "withdrawalTwice",
            inputs: vec![sol_input(100, 0)],
            ops: vec![
                TransferOp::Withdraw {
                    asset: SOL_MINT,
                    amount: 10,
                    target: "sol",
                },
                TransferOp::Withdraw {
                    asset: SOL_MINT,
                    amount: 10,
                    target: "sol",
                },
            ],
        }),
        transfer_case(TransferCase {
            name: "splAssetAtASolTarget",
            inputs: vec![(spl_mint, 100, 0)],
            ops: vec![TransferOp::Withdraw {
                asset: spl_mint,
                amount: 10,
                target: "sol",
            }],
        }),
        transfer_case(TransferCase {
            name: "solAssetAtASplTarget",
            inputs: vec![sol_input(100, 0)],
            ops: vec![TransferOp::Withdraw {
                asset: SOL_MINT,
                amount: 10,
                target: "spl",
            }],
        }),
        transfer_case(TransferCase {
            name: "twoSplAssets",
            inputs: vec![(spl_mint, 100, 0), (address(9), 100, 1)],
            ops: Vec::new(),
        }),
        transfer_case(TransferCase {
            name: "declaredShapeWithRoomToPad",
            inputs: vec![sol_input(100, 0)],
            ops: vec![
                TransferOp::Send {
                    asset: SOL_MINT,
                    amount: 30,
                },
                TransferOp::WithShape(Shape::IN1_OUT8),
            ],
        }),
        transfer_case(TransferCase {
            name: "declaredShapeTooNarrow",
            inputs: vec![sol_input(100, 0)],
            ops: vec![
                TransferOp::Send {
                    asset: SOL_MINT,
                    amount: 30,
                },
                TransferOp::WithShape(Shape::IN1_OUT1),
            ],
        }),
        transfer_case(TransferCase {
            name: "declaredShapeUnsupported",
            inputs: vec![sol_input(100, 0)],
            ops: vec![TransferOp::WithShape(Shape::new(7, 7))],
        }),
        transfer_case(TransferCase {
            name: "maxAmountRecipient",
            inputs: vec![sol_input(u64::MAX, 0)],
            ops: vec![TransferOp::Send {
                asset: SOL_MINT,
                amount: u64::MAX,
            }],
        }),
    ];
    json!({
        "senderSlotCount": SENDER_SLOT_COUNT,
        "payer": address(PAYER_BYTE).to_string(),
        "ownerViewingSeedHex": hex(&TRANSFER_VIEWING_SEED),
        "recipientViewingSeedHex": hex(&RECIPIENT_VIEWING_SEED),
        "solTarget": address(20).to_string(),
        "splTarget": {
            "userSplToken": address(21).to_string(),
            "splTokenInterface": address(22).to_string(),
        },
        "cases": cases,
    })
}

/// One merge input. Defaults describe an input the plain merge rail accepts;
/// each case perturbs exactly one field so the rejection it triggers is
/// unambiguous.
#[derive(Clone)]
struct MergeInputSpec {
    owner: &'static str,
    nullifier: &'static str,
    asset: Address,
    amount: u64,
    position: u8,
    zone: Option<Address>,
    records: Vec<&'static str>,
    data_hash: bool,
    zone_data_hash: bool,
}

impl MergeInputSpec {
    fn new(amount: u64, position: u8) -> Self {
        Self {
            owner: "owner",
            nullifier: "owner",
            asset: SOL_MINT,
            amount,
            position,
            zone: None,
            records: Vec::new(),
            data_hash: false,
            zone_data_hash: false,
        }
    }

    fn json(&self) -> Value {
        json!({
            "owner": self.owner,
            "nullifier": self.nullifier,
            "asset": self.asset.to_string(),
            "amount": self.amount.to_string(),
            "position": self.position,
            "zone": self.zone.map_or(Value::Null, |zone| json!(zone.to_string())),
            "records": self.records,
            "dataHash": self.data_hash,
            "zoneDataHash": self.zone_data_hash,
        })
    }
}

const MERGE_DATA_HASH: [u8; 32] = [31; 32];
const MERGE_ZONE_DATA_HASH: [u8; 32] = [32; 32];

fn merge_data(records: &[&'static str]) -> Data {
    Data::new(
        records
            .iter()
            .map(|kind| match *kind {
                "zoneData" => DataRecord::ZoneData(vec![1, 2, 3]),
                "utxoData" => DataRecord::UtxoData(vec![4, 5]),
                "memo" => DataRecord::Memo(vec![6]),
                other => panic!("unknown merge data record {other}"),
            })
            .collect(),
    )
}

fn merge_input(
    spec: &MergeInputSpec,
    owner: &ShieldedKeypair,
    other: &ShieldedKeypair,
) -> SppProofInputUtxo {
    let utxo = Utxo {
        owner: if spec.owner == "owner" {
            owner.signing_pubkey()
        } else {
            other.signing_pubkey()
        },
        asset: spec.asset,
        amount: spec.amount,
        blinding: derive_blinding(&BLINDING_SEED, spec.position),
        zone_program_id: spec.zone,
        data: merge_data(&spec.records),
    };
    let source = if spec.nullifier == "owner" {
        owner
    } else {
        other
    };
    let mut input = SppProofInputUtxo::new(utxo, source);
    if spec.data_hash {
        input = input.with_data_hash(MERGE_DATA_HASH);
    }
    if spec.zone_data_hash {
        input = input.with_zone_data_hash(MERGE_ZONE_DATA_HASH);
    }
    input
}

struct MergeCase {
    name: &'static str,
    rail: &'static str,
    inputs: Vec<MergeInputSpec>,
}

fn merge_case(case: MergeCase) -> Value {
    let owner = shielded_keypair(&OWNER_SECRET, &TRANSFER_VIEWING_SEED);
    let other = shielded_keypair(&OTHER_SECRET, &RECIPIENT_VIEWING_SEED);
    let zone = address(MERGE_ZONE_BYTE);
    let inputs = case
        .inputs
        .iter()
        .map(|spec| merge_input(spec, &owner, &other))
        .collect::<Vec<_>>();

    let prepared = if case.rail == "zone" {
        MergeZone::new(&owner, inputs, zone, None).map(|builder| {
            let prepared = builder.prepare();
            (
                prepared.output.asset,
                prepared.output.amount,
                prepared.inputs.len(),
                prepared.expiry_unix_ts,
                prepared.input_utxo_hashes(),
            )
        })
    } else {
        Merge::new(&owner, inputs).map(|builder| {
            let prepared = builder.prepare();
            (
                prepared.output.asset,
                prepared.output.amount,
                prepared.inputs.len(),
                prepared.expiry_unix_ts,
                prepared.input_utxo_hashes(),
            )
        })
    };

    let mut json_case = Map::new();
    json_case.insert("name".into(), json!(case.name));
    json_case.insert("rail".into(), json!(case.rail));
    json_case.insert(
        "inputs".into(),
        Value::Array(case.inputs.iter().map(MergeInputSpec::json).collect()),
    );
    match prepared {
        Ok((asset, amount, padded, expiry, contexts)) => {
            let contexts = contexts.expect("merge input contexts");
            json_case.insert("error".into(), Value::Null);
            json_case.insert("asset".into(), json!(asset.to_string()));
            json_case.insert("outputAmount".into(), json!(amount.to_string()));
            json_case.insert("paddedInputs".into(), json!(padded));
            json_case.insert("expiryUnixTs".into(), json!(expiry.to_string()));
            json_case.insert("inputContexts".into(), context_json(&contexts));
        }
        Err(error) => {
            json_case.insert("error".into(), json!(ts_code(&error)));
            for field in [
                "asset",
                "outputAmount",
                "paddedInputs",
                "expiryUnixTs",
                "inputContexts",
            ] {
                json_case.insert(field.into(), Value::Null);
            }
        }
    }
    Value::Object(json_case)
}

const MERGE_ZONE_BYTE: u8 = 30;

/// The two merge rails' accept and reject sets. Output blindings are random, so
/// this pins what the builders decide and the deterministic part of what they
/// produce: the merged asset and amount, the padded input list, and the real
/// inputs' hashes and nullifiers.
fn merge_section() -> Value {
    let spl_mint = address(SPL_MINT_BYTE);
    let zone = address(MERGE_ZONE_BYTE);
    let zoned = |mut spec: MergeInputSpec| {
        spec.zone = Some(zone);
        spec
    };
    let perturbed = |mut spec: MergeInputSpec, apply: &dyn Fn(&mut MergeInputSpec)| {
        apply(&mut spec);
        spec
    };

    let mut cases = vec![
        merge_case(MergeCase {
            name: "single",
            rail: "plain",
            inputs: vec![MergeInputSpec::new(100, 0)],
        }),
        merge_case(MergeCase {
            name: "eightInputs",
            rail: "plain",
            inputs: (0..8u8)
                .map(|position| MergeInputSpec::new(u64::from(position) + 1, position))
                .collect(),
        }),
        merge_case(MergeCase {
            name: "zeroAmounts",
            rail: "plain",
            inputs: vec![MergeInputSpec::new(0, 0), MergeInputSpec::new(0, 1)],
        }),
        merge_case(MergeCase {
            name: "maxAmount",
            rail: "plain",
            inputs: vec![MergeInputSpec::new(u64::MAX, 0)],
        }),
        merge_case(MergeCase {
            name: "empty",
            rail: "plain",
            inputs: Vec::new(),
        }),
        merge_case(MergeCase {
            name: "nineInputs",
            rail: "plain",
            inputs: (0..9u8)
                .map(|position| MergeInputSpec::new(1, position))
                .collect(),
        }),
        merge_case(MergeCase {
            name: "overflow",
            rail: "plain",
            inputs: vec![MergeInputSpec::new(u64::MAX, 0), MergeInputSpec::new(1, 1)],
        }),
        merge_case(MergeCase {
            name: "foreignOwner",
            rail: "plain",
            inputs: vec![perturbed(MergeInputSpec::new(100, 0), &|spec| {
                spec.owner = "other";
            })],
        }),
        merge_case(MergeCase {
            name: "foreignNullifierKey",
            rail: "plain",
            inputs: vec![perturbed(MergeInputSpec::new(100, 0), &|spec| {
                spec.nullifier = "other";
            })],
        }),
        merge_case(MergeCase {
            name: "assetMismatch",
            rail: "plain",
            inputs: vec![
                MergeInputSpec::new(100, 0),
                perturbed(MergeInputSpec::new(100, 1), &|spec| spec.asset = spl_mint),
            ],
        }),
        merge_case(MergeCase {
            name: "zoneBoundInput",
            rail: "plain",
            inputs: vec![zoned(MergeInputSpec::new(100, 0))],
        }),
        merge_case(MergeCase {
            name: "inlineUtxoData",
            rail: "plain",
            inputs: vec![perturbed(MergeInputSpec::new(100, 0), &|spec| {
                spec.records = vec!["utxoData"];
            })],
        }),
        merge_case(MergeCase {
            name: "externalDataHash",
            rail: "plain",
            inputs: vec![perturbed(MergeInputSpec::new(100, 0), &|spec| {
                spec.data_hash = true;
            })],
        }),
        merge_case(MergeCase {
            name: "externalZoneDataHash",
            rail: "plain",
            inputs: vec![perturbed(MergeInputSpec::new(100, 0), &|spec| {
                spec.zone_data_hash = true;
            })],
        }),
    ];

    // The zone rail differs from the plain rail on exactly two rules: every input
    // must carry the pinned zone, and zone data is consumable where owner data is
    // not. These cases sit on both sides of each.
    cases.extend([
        merge_case(MergeCase {
            name: "zoneSingle",
            rail: "zone",
            inputs: vec![zoned(MergeInputSpec::new(100, 0))],
        }),
        merge_case(MergeCase {
            name: "zoneWithZoneData",
            rail: "zone",
            inputs: vec![perturbed(zoned(MergeInputSpec::new(100, 0)), &|spec| {
                spec.records = vec!["zoneData"];
                spec.zone_data_hash = true;
            })],
        }),
        merge_case(MergeCase {
            name: "zoneWithMemo",
            rail: "zone",
            inputs: vec![perturbed(zoned(MergeInputSpec::new(100, 0)), &|spec| {
                spec.records = vec!["memo"];
            })],
        }),
        merge_case(MergeCase {
            name: "zoneWithUtxoData",
            rail: "zone",
            inputs: vec![perturbed(zoned(MergeInputSpec::new(100, 0)), &|spec| {
                spec.records = vec!["utxoData"];
            })],
        }),
        merge_case(MergeCase {
            name: "zoneWithDataHash",
            rail: "zone",
            inputs: vec![perturbed(zoned(MergeInputSpec::new(100, 0)), &|spec| {
                spec.data_hash = true;
            })],
        }),
        merge_case(MergeCase {
            name: "zoneMissingOnInput",
            rail: "zone",
            inputs: vec![MergeInputSpec::new(100, 0)],
        }),
        merge_case(MergeCase {
            name: "zoneWrongOnInput",
            rail: "zone",
            inputs: vec![perturbed(MergeInputSpec::new(100, 0), &|spec| {
                spec.zone = Some(address(29));
            })],
        }),
    ]);

    json!({
        "mergeInputs": MERGE_INPUTS,
        "zone": zone.to_string(),
        "foreignZone": address(29).to_string(),
        "dataHashHex": hex(&MERGE_DATA_HASH),
        "zoneDataHashHex": hex(&MERGE_ZONE_DATA_HASH),
        "cases": cases,
        "preparedContexts": prepared_context_cases(),
    })
}

/// `PreparedMerge` and `PreparedMergeZone` are publicly constructible, so their
/// `input_utxo_hashes` re-checks the rail's data policy rather than trusting the
/// builder. Each case takes a builder-produced value and perturbs one input.
fn prepared_context_cases() -> Value {
    let owner = shielded_keypair(&OWNER_SECRET, &TRANSFER_VIEWING_SEED);
    let zone = address(MERGE_ZONE_BYTE);
    let other = shielded_keypair(&OTHER_SECRET, &RECIPIENT_VIEWING_SEED);
    let clean = |zone_bound: bool| {
        let mut spec = MergeInputSpec::new(100, 0);
        if zone_bound {
            spec.zone = Some(zone);
        }
        merge_input(&spec, &owner, &other)
    };

    let cases = [
        ("plainDataHash", "plain", "dataHash"),
        ("plainZoneDataHash", "plain", "zoneDataHash"),
        ("plainInlineUtxoData", "plain", "utxoData"),
        ("zoneDataHash", "zone", "dataHash"),
        ("zoneZoneDataHash", "zone", "zoneDataHash"),
        ("zoneInlineUtxoData", "zone", "utxoData"),
        ("zoneForeignZone", "zone", "foreignZone"),
    ];

    Value::Array(
        cases
            .iter()
            .map(|(name, rail, perturbation)| {
                let perturb = |input: &mut SppProofInputUtxo| match *perturbation {
                    "dataHash" => input.data_hash = Some(MERGE_DATA_HASH),
                    "zoneDataHash" => input.zone_data_hash = Some(MERGE_ZONE_DATA_HASH),
                    "utxoData" => input.utxo.data = merge_data(&["utxoData"]),
                    "foreignZone" => input.utxo.zone_program_id = Some(address(29)),
                    other => panic!("unknown perturbation {other}"),
                };
                let contexts = if *rail == "zone" {
                    let mut prepared = MergeZone::new(&owner, vec![clean(true)], zone, None)
                        .expect("merge zone")
                        .prepare();
                    perturb(prepared.inputs.first_mut().expect("prepared input"));
                    prepared.input_utxo_hashes()
                } else {
                    let mut prepared = Merge::new(&owner, vec![clean(false)])
                        .expect("merge")
                        .prepare();
                    perturb(prepared.inputs.first_mut().expect("prepared input"));
                    prepared.input_utxo_hashes()
                };
                json!({
                    "name": name,
                    "rail": rail,
                    "perturbation": perturbation,
                    "error": contexts.as_ref().err().map(ts_code),
                    "inputContexts": contexts.map_or(Value::Null, |contexts| {
                        Value::Array(
                            contexts
                                .iter()
                                .map(|context| {
                                    json!({
                                        "index": context.index,
                                        "utxoHashHex": hex(&context.utxo_hash),
                                        "nullifierHex": hex(&context.nullifier),
                                    })
                                })
                                .collect(),
                        )
                    }),
                })
            })
            .collect(),
    )
}

struct SplitCase {
    name: &'static str,
    input: MergeInputSpec,
    asset: Address,
    num_outputs: u8,
    per_output_amount: u64,
    dummy_input: bool,
}

impl SplitCase {
    fn plain(name: &'static str, amount: u64, num_outputs: u8, per_output_amount: u64) -> Self {
        Self {
            name,
            input: MergeInputSpec::new(amount, 0),
            asset: SOL_MINT,
            num_outputs,
            per_output_amount,
            dummy_input: false,
        }
    }
}

/// The split builder's accept and reject set. The blinding seed is random, so
/// this pins the decision plus the deterministic products: the per-slot amounts,
/// the first nullifier, the owner view tag, and the payer hash.
fn split_section() -> Value {
    let owner = shielded_keypair(&OWNER_SECRET, &TRANSFER_VIEWING_SEED);
    let other = shielded_keypair(&OTHER_SECRET, &RECIPIENT_VIEWING_SEED);
    let payer = address(PAYER_BYTE);
    let spl_mint = address(SPL_MINT_BYTE);
    let perturbed = |mut case: SplitCase, apply: &dyn Fn(&mut SplitCase)| {
        apply(&mut case);
        case
    };

    let cases = [
        SplitCase::plain("twoEqualParts", 100, 2, 50),
        SplitCase::plain("eightEqualParts", 80, 8, 10),
        SplitCase::plain("zeroValueSplit", 0, 2, 0),
        SplitCase::plain("maxPerOutput", u64::MAX, 1, u64::MAX),
        SplitCase::plain("onePart", 100, 1, 100),
        SplitCase::plain("ninePartsRequested", 90, 9, 10),
        SplitCase::plain("zeroParts", 100, 0, 0),
        SplitCase::plain("amountMismatch", 100, 3, 30),
        SplitCase::plain("productOverflows", 8, 8, u64::MAX),
        perturbed(SplitCase::plain("dummyInput", 100, 2, 50), &|case| {
            case.dummy_input = true;
        }),
        perturbed(SplitCase::plain("foreignOwner", 100, 2, 50), &|case| {
            case.input.owner = "other";
        }),
        perturbed(
            SplitCase::plain("foreignNullifierKey", 100, 2, 50),
            &|case| {
                case.input.nullifier = "other";
            },
        ),
        perturbed(SplitCase::plain("assetMismatch", 100, 2, 50), &|case| {
            case.asset = spl_mint;
        }),
        perturbed(SplitCase::plain("zoneBoundInput", 100, 2, 50), &|case| {
            case.input.zone = Some(address(MERGE_ZONE_BYTE));
        }),
        perturbed(SplitCase::plain("inputWithData", 100, 2, 50), &|case| {
            case.input.records = vec!["utxoData"];
        }),
        perturbed(SplitCase::plain("inputWithDataHash", 100, 2, 50), &|case| {
            case.input.data_hash = true;
        }),
    ];

    let cases = cases
        .iter()
        .map(|case| {
            let input = if case.dummy_input {
                SppProofInputUtxo::new_dummy()
            } else {
                merge_input(&case.input, &owner, &other)
            };
            let prepared = ConfidentialSplit::new(
                owner.shielded_address().expect("shielded address"),
                input,
                case.asset,
                case.num_outputs,
                case.per_output_amount,
                payer,
            )
            .and_then(ConfidentialSplit::prepare);
            let mut json_case = Map::new();
            json_case.insert("name".into(), json!(case.name));
            json_case.insert("asset".into(), json!(case.asset.to_string()));
            json_case.insert("numOutputs".into(), json!(case.num_outputs));
            json_case.insert(
                "perOutputAmount".into(),
                json!(case.per_output_amount.to_string()),
            );
            json_case.insert("dummyInput".into(), json!(case.dummy_input));
            json_case.insert("input".into(), case.input.json());
            match prepared {
                Ok(prepared) => {
                    json_case.insert("error".into(), Value::Null);
                    json_case.insert(
                        "outputAmounts".into(),
                        Value::Array(
                            prepared
                                .outputs
                                .iter()
                                .map(|output| json!(output.amount.to_string()))
                                .collect(),
                        ),
                    );
                    json_case.insert(
                        "firstNullifierHex".into(),
                        json!(hex(&prepared.first_nullifier)),
                    );
                    json_case.insert(
                        "ownerViewTagHex".into(),
                        json!(hex(&prepared.owner_view_tag().expect("owner view tag"))),
                    );
                    json_case.insert(
                        "payerPublicKeyHashHex".into(),
                        json!(hex(&prepared.payer_pubkey_hash)),
                    );
                }
                Err(error) => {
                    json_case.insert("error".into(), json!(ts_code(&error)));
                    for field in [
                        "outputAmounts",
                        "firstNullifierHex",
                        "ownerViewTagHex",
                        "payerPublicKeyHashHex",
                    ] {
                        json_case.insert(field.into(), Value::Null);
                    }
                }
            }
            Value::Object(json_case)
        })
        .collect::<Vec<_>>();

    json!({ "payer": payer.to_string(), "cases": cases })
}

/// The field encodings a proof's public inputs carry. `signed_to_field` wraps a
/// negative amount around the BN254 modulus, which is the only place the SDK
/// depends on the modulus value itself.
fn fields_section() -> Value {
    let signed = [
        0i64,
        1,
        -1,
        500,
        -500,
        i64::MAX,
        i64::MIN,
        i64::MIN + 1,
        u32::MAX as i64,
    ]
    .iter()
    .map(|value| {
        json!({
            "value": value.to_string(),
            "fieldHex": hex(&signed_to_field(*value)),
        })
    })
    .collect::<Vec<_>>();

    let assets = [SOL_MINT, address(SPL_MINT_BYTE), address(255)]
        .iter()
        .map(|asset| {
            json!({
                "asset": asset.to_string(),
                "fieldHex": hex(&asset_field(asset).expect("asset field")),
            })
        })
        .collect::<Vec<_>>();

    json!({
        "bn254Modulus": BN254_MODULUS_DEC,
        "signedToField": signed,
        "assetField": assets,
    })
}

fn slots_section() -> Value {
    let cases = [
        0usize,
        1,
        2,
        7,
        255,
        65_535,
        u32::MAX as usize,
        u32::MAX as usize + 1,
    ]
    .iter()
    .map(|position| match slot_ordinal(*position) {
        Ok(ordinal) => json!({
            "position": position.to_string(),
            "ordinal": ordinal,
            "error": Value::Null,
        }),
        Err(error) => json!({
            "position": position.to_string(),
            "ordinal": Value::Null,
            "error": ts_code(&error),
        }),
    })
    .collect::<Vec<_>>();
    json!({ "ordinals": cases })
}

fn oracle() -> Value {
    json!({
        "schema": "zolana-transaction-parity-oracle-v1",
        "generator": "ZOLANA_WRITE_TS_ORACLES=1 cargo test -p zolana-transaction --test ts_oracle",
        "errors": errors_section(),
        "data": data_section(),
        "scheme": scheme_section(),
        "shape": shape_section(),
        "asset": asset_section(),
        "utxo": utxo_section(),
        "fields": fields_section(),
        "slots": slots_section(),
        "transfer": transfer_section(),
        "merge": merge_section(),
        "split": split_section(),
        "serialization": serialization_section(),
        "fromUtxos": from_utxos_section(),
        "transactTypes": transact_types_section(),
        "zoneAuthority": zone_authority_section(),
        "decrypt": decrypt_section(),
    })
}

const DECRYPT_USER_VIEWING_SEED: [u8; 32] = [31u8; 32];
const DECRYPT_TX_VIEWING_SEED: [u8; 32] = [37u8; 32];
const DECRYPT_SALT: [u8; SALT_LEN] = [3u8; SALT_LEN];
const DECRYPT_SLOT_INDEX: u32 = 2;

/// The reader half of the two encrypted rails. A published slot is bytes an
/// attacker chose, so which category the reader rejects them under is part of
/// the protocol: a scanner that skips a slot on one category and aborts the
/// wallet sync on another must see the same category in both languages.
fn decrypt_section() -> Value {
    let user = ViewingKey::from_bytes(&DECRYPT_USER_VIEWING_SEED).expect("user viewing key");
    let tx = ViewingKey::from_bytes(&DECRYPT_TX_VIEWING_SEED).expect("tx viewing key");
    json!({
        "userViewingSeedHex": hex(&DECRYPT_USER_VIEWING_SEED),
        "txViewingSeedHex": hex(&DECRYPT_TX_VIEWING_SEED),
        "saltHex": hex(&DECRYPT_SALT),
        "slotIndex": DECRYPT_SLOT_INDEX,
        "merge": merge_decrypt_cases(&user, &tx),
        "confidential": confidential_decrypt_cases(&user, &tx),
    })
}

/// Bodies are built by perturbing one the rail itself produced, so a case that
/// should decrypt proves the two languages derive the same key from the same
/// seeds rather than merely failing in the same way.
fn merge_decrypt_cases(user: &ViewingKey, tx: &ViewingKey) -> Value {
    let plaintext = MergePlaintext {
        amount: 1_234,
        asset_field: hash_field(&SOL_MINT.to_bytes()).expect("asset field"),
        blinding: [11u8; BLINDING_LEN],
    };
    let bytes = MergeSerialization::serialize(&plaintext).expect("serialize merge");
    let body = MergeSerialization::encrypt(
        &bytes,
        &MergeEncode {
            tx: tx.clone(),
            user_viewing_pk: user.pubkey(),
        },
    )
    .expect("encrypt merge");

    let cases = perturbations(&body)
        .into_iter()
        .map(|(name, body)| {
            let cx = DecodeCx {
                viewing_key: user,
                tx_viewing_pk: None,
                salt: None,
                slot_index: 0,
                first_nullifier: None,
            };
            let decoded = MergeSerialization::decode(&body, &cx).map(|plaintext| {
                json!({
                    "amount": plaintext.amount.to_string(),
                    "assetFieldHex": hex(&plaintext.asset_field),
                    "blindingHex": hex(&plaintext.blinding),
                })
            });
            decrypt_case_json(name, &body, decoded)
        })
        .collect::<Vec<_>>();
    Value::Array(cases)
}

fn confidential_decrypt_cases(user: &ViewingKey, tx: &ViewingKey) -> Value {
    let plaintext = ConfidentialOutputPlaintext {
        asset_id: SOL_ASSET_ID,
        amount: 77,
        blinding: [11u8; BLINDING_LEN],
        zone_program_id: None,
        data: Data::default(),
    };
    let bytes = plaintext.serialize().expect("serialize confidential");
    let body = Confidential::encrypt(
        &bytes,
        &ConfidentialEncode {
            tx: tx.clone(),
            recipient_pubkey: user.pubkey(),
            salt: DECRYPT_SALT,
            slot_index: DECRYPT_SLOT_INDEX,
        },
    )
    .expect("encrypt confidential");

    let mut variants = perturbations(&body);
    // The slot index and the salt are bound into the key, so a scanner that
    // tries the wrong slot must fail the same way in both languages.
    variants.push(("wrongSlotIndex", body.clone()));
    let wrong_slot = variants.len() - 1;

    let cases = variants
        .into_iter()
        .enumerate()
        .map(|(index, (name, body))| {
            let cx = DecodeCx {
                viewing_key: user,
                tx_viewing_pk: Some(tx.pubkey()),
                salt: Some(DECRYPT_SALT),
                slot_index: if index == wrong_slot {
                    DECRYPT_SLOT_INDEX + 1
                } else {
                    DECRYPT_SLOT_INDEX
                },
                first_nullifier: None,
            };
            let decoded = Confidential::decode(&body, &cx).map(|plaintext| {
                json!({
                    "assetId": plaintext.asset_id.to_string(),
                    "amount": plaintext.amount.to_string(),
                    "blindingHex": hex(&plaintext.blinding),
                })
            });
            let mut case = decrypt_case_json(name, &body, decoded);
            if index == wrong_slot {
                case["slotIndex"] = json!(DECRYPT_SLOT_INDEX + 1);
            }
            case
        })
        .collect::<Vec<_>>();
    Value::Array(cases)
}

/// The malformed bodies both rails share: an embedded public key that is
/// absent, truncated, or off the curve, and a ciphertext whose length no longer
/// matches the plaintext the rail expects.
fn perturbations(body: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let mut off_curve = body.to_vec();
    off_curve[..33].fill(0xff);
    let mut flipped = body.to_vec();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    vec![
        ("valid", body.to_vec()),
        ("empty", Vec::new()),
        ("publicKeyTruncated", body[..32].to_vec()),
        ("publicKeyOnly", body[..33].to_vec()),
        ("publicKeyOffCurve", off_curve),
        ("ciphertextTruncated", body[..body.len() - 1].to_vec()),
        ("ciphertextExtraByte", [body, &[0u8]].concat()),
        ("ciphertextBitFlipped", flipped),
    ]
}

fn decrypt_case_json(name: &str, body: &[u8], decoded: Result<Value, TransactionError>) -> Value {
    let mut case = Map::new();
    case.insert("name".into(), json!(name));
    case.insert("bodyHex".into(), json!(hex(body)));
    match decoded {
        Ok(plaintext) => {
            case.insert("plaintext".into(), plaintext);
            case.insert("error".into(), Value::Null);
        }
        Err(error) => {
            case.insert("plaintext".into(), Value::Null);
            case.insert("error".into(), error_json(&error));
        }
    }
    Value::Object(case)
}

/// The code plus the two length fields, which are the only error details these
/// paths carry and the ones a caller reads to decide whether to retry.
fn error_json(error: &TransactionError) -> Value {
    let (expected, actual) = match error {
        TransactionError::InvalidLength { expected, actual } => (json!(expected), json!(actual)),
        _ => (Value::Null, Value::Null),
    };
    json!({ "code": ts_code(error), "expected": expected, "actual": actual })
}

/// `PreparedZoneAuthority`: the unsigned rail whose only containment is the
/// pinned zone, so every acceptance and rejection here is load-bearing.
fn zone_authority_section() -> Value {
    struct Case {
        name: &'static str,
        /// Zone carried by the real input and output; `None` leaves them unbound.
        input_zone: Option<Address>,
        output_zone: Option<Address>,
        pinned_zone: Address,
        public_sol: Option<i64>,
        /// Extra dummy slots appended past the two the padded pair already has.
        extra_outputs: usize,
    }
    let owner = shielded_keypair(&OWNER_SECRET, &TRANSFER_VIEWING_SEED);
    let zone = address(MERGE_ZONE_BYTE);
    let other_zone = address(MERGE_ZONE_BYTE + 1);
    let payer = address(PAYER_BYTE);
    let case = |name, input_zone, output_zone, pinned_zone, public_sol, extra_outputs| Case {
        name,
        input_zone,
        output_zone,
        pinned_zone,
        public_sol,
        extra_outputs,
    };
    let cases = [
        case("zoneBound", Some(zone), Some(zone), zone, None, 0),
        case(
            "unpinnedZone",
            Some(zone),
            Some(zone),
            Address::default(),
            None,
            0,
        ),
        case(
            "inputOutsideZone",
            Some(other_zone),
            Some(zone),
            zone,
            None,
            0,
        ),
        case("inputUnbound", None, Some(zone), zone, None, 0),
        case(
            "outputOutsideZone",
            Some(zone),
            Some(other_zone),
            zone,
            None,
            0,
        ),
        case("outputUnbound", Some(zone), None, zone, None, 0),
        case("depositLeg", Some(zone), Some(zone), zone, Some(500), 0),
        case("withdrawalLeg", Some(zone), Some(zone), zone, Some(-500), 0),
        // 2 inputs by 5 outputs names no proving system.
        case("unsupportedShape", Some(zone), Some(zone), zone, None, 3),
    ];

    Value::Array(
        cases
            .iter()
            .map(|case| {
                let inputs = vec![
                    zone_authority_input(&owner, case.input_zone),
                    SppProofInputUtxo::new_dummy(),
                ];
                let mut outputs = vec![
                    zone_authority_output(&owner, case.output_zone),
                    SppProofOutputUtxo::default(),
                ];
                outputs.extend((0..case.extra_outputs).map(|_| SppProofOutputUtxo::default()));
                let external_data = match case.public_sol {
                    Some(amount) => {
                        ExternalData::new([0u8; 33], [0u8; 16], Vec::new(), Vec::new(), Vec::new())
                            .with_public_sol(amount, Address::default())
                            .expect("public sol leg")
                    }
                    None => {
                        ExternalData::new([0u8; 33], [0u8; 16], Vec::new(), Vec::new(), Vec::new())
                    }
                };
                let prepared = PreparedZoneAuthority::new(
                    case.pinned_zone,
                    inputs,
                    outputs,
                    external_data,
                    payer,
                );
                let contexts = prepared
                    .as_ref()
                    .ok()
                    .map(|prepared| context_json(&prepared.input_utxo_hashes().expect("contexts")));
                json!({
                    "name": case.name,
                    "inputZone": case.input_zone.map(|id| id.to_string()),
                    "outputZone": case.output_zone.map(|id| id.to_string()),
                    "pinnedZone": case.pinned_zone.to_string(),
                    "publicSol": case.public_sol.map(|amount| amount.to_string()),
                    "extraOutputs": case.extra_outputs,
                    "error": prepared.as_ref().err().map(ts_code),
                    "index": match &prepared {
                        Err(TransactionError::ZoneAuthorityInputZoneMismatch { index })
                        | Err(TransactionError::ZoneAuthorityOutputZoneMismatch { index }) => {
                            json!(index)
                        }
                        _ => Value::Null,
                    },
                    "shape": prepared.as_ref().ok().map(|prepared| json!({
                        "inputs": prepared.shape.n_inputs(),
                        "outputs": prepared.shape.n_outputs(),
                    })),
                    "payerPublicKeyHashHex": prepared
                        .as_ref()
                        .ok()
                        .map(|prepared| hex(&prepared.payer_pubkey_hash)),
                    "inputContexts": contexts,
                })
            })
            .collect(),
    )
}

fn zone_authority_input(
    owner: &ShieldedKeypair,
    zone_program_id: Option<Address>,
) -> SppProofInputUtxo {
    SppProofInputUtxo::new(
        Utxo {
            owner: owner.signing_key.pubkey(),
            asset: SOL_MINT,
            amount: 500,
            blinding: TRANSACT_TYPES_BLINDING,
            zone_program_id,
            data: Data::default(),
        },
        owner,
    )
}

fn zone_authority_output(
    owner: &ShieldedKeypair,
    zone_program_id: Option<Address>,
) -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        asset: SOL_MINT,
        amount: 500,
        blinding: TRANSACT_TYPES_BLINDING,
        zone_program_id,
        owner_address: Some(owner.shielded_address().expect("shielded address")),
        ..Default::default()
    }
}

const TRANSACT_TYPES_BLINDING: [u8; BLINDING_LEN] = [23; BLINDING_LEN];
const TRANSACT_TYPES_EXTERNAL_HASH: [u8; 32] = [5; 32];

/// `InputUtxo`, `SppProofOutputUtxo`, `PrivateTxHash`, and `EncryptedTransaction`:
/// the four transaction types whose behaviour is not reachable through a builder.
fn transact_types_section() -> Value {
    let owner = shielded_keypair(&OWNER_SECRET, &TRANSFER_VIEWING_SEED);
    let nullifier_pk = owner.nullifier_key.pubkey().expect("nullifier public key");
    let external_data = ExternalData::new([0u8; 33], [0u8; 16], Vec::new(), Vec::new(), Vec::new());

    json!({
        "blindingHex": hex(&TRANSACT_TYPES_BLINDING),
        "externalDataHashHex": hex(&TRANSACT_TYPES_EXTERNAL_HASH),
        "nullifierPublicKeyHex": hex(&nullifier_pk),
        "privateTxHashes": private_tx_hash_cases(),
        "inputUtxos": input_utxo_cases(&owner, &nullifier_pk),
        "outputBuilders": output_builder_cases(&owner),
        "encryptedTransaction": encrypted_transaction_cases(&owner, &nullifier_pk, &external_data),
        "emptyExternalData": json!({
            "instructionDiscriminator": external_data.instruction_discriminator,
            "expiryUnixTs": external_data.expiry_unix_ts.to_string(),
            "relayerFee": external_data.relayer_fee,
            "hashHex": hex(&external_data.hash().expect("external data hash")),
        }),
    })
}

fn private_tx_hash_cases() -> Value {
    struct Case {
        name: &'static str,
        inputs: usize,
        outputs: usize,
        /// Address-hash count and the byte every one of them is filled with.
        addresses: Option<(usize, u8)>,
    }
    let case = |name, inputs, outputs, addresses| Case {
        name,
        inputs,
        outputs,
        addresses,
    };
    // The last case's address hash exceeds the BN254 modulus, which pins the
    // error category Poseidon failures report.
    let cases = [
        case("empty", 0, 0, None),
        case("oneInputOneOutput", 1, 1, None),
        case("twoInputsThreeOutputs", 2, 3, None),
        case("addressHashesPaired", 2, 1, Some((2, 8))),
        case("addressHashesShort", 2, 1, Some((1, 8))),
        case("addressHashesLong", 1, 1, Some((2, 8))),
        case("addressHashOutOfField", 1, 1, Some((1, 0xf0))),
    ];

    Value::Array(
        cases
            .iter()
            .map(|case| {
                let name = case.name;
                let input_hashes = filled_hashes(case.inputs, 1);
                let output_hashes = filled_hashes(case.outputs, 40);
                let address_hashes = case
                    .addresses
                    .map(|(count, first_byte)| filled_hashes(count, first_byte));
                let mut private_tx = PrivateTxHash::new(
                    &input_hashes,
                    &output_hashes,
                    &TRANSACT_TYPES_EXTERNAL_HASH,
                );
                private_tx.address_hashes = address_hashes.as_deref();
                let outcome = private_tx.hash();
                json!({
                    "name": name,
                    "inputHashesHex": hex_all(&input_hashes),
                    "outputHashesHex": hex_all(&output_hashes),
                    "addressHashesHex": address_hashes.as_ref().map(|hashes| hex_all(hashes)),
                    "hashHex": outcome.as_ref().ok().map(|hash| hex(hash)),
                    "error": outcome.as_ref().err().map(ts_code),
                    "expected": match &outcome {
                        Err(TransactionError::AddressHashCountMismatch { expected, .. }) => {
                            json!(expected)
                        }
                        _ => Value::Null,
                    },
                    "actual": match &outcome {
                        Err(TransactionError::AddressHashCountMismatch { actual, .. }) => {
                            json!(actual)
                        }
                        _ => Value::Null,
                    },
                })
            })
            .collect(),
    )
}

fn filled_hashes(count: usize, first_byte: u8) -> Vec<[u8; 32]> {
    (0..count)
        .map(|index| [first_byte + index as u8; 32])
        .collect()
}

fn hex_all(hashes: &[[u8; 32]]) -> Vec<String> {
    hashes.iter().map(|hash| hex(hash)).collect()
}

fn transact_types_input(
    owner: &ShieldedKeypair,
    nullifier_pk: &[u8; 32],
    zone: bool,
    data_hash: bool,
    zone_data_hash: bool,
) -> InputUtxo {
    InputUtxo {
        utxo: Utxo {
            owner: owner.signing_key.pubkey(),
            asset: SOL_MINT,
            amount: 100,
            blinding: TRANSACT_TYPES_BLINDING,
            zone_program_id: zone.then(|| address(MERGE_ZONE_BYTE)),
            data: Data::default(),
        },
        nullifier_pk: *nullifier_pk,
        zone_data_hash: zone_data_hash.then_some(MERGE_ZONE_DATA_HASH),
        data_hash: data_hash.then_some(MERGE_DATA_HASH),
    }
}

fn input_utxo_cases(owner: &ShieldedKeypair, nullifier_pk: &[u8; 32]) -> Value {
    let cases: [(&str, bool, bool, bool); 4] = [
        ("bare", false, false, false),
        ("dataHash", false, true, false),
        ("zoneBound", true, false, true),
        ("bothHashes", true, true, true),
    ];

    Value::Array(
        cases
            .iter()
            .map(|(name, zone, data_hash, zone_data_hash)| {
                let input =
                    transact_types_input(owner, nullifier_pk, *zone, *data_hash, *zone_data_hash);
                json!({
                    "name": name,
                    "zone": zone.then(|| address(MERGE_ZONE_BYTE).to_string()),
                    "dataHash": data_hash,
                    "zoneDataHash": zone_data_hash,
                    "isDummy": input.is_dummy(),
                    "hashHex": hex(&input.hash().expect("input utxo hash")),
                })
            })
            .collect(),
    )
}

/// Payloads the output builders attach; the second of each kind must replace the
/// first rather than add a duplicate record.
fn output_builder_payload(op: &str) -> Vec<u8> {
    match op {
        "memoA" => vec![6],
        "memoB" => vec![9, 9],
        "utxoDataA" => vec![4, 5],
        "utxoDataB" => vec![7],
        "zoneDataA" => vec![1, 2, 3],
        other => panic!("unknown output builder op {other}"),
    }
}

fn output_builder_cases(owner: &ShieldedKeypair) -> Value {
    let sequences: [(&str, &[&str]); 9] = [
        ("bare", &[]),
        ("memo", &["memoA"]),
        ("memoReplaced", &["memoA", "memoB"]),
        ("utxoDataReplaced", &["utxoDataA", "utxoDataB"]),
        ("memoThenUtxoData", &["memoA", "utxoDataA"]),
        ("memoThenZoneData", &["memoA", "zoneDataA"]),
        ("allThreeOutOfOrder", &["memoA", "zoneDataA", "utxoDataA"]),
        ("zoneProgramIdOnly", &["zoneProgramId"]),
        ("zoneDataHashOnly", &["zoneDataHash"]),
    ];
    let address = owner.shielded_address().expect("shielded address");
    let zone = self::address(MERGE_ZONE_BYTE);

    Value::Array(
        sequences
            .iter()
            .map(|(name, ops)| {
                let mut output = SppProofOutputUtxo {
                    asset: SOL_MINT,
                    amount: 100,
                    blinding: TRANSACT_TYPES_BLINDING,
                    owner_address: Some(address),
                    ..Default::default()
                };
                for op in *ops {
                    output = match *op {
                        "memoA" | "memoB" => output.with_memo(output_builder_payload(op)),
                        "utxoDataA" | "utxoDataB" => {
                            output.with_utxo_data(output_builder_payload(op), MERGE_DATA_HASH)
                        }
                        "zoneDataA" => output.with_zone_data(
                            zone,
                            output_builder_payload(op),
                            MERGE_ZONE_DATA_HASH,
                        ),
                        "zoneProgramId" => output.with_zone_program_id(zone),
                        "zoneDataHash" => output.with_zone_data_hash(zone, MERGE_ZONE_DATA_HASH),
                        other => panic!("unknown output builder op {other}"),
                    };
                }
                json!({
                    "name": name,
                    "ops": ops,
                    "records": output
                        .data
                        .records
                        .iter()
                        .map(record_json)
                        .collect::<Vec<_>>(),
                    "dataHashHex": output.data_hash.as_ref().map(|hash| hex(hash)),
                    "zoneDataHashHex": output.zone_data_hash.as_ref().map(|hash| hex(hash)),
                    "zoneProgramId": output.zone_program_id.map(|id| id.to_string()),
                    "isDummy": output.is_dummy(),
                    "ownerHashHex": hex(&output.owner_hash().expect("owner hash")),
                    "hashHex": hex(&output.hash().expect("output hash")),
                })
            })
            .collect(),
    )
}

fn encrypted_transaction_cases(
    owner: &ShieldedKeypair,
    nullifier_pk: &[u8; 32],
    external_data: &ExternalData,
) -> Value {
    let real_output = SppProofOutputUtxo {
        asset: SOL_MINT,
        amount: 100,
        blinding: TRANSACT_TYPES_BLINDING,
        owner_address: Some(owner.shielded_address().expect("shielded address")),
        ..Default::default()
    };
    let cases: [(&str, bool, bool); 4] = [
        ("bothDummy", false, false),
        ("realInputDummyOutput", true, false),
        ("dummyInputRealOutput", false, true),
        ("bothReal", true, true),
    ];

    Value::Array(
        cases
            .iter()
            .map(|(name, real_input, real_output_slot)| {
                let input = if *real_input {
                    transact_types_input(owner, nullifier_pk, false, false, false)
                } else {
                    InputUtxo {
                        utxo: Utxo {
                            owner: PublicKey::zeroed(),
                            asset: Address::default(),
                            amount: 0,
                            blinding: TRANSACT_TYPES_BLINDING,
                            zone_program_id: None,
                            data: Data::default(),
                        },
                        nullifier_pk: [0u8; 32],
                        zone_data_hash: None,
                        data_hash: None,
                    }
                };
                let output = if *real_output_slot {
                    real_output.clone()
                } else {
                    SppProofOutputUtxo::default()
                };
                let transaction = EncryptedTransaction {
                    inputs: vec![input],
                    outputs: vec![output],
                    external_data: external_data.clone(),
                };
                json!({
                    "name": name,
                    "realInput": real_input,
                    "realOutput": real_output_slot,
                    "hashHex": hex(&transaction.hash().expect("transaction hash")),
                })
            })
            .collect(),
    )
}

fn oracle_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(ORACLE_PATH)
}

#[test]
fn every_variant_has_a_sample() {
    let samples = samples();
    let mut codes = samples
        .iter()
        .map(|(_, error)| ts_code(error))
        .collect::<Vec<_>>();
    codes.sort_unstable();
    let before = codes.len();
    codes.dedup();
    assert_eq!(
        codes.len(),
        before,
        "two samples map onto the same TypeScript code"
    );
}

#[test]
fn the_typescript_oracle_matches_current_rust() {
    let path = oracle_path();
    let generated = oracle();
    if std::env::var_os("ZOLANA_WRITE_TS_ORACLES").is_some() {
        fs::create_dir_all(path.parent().expect("oracle directory")).expect("create directory");
        fs::write(
            &path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&generated).expect("serialize oracle")
            ),
        )
        .expect("write oracle");
        return;
    }
    let committed: Value = serde_json::from_slice(
        &fs::read(&path).expect("read the committed oracle; regenerate it if this is a new file"),
    )
    .expect("parse the committed oracle");
    assert_eq!(
        committed, generated,
        "the committed oracle no longer matches Rust; regenerate it and re-run the TypeScript side"
    );
}
