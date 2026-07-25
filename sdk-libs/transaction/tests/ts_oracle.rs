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
use wincode;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_transaction::{
    derive_blinding,
    serialization::{confidential::ConfidentialOutputPlaintext, merge::MergePlaintext},
    instructions::transact::{canonical_shape, shape::resolve_shape, slot_ordinal, Shape},
    owner_utxo_hash, AssetRegistry, Data, DataRecord, EncryptedScheme, ProofInputUtxo,
    TransactionError, SOL_ASSET_ID, SOL_MINT,
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
        TransactionError::MergeInputOwnerMismatch { .. } => "TRANSACTION_MERGE_INPUT_OWNER_MISMATCH",
        TransactionError::MergeInputNullifierKeyMismatch { .. } => {
            "TRANSACTION_MERGE_INPUT_NULLIFIER_KEY_MISMATCH"
        }
        TransactionError::MergeInputAssetMismatch { .. } => "TRANSACTION_MERGE_INPUT_ASSET_MISMATCH",
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
        ("MissingZoneProgramId", TransactionError::MissingZoneProgramId),
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
        ("ZoneHashesAlreadySet", TransactionError::ZoneHashesAlreadySet),
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
        data_case(
            "duplicateMemo",
            &[("memo", vec![1]), ("memo", vec![2])],
        ),
        data_case(
            "duplicateZone",
            &[("zoneData", vec![1]), ("zoneData", vec![2])],
        ),
        data_case(
            "utxoBeforeZone",
            &[("utxoData", vec![1]), ("zoneData", vec![2])],
        ),
        data_case(
            "zoneAfterMemo",
            &[("memo", vec![0]), ("zoneData", vec![1])],
        ),
        data_case(
            "utxoAfterMemo",
            &[("memo", vec![0]), ("utxoData", vec![1])],
        ),
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
    case.insert(
        "declared".into(),
        declared.map_or(Value::Null, shape_json),
    );
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
            input.with_zone(case.zone_data_hash.unwrap_or_default(), &case.zone_program_id)
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
    })
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
                .map(|record| match record {
                    DataRecord::ZoneData(bytes) => json!({ "kind": "zoneData", "bytesHex": hex(bytes) }),
                    DataRecord::UtxoData(bytes) => json!({ "kind": "utxoData", "bytesHex": hex(bytes) }),
                    DataRecord::Memo(bytes) => json!({ "kind": "memo", "bytesHex": hex(bytes) }),
                })
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

    json!({ "confidential": confidential, "merge": merge })
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
        "slots": slots_section(),
        "serialization": serialization_section(),
    })
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
