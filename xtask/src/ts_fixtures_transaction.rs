use p256::SecretKey;
use serde_json::{json, Map, Value};
use zolana_interface::instruction::instruction_data::transact::InputUtxo as WireInputUtxo;
use zolana_keypair::{
    constants::{BLINDING_LEN, SALT_LEN},
    NullifierKey, P256Pubkey, PublicKey, ShieldedKeypair, SigningKey, ViewingKey,
};
use zolana_transaction::{
    instructions::{
        merge::{Merge as MergeBuilder, PreparedMerge, MERGE_INPUTS},
        merge_zone::{MergeZone, PreparedMergeZone},
        transact::{
            canonical_shape, encode_confidential_slots,
            shape::resolve_shape,
            signed_to_field,
            split::ConfidentialSplit,
            transfer::{ConfidentialTransfer, WithdrawalTarget},
            ExternalData, PrivateTxHash, SppProofInputs, SppProofOutputUtxo,
        },
        types::SppProofInputUtxo,
    },
    serialization::{
        anonymous::{
            AnonymousRecipient, AnonymousRecipientEncode, AnonymousSenderBundle,
            AnonymousSenderEncode, AnonymousTransferRecipientPlaintext,
            AnonymousTransferSenderPlaintext,
        },
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        merge::{Merge, MergeEncode, MergePlaintext},
        plaintext::{
            PlaintextEncode, PlaintextTransfer, TransferPlaintextRecipient,
            TransferPlaintextSender, TransferPlaintextSplChange, TransferPlaintextUtxos,
        },
        proofless::{Proofless, ProoflessEncode},
        split::{Split, SplitBundlePlaintext, SplitEncode, SplitEncryptedUtxos},
        DecodeCx, UtxoSerialization,
    },
    wallet::{LocalWalletAuthority, SyncWalletAuthority, WalletSyncMaterial},
    Address, AssetRegistry, Data, DataRecord, EncryptedScheme, Filter, OutputContext, OutputSlot,
    PrivateTransaction, PrivateTransactionDirection, PrivateTransactionId, PrivateTransactionKind,
    PrivateTransactionStatus, ShieldedTransaction, Utxo, Wallet, WalletUtxo, SOL_ASSET_ID,
    SOL_MINT,
};

const SIGNING_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
];
const VIEWING_SEED: [u8; 32] = [8; 32];
const TX_VIEWING_SEED: [u8; 32] = [9; 32];
const SALT: [u8; SALT_LEN] = [10; SALT_LEN];
const BLINDING_SEED: [u8; BLINDING_LEN] = [11; BLINDING_LEN];

fn main() {
    match sections() {
        Ok(value) => println!(
            "{}",
            serde_json::to_string(&value).expect("serialize fixture JSON")
        ),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn sections() -> Result<Value, Box<dyn std::error::Error>> {
    let keypair = fixed_keypair()?;
    let recipient = fixed_recipient()?;
    let mut sections = Map::new();
    sections.insert("data".into(), data_vectors()?);
    sections.insert("utxo".into(), utxo_vectors(&keypair)?);
    sections.insert(
        "serialization".into(),
        serialization_vectors(&keypair, &recipient)?,
    );
    sections.insert("transact".into(), transact_vectors(&keypair)?);
    sections.insert("transfer".into(), transfer_vectors(&keypair, &recipient)?);
    sections.insert("split".into(), split_vectors(&keypair)?);
    sections.insert("merge".into(), merge_vectors(&keypair)?);
    sections.insert("zone".into(), zone_vectors(&keypair)?);
    sections.insert("asset".into(), asset_vectors()?);
    sections.insert("authority".into(), authority_vectors(&keypair)?);
    sections.insert("wallet_state".into(), wallet_state_vectors(&keypair)?);
    sections.insert("wallet_sync".into(), wallet_sync_vectors(&keypair)?);
    sections.insert("tests".into(), assigned_test_vectors()?);
    Ok(Value::Object(sections))
}

fn fixed_keypair() -> Result<ShieldedKeypair, Box<dyn std::error::Error>> {
    Ok(ShieldedKeypair::from_keys(
        SigningKey::from_bytes(&SIGNING_SECRET)?,
        ViewingKey::from_seed(&VIEWING_SEED, 0)?,
    )?)
}

fn fixed_recipient() -> Result<ShieldedKeypair, Box<dyn std::error::Error>> {
    let mut secret = SIGNING_SECRET;
    secret[31] = 12;
    Ok(ShieldedKeypair::from_keys(
        SigningKey::from_bytes(&secret)?,
        ViewingKey::from_seed(&[13; 32], 0)?,
    )?)
}

fn fixed_utxo(keypair: &ShieldedKeypair, amount: u64, position: u8) -> Utxo {
    Utxo {
        owner: keypair.signing_pubkey(),
        asset: SOL_MINT,
        amount,
        blinding: zolana_transaction::derive_blinding(&BLINDING_SEED, position),
        zone_program_id: None,
        data: Data::default(),
    }
}

fn fixed_input(keypair: &ShieldedKeypair, amount: u64, position: u8) -> SppProofInputUtxo {
    SppProofInputUtxo::new(fixed_utxo(keypair, amount, position), keypair)
}

fn fixed_dummy(position: u8) -> SppProofInputUtxo {
    SppProofInputUtxo {
        utxo: Utxo {
            owner: PublicKey::zeroed(),
            asset: SOL_MINT,
            amount: 0,
            blinding: zolana_transaction::derive_blinding(&BLINDING_SEED, position),
            zone_program_id: None,
            data: Data::default(),
        },
        nullifier_key: NullifierKey::from_secret([0; BLINDING_LEN]),
        data_hash: None,
        zone_data_hash: None,
    }
}

fn marked_inputs(value: Value) -> Value {
    let mut object = value.as_object().cloned().unwrap_or_default();
    object.insert("testOnlySecret".into(), Value::Bool(true));
    Value::Object(object)
}

fn section(inputs: Value, expected: Value) -> Value {
    json!({"inputs": marked_inputs(inputs), "expected": expected})
}

fn error(error: &impl std::fmt::Debug) -> Value {
    let details = format!("{error:?}");
    let code = details.split(['(', ' ', '{']).next().unwrap_or("Unknown");
    json!({"code": code, "details": details})
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn data_json(data: &Data) -> Value {
    Value::Array(
        data.records
            .iter()
            .map(|record| match record {
                DataRecord::ZoneData(bytes) => {
                    json!({"tag": "ZoneData", "tagByte": "1", "bytes": hex(bytes)})
                }
                DataRecord::UtxoData(bytes) => {
                    json!({"tag": "UtxoData", "tagByte": "2", "bytes": hex(bytes)})
                }
                DataRecord::Memo(bytes) => {
                    json!({"tag": "Memo", "tagByte": "3", "bytes": hex(bytes)})
                }
            })
            .collect(),
    )
}

fn utxo_json(utxo: &Utxo) -> Value {
    json!({
        "ownerBytes": hex(utxo.owner.as_bytes()),
        "assetBytes": hex(utxo.asset.as_array()),
        "amount": utxo.amount.to_string(),
        "blindingBytes": hex(&utxo.blinding),
        "zoneProgramIdBytes": utxo.zone_program_id.map(|address| hex(address.as_array())),
        "data": data_json(&utxo.data)
    })
}

fn data_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    let data = Data::new(vec![
        DataRecord::ZoneData(vec![1, 2]),
        DataRecord::UtxoData(vec![3, 4, 5]),
        DataRecord::Memo(b"fixture memo".to_vec()),
    ]);
    data.validate()?;
    let bytes = wincode::serialize(&data)?;
    let decoded: Data = wincode::deserialize_exact(&bytes)?;
    assert_eq!(decoded, data);

    let duplicate = Data::new(vec![
        DataRecord::UtxoData(vec![1]),
        DataRecord::UtxoData(vec![2]),
    ])
    .validate()
    .expect_err("duplicate record");
    let order = Data::new(vec![
        DataRecord::Memo(vec![1]),
        DataRecord::ZoneData(vec![2]),
    ])
    .validate()
    .expect_err("non-canonical order");
    let mut trailing = bytes.clone();
    trailing.push(0xff);
    let trailing_error = wincode::deserialize_exact::<Data>(&trailing).expect_err("trailing bytes");
    let truncated_error =
        wincode::deserialize_exact::<Data>(&bytes[..bytes.len() - 1]).expect_err("truncated");

    Ok(section(
        json!({"records": data_json(&data)}),
        json!({
            "wincodeBytes": hex(&bytes),
            "recordCountPrefixBytes": hex(&bytes[..1]),
            "roundTripVerified": true,
            "accessors": {
                "zoneDataBytes": hex(data.zone_data().expect("zone data")),
                "utxoDataBytes": hex(data.utxo_data().expect("utxo data")),
                "memoBytes": hex(data.memo().expect("memo"))
            },
            "errors": [
                error(&duplicate),
                error(&order),
                error(&trailing_error),
                error(&truncated_error)
            ]
        }),
    ))
}

/// One case per field a zero-owner input has to leave zero. Each carries the
/// exact input Rust rejects, so the TypeScript port can rebuild it and prove it
/// rejects the same set for the same reason.
fn noncanonical_dummy_vectors(dummy: &SppProofInputUtxo) -> Value {
    let mut asset = dummy.clone();
    asset.utxo.asset = Address::new_from_array([7u8; 32]);
    let mut amount = dummy.clone();
    amount.utxo.amount = 1;
    let mut data = dummy.clone();
    data.utxo.data = Data::new(vec![DataRecord::UtxoData(vec![1, 2, 3])]);
    let mut zone_program_id = dummy.clone();
    zone_program_id.utxo.zone_program_id = Some(Address::new_from_array([8u8; 32]));
    let mut data_hash = dummy.clone();
    data_hash.data_hash = Some([9u8; 32]);
    let mut zone_data_hash = dummy.clone();
    zone_data_hash.zone_data_hash = Some([10u8; 32]);
    let mut nullifier_key = dummy.clone();
    nullifier_key.nullifier_key = NullifierKey::from_secret([11u8; BLINDING_LEN]);

    Value::Array(
        [
            asset,
            amount,
            data,
            zone_program_id,
            data_hash,
            zone_data_hash,
            nullifier_key,
        ]
        .iter()
        .map(|spend| {
            let rejection = spend.hash().expect_err("noncanonical dummy is rejected");
            json!({
                "utxo": utxo_json(&spend.utxo),
                "dataHashBytes": spend.data_hash.map(|hash| hex(&hash)),
                "zoneDataHashBytes": spend.zone_data_hash.map(|hash| hex(&hash)),
                "nullifierSecretBytes": hex(spend.nullifier_key.secret()),
                "error": error(&rejection)
            })
        })
        .collect(),
    )
}

fn utxo_vectors(keypair: &ShieldedKeypair) -> Result<Value, Box<dyn std::error::Error>> {
    let mut utxo = fixed_utxo(keypair, 42, 0);
    utxo.data = Data::new(vec![
        DataRecord::UtxoData(vec![1, 2, 3]),
        DataRecord::Memo(b"hello".to_vec()),
    ]);
    let nullifier_pk = keypair.nullifier_key.pubkey()?;
    let data_hash = [14; 32];
    let zone_data_hash = [0; 32];
    let proof = utxo.proof_input(&nullifier_pk, &data_hash, &zone_data_hash)?;
    let utxo_hash = proof.hash()?;
    let nullifier = utxo.nullifier(&utxo_hash, &keypair.nullifier_key)?;
    let owner_hash = zolana_keypair::hash::owner_hash(&utxo.owner, &nullifier_pk)?;
    let owner_utxo_hash = zolana_transaction::owner_utxo_hash(&owner_hash, &utxo.blinding)?;

    let dummy = fixed_dummy(255);
    let dummy_hash = dummy.hash()?;
    let dummy_nullifier = dummy.nullifier()?;
    assert!(dummy.is_dummy());

    let missing_zone = ConfidentialOutputPlaintext {
        asset_id: SOL_ASSET_ID,
        amount: 1,
        blinding: [1; BLINDING_LEN],
        zone_program_id: None,
        data: Data::new(vec![DataRecord::ZoneData(vec![1])]),
    }
    .into_utxo(keypair.signing_pubkey(), &AssetRegistry::default())
    .expect_err("zone data requires a program id");

    Ok(section(
        json!({
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "blindingSeedBytes": hex(&BLINDING_SEED),
            "utxo": utxo_json(&utxo),
            "dataHashBytes": hex(&data_hash)
        }),
        json!({
            "proofInput": {
                "domainBytes": hex(&proof.domain),
                "ownerHashBytes": hex(&proof.owner_hash),
                "assetBytes": hex(&proof.asset),
                "amountBytes": hex(&proof.amount),
                "blindingBytes": hex(&proof.blinding),
                "dataHashBytes": hex(&proof.data_hash),
                "zoneDataHashBytes": hex(&proof.zone_data_hash),
                "zoneProgramIdBytes": hex(&proof.zone_program_id)
            },
            "utxoHashBytes": hex(&utxo_hash),
            "nullifierBytes": hex(&nullifier),
            "ownerUtxoHashBytes": hex(&owner_utxo_hash),
            "dummy": {
                "isDummy": true,
                "utxo": utxo_json(&dummy.utxo),
                "nullifierSecretBytes": hex(dummy.nullifier_key.secret()),
                "hashBytes": hex(&dummy_hash),
                "nullifierBytes": hex(&dummy_nullifier),
                "rejected": noncanonical_dummy_vectors(&dummy)
            },
            "error": error(&missing_zone)
        }),
    ))
}

fn serialization_vectors(
    keypair: &ShieldedKeypair,
    recipient: &ShieldedKeypair,
) -> Result<Value, Box<dyn std::error::Error>> {
    let assets = AssetRegistry::default();
    let owner = keypair.signing_pubkey();
    let data = Data::new(vec![DataRecord::Memo(b"codec".to_vec())]);

    let confidential = ConfidentialOutputPlaintext {
        asset_id: SOL_ASSET_ID,
        amount: 55,
        blinding: zolana_transaction::derive_blinding(&BLINDING_SEED, 1),
        zone_program_id: None,
        data: data.clone(),
    };
    let confidential_bytes = confidential.serialize()?;
    assert_eq!(
        ConfidentialOutputPlaintext::deserialize(&confidential_bytes)?,
        confidential
    );
    let tx = ViewingKey::from_seed(&TX_VIEWING_SEED, 0)?;
    let confidential_cx = ConfidentialEncode {
        tx: tx.clone(),
        recipient_pubkey: recipient.viewing_pubkey(),
        salt: SALT,
        slot_index: 0,
    };
    let confidential_body = Confidential::encrypt(&confidential_bytes, &confidential_cx)?;
    let confidential_decode = DecodeCx {
        viewing_key: &recipient.viewing_key,
        tx_viewing_pk: Some(tx.pubkey()),
        salt: Some(SALT),
        slot_index: 0,
        first_nullifier: None,
    };
    assert_eq!(
        Confidential::decode(&confidential_body, &confidential_decode)?,
        confidential
    );
    let confidential_envelope =
        Confidential::encode_plaintext(&confidential, [1; 32], &confidential_cx)?;

    let anonymous_recipient = AnonymousTransferRecipientPlaintext {
        owner_pubkey: recipient.signing_pubkey(),
        sender_pubkey: keypair.viewing_pubkey(),
        asset_id: SOL_ASSET_ID,
        amount: 19,
        blinding: zolana_transaction::derive_blinding(&BLINDING_SEED, 2),
        data: data.clone(),
    };
    let anonymous_recipient_bytes = anonymous_recipient.serialize()?;
    assert_eq!(
        AnonymousTransferRecipientPlaintext::deserialize(&anonymous_recipient_bytes)?,
        anonymous_recipient
    );
    let anonymous_recipient_cx = AnonymousRecipientEncode {
        tx: tx.clone(),
        recipient_pubkey: recipient.viewing_pubkey(),
        sender_pubkey: keypair.viewing_pubkey(),
        salt: SALT,
        slot_index: 1,
    };
    let anonymous_recipient_body =
        AnonymousRecipient::encrypt(&anonymous_recipient_bytes, &anonymous_recipient_cx)?;
    let anonymous_recipient_decode = DecodeCx {
        viewing_key: &recipient.viewing_key,
        tx_viewing_pk: Some(tx.pubkey()),
        salt: Some(SALT),
        slot_index: 1,
        first_nullifier: None,
    };
    assert_eq!(
        AnonymousRecipient::decode(&anonymous_recipient_body, &anonymous_recipient_decode)?,
        anonymous_recipient
    );
    let anonymous_recipient_envelope = AnonymousRecipient::encode_plaintext(
        &anonymous_recipient,
        [2; 32],
        &anonymous_recipient_cx,
    )?;

    let anonymous_sender = AnonymousTransferSenderPlaintext {
        owner_pubkey: owner,
        spl_asset_id: 0,
        spl_amount: 0,
        sol_amount: 36,
        blinding_seed: BLINDING_SEED,
        recipient_viewing_pks: vec![recipient.viewing_pubkey()],
        spl_data: Data::default(),
        sol_data: data.clone(),
    };
    let anonymous_sender_bytes = anonymous_sender.serialize()?;
    assert_eq!(
        AnonymousTransferSenderPlaintext::deserialize(&anonymous_sender_bytes)?,
        anonymous_sender
    );
    let anonymous_sender_cx = AnonymousSenderEncode {
        tx: tx.clone(),
        self_pubkey: keypair.viewing_pubkey(),
        salt: SALT,
        slot_index: 2,
        blinding_seed: BLINDING_SEED,
        recipient_viewing_pks: vec![recipient.viewing_pubkey()],
    };
    let anonymous_sender_body =
        AnonymousSenderBundle::encrypt(&anonymous_sender_bytes, &anonymous_sender_cx)?;
    let anonymous_sender_decode = DecodeCx {
        viewing_key: &keypair.viewing_key,
        tx_viewing_pk: Some(tx.pubkey()),
        salt: Some(SALT),
        slot_index: 2,
        first_nullifier: None,
    };
    assert_eq!(
        AnonymousSenderBundle::decode(&anonymous_sender_body, &anonymous_sender_decode)?,
        anonymous_sender
    );
    let anonymous_sender_envelope =
        AnonymousSenderBundle::encode_plaintext(&anonymous_sender, [3; 32], &anonymous_sender_cx)?;

    let plaintext = TransferPlaintextUtxos {
        type_prefix: zolana_transaction::TRANSFER_PLAINTEXT,
        blinding_seed: BLINDING_SEED,
        sender: Some(TransferPlaintextSender {
            owner_pubkey: owner,
            spl: Some(TransferPlaintextSplChange {
                amount: 7,
                asset_id: SOL_ASSET_ID,
            }),
            sol_amount: Some(8),
            spl_data: Data::default(),
            sol_data: data.clone(),
        }),
        recipient_slots: vec![TransferPlaintextRecipient {
            owner_pubkey: recipient.signing_pubkey(),
            asset_id: SOL_ASSET_ID,
            amount: 9,
            data: data.clone(),
        }],
    };
    let plaintext_bytes = plaintext.serialize()?;
    assert_eq!(
        TransferPlaintextUtxos::deserialize(&plaintext_bytes)?,
        plaintext
    );
    let plaintext_cx = PlaintextEncode {
        blinding_seed: BLINDING_SEED,
    };
    let plaintext_envelope =
        PlaintextTransfer::encode_plaintext(&plaintext, [4; 32], &plaintext_cx)?;
    let mut bad_plaintext = plaintext_bytes.clone();
    bad_plaintext[0] = 0xff;
    let bad_plaintext_error =
        TransferPlaintextUtxos::deserialize(&bad_plaintext).expect_err("bad discriminator");

    let split = SplitBundlePlaintext {
        owner_pubkey: owner,
        num_outputs: 3,
        asset_id: SOL_ASSET_ID,
        asset_amount: 12,
        blinding_seed: BLINDING_SEED,
        data: data.clone(),
    };
    let split_bytes = split.serialize()?;
    assert_eq!(SplitBundlePlaintext::deserialize(&split_bytes)?, split);
    let split_cx = SplitEncode {
        tx: tx.clone(),
        recipient_pubkey: keypair.viewing_pubkey(),
        salt: SALT,
        slot_index: 3,
        blinding_seed: BLINDING_SEED,
    };
    let split_body = Split::encrypt(&split_bytes, &split_cx)?;
    let split_decode = DecodeCx {
        viewing_key: &keypair.viewing_key,
        tx_viewing_pk: Some(tx.pubkey()),
        salt: Some(SALT),
        slot_index: 3,
        first_nullifier: None,
    };
    assert_eq!(Split::decode(&split_body, &split_decode)?, split);
    let split_envelope = Split::encode_plaintext(&split, [5; 32], &split_cx)?;
    let split_encrypted = SplitEncryptedUtxos {
        type_prefix: zolana_transaction::SPLIT,
        tx_viewing_pk: ViewingKey::from_seed(&TX_VIEWING_SEED, 0)?.pubkey(),
        salt: SALT,
        ciphertext: vec![1, 2, 3, 4, 5],
    };
    let split_encrypted_bytes = split_encrypted.serialize()?;
    assert_eq!(
        SplitEncryptedUtxos::deserialize(&split_encrypted_bytes)?,
        split_encrypted
    );

    let merge = MergePlaintext {
        amount: 77,
        asset_field: zolana_keypair::hash::hash_field(SOL_MINT.as_array())?,
        blinding: zolana_transaction::derive_blinding(&BLINDING_SEED, 3),
    };
    let merge_bytes = merge.serialize()?;
    let merge_decoded = MergePlaintext::deserialize(&merge_bytes)?;
    assert_eq!(merge_decoded.amount, merge.amount);
    assert_eq!(merge_decoded.asset_field, merge.asset_field);
    assert_eq!(merge_decoded.blinding, merge.blinding);
    let merge_cx = MergeEncode {
        tx: tx.clone(),
        user_viewing_pk: keypair.viewing_pubkey(),
    };
    let merge_body = Merge::encrypt(&merge_bytes, &merge_cx)?;
    let merge_decode = DecodeCx {
        viewing_key: &keypair.viewing_key,
        tx_viewing_pk: None,
        salt: None,
        slot_index: 0,
        first_nullifier: None,
    };
    let merge_round_trip = Merge::decode(&merge_body, &merge_decode)?;
    assert_eq!(merge_round_trip.amount, merge.amount);
    assert_eq!(merge_round_trip.asset_field, merge.asset_field);
    assert_eq!(merge_round_trip.blinding, merge.blinding);
    let merge_envelope = Merge::encode_plaintext(&merge, [6; 32], &merge_cx)?;
    let merge_error = match MergePlaintext::deserialize(&merge_bytes[..merge_bytes.len() - 1]) {
        Ok(_) => panic!("short merge accepted"),
        Err(error) => error,
    };

    let proofless_utxo = fixed_utxo(keypair, 33, 4);
    let owner_cx = zolana_transaction::OwnerCx {
        owner,
        assets: &assets,
        zone_program_id: None,
    };
    let proofless_cx = ProoflessEncode {
        owner_hash: keypair.owner_hash()?,
        data_hash: None,
        zone_data_hash: None,
    };
    let proofless = Proofless::from_utxos(&[proofless_utxo.clone()], &owner_cx, &proofless_cx)?;
    let proofless_bytes = Proofless::serialize(&proofless)?;
    let proofless_decoded = Proofless::deserialize(&proofless_bytes)?;
    let proofless_utxos = Proofless::into_utxos(proofless_decoded, &owner_cx)?;
    assert_eq!(proofless_utxos, vec![proofless_utxo]);
    let proofless_envelope = Proofless::encode_plaintext(&proofless, [7; 32], &proofless_cx)?;
    let proofless_error = Proofless::deserialize(&proofless_bytes[..proofless_bytes.len() - 1])
        .expect_err("short borsh payload");

    let data_300 = Data::new(vec![DataRecord::Memo(vec![7; 300])]);
    let data_300_bytes = wincode::serialize(&data_300)?;
    assert_eq!(&data_300_bytes[2..4], &[44, 1]);
    let schemes = [0, 1, 2, 3, 5, 6, 7]
        .into_iter()
        .map(|byte| {
            let scheme = EncryptedScheme::from_byte(byte).expect("known scheme");
            json!({
                "byte": byte.to_string(),
                "name": format!("{scheme:?}"),
                "roundTripByte": scheme.as_byte().to_string()
            })
        })
        .collect::<Vec<_>>();

    Ok(section(
        json!({
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "txViewingSeedBytes": hex(&TX_VIEWING_SEED),
            "saltBytes": hex(&SALT),
            "blindingSeedBytes": hex(&BLINDING_SEED)
        }),
        json!({
            "schemes": schemes,
            "families": {
                "confidential": {
                    "wincodeBytes": hex(&confidential_bytes),
                    "encryptedBodyBytes": hex(&confidential_body),
                    "envelopeBorshBytes": hex(&confidential_envelope.data),
                    "roundTripVerified": true
                },
                "anonymousRecipient": {
                    "wincodeBytes": hex(&anonymous_recipient_bytes),
                    "encryptedBodyBytes": hex(&anonymous_recipient_body),
                    "envelopeBorshBytes": hex(&anonymous_recipient_envelope.data),
                    "roundTripVerified": true
                },
                "anonymousSender": {
                    "wincodeBytes": hex(&anonymous_sender_bytes),
                    "encryptedBodyBytes": hex(&anonymous_sender_body),
                    "envelopeBorshBytes": hex(&anonymous_sender_envelope.data),
                    "roundTripVerified": true
                },
                "plaintextTransfer": {
                    "wincodeBytes": hex(&plaintext_bytes),
                    "envelopeBorshBytes": hex(&plaintext_envelope.data),
                    "roundTripVerified": true
                },
                "split": {
                    "wincodeBytes": hex(&split_bytes),
                    "encryptedBodyBytes": hex(&split_body),
                    "envelopeBorshBytes": hex(&split_envelope.data),
                    "roundTripVerified": true
                },
                "splitEncrypted": {"wincodeBytes": hex(&split_encrypted_bytes), "ciphertextLengthPrefixBytes": "0500", "roundTripVerified": true},
                "merge": {
                    "fixedBytes": hex(&merge_bytes),
                    "encryptedBodyBytes": hex(&merge_body),
                    "envelopeBorshBytes": hex(&merge_envelope.data),
                    "roundTripVerified": true
                },
                "proofless": {
                    "borshBytes": hex(&proofless_bytes),
                    "envelopeBorshBytes": hex(&proofless_envelope.data),
                    "roundTripVerified": true
                },
                "dataLength300": {"wincodeBytes": hex(&data_300_bytes), "u16LengthPrefixBytes": "2c01"}
            },
            "errors": [
                error(&EncryptedScheme::from_byte(4).expect_err("reserved scheme")),
                error(&bad_plaintext_error),
                error(&merge_error),
                error(&proofless_error)
            ]
        }),
    ))
}

fn transact_vectors(keypair: &ShieldedKeypair) -> Result<Value, Box<dyn std::error::Error>> {
    let input = fixed_input(keypair, 100, 0);
    let output = SppProofOutputUtxo {
        owner_address: Some(keypair.shielded_address()?),
        owner_tag: Some(keypair.signing_pubkey().confidential_view_tag()?),
        asset: SOL_MINT,
        amount: 100,
        blinding: zolana_transaction::derive_blinding(&BLINDING_SEED, 1),
        ..Default::default()
    };
    let tx_viewing = ViewingKey::from_seed(&TX_VIEWING_SEED, 0)?;
    let external = ExternalData::new(
        *tx_viewing.pubkey().as_bytes(),
        SALT,
        vec![],
        vec![],
        vec![],
    )
    .with_public_sol(-5, Address::new_from_array([21; 32]))?
    .with_zone_hashes([22; 32], [23; 32])?;
    let external_hash = external.hash()?;
    let private_hash =
        PrivateTxHash::new(&[input.hash()?], &[output.hash()?], &external_hash).hash()?;
    let proof_inputs = SppProofInputs::new(
        vec![input.clone()],
        vec![output.clone()],
        external,
        Address::new_from_array([24; 32]),
    );
    let message_hash = proof_inputs.message_hash()?;
    let public = proof_inputs.public_amounts()?;
    let context = proof_inputs.input_utxo_hashes()?;
    let wire_input = WireInputUtxo {
        nullifier_hash: context[0].nullifier,
        nullifier_tree_root_index: 7,
        utxo_tree_root_index: 9,
        tree_index: 0,
        eddsa_signer_index: u8::MAX,
    };
    let wire_input_bytes = wincode::serialize(&wire_input)?;
    let wire_input_decoded: WireInputUtxo = wincode::deserialize_exact(&wire_input_bytes)?;
    assert_eq!(wire_input_decoded, wire_input);

    let shape_cases = [(1, 1), (1, 8), (2, 3), (5, 4)]
        .into_iter()
        .map(|(n_in, n_out)| {
            let shape = canonical_shape(n_in, n_out).expect("supported shape");
            json!({
                "requestedInputs": n_in.to_string(),
                "requestedOutputs": n_out.to_string(),
                "shapeInputs": shape.n_inputs().to_string(),
                "shapeOutputs": shape.n_outputs().to_string()
            })
        })
        .collect::<Vec<_>>();
    let unsupported = canonical_shape(9, 9).expect_err("unsupported shape");
    let too_many =
        resolve_shape(Some(canonical_shape(1, 1)?), 2, 1).expect_err("declared input capacity");

    Ok(section(
        json!({
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "txViewingSeedBytes": hex(&TX_VIEWING_SEED),
            "saltBytes": hex(&SALT),
            "payerBytes": hex(&[24; 32])
        }),
        json!({
            "shapeCases": shape_cases,
            "externalData": {
                "hashBytes": hex(&external_hash),
                "relayerFee": "0",
                "publicSolAmount": "-5",
                "dataHashBytes": hex(&[22; 32]),
                "zoneDataHashBytes": hex(&[23; 32]),
                "txViewingPkBytes": hex(tx_viewing.pubkey().as_bytes()),
                "saltBytes": hex(&SALT)
            },
            "proofInputs": {
                "messageHashBytes": hex(&message_hash),
                "privateTxHashBytes": hex(&private_hash),
                "payerPubkeyHashBytes": hex(&proof_inputs.payer_pubkey_hash),
                "publicSolFieldBytes": hex(&public.sol),
                "publicSplFieldBytes": hex(&public.spl),
                "signedNegativeFiveBytes": hex(&signed_to_field(-5)),
                "inputContexts": context.iter().map(|value| json!({
                    "index": value.index.to_string(),
                    "utxoHashBytes": hex(&value.utxo_hash),
                    "nullifierBytes": hex(&value.nullifier),
                    "wire": {
                        "nullifierHashBytes": hex(&wire_input.nullifier_hash),
                        "nullifierTreeRootIndex": wire_input.nullifier_tree_root_index.to_string(),
                        "utxoTreeRootIndex": wire_input.utxo_tree_root_index.to_string(),
                        "treeIndex": wire_input.tree_index.to_string(),
                        "eddsaSignerIndex": wire_input.eddsa_signer_index.to_string(),
                        "wincodeBytes": hex(&wire_input_bytes),
                        "roundTripVerified": true
                    }
                })).collect::<Vec<_>>()
            },
            "compressedP256ProofBoundary": {
                "commitmentBytesLength": "32",
                "commitmentPokBytesLength": "32"
            },
            "errors": [error(&unsupported), error(&too_many)]
        }),
    ))
}

fn transfer_vectors(
    keypair: &ShieldedKeypair,
    recipient: &ShieldedKeypair,
) -> Result<Value, Box<dyn std::error::Error>> {
    let input = fixed_input(keypair, 100, 0);
    let mint = Address::new_from_array([44; 32]);
    let token_input = SppProofInputUtxo::new(
        Utxo {
            asset: mint,
            amount: 60,
            blinding: zolana_transaction::derive_blinding(&BLINDING_SEED, 1),
            ..fixed_utxo(keypair, 0, 1)
        },
        keypair,
    );
    let payer = Address::new_from_array([25; 32]);
    let mut registry = AssetRegistry::default();
    registry.insert(2, mint)?;
    let mut transfer = ConfidentialTransfer::new(
        keypair.shielded_address()?,
        vec![input.clone(), token_input],
        payer,
    );
    transfer.blinding_seed = BLINDING_SEED;
    transfer.send(&recipient.shielded_address()?, SOL_MINT, 40)?;
    let prepared = transfer.prepare()?;
    let shape = prepared.shape;
    let first_nullifier = prepared.first_nullifier;
    let tx = ViewingKey::from_seed(&TX_VIEWING_SEED, 0)?;
    let slots = encode_confidential_slots(&prepared.outputs, &registry, &tx, SALT)?;
    assert!(slots.iter().all(Option::is_some));
    let proof_inputs = prepared.finalize(tx.pubkey(), SALT, slots)?;
    let external_data_hash = proof_inputs.external_data.hash()?;
    let message_hash = proof_inputs.message_hash()?;
    assert_eq!(
        proof_inputs
            .output_utxos
            .iter()
            .map(|value| value.amount)
            .sum::<u64>(),
        160
    );

    let mut insufficient =
        ConfidentialTransfer::new(keypair.shielded_address()?, vec![input.clone()], payer);
    insufficient.blinding_seed = BLINDING_SEED;
    insufficient.send(&recipient.shielded_address()?, SOL_MINT, 101)?;
    let insufficient_error = match insufficient.prepare() {
        Ok(_) => panic!("insufficient transfer accepted"),
        Err(error) => error,
    };

    let mut duplicate_withdrawal =
        ConfidentialTransfer::new(keypair.shielded_address()?, vec![input], payer);
    duplicate_withdrawal.blinding_seed = BLINDING_SEED;
    duplicate_withdrawal.withdraw(
        SOL_MINT,
        1,
        WithdrawalTarget::Sol {
            recipient: Address::new_from_array([26; 32]),
        },
    )?;
    let duplicate_withdrawal_error = match duplicate_withdrawal.withdraw(
        SOL_MINT,
        1,
        WithdrawalTarget::Sol {
            recipient: Address::new_from_array([26; 32]),
        },
    ) {
        Ok(_) => panic!("duplicate withdrawal accepted"),
        Err(error) => error,
    };

    Ok(section(
        json!({
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "blindingSeedBytes": hex(&BLINDING_SEED),
            "solInputAmount": "100",
            "splInputAmount": "60",
            "splMintBytes": hex(mint.as_array()),
            "recipientAmount": "40",
            "txViewingSeedBytes": hex(&TX_VIEWING_SEED),
            "saltBytes": hex(&SALT),
            "payerBytes": hex(&[25; 32])
        }),
        json!({
            "shape": {"inputs": shape.n_inputs().to_string(), "outputs": shape.n_outputs().to_string()},
            "firstNullifierBytes": hex(&first_nullifier),
            "outputs": proof_inputs.output_utxos.iter().enumerate().map(|(index, output)| json!({
                "slot": index.to_string(),
                "amount": output.amount.to_string(),
                "assetBytes": hex(output.asset.as_array()),
                "blindingBytes": hex(&output.blinding),
                "isDummy": output.is_dummy(),
                "ownerHashBytes": hex(&output.owner_hash().expect("owner hash")),
                "utxoHashBytes": hex(&output.hash().expect("output hash"))
            })).collect::<Vec<_>>(),
            "wireOutputs": proof_inputs.external_data.outputs.iter().enumerate().map(|(index, output)| json!({
                "slot": index.to_string(),
                "utxoHashBytes": hex(&output.utxo_hash),
                "ownerTag": format!("{:?}", output.owner_tag),
                "dataBytes": output.data.as_ref().map(|data| hex(data))
            })).collect::<Vec<_>>(),
            "resolvedOwnerTagBytes": proof_inputs.external_data.resolved_owner_tags.iter().map(|tag| hex(tag)).collect::<Vec<_>>(),
            "txViewingPkBytes": hex(tx.pubkey().as_bytes()),
            "externalDataHashBytes": hex(&external_data_hash),
            "messageHashBytes": hex(&message_hash),
            "conservedAmount": proof_inputs.output_utxos.iter().map(|output| output.amount).sum::<u64>().to_string(),
            "errors": [error(&insufficient_error), error(&duplicate_withdrawal_error)]
        }),
    ))
}

fn split_vectors(keypair: &ShieldedKeypair) -> Result<Value, Box<dyn std::error::Error>> {
    let input = fixed_input(keypair, 96, 0);
    let payer = Address::new_from_array([27; 32]);
    let mut split = ConfidentialSplit::new(
        keypair.shielded_address()?,
        input.clone(),
        SOL_MINT,
        3,
        32,
        payer,
    )?;
    split.blinding_seed = BLINDING_SEED;
    let prepared = split.prepare()?;
    let bundle = prepared.bundle_plaintext(&AssetRegistry::default())?;
    let bundle_bytes = bundle.serialize()?;
    let output_snapshot = prepared.outputs.clone();
    let first_nullifier = prepared.first_nullifier;
    let tx = ViewingKey::from_seed(&TX_VIEWING_SEED, 0)?;
    let bundle_message = Split::encode_plaintext(
        &bundle,
        prepared.owner_view_tag()?,
        &SplitEncode {
            tx: tx.clone(),
            recipient_pubkey: keypair.viewing_pubkey(),
            salt: SALT,
            slot_index: 0,
            blinding_seed: BLINDING_SEED,
        },
    )?;
    let proof_inputs = prepared.finalize(tx.pubkey(), SALT, bundle_message)?;
    let external_data_hash = proof_inputs.external_data.hash()?;
    assert_eq!(output_snapshot.len(), 8);
    assert_eq!(
        output_snapshot
            .iter()
            .map(|value| value.amount)
            .sum::<u64>(),
        96
    );

    let count_error = match ConfidentialSplit::new(
        keypair.shielded_address()?,
        input.clone(),
        SOL_MINT,
        1,
        96,
        payer,
    ) {
        Ok(_) => panic!("invalid part count accepted"),
        Err(error) => error,
    };
    let amount_error =
        match ConfidentialSplit::new(keypair.shielded_address()?, input, SOL_MINT, 3, 31, payer) {
            Ok(_) => panic!("invalid amount accepted"),
            Err(error) => error,
        };

    Ok(section(
        json!({
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "blindingSeedBytes": hex(&BLINDING_SEED),
            "inputAmount": "96",
            "partCount": "3",
            "partAmount": "32",
            "txViewingSeedBytes": hex(&TX_VIEWING_SEED),
            "saltBytes": hex(&SALT)
        }),
        json!({
            "shape": {"inputs": "1", "outputs": output_snapshot.len().to_string()},
            "firstNullifierBytes": hex(&first_nullifier),
            "bundleWincodeBytes": hex(&bundle_bytes),
            "outputs": output_snapshot.iter().enumerate().map(|(index, output)| json!({
                "slot": index.to_string(),
                "amount": output.amount.to_string(),
                "blindingBytes": hex(&output.blinding),
                "ownerBound": !output.is_dummy()
            })).collect::<Vec<_>>(),
            "wireOutputs": proof_inputs.external_data.outputs.iter().enumerate().map(|(index, output)| json!({
                "slot": index.to_string(),
                "utxoHashBytes": hex(&output.utxo_hash),
                "ownerTag": format!("{:?}", output.owner_tag),
                "dataBytes": output.data.as_ref().map(|data| hex(data))
            })).collect::<Vec<_>>(),
            "txViewingPkBytes": hex(tx.pubkey().as_bytes()),
            "externalDataHashBytes": hex(&external_data_hash),
            "valueOutputCount": output_snapshot.iter().filter(|output| output.amount != 0).count().to_string(),
            "paddingOutputCount": output_snapshot.iter().filter(|output| output.amount == 0).count().to_string(),
            "conservedAmount": output_snapshot.iter().map(|output| output.amount).sum::<u64>().to_string(),
            "errors": [error(&count_error), error(&amount_error)]
        }),
    ))
}

fn merge_vectors(keypair: &ShieldedKeypair) -> Result<Value, Box<dyn std::error::Error>> {
    let real_inputs = vec![fixed_input(keypair, 10, 0), fixed_input(keypair, 20, 1)];
    let output = SppProofOutputUtxo {
        owner_address: Some(keypair.shielded_address()?),
        owner_tag: Some(keypair.signing_pubkey().confidential_view_tag()?),
        asset: SOL_MINT,
        amount: 30,
        blinding: zolana_transaction::derive_blinding(&BLINDING_SEED, 2),
        ..Default::default()
    };
    let mut inputs = real_inputs.clone();
    for position in inputs.len()..MERGE_INPUTS {
        inputs.push(fixed_dummy(position as u8));
    }
    let tx_secret = SecretKey::from_slice(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 15,
    ])?;
    let prepared = PreparedMerge {
        inputs,
        output,
        expiry_unix_ts: u64::MAX,
        signing_pubkey: keypair.signing_pubkey(),
        user_viewing_pk: keypair.viewing_pubkey(),
        tx_viewing_sk: tx_secret,
    };
    let contexts = prepared.input_utxo_hashes()?;
    assert_eq!(contexts.len(), 2);

    let no_input_error = match MergeBuilder::new(keypair, vec![]) {
        Ok(_) => panic!("empty merge accepted"),
        Err(error) => error,
    };
    let mut foreign = real_inputs[0].clone();
    foreign.utxo.owner = fixed_recipient()?.signing_pubkey();
    let owner_error = match MergeBuilder::new(keypair, vec![foreign]) {
        Ok(_) => panic!("foreign merge owner accepted"),
        Err(error) => error,
    };

    Ok(section(
        json!({
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "txViewingSecretBytes": format!("{:064x}", 15),
            "blindingSeedBytes": hex(&BLINDING_SEED),
            "realInputAmounts": ["10", "20"]
        }),
        json!({
            "inputCount": prepared.inputs.len().to_string(),
            "realInputCount": contexts.len().to_string(),
            "dummyCount": prepared.inputs.iter().filter(|input| input.is_dummy()).count().to_string(),
            "outputAmount": prepared.output.amount.to_string(),
            "outputHashBytes": hex(&prepared.output.hash()?),
            "inputContexts": contexts.iter().map(|context| json!({
                "index": context.index.to_string(),
                "utxoHashBytes": hex(&context.utxo_hash),
                "nullifierBytes": hex(&context.nullifier)
            })).collect::<Vec<_>>(),
            "errors": [error(&no_input_error), error(&owner_error)]
        }),
    ))
}

fn zone_vectors(keypair: &ShieldedKeypair) -> Result<Value, Box<dyn std::error::Error>> {
    let zone = Address::new_from_array([28; 32]);
    let mut real = fixed_input(keypair, 50, 0).with_zone_data_hash([29; 32]);
    real.utxo.zone_program_id = Some(zone);
    let output = SppProofOutputUtxo {
        owner_address: Some(keypair.shielded_address()?),
        owner_tag: Some(keypair.signing_pubkey().confidential_view_tag()?),
        asset: SOL_MINT,
        amount: 50,
        blinding: zolana_transaction::derive_blinding(&BLINDING_SEED, 1),
        zone_program_id: Some(zone),
        zone_data_hash: Some([30; 32]),
        ..Default::default()
    };
    let mut inputs = vec![real.clone()];
    for position in 1..MERGE_INPUTS {
        inputs.push(fixed_dummy(position as u8));
    }
    let tx_secret = SecretKey::from_slice(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 16,
    ])?;
    let prepared = PreparedMergeZone {
        inputs,
        output,
        expiry_unix_ts: 1234,
        signing_pubkey: keypair.signing_pubkey(),
        user_viewing_pk: keypair.viewing_pubkey(),
        tx_viewing_sk: tx_secret,
        zone_program_id: zone,
    };
    let contexts = prepared.input_utxo_hashes()?;

    let mut unbound = real;
    unbound.utxo.zone_program_id = None;
    let zone_error = match MergeZone::new(keypair, vec![unbound], zone, None) {
        Ok(_) => panic!("unbound zone input accepted"),
        Err(error) => error,
    };

    Ok(section(
        json!({
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "txViewingSecretBytes": format!("{:064x}", 16),
            "zoneProgramIdBytes": hex(zone.as_array()),
            "inputZoneDataHashBytes": hex(&[29; 32]),
            "outputZoneDataHashBytes": hex(&[30; 32])
        }),
        json!({
            "inputCount": prepared.inputs.len().to_string(),
            "realInputCount": contexts.len().to_string(),
            "outputAmount": prepared.output.amount.to_string(),
            "outputHashBytes": hex(&prepared.output.hash()?),
            "zoneProgramIdBytes": hex(prepared.zone_program_id.as_array()),
            "inputContext": {
                "utxoHashBytes": hex(&contexts[0].utxo_hash),
                "nullifierBytes": hex(&contexts[0].nullifier)
            },
            "error": error(&zone_error)
        }),
    ))
}

fn asset_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    let mint = Address::new_from_array([31; 32]);
    let mut registry = AssetRegistry::new([(2, mint)])?;
    let field = zolana_keypair::hash::hash_field(mint.as_array())?;
    let reserved = registry
        .insert(SOL_ASSET_ID, Address::new_from_array([32; 32]))
        .expect_err("reserved id");
    let duplicate_id = registry
        .insert(2, Address::new_from_array([33; 32]))
        .expect_err("duplicate id");
    let duplicate_mint = registry.insert(3, mint).expect_err("duplicate mint");
    let unknown_id = registry.resolve(999).expect_err("unknown id");
    let unknown_mint = registry
        .asset_id(&Address::new_from_array([34; 32]))
        .expect_err("unknown mint");

    Ok(section(
        json!({"entries": [{"assetId": "2", "mintBytes": hex(mint.as_array())}]}),
        json!({
            "sol": {"assetId": SOL_ASSET_ID.to_string(), "mintBytes": hex(SOL_MINT.as_array())},
            "resolvedMintBytes": hex(registry.resolve(2)?.as_array()),
            "resolvedAssetId": registry.asset_id(&mint)?.to_string(),
            "assetFieldBytes": hex(&field),
            "fieldLookupMintBytes": hex(registry.address_for_field(&field)?.expect("field lookup").as_array()),
            "errors": [error(&reserved), error(&duplicate_id), error(&duplicate_mint), error(&unknown_id), error(&unknown_mint)]
        }),
    ))
}

fn authority_vectors(keypair: &ShieldedKeypair) -> Result<Value, Box<dyn std::error::Error>> {
    let solana = Address::new_from_array([35; 32]);
    let authority = LocalWalletAuthority::new(solana, keypair);
    let material = authority.sync_material()?;
    let message_hash = [36; 32];
    let signature = authority.sign_p256(&message_hash)?;
    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(&signature.sig_r);
    signature_bytes[32..].copy_from_slice(&signature.sig_s);
    assert!(keypair.signing_key.verify(&message_hash, &signature_bytes));

    Ok(section(
        json!({
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "solanaPubkeyBytes": hex(solana.as_array()),
            "messageHashBytes": hex(&message_hash)
        }),
        json!({
            "authority": {
                "solanaPubkeyBytes": hex(SyncWalletAuthority::solana_pubkey(&authority).as_array()),
                "shieldedAddress": {
                    "signingPubkeyBytes": hex(material.identity.signing_pubkey.as_bytes()),
                    "nullifierPubkeyBytes": hex(&material.identity.nullifier_pubkey),
                    "viewingPubkeyBytes": hex(material.identity.viewing_pubkey.as_bytes())
                },
                "viewingKeyCount": material.viewing_keys.len().to_string(),
                "nullifierPubkeyBytes": hex(&material.nullifier_key.pubkey()?)
            },
            "approvalRequest": {
                "solanaPubkeyBytes": hex(solana.as_array()),
                "summary": "fixture transfer"
            },
            "p256Signature": {
                "pubkeyBytes": hex(signature.pubkey.as_bytes()),
                "rBytes": hex(&signature.sig_r),
                "sBytes": hex(&signature.sig_s),
                "verified": true
            },
            "envelope": {
                "txViewingPkBytes": hex(ViewingKey::from_seed(&TX_VIEWING_SEED, 0)?.pubkey().as_bytes()),
                "saltBytes": hex(&SALT),
                "payloadSlots": "2"
            }
        }),
    ))
}

fn wallet_state_vectors(keypair: &ShieldedKeypair) -> Result<Value, Box<dyn std::error::Error>> {
    let mint = Address::new_from_array([37; 32]);
    let registry = AssetRegistry::new([(2, mint)])?;
    let mut wallet = Wallet::new(keypair.shielded_address()?, registry)?;
    let sol = fixed_utxo(keypair, 40, 0);
    let token = Utxo {
        asset: mint,
        amount: 70,
        blinding: zolana_transaction::derive_blinding(&BLINDING_SEED, 1),
        ..fixed_utxo(keypair, 0, 1)
    };
    wallet.utxos = vec![
        wallet_utxo(keypair, sol, [38; 32], 1, false)?,
        wallet_utxo(keypair, token, [39; 32], 2, false)?,
        wallet_utxo(keypair, fixed_utxo(keypair, 5, 2), [40; 32], 3, true)?,
    ];
    wallet.transactions = vec![
        PrivateTransaction {
            id: PrivateTransactionId {
                signature: "fixture-a".into(),
                slot: 5,
                index: 1,
            },
            kind: PrivateTransactionKind::Deposit,
            direction: PrivateTransactionDirection::Inbound,
            status: PrivateTransactionStatus::Confirmed,
            asset: SOL_MINT,
            amount: 40,
            counterparty_viewing_pubkey: None,
        },
        PrivateTransaction {
            id: PrivateTransactionId {
                signature: "fixture-b".into(),
                slot: 6,
                index: 2,
            },
            kind: PrivateTransactionKind::PrivateTransfer,
            direction: PrivateTransactionDirection::Outbound,
            status: PrivateTransactionStatus::Confirmed,
            asset: mint,
            amount: 7,
            counterparty_viewing_pubkey: Some(fixed_recipient()?.viewing_pubkey()),
        },
    ];
    let balances = wallet.balances(false)?;
    let compact = wallet.balances(true)?;
    let filtered = wallet.balance(SOL_MINT, Some(Filter::MinAmount(41)))?;

    Ok(section(
        json!({
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "mintBytes": hex(mint.as_array()),
            "walletUtxos": wallet.utxos.iter().map(|value| json!({
                "utxo": utxo_json(&value.utxo),
                "hashBytes": hex(&value.output_context.hash),
                "leafIndex": value.output_context.leaf_index.to_string(),
                "nullifierBytes": hex(&value.nullifier),
                "spent": value.spent
            })).collect::<Vec<_>>()
        }),
        json!({
            "balances": balances.iter().map(|value| json!({
                "assetId": value.asset_id.to_string(),
                "mintBytes": hex(value.mint.as_array()),
                "amount": value.amount.to_string(),
                "utxoCount": value.utxos.len().to_string()
            })).collect::<Vec<_>>(),
            "compactBalances": compact.iter().map(|value| json!({
                "assetId": value.asset_id.to_string(),
                "amount": value.amount.to_string(),
                "utxoCount": value.utxos.len().to_string()
            })).collect::<Vec<_>>(),
            "filteredSol": {"amount": filtered.amount.to_string(), "utxoCount": filtered.utxos.len().to_string()},
            "history": wallet.private_transactions().iter().map(transaction_json).collect::<Vec<_>>(),
            "lastSynced": wallet.last_synced.to_string(),
            "viewingKeyHistoryCount": wallet.viewing_key_history.len().to_string()
        }),
    ))
}

fn wallet_utxo(
    keypair: &ShieldedKeypair,
    utxo: Utxo,
    hash: [u8; 32],
    leaf_index: u64,
    spent: bool,
) -> Result<WalletUtxo, Box<dyn std::error::Error>> {
    Ok(WalletUtxo {
        nullifier: utxo.nullifier(&hash, &keypair.nullifier_key)?,
        utxo,
        output_context: OutputContext {
            hash,
            tree: Address::new_from_array([41; 32]),
            leaf_index,
        },
        data_hash: None,
        zone_data_hash: None,
        spent,
    })
}

fn transaction_json(transaction: &PrivateTransaction) -> Value {
    json!({
        "id": {
            "signature": transaction.id.signature,
            "slot": transaction.id.slot.to_string(),
            "index": transaction.id.index.to_string()
        },
        "kind": format!("{:?}", transaction.kind),
        "direction": format!("{:?}", transaction.direction),
        "status": format!("{:?}", transaction.status),
        "assetBytes": hex(transaction.asset.as_array()),
        "amount": transaction.amount.to_string(),
        "counterpartyViewingPkBytes": transaction.counterparty_viewing_pubkey.map(|key| hex(key.as_bytes()))
    })
}

fn wallet_sync_vectors(keypair: &ShieldedKeypair) -> Result<Value, Box<dyn std::error::Error>> {
    let (history_inputs, history_expected) = wallet_history_vectors(keypair, &fixed_recipient()?)?;
    let registry = AssetRegistry::default();
    let material = WalletSyncMaterial {
        identity: keypair.shielded_address()?,
        viewing_keys: vec![keypair.viewing_key.clone()],
        nullifier_key: keypair.nullifier_key.clone(),
    };
    let transactions = vec![
        proofless_transaction(keypair, 20, 1, 100)?,
        proofless_transaction(keypair, 30, 2, 101)?,
    ];
    let mut sequential = Wallet::new(material.identity, registry.clone())?;
    let first = sequential.sync_with_material(&material, &transactions[..1], 10, 64)?;
    let second = sequential.sync_with_material(&material, &transactions[1..], 20, 64)?;
    let idempotent = sequential.sync_with_material(&material, &transactions, 30, 64)?;

    let mut parallel = Wallet::new(material.identity, registry.clone())?;
    let parallel_report = parallel.sync_parallel_with_material(&material, &transactions, 20, 64)?;
    assert_eq!(sequential.utxos, parallel.utxos);
    assert_eq!(sequential.transactions, parallel.transactions);

    let balances = zolana_transaction::decrypt_transactions(keypair, &transactions, &registry)?;
    let mut tampered = transactions.clone();
    let payload = &mut tampered[0].output_slots[0].payload;
    let last = payload.len() - 1;
    payload[last] ^= 1;
    let mut tamper_wallet = Wallet::new(material.identity, registry.clone())?;
    let tamper_report = tamper_wallet.sync_with_material(&material, &tampered, 20, 64)?;

    let mut wrong_material = material.clone();
    wrong_material.identity = fixed_recipient()?.shielded_address()?;
    let mut mismatch_wallet = Wallet::new(material.identity, registry)?;
    let mismatch = mismatch_wallet
        .sync_with_material(&wrong_material, &[], 0, 64)
        .expect_err("authority identity mismatch");
    let mut missing_current = material.clone();
    missing_current.viewing_keys = vec![ViewingKey::from_seed(&[42; 32], 0)?];
    let missing_current_error = mismatch_wallet
        .sync_with_material(&missing_current, &[], 0, 64)
        .expect_err("current viewing key required");

    Ok(section(
        json!({
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "transactions": transactions.iter().map(shielded_transaction_json).collect::<Vec<_>>(),
            "history": history_inputs
        }),
        json!({
            "history": history_expected,
            "sequential": {
                "reports": [sync_report_json(&first), sync_report_json(&second), sync_report_json(&idempotent)],
                "utxoCount": sequential.utxos.len().to_string(),
                "historyCount": sequential.transactions.len().to_string(),
                "balance": sequential.balance(SOL_MINT, None)?.amount.to_string(),
                "lastSynced": sequential.last_synced.to_string()
            },
            "parallelEquivalent": {
                "report": sync_report_json(&parallel_report),
                "utxosEqual": true,
                "historyEqual": true,
                "balance": parallel.balance(SOL_MINT, None)?.amount.to_string()
            },
            "decryptTransactionsBalance": balances.get_balance(SOL_MINT).expect("SOL balance").amount.to_string(),
            "tamper": {
                "report": sync_report_json(&tamper_report),
                "utxoCount": tamper_wallet.utxos.len().to_string(),
                "stateCommitRejected": tamper_wallet.utxos.len() < sequential.utxos.len()
            },
            "errors": [error(&mismatch), error(&missing_current_error)]
        }),
    ))
}

fn proofless_transaction(
    keypair: &ShieldedKeypair,
    amount: u64,
    leaf_index: u64,
    slot: u64,
) -> Result<ShieldedTransaction, Box<dyn std::error::Error>> {
    let registry = AssetRegistry::default();
    let utxo = fixed_utxo(keypair, amount, leaf_index as u8);
    let hash = utxo.hash(&keypair.nullifier_key.pubkey()?, &[0; 32], &[0; 32])?;
    let owner = zolana_transaction::OwnerCx {
        owner: keypair.signing_pubkey(),
        assets: &registry,
        zone_program_id: None,
    };
    let encoded = Proofless::encode(
        &[utxo],
        &owner,
        keypair.viewing_key.recipient_bootstrap_view_tag(),
        &ProoflessEncode {
            owner_hash: keypair.owner_hash()?,
            data_hash: None,
            zone_data_hash: None,
        },
    )?;
    Ok(ShieldedTransaction {
        slot,
        tx_signature: Default::default(),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: encoded.view_tag,
            output_context: OutputContext {
                hash,
                tree: Address::new_from_array([43; 32]),
                leaf_index,
            },
            payload: encoded.data,
        }],
        messages: vec![],
        nullifiers: vec![],
        proofless: true,
    })
}

fn shielded_transaction_json(transaction: &ShieldedTransaction) -> Value {
    json!({
        "slot": transaction.slot.to_string(),
        "signature": transaction.tx_signature.to_string(),
        "proofless": transaction.proofless,
        "txViewingPkBytes": transaction.tx_viewing_pk.map(|pubkey| hex(pubkey.as_bytes())),
        "saltBytes": transaction.salt.map(|salt| hex(&salt)),
        "outputSlots": transaction.output_slots.iter().map(|slot| json!({
            "viewTagBytes": hex(&slot.view_tag),
            "hashBytes": hex(&slot.output_context.hash),
            "treeBytes": hex(slot.output_context.tree.as_array()),
            "leafIndex": slot.output_context.leaf_index.to_string(),
            "payloadBytes": hex(&slot.payload)
        })).collect::<Vec<_>>(),
        "nullifiers": transaction.nullifiers.iter().map(|value| hex(value)).collect::<Vec<_>>()
    })
}

fn sync_report_json(report: &zolana_transaction::SyncReport) -> Value {
    json!({
        "storedUtxos": report.stored_utxos.to_string(),
        "unparsedTransactions": report.unparsed_transactions.to_string(),
        "undecryptableCandidates": report.undecryptable_candidates.to_string(),
        "unknownAssetIds": report.unknown_asset_ids.iter().map(ToString::to_string).collect::<Vec<_>>()
    })
}

const HISTORY_TREE: [u8; 32] = [44; 32];
/// A dummy change slot is a length-matched ciphertext no key of the wallet's
/// opens, so it carries a tag the wallet never derives and a body sealed under
/// an unrelated transaction key.
const HISTORY_DUMMY_TAG: [u8; 32] = [45; 32];
const HISTORY_DUMMY_SEED: [u8; 32] = [46; 32];

fn history_slot(
    view_tag: [u8; 32],
    hash: [u8; 32],
    leaf_index: u64,
    payload: Vec<u8>,
) -> OutputSlot {
    OutputSlot {
        view_tag,
        output_context: OutputContext {
            hash,
            tree: Address::new_from_array(HISTORY_TREE),
            leaf_index,
        },
        payload,
    }
}

fn history_note(keypair: &ShieldedKeypair, amount: u64, position: u8) -> Utxo {
    Utxo {
        owner: keypair.signing_pubkey(),
        asset: SOL_MINT,
        amount,
        blinding: zolana_transaction::derive_blinding(&BLINDING_SEED, position),
        zone_program_id: None,
        data: Data::default(),
    }
}

fn history_hash(
    keypair: &ShieldedKeypair,
    utxo: &Utxo,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(utxo.hash(&keypair.nullifier_key.pubkey()?, &[0; 32], &[0; 32])?)
}

/// The nullifier the wallet stores against `utxo`, which is what a later
/// transaction must publish for that note to be netted out of its history row.
fn history_nullifier(
    keypair: &ShieldedKeypair,
    utxo: &Utxo,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let hash = history_hash(keypair, utxo)?;
    Ok(utxo.nullifier(&hash, &keypair.nullifier_key)?)
}

fn history_owner_cx<'a>(
    keypair: &ShieldedKeypair,
    assets: &'a AssetRegistry,
) -> zolana_transaction::OwnerCx<'a> {
    zolana_transaction::OwnerCx {
        owner: keypair.signing_pubkey(),
        assets,
        zone_program_id: None,
    }
}

/// The transaction viewing key and salt a spending wallet publishes. Both come
/// from the first nullifier, which is what lets the author alone re-derive them
/// and reconstruct its own outbound history.
fn history_envelope(
    keypair: &ShieldedKeypair,
    first_nullifier: &[u8; 32],
) -> Result<(ViewingKey, [u8; SALT_LEN]), Box<dyn std::error::Error>> {
    let tx = keypair
        .viewing_key
        .get_transaction_viewing_key(first_nullifier)?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&first_nullifier[..SALT_LEN]);
    Ok((tx, salt))
}

fn history_transaction(
    slot: u64,
    envelope: Option<(&ViewingKey, [u8; SALT_LEN])>,
    nullifiers: Vec<[u8; 32]>,
    output_slots: Vec<OutputSlot>,
) -> ShieldedTransaction {
    ShieldedTransaction {
        slot,
        tx_signature: Default::default(),
        tx_viewing_pk: envelope.map(|(tx, _)| tx.pubkey()),
        salt: envelope.map(|(_, salt)| salt),
        output_slots,
        messages: Vec::new(),
        nullifiers,
        proofless: false,
    }
}

/// A proofless deposit: one plaintext slot under the recipient bootstrap tag.
fn history_deposit(
    owner: &ShieldedKeypair,
    assets: &AssetRegistry,
    note: &Utxo,
    slot: u64,
) -> Result<ShieldedTransaction, Box<dyn std::error::Error>> {
    let message = Proofless::encode(
        std::slice::from_ref(note),
        &history_owner_cx(owner, assets),
        owner.viewing_key.recipient_bootstrap_view_tag(),
        &ProoflessEncode {
            owner_hash: owner.owner_hash()?,
            data_hash: None,
            zone_data_hash: None,
        },
    )?;
    let mut deposit = history_transaction(
        slot,
        None,
        Vec::new(),
        vec![history_slot(
            message.view_tag,
            history_hash(owner, note)?,
            0,
            message.data,
        )],
    );
    deposit.proofless = true;
    Ok(deposit)
}

struct HistoryAnonymous<'a> {
    sender: &'a ShieldedKeypair,
    recipient: &'a ShieldedKeypair,
    assets: &'a AssetRegistry,
    slot: u64,
    leaf_index: u64,
    nullifiers: Vec<[u8; 32]>,
    change: u64,
    recipient_note: &'a Utxo,
    blinding_seed: [u8; BLINDING_LEN],
    sender_tag: [u8; 32],
    recipient_tag: [u8; 32],
}

impl HistoryAnonymous<'_> {
    /// The two-rail anonymous transfer: slot 0 is the sender bundle that
    /// carries the change back, slot 1 is the recipient's sealed note.
    fn build(self) -> Result<(ShieldedTransaction, Utxo), Box<dyn std::error::Error>> {
        let first_nullifier = *self
            .nullifiers
            .first()
            .ok_or("an anonymous transfer spends at least one note")?;
        let (tx, salt) = history_envelope(self.sender, &first_nullifier)?;
        let recipient_pks = vec![self.recipient.viewing_pubkey()];
        let plaintext = AnonymousTransferSenderPlaintext {
            owner_pubkey: self.sender.signing_pubkey(),
            spl_asset_id: 0,
            spl_amount: 0,
            sol_amount: self.change,
            blinding_seed: self.blinding_seed,
            recipient_viewing_pks: recipient_pks.clone(),
            spl_data: Data::default(),
            sol_data: Data::default(),
        };
        let change = AnonymousSenderBundle::into_utxos(
            plaintext.clone(),
            &history_owner_cx(self.sender, self.assets),
        )?;
        let change_note = change
            .into_iter()
            .next()
            .ok_or("the sender bundle carries one change note")?;
        let sender_message = AnonymousSenderBundle::encode_plaintext(
            &plaintext,
            self.sender_tag,
            &AnonymousSenderEncode {
                tx: tx.clone(),
                self_pubkey: self.sender.viewing_pubkey(),
                salt,
                slot_index: 0,
                blinding_seed: self.blinding_seed,
                recipient_viewing_pks: recipient_pks,
            },
        )?;
        let recipient_message = AnonymousRecipient::encode(
            std::slice::from_ref(self.recipient_note),
            &history_owner_cx(self.recipient, self.assets),
            self.recipient_tag,
            &AnonymousRecipientEncode {
                tx: tx.clone(),
                recipient_pubkey: self.recipient.viewing_pubkey(),
                sender_pubkey: self.sender.viewing_pubkey(),
                salt,
                slot_index: 1,
            },
        )?;
        let transaction = history_transaction(
            self.slot,
            Some((&tx, salt)),
            self.nullifiers,
            vec![
                history_slot(
                    sender_message.view_tag,
                    history_hash(self.sender, &change_note)?,
                    self.leaf_index,
                    sender_message.data,
                ),
                history_slot(
                    recipient_message.view_tag,
                    history_hash(self.recipient, self.recipient_note)?,
                    self.leaf_index + 1,
                    recipient_message.data,
                ),
            ],
        );
        Ok((transaction, change_note))
    }
}

struct HistoryConfidential<'a> {
    sender: &'a ShieldedKeypair,
    assets: &'a AssetRegistry,
    slot: u64,
    leaf_index: u64,
    nullifiers: Vec<[u8; 32]>,
    change_note: &'a Utxo,
    /// Absent for a withdrawal, which pays a public address rather than a
    /// shielded one and so publishes no recipient slot at all.
    recipient: Option<(&'a ShieldedKeypair, &'a Utxo)>,
}

impl HistoryConfidential<'_> {
    /// The unified confidential rail: the two leading slots are the sender's own
    /// SPL and SOL change, recipients follow. This scenario moves SOL only, so
    /// slot 0 is the dummy that a real transfer length-matches into the SPL
    /// position and that the author's own key fails to open.
    fn build(self) -> Result<ShieldedTransaction, Box<dyn std::error::Error>> {
        let first_nullifier = *self
            .nullifiers
            .first()
            .ok_or("a confidential transfer spends at least one note")?;
        let (tx, salt) = history_envelope(self.sender, &first_nullifier)?;
        let dummy = Confidential::encode(
            std::slice::from_ref(self.change_note),
            &history_owner_cx(self.sender, self.assets),
            HISTORY_DUMMY_TAG,
            &ConfidentialEncode {
                tx: ViewingKey::from_seed(&HISTORY_DUMMY_SEED, 0)?,
                recipient_pubkey: self.sender.viewing_pubkey(),
                salt,
                slot_index: 0,
            },
        )?;
        let change = Confidential::encode(
            std::slice::from_ref(self.change_note),
            &history_owner_cx(self.sender, self.assets),
            self.sender.signing_pubkey().confidential_view_tag()?,
            &ConfidentialEncode {
                tx: tx.clone(),
                recipient_pubkey: self.sender.viewing_pubkey(),
                salt,
                slot_index: 1,
            },
        )?;
        let mut output_slots = vec![
            history_slot(dummy.view_tag, [0u8; 32], self.leaf_index, dummy.data),
            history_slot(
                change.view_tag,
                history_hash(self.sender, self.change_note)?,
                self.leaf_index + 1,
                change.data,
            ),
        ];
        if let Some((recipient, note)) = self.recipient {
            let message = Confidential::encode(
                std::slice::from_ref(note),
                &history_owner_cx(recipient, self.assets),
                recipient.signing_pubkey().confidential_view_tag()?,
                &ConfidentialEncode {
                    tx: tx.clone(),
                    recipient_pubkey: recipient.viewing_pubkey(),
                    salt,
                    slot_index: 2,
                },
            )?;
            output_slots.push(history_slot(
                message.view_tag,
                history_hash(recipient, note)?,
                self.leaf_index + 2,
                message.data,
            ));
        }
        Ok(history_transaction(
            self.slot,
            Some((&tx, salt)),
            self.nullifiers,
            output_slots,
        ))
    }
}

/// A split: one bundle at slot 0 describes every equal output, and the later
/// slots publish only their leaves, which is what the wallet matches its
/// reconstructed notes against.
fn history_split(
    owner: &ShieldedKeypair,
    assets: &AssetRegistry,
    outputs: &[Utxo],
    slot: u64,
    nullifiers: Vec<[u8; 32]>,
) -> Result<ShieldedTransaction, Box<dyn std::error::Error>> {
    let first_nullifier = *nullifiers.first().ok_or("a split spends one note")?;
    let (tx, salt) = history_envelope(owner, &first_nullifier)?;
    let message = Split::encode(
        outputs,
        &history_owner_cx(owner, assets),
        owner.signing_pubkey().confidential_view_tag()?,
        &SplitEncode {
            tx: tx.clone(),
            recipient_pubkey: owner.viewing_pubkey(),
            salt,
            slot_index: 0,
            blinding_seed: BLINDING_SEED,
        },
    )?;
    let mut payload = Some(message.data);
    let output_slots = outputs
        .iter()
        .enumerate()
        .map(|(index, output)| {
            Ok(history_slot(
                message.view_tag,
                history_hash(owner, output)?,
                20 + index as u64,
                payload.take().unwrap_or_default(),
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    Ok(history_transaction(
        slot,
        Some((&tx, salt)),
        nullifiers,
        output_slots,
    ))
}

/// A merge seals its output under a transaction key carried inside the slot, so
/// the transaction publishes no envelope key and no salt of its own.
fn history_merge(
    owner: &ShieldedKeypair,
    assets: &AssetRegistry,
    output: &Utxo,
    slot: u64,
    nullifiers: Vec<[u8; 32]>,
) -> Result<ShieldedTransaction, Box<dyn std::error::Error>> {
    let message = Merge::encode(
        std::slice::from_ref(output),
        &history_owner_cx(owner, assets),
        owner.signing_pubkey().confidential_view_tag()?,
        &MergeEncode {
            tx: ViewingKey::from_seed(&TX_VIEWING_SEED, 0)?,
            user_viewing_pk: owner.viewing_pubkey(),
        },
    )?;
    Ok(history_transaction(
        slot,
        None,
        nullifiers,
        vec![history_slot(
            message.view_tag,
            history_hash(owner, output)?,
            30,
            message.data,
        )],
    ))
}

/// One transaction per history-recording path, in the order a wallet sees them:
/// each sync spends notes the previous sync stored, which is what makes the
/// outbound rows carry real spent amounts rather than zero.
fn wallet_history_transactions(
    owner: &ShieldedKeypair,
    peer: &ShieldedKeypair,
    assets: &AssetRegistry,
) -> Result<Vec<ShieldedTransaction>, Box<dyn std::error::Error>> {
    let deposited = history_note(owner, 100, 1);
    let deposit = history_deposit(owner, assets, &deposited, 200)?;

    let received = history_note(owner, 40, 2);
    let (inbound, _) = HistoryAnonymous {
        sender: peer,
        recipient: owner,
        assets,
        slot: 201,
        leaf_index: 2,
        nullifiers: vec![history_nullifier(peer, &history_note(peer, 55, 3))?],
        change: 15,
        recipient_note: &received,
        blinding_seed: zolana_transaction::derive_blinding(&BLINDING_SEED, 4),
        sender_tag: peer.viewing_key.get_sender_view_tag(0)?,
        recipient_tag: owner.viewing_key.recipient_bootstrap_view_tag(),
    }
    .build()?;

    let (outbound, anonymous_change) = HistoryAnonymous {
        sender: owner,
        recipient: peer,
        assets,
        slot: 202,
        leaf_index: 4,
        nullifiers: vec![history_nullifier(owner, &deposited)?],
        change: 76,
        recipient_note: &history_note(peer, 24, 5),
        blinding_seed: zolana_transaction::derive_blinding(&BLINDING_SEED, 6),
        sender_tag: owner.viewing_key.get_sender_view_tag(0)?,
        recipient_tag: peer.viewing_key.recipient_bootstrap_view_tag(),
    }
    .build()?;

    let confidential_change = history_note(owner, 44, 7);
    let sent = HistoryConfidential {
        sender: owner,
        assets,
        slot: 203,
        leaf_index: 6,
        nullifiers: vec![history_nullifier(owner, &anonymous_change)?],
        change_note: &confidential_change,
        recipient: Some((peer, &history_note(peer, 32, 8))),
    }
    .build()?;

    let withdrawn = HistoryConfidential {
        sender: owner,
        assets,
        slot: 204,
        leaf_index: 9,
        nullifiers: vec![history_nullifier(owner, &received)?],
        change_note: &history_note(owner, 15, 9),
        recipient: None,
    }
    .build()?;

    // A split's outputs are equal and blinded by position from the bundle seed,
    // so their positions are fixed rather than free.
    let parts = (0..2)
        .map(|part| history_note(owner, 22, part))
        .collect::<Vec<_>>();
    let split = history_split(
        owner,
        assets,
        &parts,
        205,
        vec![history_nullifier(owner, &confidential_change)?],
    )?;

    let merged = history_note(owner, 44, 10);
    let merge = history_merge(
        owner,
        assets,
        &merged,
        206,
        parts
            .iter()
            .map(|part| history_nullifier(owner, part))
            .collect::<Result<Vec<_>, _>>()?,
    )?;

    Ok(vec![
        deposit, inbound, outbound, sent, withdrawn, split, merge,
    ])
}

/// Counterparty counters, ordered by viewing pubkey because Rust holds them in
/// a hash map and the fixture has to be byte-reproducible.
fn counter_rows<'a>(counters: impl Iterator<Item = (&'a P256Pubkey, &'a u64)>) -> Value {
    let mut rows = counters
        .map(|(pubkey, count)| (hex(pubkey.as_bytes()), count.to_string()))
        .collect::<Vec<_>>();
    rows.sort();
    Value::Array(
        rows.into_iter()
            .map(|(pubkey, count)| json!({"viewingPkBytes": pubkey, "count": count}))
            .collect(),
    )
}

/// How far each tag family of each viewing key has been scanned. A sync resumes
/// from these, so they are the part of the wallet a later sync reads back.
fn viewing_key_counters_json(wallet: &Wallet) -> Value {
    Value::Array(
        wallet
            .viewing_key_history
            .iter()
            .map(|entry| {
                json!({
                    "viewingPkBytes": hex(entry.viewing_pubkey.as_bytes()),
                    "txCount": entry.tx_count.to_string(),
                    "requestCount": entry.request_count.to_string(),
                    "knownSenders": counter_rows(entry.known_senders.iter()),
                    "knownRecipients": counter_rows(entry.known_recipients.iter())
                })
            })
            .collect(),
    )
}

/// Sync the scenario one transaction at a time and record the report and the
/// full history after each, so the fixture pins both the rows each recording
/// path writes and the order the wallet keeps them in.
fn wallet_history_vectors(
    owner: &ShieldedKeypair,
    peer: &ShieldedKeypair,
) -> Result<(Value, Value), Box<dyn std::error::Error>> {
    let assets = AssetRegistry::default();
    let transactions = wallet_history_transactions(owner, peer, &assets)?;
    let material = WalletSyncMaterial {
        identity: owner.shielded_address()?,
        viewing_keys: vec![owner.viewing_key.clone()],
        nullifier_key: owner.nullifier_key.clone(),
    };
    let mut wallet = Wallet::new(material.identity, assets)?;
    let steps = transactions
        .iter()
        .enumerate()
        .map(|(index, transaction)| {
            let report = wallet.sync_with_material(
                &material,
                std::slice::from_ref(transaction),
                300 + index as i64,
                64,
            )?;
            Ok(json!({
                "report": sync_report_json(&report),
                "rows": wallet.private_transactions().iter().map(transaction_json).collect::<Vec<_>>(),
                "viewingKeyHistory": viewing_key_counters_json(&wallet)
            }))
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;

    Ok((
        json!({
            "transactions": transactions.iter().map(shielded_transaction_json).collect::<Vec<_>>()
        }),
        json!({
            "steps": steps,
            "utxoCount": wallet.utxos.len().to_string(),
            "unspentCount": wallet.utxos.iter().filter(|utxo| !utxo.spent).count().to_string(),
            "balance": wallet.balance(SOL_MINT, None)?.amount.to_string(),
            "lastSynced": wallet.last_synced.to_string()
        }),
    ))
}

fn assigned_test_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    let regression_seeds =
        include_str!("../../sdk-libs/transaction/tests/wallet_prop.proptest-regressions");
    Ok(section(
        json!({
            "frozenTestPaths": [
                "sdk-libs/transaction/BENCHMARKS.md",
                "sdk-libs/transaction/benches/wallet_ops.rs",
                "sdk-libs/transaction/tests/bdd.rs",
                "sdk-libs/transaction/tests/bench_scenarios.rs",
                "sdk-libs/transaction/tests/common/mod.rs",
                "sdk-libs/transaction/tests/features/asset.feature",
                "sdk-libs/transaction/tests/features/blinding.feature",
                "sdk-libs/transaction/tests/features/plaintext_transfer.feature",
                "sdk-libs/transaction/tests/features/program_data.feature",
                "sdk-libs/transaction/tests/features/serialization.feature",
                "sdk-libs/transaction/tests/features/split.feature",
                "sdk-libs/transaction/tests/features/transfer.feature",
                "sdk-libs/transaction/tests/features/utxo.feature",
                "sdk-libs/transaction/tests/features/utxo_encryption.feature",
                "sdk-libs/transaction/tests/features/wallet.feature",
                "sdk-libs/transaction/tests/steps/asset.rs",
                "sdk-libs/transaction/tests/steps/blinding.rs",
                "sdk-libs/transaction/tests/steps/common.rs",
                "sdk-libs/transaction/tests/steps/plaintext_transfer.rs",
                "sdk-libs/transaction/tests/steps/serialization.rs",
                "sdk-libs/transaction/tests/steps/split.rs",
                "sdk-libs/transaction/tests/steps/transfer.rs",
                "sdk-libs/transaction/tests/steps/utxo.rs",
                "sdk-libs/transaction/tests/steps/utxo_encryption.rs",
                "sdk-libs/transaction/tests/steps/wallet.rs",
                "sdk-libs/transaction/tests/tamper.rs",
                "sdk-libs/transaction/tests/wallet_history.rs",
                "sdk-libs/transaction/tests/wallet_proofless.rs",
                "sdk-libs/transaction/tests/wallet_prop.proptest-regressions",
                "sdk-libs/transaction/tests/wallet_prop.rs",
                "sdk-libs/transaction/tests/wallet_unified.rs"
            ]
        }),
        json!({
            "namedScenarioDomains": [
                "asset", "blinding", "data", "plaintext-transfer", "serialization", "split",
                "transfer", "utxo", "utxo-encryption", "wallet", "tamper", "history",
                "proofless", "property", "unified"
            ],
            "regressionSeedFileBytes": hex(regression_seeds.as_bytes()),
            "regressionSeedLines": regression_seeds.lines().filter(|line| line.trim_start().starts_with("cc ")).count().to_string(),
            "frozenTestPathCount": "31",
            "productionOracleSections": "13"
        }),
    ))
}
