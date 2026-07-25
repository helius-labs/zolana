//! Emits the cross-language parity vectors the TypeScript `@zolana/keypair`
//! port is checked against, and fails when the committed file no longer matches
//! what this crate produces. Every value here is computed by the current Rust
//! code, so a behaviour change breaks this test before it can reach a reviewer
//! as "the two files look similar".
//!
//! Regenerate with `UPDATE_KEYPAIR_VECTORS=1 cargo test -p zolana-keypair
//! --test parity_vectors`.

use serde_json::{json, Map, Value};
use zolana_keypair::{
    constants::{
        BLINDING_LEN, DST_VIEW_ROOT_P_CONST, PUBLIC_KEY_LEN, P256_PUBKEY_LEN, P_CONST_SEC1,
        SALT_LEN, VIEW_TAG_LEN,
    },
    error::KeypairError,
    hash::{hash_field, owner_hash, poseidon, sha256, sha256_be, split_be_128},
    merge::{
        merge_ciphertext_hash, merge_public_contribution, symmetric_apply, MAX_INFO_LEN,
        MERGE_INFO,
    },
    nullifier_key::NullifierKey,
    pubkey::{P256Pubkey, PublicKey, SignatureType},
    shielded::ShieldedKeypair,
    signing_key::SigningKey,
    viewing_key::ViewingKey,
};

const VECTOR_PATH: &str = "../ts/vectors/keypair-parity-v1.json";

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Deterministic 32-byte secret material: no vector in this file depends on the
/// OS RNG, so the committed values are reproducible on any machine.
fn secret32(seed: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8).wrapping_mul(7) | 1;
    }
    bytes
}

fn p256_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&secret32(seed)).expect("seeded p256 secret is in range")
}

fn viewing(seed: u8) -> ViewingKey {
    ViewingKey::from_bytes(&secret32(seed)).expect("seeded p256 secret is in range")
}

fn constants() -> Value {
    json!({
        "publicKeyLen": PUBLIC_KEY_LEN,
        "p256PubkeyLen": P256_PUBKEY_LEN,
        "blindingLen": BLINDING_LEN,
        "saltLen": SALT_LEN,
        "viewTagLen": VIEW_TAG_LEN,
        "dstViewRootPConst": String::from_utf8(DST_VIEW_ROOT_P_CONST.to_vec()).unwrap(),
        "dstViewRootPConstBytes": hex(DST_VIEW_ROOT_P_CONST),
        "pConstSec1Bytes": hex(&P_CONST_SEC1),
        "mergeInfoBytes": hex(MERGE_INFO),
        "maxInfoLen": MAX_INFO_LEN,
    })
}

fn signing() -> Value {
    let p256 = p256_key(3);
    let digest = sha256(b"parity/prehash");
    let signature = p256.sign(&digest);

    let ed_secret = secret32(9);
    let ed = SigningKey::from_ed25519(&ed_secret);
    let ed_message = b"parity/ed25519 message".to_vec();
    let ed_signature = ed.sign(&ed_message);

    // Rust signs whatever P256 `s` RFC6979 produces: the circuit range-checks
    // `s` against the curve order alone, so a high-`s` signature is valid and
    // must verify on both rails.
    let mut high_s = signature;
    let order = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let s = u256_sub(&order, &high_s[32..64]);
    high_s[32..64].copy_from_slice(&s);

    json!({
        "p256": {
            "secretBytes": hex(&secret32(3)),
            "secretRoundTripBytes": hex(p256.secret_bytes().as_slice()),
            "isEd25519": p256.is_ed25519(),
            "publicKeyBytes": hex(p256.pubkey().as_bytes()),
            "messageBytes": hex(&digest),
            "signatureBytes": hex(&signature),
            "verified": p256.verify(&digest, &signature),
            "negatedSVerified": p256.verify(&digest, &high_s),
            "wrongMessageVerified": p256.verify(&sha256(b"other"), &signature),
            "shortPrehashError": error_name(&p256.try_sign(&digest[..31]).unwrap_err()),
            "longPrehashError": error_name(&p256.try_sign(&[7u8; 33]).unwrap_err()),
            "emptyPrehashError": error_name(&p256.try_sign(&[]).unwrap_err()),
        },
        "ed25519": {
            "secretBytes": hex(&ed_secret),
            "secretRoundTripBytes": hex(ed.secret_bytes().as_slice()),
            "isEd25519": ed.is_ed25519(),
            "publicKeyBytes": hex(ed.pubkey().as_bytes()),
            "messageBytes": hex(&ed_message),
            "signatureBytes": hex(&ed_signature),
            "verified": ed.verify(&ed_message, &ed_signature),
            "emptyMessageSignatureBytes": hex(&ed.sign(&[])),
            "emptyMessageVerified": ed.verify(&[], &ed.sign(&[])),
            "wrongMessageVerified": ed.verify(b"other", &ed_signature),
        },
        "invalidSecretBytes": hex(&[0u8; 32]),
        "invalidSecretError": error_name(&expect_err(SigningKey::from_bytes(&[0u8; 32]))),
    })
}

fn u256_sub(left: &[u8; 32], right: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let diff = left[index] as i16 - right[index] as i16 - borrow;
        if diff < 0 {
            out[index] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[index] = diff as u8;
            borrow = 0;
        }
    }
    out
}

/// `SigningKey` and `ViewingKey` deliberately have no `Debug`, so `unwrap_err`
/// is unavailable on results carrying them.
fn expect_err<T>(result: Result<T, KeypairError>) -> KeypairError {
    match result {
        Ok(_) => panic!("expected the key constructor to refuse this secret"),
        Err(error) => error,
    }
}

fn error_name(error: &KeypairError) -> Value {
    let name = match error {
        KeypairError::InvalidPublicKey => "InvalidPublicKey",
        KeypairError::InvalidSecretKey => "InvalidSecretKey",
        KeypairError::ZeroScalar => "ZeroScalar",
        KeypairError::InvalidSignatureType(_) => "InvalidSignatureType",
        KeypairError::NotEd25519 => "NotEd25519",
        KeypairError::Hkdf => "Hkdf",
        KeypairError::Poseidon(_) => "Poseidon",
        KeypairError::FieldElementTooLong => "FieldElementTooLong",
        KeypairError::InvalidPrehashLength(_) => "InvalidPrehashLength",
        KeypairError::InfoTooLong => "InfoTooLong",
    };
    json!({ "variant": name, "display": error.to_string() })
}

fn errors() -> Value {
    let ed_public = SigningKey::from_ed25519(&secret32(9)).pubkey();
    let p256_public = p256_key(3).pubkey();

    let mut bad_prefix = *p256_public.as_bytes();
    bad_prefix[0] = 2;
    let mut bad_padding = *ed_public.as_bytes();
    bad_padding[PUBLIC_KEY_LEN - 1] = 1;
    let mut bad_point = *p256_public.as_bytes();
    bad_point[PUBLIC_KEY_LEN - 1] ^= 0xff;

    json!({
        "variants": [
            error_name(&KeypairError::InvalidPublicKey),
            error_name(&KeypairError::InvalidSecretKey),
            error_name(&KeypairError::ZeroScalar),
            error_name(&KeypairError::InvalidSignatureType(7)),
            error_name(&KeypairError::NotEd25519),
            error_name(&KeypairError::Hkdf),
            error_name(&KeypairError::Poseidon(3)),
            error_name(&KeypairError::FieldElementTooLong),
            error_name(&KeypairError::InvalidPrehashLength(31)),
            error_name(&KeypairError::InfoTooLong),
        ],
        "badPrefixBytes": hex(&bad_prefix),
        "badPrefixError": error_name(&PublicKey::from_bytes(bad_prefix).unwrap_err()),
        "badPaddingBytes": hex(&bad_padding),
        "badPaddingError": error_name(&PublicKey::from_bytes(bad_padding).unwrap_err()),
        "badPointBytes": hex(&bad_point),
        "badPointError": error_name(&PublicKey::from_bytes(bad_point).unwrap_err()),
        "wrongRailError": error_name(&p256_public.as_ed25519().unwrap_err()),
        "notEd25519Error": error_name(
            &ShieldedKeypair::from_keys(p256_key(3), viewing(11))
                .unwrap()
                .to_solana_keypair()
                .unwrap_err(),
        ),
        // `FieldElementTooLong` comes from the crate-private `fe_right_align`,
        // which every public caller feeds a 31- or 32-byte value, so no public
        // Rust entry point can produce it today.
        "fieldElementTooLongReachableFromPublicApi": false,
    })
}

fn pubkeys() -> Value {
    let p256_public = p256_key(3).pubkey();
    let ed_public = SigningKey::from_ed25519(&secret32(9)).pubkey();
    let inner = p256_public.as_p256().unwrap();

    json!({
        "p256": {
            "taggedBytes": hex(p256_public.as_bytes()),
            "compressedBytes": hex(inner.as_bytes()),
            "xBytes": hex(&inner.x()),
            "yIsOdd": inner.y_is_odd(),
            "signatureType": signature_type_name(p256_public.signature_type().unwrap()),
            "confidentialViewTagBytes": hex(&p256_public.confidential_view_tag().unwrap()),
            "hashBytes": hex(&p256_public.hash().unwrap()),
            "ownerPkFieldBytes": hex(&p256_public.owner_pk_field().unwrap()),
            "isZero": p256_public.is_zero(),
        },
        "ed25519": {
            "taggedBytes": hex(ed_public.as_bytes()),
            "rawBytes": hex(&ed_public.as_ed25519().unwrap()),
            "signatureType": signature_type_name(ed_public.signature_type().unwrap()),
            "confidentialViewTagBytes": hex(&ed_public.confidential_view_tag().unwrap()),
            "hashBytes": hex(&ed_public.hash().unwrap()),
            "ownerPkFieldBytes": hex(&ed_public.owner_pk_field().unwrap()),
            "isZero": ed_public.is_zero(),
        },
        "zeroed": {
            "taggedBytes": hex(PublicKey::zeroed().as_bytes()),
            "isZero": PublicKey::zeroed().is_zero(),
        },
        "equality": {
            "sameKeyEqual": p256_public == p256_key(3).pubkey(),
            "differentKeyEqual": p256_public == p256_key(5).pubkey(),
            "crossRailEqual": p256_public == ed_public,
        },
        "signatureTypeBytes": {
            "p256": u8::from(SignatureType::P256),
            "ed25519": u8::from(SignatureType::Ed25519),
        },
    })
}

fn signature_type_name(value: SignatureType) -> &'static str {
    match value {
        SignatureType::P256 => "p256",
        SignatureType::Ed25519 => "ed25519",
    }
}

fn nullifier_keys() -> Value {
    let direct = NullifierKey::from_secret([5u8; BLINDING_LEN]);
    let signing = p256_key(3);
    let derived = NullifierKey::from_signing_key(&signing).unwrap();

    // Rust takes `&[u8]` here, so the IKM length is unconstrained. TypeScript
    // must accept exactly the same widths rather than demanding 32 bytes.
    let ikm_lengths: Vec<Value> = [0usize, 1, 16, 32, 64, 97]
        .into_iter()
        .map(|length| {
            let ikm = vec![0xa7u8; length];
            let key = NullifierKey::from_signing_secret_key_bytes(&ikm).unwrap();
            json!({
                "ikmBytes": hex(&ikm),
                "secretBytes": hex(key.secret()),
                "publicKeyBytes": hex(&key.pubkey().unwrap()),
            })
        })
        .collect();

    json!({
        "direct": {
            "secretBytes": hex(direct.secret()),
            "publicKeyBytes": hex(&direct.pubkey().unwrap()),
            "nullifierBytes": hex(&direct.nullifier(&sha256_be(b"parity/utxo"), &[3u8; BLINDING_LEN]).unwrap()),
            "zeroBlindingNullifierBytes": hex(&direct.nullifier(&sha256_be(b"parity/utxo"), &[0u8; BLINDING_LEN]).unwrap()),
            "maxBlindingNullifierBytes": hex(&direct.nullifier(&sha256_be(b"parity/utxo"), &[0xff; BLINDING_LEN]).unwrap()),
            "zeroUtxoNullifierBytes": hex(&direct.nullifier(&[0u8; 32], &[3u8; BLINDING_LEN]).unwrap()),
        },
        "zeroSecret": {
            "secretBytes": hex(NullifierKey::from_secret([0u8; BLINDING_LEN]).secret()),
            "publicKeyBytes": hex(&NullifierKey::from_secret([0u8; BLINDING_LEN]).pubkey().unwrap()),
        },
        "maxSecret": {
            "publicKeyBytes": hex(&NullifierKey::from_secret([0xff; BLINDING_LEN]).pubkey().unwrap()),
        },
        "fromSigningKey": {
            "signingSecretBytes": hex(&secret32(3)),
            "secretBytes": hex(derived.secret()),
            "publicKeyBytes": hex(&derived.pubkey().unwrap()),
            "repeatsIdentically": derived.secret()
                == NullifierKey::from_signing_key(&signing).unwrap().secret(),
        },
        "ikmLengths": ikm_lengths,
    })
}

fn hashes() -> Value {
    let value = sha256(b"parity/hash");
    let (low, high) = split_be_128(&value);
    let signing_public = p256_key(3).pubkey();
    let nullifier_public = NullifierKey::from_secret([5u8; BLINDING_LEN]).pubkey().unwrap();

    let arities: Vec<Value> = (1..=12usize)
        .map(|arity| {
            let inputs: Vec<[u8; 32]> = (0..arity)
                .map(|index| {
                    let mut fe = [0u8; 32];
                    fe[31] = index as u8 + 1;
                    fe[30] = arity as u8;
                    fe
                })
                .collect();
            let refs: Vec<&[u8]> = inputs.iter().map(|fe| fe.as_slice()).collect();
            json!({
                "inputsBytes": inputs.iter().map(|fe| hex(fe)).collect::<Vec<_>>(),
                "digestBytes": hex(&poseidon(&refs).unwrap()),
            })
        })
        .collect();

    json!({
        "preimageBytes": hex(b"parity/hash"),
        "sha256Bytes": hex(&value),
        "sha256BeBytes": hex(&sha256_be(b"parity/hash")),
        "splitLowBytes": hex(&low),
        "splitHighBytes": hex(&high),
        "hashFieldBytes": hex(&hash_field(&value).unwrap()),
        "hashFieldZeroBytes": hex(&hash_field(&[0u8; 32]).unwrap()),
        "ownerHashBytes": hex(&owner_hash(&signing_public, &nullifier_public).unwrap()),
        "poseidonArities": arities,
        "tooManyInputsRejected": poseidon(&[&[1u8; 32][..]; 13]).is_err(),
        "zeroInputsRejected": poseidon(&[]).is_err(),
        // A raw SHA-256 digest is not automatically a field element: the Rust
        // hasher refuses one above the BN254 modulus rather than reducing it.
        "nonCanonicalInputBytes": hex(&[0xff; 32]),
        "nonCanonicalInputRejected": poseidon(&[&[0xff; 32][..]]).is_err(),
        "nonCanonicalNullifierRejected": NullifierKey::from_secret([5u8; BLINDING_LEN])
            .nullifier(&[0xff; 32], &[3u8; BLINDING_LEN])
            .is_err(),
    })
}

fn viewing_keys() -> Value {
    let key = viewing(11);
    let counterparty = viewing(23);

    let counters = [0u64, 1, 42, u64::MAX];
    let tags: Vec<Value> = counters
        .iter()
        .map(|counter| {
            json!({
                "counter": counter.to_string(),
                "senderBytes": hex(&key.get_sender_view_tag(*counter).unwrap()),
                "recipientRequestBytes": hex(&key.get_recipient_request_view_tag(*counter).unwrap()),
                "mergeBytes": hex(&key.get_merge_view_tag(*counter).unwrap()),
                "sendSharedBytes": hex(&key.get_send_shared_view_tag(&counterparty.pubkey(), *counter).unwrap()),
                "recipientSharedBytes": hex(&key.get_recipient_shared_view_tag(&counterparty.pubkey(), *counter).unwrap()),
            })
        })
        .collect();

    let seeded: Vec<Value> = [0u32, 1, 7, u32::MAX]
        .into_iter()
        .map(|account| {
            let derived = ViewingKey::from_seed(&secret32(31), account).unwrap();
            json!({
                "account": account,
                "secretBytes": hex(derived.secret_bytes().as_slice()),
                "publicKeyBytes": hex(derived.pubkey().as_bytes()),
            })
        })
        .collect();

    let transaction = key.get_transaction_viewing_key(&sha256_be(b"parity/nullifier")).unwrap();

    json!({
        "secretBytes": hex(&secret32(11)),
        "publicKeyBytes": hex(key.pubkey().as_bytes()),
        "counterpartySecretBytes": hex(&secret32(23)),
        "counterpartyPublicKeyBytes": hex(counterparty.pubkey().as_bytes()),
        "ecdhBytes": hex(&key.ecdh(&counterparty.pubkey()).unwrap()),
        "ecdhWithPConstBytes": hex(&key.ecdh(&P256Pubkey::from_bytes(P_CONST_SEC1).unwrap()).unwrap()),
        "bootstrapTagBytes": hex(&key.recipient_bootstrap_view_tag()),
        "tags": tags,
        "seedBytes": hex(&secret32(31)),
        "seeded": seeded,
        "firstNullifierBytes": hex(&sha256_be(b"parity/nullifier")),
        "transactionSecretBytes": hex(transaction.secret_bytes().as_slice()),
        "transactionPublicKeyBytes": hex(transaction.pubkey().as_bytes()),
        "sharedTagsAgree": key.get_send_shared_view_tag(&counterparty.pubkey(), 42).unwrap()
            == counterparty.get_recipient_shared_view_tag(&key.pubkey(), 42).unwrap(),
        "invalidSecretError": error_name(&expect_err(ViewingKey::from_bytes(&[0u8; 32]))),
    })
}

fn encryption() -> Value {
    let sender = viewing(11);
    let recipient = viewing(23);

    // Length sweep across the AES-CTR block boundary: an off-by-one in the
    // counter only shows up once the keystream crosses 16 bytes.
    let lengths: Vec<Value> = [0usize, 1, 15, 16, 17, 31, 32, 33, 64, 71, 128, 129]
        .into_iter()
        .map(|length| {
            let plaintext: Vec<u8> = (0..length).map(|index| (index * 5 + 1) as u8).collect();
            let ciphertext = sender
                .encrypt_slot(&recipient.pubkey(), &plaintext, [0x5a; SALT_LEN], 3)
                .unwrap();
            json!({
                "length": length,
                "plaintextBytes": hex(&plaintext),
                "ciphertextBytes": hex(&ciphertext),
                "recoveredBytes": hex(
                    &recipient
                        .decrypt_utxo(&ciphertext, &sender.pubkey(), [0x5a; SALT_LEN], 3)
                        .unwrap(),
                ),
            })
        })
        .collect();

    let plaintext = b"parity/encryption plaintext block boundary".to_vec();
    let slots: Vec<Value> = [0u32, 1, 2, 65_535, u32::MAX]
        .into_iter()
        .map(|slot| {
            json!({
                "slot": slot,
                "ciphertextBytes": hex(
                    &sender
                        .encrypt_slot(&recipient.pubkey(), &plaintext, [0x5a; SALT_LEN], slot)
                        .unwrap(),
                ),
            })
        })
        .collect();

    let salts: Vec<Value> = [[0u8; SALT_LEN], [0xff; SALT_LEN], [0x5a; SALT_LEN]]
        .into_iter()
        .map(|salt| {
            json!({
                "saltBytes": hex(&salt),
                "ciphertextBytes": hex(
                    &sender.encrypt_slot(&recipient.pubkey(), &plaintext, salt, 3).unwrap(),
                ),
            })
        })
        .collect();

    let ciphertext = sender
        .encrypt_slot(&recipient.pubkey(), &plaintext, [0x5a; SALT_LEN], 3)
        .unwrap();

    json!({
        "senderSecretBytes": hex(&secret32(11)),
        "recipientSecretBytes": hex(&secret32(23)),
        "plaintextBytes": hex(&plaintext),
        "lengths": lengths,
        "slots": slots,
        "salts": salts,
        "ephemeralRecoveredBytes": hex(
            &sender
                .decrypt_slot_ephemeral(&recipient.pubkey(), &ciphertext, [0x5a; SALT_LEN], 3)
                .unwrap(),
        ),
        "wrongSlotRecoveredBytes": hex(
            &recipient
                .decrypt_utxo(&ciphertext, &sender.pubkey(), [0x5a; SALT_LEN], 4)
                .unwrap(),
        ),
        "wrongSaltRecoveredBytes": hex(
            &recipient
                .decrypt_utxo(&ciphertext, &sender.pubkey(), [0x5b; SALT_LEN], 3)
                .unwrap(),
        ),
        "truncatedRecoveredBytes": hex(
            &recipient
                .decrypt_utxo(&ciphertext[..8], &sender.pubkey(), [0x5a; SALT_LEN], 3)
                .unwrap(),
        ),
        "extendedRecoveredBytes": hex(&{
            let mut extended = ciphertext.clone();
            extended.extend_from_slice(&[0u8; 16]);
            recipient
                .decrypt_utxo(&extended, &sender.pubkey(), [0x5a; SALT_LEN], 3)
                .unwrap()
        }),
        "tamperedRecoveredBytes": hex(&{
            let mut tampered = ciphertext.clone();
            tampered[0] ^= 0xff;
            recipient
                .decrypt_utxo(&tampered, &sender.pubkey(), [0x5a; SALT_LEN], 3)
                .unwrap()
        }),
    })
}

fn merge() -> Value {
    let tx = viewing(41);
    let user = viewing(53);
    let plaintext: Vec<u8> = (0..71u8).collect();

    let (ciphertext, tx_public) = tx
        .encrypt_verifiable(&user.pubkey(), &plaintext)
        .expect("merge encryption");
    let contribution = merge_public_contribution(&tx_public, &ciphertext).unwrap();

    // `symmetric_apply` is the public capability the TypeScript port has to
    // grow: same key schedule, caller-chosen `info`, no ECDH.
    let symmetric: Vec<Value> = [0usize, 1, 10, 31, 32, 47]
        .into_iter()
        .map(|length| {
            let info = vec![0x6cu8; length];
            let mut buffer = plaintext.clone();
            symmetric_apply(&sha256_be(b"parity/shared"), &info, &mut buffer).unwrap();
            let mut round_trip = buffer.clone();
            symmetric_apply(&sha256_be(b"parity/shared"), &info, &mut round_trip).unwrap();
            json!({
                "infoLength": length,
                "infoBytes": hex(&info),
                "ciphertextBytes": hex(&buffer),
                "roundTripBytes": hex(&round_trip),
            })
        })
        .collect();

    let mut overlong = plaintext.clone();
    let overlong_error =
        symmetric_apply(&sha256_be(b"parity/shared"), &[0x6c; MAX_INFO_LEN + 1], &mut overlong)
            .unwrap_err();

    json!({
        "txSecretBytes": hex(&secret32(41)),
        "userSecretBytes": hex(&secret32(53)),
        "userPublicKeyBytes": hex(user.pubkey().as_bytes()),
        "plaintextBytes": hex(&plaintext),
        "ciphertextBytes": hex(&ciphertext),
        "txViewingPublicKeyBytes": hex(tx_public.as_bytes()),
        "recoveredBytes": hex(
            &user.decrypt_verifiable(&tx_public, &ciphertext).unwrap(),
        ),
        "ciphertextHashBytes": hex(&merge_ciphertext_hash(&ciphertext).unwrap()),
        "txViewingPublicKeyLowBytes": hex(&contribution.tx_viewing_pk_lo),
        "txViewingPublicKeyHighBytes": hex(&contribution.tx_viewing_pk_hi),
        "symmetric": symmetric,
        "symmetricSharedSecretBytes": hex(&sha256_be(b"parity/shared")),
        "overlongInfoBytes": hex(&[0x6c; MAX_INFO_LEN + 1]),
        "overlongInfoError": error_name(&overlong_error),
        // `pack_info` writes the length into the top byte of the low limb, so an
        // `info` of 48 bytes or more can land above the BN254 modulus and the
        // Poseidon key schedule refuses it before `InfoTooLong` ever applies.
        // Whether it does depends on the label bytes, not the length alone,
        // so the exact refused label is recorded here.
        "fieldLimitedInfoBytes": hex(&[0x6c; 48]),
        "fieldLimitedInfoError": error_name(&{
            let mut buffer = plaintext.clone();
            symmetric_apply(&sha256_be(b"parity/shared"), &[0x6c; 48], &mut buffer).unwrap_err()
        }),
        "emptyCiphertextHashRejected": merge_ciphertext_hash(&[]).is_err(),
    })
}

fn shielded() -> Value {
    let p256 = ShieldedKeypair::from_keys(p256_key(3), viewing(11)).unwrap();
    let ed = ShieldedKeypair::from_ed25519(&secret32(9), ViewingKey::from_seed(&secret32(9), 0).unwrap())
        .unwrap();

    let describe = |keypair: &ShieldedKeypair| -> Value {
        let address = keypair.shielded_address().unwrap();
        let compressed = keypair.compressed_address().unwrap();
        json!({
            "signingPublicKeyBytes": hex(address.signing_pubkey.as_bytes()),
            "nullifierPublicKeyBytes": hex(&address.nullifier_pubkey),
            "viewingPublicKeyBytes": hex(address.viewing_pubkey.as_bytes()),
            "ownerHashBytes": hex(&keypair.owner_hash().unwrap()),
            "addressOwnerHashBytes": hex(&address.owner_hash().unwrap()),
            "confidentialViewTagBytes": hex(&address.confidential_view_tag().unwrap()),
            "compressedOwnerHashBytes": hex(&compressed.owner_hash),
            "compressedViewingPublicKeyBytes": hex(compressed.viewing_pubkey.as_bytes()),
            "compressedHashBytes": hex(&compressed.hash().unwrap()),
            "solanaAddress": address
                .solana_address()
                .map(|value| Value::String(value.to_string()))
                .unwrap_or(Value::Null),
            "nullifierBytes": hex(
                &keypair.nullifier(&sha256_be(b"parity/utxo"), &[3u8; BLINDING_LEN]).unwrap(),
            ),
        })
    };

    json!({
        "p256": {
            "signingSecretBytes": hex(&secret32(3)),
            "viewingSecretBytes": hex(&secret32(11)),
            "derived": describe(&p256),
        },
        "ed25519": {
            "signingSecretBytes": hex(&secret32(9)),
            "viewingAccount": 0,
            "derived": describe(&ed),
            "solanaKeypairSecretBytes": hex(&ed.to_solana_keypair().unwrap().secret_bytes()[..]),
        },
        "fromKeysDerivesNullifierFromSigningSecret":
            p256.nullifier_key.secret()
                == NullifierKey::from_signing_key(&p256_key(3)).unwrap().secret(),
    })
}

fn document() -> Value {
    let mut root = Map::new();
    root.insert("schema".into(), json!("zolana-keypair-parity-v1"));
    root.insert(
        "source".into(),
        json!("sdk-libs/keypair/tests/parity_vectors.rs"),
    );
    root.insert(
        "note".into(),
        json!(
            "Every value is produced by the current zolana-keypair crate. \
             Regenerate with UPDATE_KEYPAIR_VECTORS=1."
        ),
    );
    root.insert("constants".into(), constants());
    root.insert("errors".into(), errors());
    root.insert("signing".into(), signing());
    root.insert("pubkeys".into(), pubkeys());
    root.insert("nullifierKeys".into(), nullifier_keys());
    root.insert("hashes".into(), hashes());
    root.insert("viewingKeys".into(), viewing_keys());
    root.insert("encryption".into(), encryption());
    root.insert("merge".into(), merge());
    root.insert("shielded".into(), shielded());
    Value::Object(root)
}

#[test]
fn committed_vectors_match_current_rust() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTOR_PATH);
    let generated = format!("{}\n", serde_json::to_string_pretty(&document()).unwrap());

    if std::env::var_os("UPDATE_KEYPAIR_VECTORS").is_some() {
        std::fs::write(&path, &generated).expect("write parity vectors");
        return;
    }

    let committed = std::fs::read_to_string(&path).expect(
        "sdk-libs/ts/vectors/keypair-parity-v1.json is missing; regenerate with \
         UPDATE_KEYPAIR_VECTORS=1",
    );
    assert_eq!(
        committed, generated,
        "committed parity vectors drifted from the current Rust crate",
    );
}
