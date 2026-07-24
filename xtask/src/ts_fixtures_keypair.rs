#[path = "../../sdk-libs/keypair/src/constants.rs"]
mod constants;
#[path = "../../sdk-libs/keypair/src/encryption.rs"]
mod encryption;
#[path = "../../sdk-libs/keypair/src/error.rs"]
mod error;
#[path = "../../sdk-libs/keypair/src/hash.rs"]
mod hash;
#[path = "../../sdk-libs/keypair/src/merge.rs"]
mod merge;
#[path = "../../sdk-libs/keypair/src/nullifier_key.rs"]
mod nullifier_key;
#[path = "../../sdk-libs/keypair/src/pubkey.rs"]
mod pubkey;
#[path = "../../sdk-libs/keypair/src/shielded.rs"]
mod shielded;
#[path = "../../sdk-libs/keypair/src/signing_key.rs"]
mod signing_key;
#[path = "../../sdk-libs/keypair/src/viewing_key.rs"]
mod viewing_key;

use serde_json::{json, Value};

use crate::{
    constants::{
        BLINDING_LEN, DST_VIEW_ROOT_P_CONST, P256_PUBKEY_LEN, PUBLIC_KEY_LEN, P_CONST_SEC1,
        SALT_LEN, VIEW_TAG_LEN,
    },
    error::KeypairError,
    nullifier_key::NullifierKey,
    pubkey::{P256Pubkey, PublicKey},
    shielded::{CompressedShieldedAddress, ShieldedKeypair},
    signing_key::SigningKey,
    viewing_key::ViewingKey,
};

fn main() {
    let sections = sections().expect("generate keypair fixtures");
    println!(
        "{}",
        serde_json::to_string(&sections).expect("serialize fixtures")
    );
}

fn sections() -> Result<Value, KeypairError> {
    let p256_secret = scalar(1);
    let recipient_secret = scalar(2);
    let p256_signing = SigningKey::from_bytes(&p256_secret)?;
    let p256_public = p256_signing.pubkey();
    let p256_body = p256_public.as_p256()?;
    let message = hash::sha256(b"same");
    let p256_signature = p256_signing.sign(&message);
    assert!(p256_signing.verify(&message, &p256_signature));
    let mut tampered_signature = p256_signature;
    tampered_signature[0] ^= 1;
    assert!(!p256_signing.verify(&message, &tampered_signature));

    let ed25519_secret =
        decode32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let ed25519_signing = SigningKey::from_ed25519(&ed25519_secret);
    let ed25519_public = ed25519_signing.pubkey();
    let ed25519_signature = ed25519_signing.sign(&[]);
    assert!(ed25519_signing.verify(&[], &ed25519_signature));

    let nullifier_secret = [7u8; BLINDING_LEN];
    let nullifier = NullifierKey::from_secret(nullifier_secret);
    let utxo_hash = [6u8; 32];
    let blinding = [8u8; BLINDING_LEN];
    let nullifier_value = nullifier.nullifier(&utxo_hash, &blinding)?;
    assert_eq!(nullifier_value, nullifier.nullifier(&utxo_hash, &blinding)?);

    let viewing = ViewingKey::from_bytes(&p256_secret)?;
    let recipient = ViewingKey::from_bytes(&recipient_secret)?;
    let shared = viewing.ecdh(&recipient.pubkey())?;
    assert_eq!(shared, recipient.ecdh(&viewing.pubkey())?);
    let sender_tag = viewing.get_sender_view_tag(11)?;
    let recipient_request_tag = viewing.get_recipient_request_view_tag(11)?;
    let merge_tag = viewing.get_merge_view_tag(11)?;
    let send_shared_tag = viewing.get_send_shared_view_tag(&recipient.pubkey(), 11)?;
    let recipient_shared_tag = recipient.get_recipient_shared_view_tag(&viewing.pubkey(), 11)?;
    assert_eq!(send_shared_tag, recipient_shared_tag);
    let first_nullifier = [8u8; 32];
    let transaction_viewing_key = viewing.get_transaction_viewing_key(&first_nullifier)?;
    let seeded_viewing = ViewingKey::from_seed(&[7u8; 32], 9)?;

    let plaintext = b"deterministic";
    let salt = [0u8; SALT_LEN];
    let ciphertext = viewing.encrypt_slot(&recipient.pubkey(), plaintext, salt, 0)?;
    let recipient_plaintext = recipient.decrypt_utxo(&ciphertext, &viewing.pubkey(), salt, 0)?;
    let ephemeral_plaintext =
        viewing.decrypt_slot_ephemeral(&recipient.pubkey(), &ciphertext, salt, 0)?;
    assert_eq!(recipient_plaintext, plaintext);
    assert_eq!(ephemeral_plaintext, plaintext);
    let wrong_slot = recipient.decrypt_utxo(&ciphertext, &viewing.pubkey(), salt, 1)?;
    assert_ne!(wrong_slot, plaintext);

    let merge_tx_secret = scalar(123_456_789);
    let merge_user_secret = scalar(7);
    let merge_tx = ViewingKey::from_bytes(&merge_tx_secret)?;
    let merge_user = ViewingKey::from_bytes(&merge_user_secret)?;
    let merge_plaintext = (0..71u8).collect::<Vec<_>>();
    let (merge_ciphertext, merge_tx_public) =
        merge_tx.encrypt_verifiable(&merge_user.pubkey(), &merge_plaintext)?;
    let merge_recovered = merge_user.decrypt_verifiable(&merge_tx_public, &merge_ciphertext)?;
    assert_eq!(merge_recovered, merge_plaintext);
    let merge_contribution = merge::merge_public_contribution(&merge_tx_public, &merge_ciphertext)?;
    let mut tampered_merge = merge_ciphertext.clone();
    tampered_merge[0] ^= 1;

    let p256_keypair = ShieldedKeypair::from_keys(
        SigningKey::from_bytes(&scalar(3))?,
        ViewingKey::from_bytes(&scalar(4))?,
    )?;
    let p256_address = p256_keypair.shielded_address()?;
    let p256_compressed = p256_keypair.compressed_address()?;
    assert_eq!(p256_address.owner_hash()?, p256_keypair.owner_hash()?);
    assert_eq!(
        CompressedShieldedAddress::try_from(&p256_address)?,
        p256_compressed
    );
    let ed25519_viewing = ViewingKey::from_seed(&[5u8; 32], 9)?;
    let ed25519_keypair = ShieldedKeypair::from_ed25519(&[5u8; 32], ed25519_viewing)?;
    let ed25519_address = ed25519_keypair.shielded_address()?;
    let ed25519_compressed = ed25519_keypair.compressed_address()?;
    assert_eq!(ed25519_address.owner_hash()?, ed25519_keypair.owner_hash()?);
    assert_eq!(
        CompressedShieldedAddress::try_from(&ed25519_address)?,
        ed25519_compressed
    );

    let mut invalid_prefix = [0u8; PUBLIC_KEY_LEN];
    invalid_prefix[0] = 9;
    let invalid_prefix_error = PublicKey::from_bytes(invalid_prefix).expect_err("prefix");
    let invalid_p256_error =
        P256Pubkey::from_bytes([0u8; P256_PUBKEY_LEN]).expect_err("P256 point");
    let invalid_secret_error = match SigningKey::from_bytes(&[0u8; 32]) {
        Err(error) => error,
        Ok(_) => panic!("zero P256 scalar was accepted"),
    };
    let wrong_rail_error = p256_public.as_ed25519().expect_err("P256 as Ed25519");
    let not_ed25519_error = p256_keypair
        .to_solana_keypair()
        .expect_err("P256 Solana keypair");
    let mut invalid_ed25519 = *ed25519_public.as_bytes();
    invalid_ed25519[PUBLIC_KEY_LEN - 1] = 1;
    let invalid_ed25519_error =
        PublicKey::from_bytes(invalid_ed25519).expect_err("Ed25519 padding");

    Ok(json!({
        "constants": {
            "expected": {
                "blindingLength": BLINDING_LEN.to_string(),
                "dstViewRootBytes": hex(DST_VIEW_ROOT_P_CONST),
                "mergeInfoBytes": hex(merge::MERGE_INFO),
                "p256PublicKeyLength": P256_PUBKEY_LEN.to_string(),
                "pConstBytes": hex(&P_CONST_SEC1),
                "publicKeyLength": PUBLIC_KEY_LEN.to_string(),
                "saltLength": SALT_LEN.to_string(),
                "viewTagLength": VIEW_TAG_LEN.to_string()
            },
            "inputs": {
                "recordedBlindingBytes": hex(&blinding),
                "recordedSaltBytes": hex(&salt),
                "testOnlySecret": true
            }
        },
        "encryption": {
            "expected": {
                "ciphertextBytes": hex(&ciphertext),
                "ephemeralRecoveredBytes": hex(&ephemeral_plaintext),
                "recipientRecoveredBytes": hex(&recipient_plaintext),
                "wrongSlotRecoveredBytes": hex(&wrong_slot)
            },
            "inputs": {
                "ephemeralSecretBytes": hex(&p256_secret),
                "plaintextBytes": hex(plaintext),
                "recipientPublicKeyBytes": hex(recipient.pubkey().as_bytes()),
                "recipientSecretBytes": hex(&recipient_secret),
                "saltBytes": hex(&salt),
                "slotIndex": "0",
                "testOnlySecret": true
            }
        },
        "error": {
            "expected": {
                "invalidEd25519Padding": error_json(invalid_ed25519_error),
                "invalidP256Point": error_json(invalid_p256_error),
                "invalidSecretScalar": error_json(invalid_secret_error),
                "invalidSignaturePrefix": error_json(invalid_prefix_error),
                "notEd25519": error_json(not_ed25519_error),
                "tamperedEd25519SignatureValid": ed25519_signing.verify(&[1], &ed25519_signature),
                "tamperedP256SignatureValid": p256_signing.verify(&message, &tampered_signature),
                "wrongRail": error_json(wrong_rail_error)
            },
            "inputs": {
                "invalidP256Bytes": hex(&[0u8; P256_PUBKEY_LEN]),
                "invalidSecretBytes": hex(&[0u8; 32]),
                "invalidSignaturePrefix": "9",
                "testOnlySecret": true
            }
        },
        "hash": {
            "expected": {
                "ed25519OwnerFieldBytes": hex(&ed25519_public.owner_pk_field()?),
                "ed25519PublicHashBytes": hex(&ed25519_public.hash()?),
                "p256OwnerFieldBytes": hex(&p256_public.owner_pk_field()?),
                "p256PublicHashBytes": hex(&p256_public.hash()?),
                "sha256BeBytes": hex(&hash::sha256_be(b"same")),
                "sha256Bytes": hex(&message),
                "splitHighBytes": hex(&hash::split_be_128(&message).1),
                "splitLowBytes": hex(&hash::split_be_128(&message).0)
            },
            "inputs": {
                "preimageBytes": hex(b"same"),
                "testOnlySecret": true
            }
        },
        "lib": {
            "expected": {
                "ed25519SignatureLength": ed25519_signature.len().to_string(),
                "p256SignatureLength": p256_signature.len().to_string(),
                "randomBlindingLength": BLINDING_LEN.to_string(),
                "randomSaltLength": SALT_LEN.to_string(),
                "signatureTypes": ["p256", "ed25519"]
            },
            "inputs": {
                "recordedRandomBlindingBytes": hex(&blinding),
                "recordedRandomSaltBytes": hex(&salt),
                "testOnlySecret": true
            }
        },
        "merge": {
            "expected": {
                "ciphertextBytes": hex(&merge_ciphertext),
                "ciphertextHashBytes": hex(&merge_contribution.ciphertext_hash),
                "recoveredBytes": hex(&merge_recovered),
                "tamperedCiphertextHashBytes": hex(&merge::merge_ciphertext_hash(&tampered_merge)?),
                "txViewingPublicKeyBytes": hex(merge_tx_public.as_bytes()),
                "txViewingPublicKeyHighBytes": hex(&merge_contribution.tx_viewing_pk_hi),
                "txViewingPublicKeyLowBytes": hex(&merge_contribution.tx_viewing_pk_lo)
            },
            "inputs": {
                "plaintextBytes": hex(&merge_plaintext),
                "testOnlySecret": true,
                "txViewingSecretBytes": hex(&merge_tx_secret),
                "userViewingPublicKeyBytes": hex(merge_user.pubkey().as_bytes()),
                "userViewingSecretBytes": hex(&merge_user_secret)
            }
        },
        "nullifier_key": {
            "expected": {
                "derivedFromSigningPublicKeyBytes": hex(&NullifierKey::from_signing_key(&SigningKey::from_bytes(&scalar(3))?)?.pubkey()?),
                "nullifierBytes": hex(&nullifier_value),
                "publicKeyBytes": hex(&nullifier.pubkey()?)
            },
            "inputs": {
                "blindingBytes": hex(&blinding),
                "secretBytes": hex(&nullifier_secret),
                "signingSecretBytes": hex(&scalar(3)),
                "testOnlySecret": true,
                "utxoHashBytes": hex(&utxo_hash)
            }
        },
        "pubkey": {
            "expected": {
                "ed25519Bytes": hex(ed25519_public.as_bytes()),
                "ed25519ConfidentialViewTagBytes": hex(&ed25519_public.confidential_view_tag()?),
                "ed25519RoundTripBytes": hex(PublicKey::from_bytes(*ed25519_public.as_bytes())?.as_bytes()),
                "p256Bytes": hex(p256_public.as_bytes()),
                "p256ConfidentialViewTagBytes": hex(&p256_public.confidential_view_tag()?),
                "p256RoundTripBytes": hex(PublicKey::from_bytes(*p256_public.as_bytes())?.as_bytes()),
                "p256XBytes": hex(&p256_body.x()),
                "p256YIsOdd": p256_body.y_is_odd()
            },
            "inputs": {
                "ed25519SecretBytes": hex(&ed25519_secret),
                "p256SecretBytes": hex(&p256_secret),
                "testOnlySecret": true
            }
        },
        "shielded": {
            "expected": {
                "ed25519": shielded_json(&ed25519_keypair, &ed25519_address, &ed25519_compressed)?,
                "p256": shielded_json(&p256_keypair, &p256_address, &p256_compressed)?
            },
            "inputs": {
                "ed25519SecretBytes": hex(&[5u8; 32]),
                "ed25519ViewingAccount": "9",
                "p256SigningSecretBytes": hex(&scalar(3)),
                "p256ViewingSecretBytes": hex(&scalar(4)),
                "testOnlySecret": true
            }
        },
        "signing_key": {
            "expected": {
                "ed25519": {
                    "confidentialViewTagBytes": hex(&ed25519_public.confidential_view_tag()?),
                    "publicKeyBytes": hex(ed25519_public.as_bytes()),
                    "signatureBytes": hex(&ed25519_signature),
                    "signatureType": "ed25519",
                    "verified": ed25519_signing.verify(&[], &ed25519_signature)
                },
                "p256": {
                    "publicKeyBytes": hex(p256_public.as_bytes()),
                    "signatureBytes": hex(&p256_signature),
                    "signatureType": "p256",
                    "verified": p256_signing.verify(&message, &p256_signature)
                }
            },
            "inputs": {
                "ed25519MessageBytes": "",
                "ed25519SecretBytes": hex(&ed25519_secret),
                "p256MessageDigestBytes": hex(&message),
                "p256SecretBytes": hex(&p256_secret),
                "testOnlySecret": true
            }
        },
        "tests": {
            "expected": {
                "allTagDirectionsAgree": send_shared_tag == recipient_shared_tag,
                "ed25519RoundTripVerified": ed25519_signing.verify(&[], &ed25519_signature),
                "mergeRoundTripVerified": merge_recovered == merge_plaintext,
                "p256RoundTripVerified": p256_signing.verify(&message, &p256_signature),
                "slotRoundTripVerified": recipient_plaintext == plaintext
            },
            "inputs": {
                "fixedRandomnessOnly": true,
                "testOnlySecret": true
            }
        },
        "viewing_key": {
            "expected": {
                "bootstrapTagBytes": hex(&viewing.recipient_bootstrap_view_tag()),
                "ecdhSharedBytes": hex(&shared),
                "mergeTagBytes": hex(&merge_tag),
                "mergeTagRootBytes": hex(&viewing.merge_view_tag_secret()?),
                "publicKeyBytes": hex(viewing.pubkey().as_bytes()),
                "recipientRequestTagBytes": hex(&recipient_request_tag),
                "recipientTagRootBytes": hex(&viewing.recipient_view_tag_secret()?),
                "seededPublicKeyBytes": hex(seeded_viewing.pubkey().as_bytes()),
                "seededSecretBytes": hex(seeded_viewing.secret_bytes().as_slice()),
                "sendSharedTagBytes": hex(&send_shared_tag),
                "senderTagBytes": hex(&sender_tag),
                "senderTagRootBytes": hex(&viewing.sender_view_tag_secret()?),
                "transactionViewingPublicKeyBytes": hex(transaction_viewing_key.pubkey().as_bytes()),
                "transactionViewingSecretBytes": hex(transaction_viewing_key.secret_bytes().as_slice()),
                "txViewingTagRootBytes": hex(&viewing.tx_viewing_secret()?)
            },
            "inputs": {
                "counterpartySecretBytes": hex(&recipient_secret),
                "firstNullifierBytes": hex(&first_nullifier),
                "seedAccount": "9",
                "seedBytes": hex(&[7u8; 32]),
                "tagIndex": "11",
                "testOnlySecret": true,
                "viewingSecretBytes": hex(&p256_secret)
            }
        }
    }))
}

fn shielded_json(
    keypair: &ShieldedKeypair,
    address: &shielded::ShieldedAddress,
    compressed: &CompressedShieldedAddress,
) -> Result<Value, KeypairError> {
    Ok(json!({
        "compressedAddressHashBytes": hex(&compressed.hash()?),
        "compressedOwnerHashBytes": hex(&compressed.owner_hash),
        "compressedViewingPublicKeyBytes": hex(compressed.viewing_pubkey.as_bytes()),
        "confidentialViewTagBytes": hex(&address.confidential_view_tag()?),
        "nullifierPublicKeyBytes": hex(&address.nullifier_pubkey),
        "ownerHashBytes": hex(&keypair.owner_hash()?),
        "signingPublicKeyBytes": hex(address.signing_pubkey.as_bytes()),
        "solanaAddress": address.solana_address().ok().map(|value| value.to_string()),
        "viewingPublicKeyBytes": hex(address.viewing_pubkey.as_bytes())
    }))
}

fn error_json(error: KeypairError) -> Value {
    json!({
        "code": match error {
            KeypairError::InvalidPublicKey => "InvalidPublicKey",
            KeypairError::InvalidSecretKey => "InvalidSecretKey",
            KeypairError::ZeroScalar => "ZeroScalar",
            KeypairError::InvalidSignatureType(_) => "InvalidSignatureType",
            KeypairError::NotEd25519 => "NotEd25519",
            KeypairError::Hkdf => "Hkdf",
            KeypairError::Poseidon(_) => "Poseidon",
            KeypairError::FieldElementTooLong => "FieldElementTooLong"
        },
        "details": format!("{error:?}")
    })
}

fn scalar(value: u32) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[28..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn decode32(value: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("test hex");
    }
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
