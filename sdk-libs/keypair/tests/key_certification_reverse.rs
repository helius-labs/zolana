//! Verifies the corpus produced by `@zolana/keypair`, closing the direction the
//! replay suites cannot: TypeScript signs and derives, Rust checks.
//!
//! `sdk-libs/ts/keypair/test/vectors/key-certification-reverse.test.ts` writes
//! the file and pins it against a regeneration, so material accepted here was
//! produced by the TypeScript implementation rather than transcribed from this
//! one. A signature is both verified and re-signed: verification alone would
//! pass for any valid signature, and re-signing is what makes the deterministic
//! bytes agree.

use serde_json::Value;
use zolana_keypair::{
    constants::BLINDING_LEN, nullifier_key::NullifierKey, signing_key::SigningKey,
    viewing_key::ViewingKey,
};

const VECTOR_PATH: &str = "../ts/vectors/key-certification-typescript-v1.json";

fn corpus() -> Value {
    let raw = std::fs::read_to_string(VECTOR_PATH).expect("TypeScript corpus is committed");
    serde_json::from_str(&raw).expect("TypeScript corpus is valid json")
}

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(value[key].as_str().expect("hex string")).expect("hex string")
}

fn array32(value: &Value, key: &str) -> [u8; 32] {
    bytes(value, key).try_into().expect("32 bytes")
}

fn array64(value: &Value, key: &str) -> [u8; 64] {
    bytes(value, key).try_into().expect("64 bytes")
}

fn entries<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value[key].as_array().expect("array")
}

#[test]
fn rust_verifies_typescript_p256_signatures() {
    let corpus = corpus();
    let section = &corpus["p256"];
    let key = SigningKey::from_bytes(&array32(section, "secretBytes")).expect("secret in range");
    assert_eq!(
        hex::encode(key.pubkey().as_bytes()),
        section["taggedPublicKeyBytes"].as_str().expect("hex")
    );

    let signatures = entries(section, "signatures");
    assert!(!signatures.is_empty());
    for entry in signatures {
        let digest = array32(entry, "digestBytes");
        let signature = array64(entry, "signatureBytes");
        assert!(
            key.verify(&digest, &signature),
            "rust rejected a typescript p256 signature over {}",
            hex::encode(digest)
        );
        assert_eq!(
            key.sign(&digest),
            signature,
            "deterministic p256 signature differs for {}",
            hex::encode(digest)
        );
    }
}

#[test]
fn rust_verifies_typescript_ed25519_signatures() {
    let corpus = corpus();
    let section = &corpus["ed25519"];
    let key = SigningKey::from_ed25519(&array32(section, "secretBytes"));
    assert_eq!(
        hex::encode(key.pubkey().as_bytes()),
        section["taggedPublicKeyBytes"].as_str().expect("hex")
    );

    let signatures = entries(section, "signatures");
    assert!(!signatures.is_empty());
    for entry in signatures {
        let message = bytes(entry, "messageBytes");
        let signature = array64(entry, "signatureBytes");
        assert!(
            key.verify(&message, &signature),
            "verify_strict rejected a typescript signature over {}",
            hex::encode(&message)
        );
        assert_eq!(key.sign(&message), signature);
    }
}

#[test]
fn rust_reproduces_typescript_nullifiers() {
    let corpus = corpus();
    let section = &corpus["nullifiers"];
    let signing =
        SigningKey::from_bytes(&array32(section, "signingSecretBytes")).expect("secret in range");
    let key = NullifierKey::from_signing_key(&signing).expect("hkdf");
    assert_eq!(
        hex::encode(key.secret()),
        section["secretBytes"].as_str().expect("hex")
    );
    assert_eq!(
        hex::encode(key.pubkey().expect("poseidon")),
        section["publicKeyBytes"].as_str().expect("hex")
    );

    for entry in entries(section, "derivations") {
        let blinding: [u8; BLINDING_LEN] = bytes(entry, "blindingBytes")
            .try_into()
            .expect("31-byte blinding");
        let nullifier = key
            .nullifier(&array32(entry, "utxoHashBytes"), &blinding)
            .expect("poseidon");
        assert_eq!(
            hex::encode(nullifier),
            entry["nullifierBytes"].as_str().expect("hex")
        );
    }
}

#[test]
fn rust_reproduces_typescript_viewing_key_material() {
    let corpus = corpus();
    let section = &corpus["viewing"];
    let key = ViewingKey::from_bytes(&array32(section, "secretBytes")).expect("secret in range");
    assert_eq!(
        hex::encode(key.pubkey().as_bytes()),
        section["publicKeyBytes"].as_str().expect("hex")
    );

    for entry in entries(section, "senderTagBytes") {
        let counter: u64 = entry["counter"]
            .as_str()
            .expect("counter is a decimal string")
            .parse()
            .expect("counter fits u64");
        assert_eq!(
            hex::encode(key.get_sender_view_tag(counter).expect("hkdf")),
            entry["tagBytes"].as_str().expect("hex"),
            "sender view tag differs at counter {counter}"
        );
    }

    for entry in entries(section, "transactionKeys") {
        let derived = key
            .get_transaction_viewing_key(&array32(entry, "firstNullifierBytes"))
            .expect("hkdf");
        assert_eq!(
            hex::encode(derived.secret_bytes()),
            entry["secretBytes"].as_str().expect("hex")
        );
        assert_eq!(
            hex::encode(derived.pubkey().as_bytes()),
            entry["publicKeyBytes"].as_str().expect("hex")
        );
    }
}
