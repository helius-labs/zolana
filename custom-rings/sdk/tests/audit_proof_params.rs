//! `AuditProofParams::encrypt` + `PendingAuditProof::finish` is the only place the
//! sdk turns domain values into a witness, so what is pinned here is that it lands
//! on the public input the program recomputes, that it never reuses an AES-CTR
//! keystream, and that the split across the two calls puts `private_tx_hash` on
//! the `finish` side alone.

use custom_ring_sdk::{
    to_instruction_proof, AuditProofError, AuditProofParams, AuditorMessage, EncryptedAudit,
};
use zolana_client::Proof;
use zolana_interface::custom_ring::AuditPublicInput;
use zolana_keypair::{P256Pubkey, ViewingKey};

/// The `custom-rings/sdk/tests/go_vectors.rs` fixture, which is the Go
/// circuit test's own: byte `i` is `seed ^ i` with byte 0 forced to 0x01 so the
/// scalar stays below the P-256 group order.
const TX_SK: &str = "011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e";
const AUDITOR_SK: &str = "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c";

/// Right-aligned `0xabcdef`, the Go fixture's `PrivateTxHash`.
const PRIVATE_TX_HASH: &str = "0000000000000000000000000000000000000000000000000000000000abcdef";

fn hex_bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    let decoded = hex::decode(hex_str).expect("valid hex");
    <[u8; N]>::try_from(decoded.as_slice()).expect("expected byte length")
}

fn encrypt(auditor_pk: P256Pubkey) -> EncryptedAudit {
    AuditProofParams {
        tx_viewing_key: ViewingKey::from_bytes(&hex_bytes::<32>(TX_SK))
            .expect("valid P-256 scalar"),
        auditor_pk,
    }
    .encrypt()
    .expect("encrypt to the auditor")
}

fn auditor() -> ViewingKey {
    ViewingKey::from_bytes(&hex_bytes::<32>(AUDITOR_SK)).expect("valid P-256 scalar")
}

/// The gate against sdk/program drift: the witness's single public input must be
/// exactly what the on-chain `AuditPublicInput::hash()` produces from the values
/// the program itself trusts -- the payload's `private_tx_hash` and
/// `tx_viewing_pk`, the config account's auditor key, and the published message.
#[test]
fn proof_inputs_carry_the_public_input_the_program_recomputes() {
    let auditor_pk = auditor().pubkey();
    let private_tx_hash = hex_bytes::<32>(PRIVATE_TX_HASH);

    let EncryptedAudit { pending, message } = encrypt(auditor_pk);
    let inputs = pending
        .finish(private_tx_hash.try_into().expect("canonical field"))
        .expect("proof inputs");

    let tx_viewing_pk = ViewingKey::from_bytes(&hex_bytes::<32>(TX_SK))
        .expect("valid P-256 scalar")
        .pubkey();
    let expected = AuditPublicInput {
        private_tx_hash: &private_tx_hash,
        tx_viewing_pk: tx_viewing_pk.as_bytes(),
        auditor_pk: auditor_pk.as_bytes(),
        eph_pk: message.ephemeral_pubkey_bytes(),
        ciphertext: message.ciphertext(),
    }
    .hash()
    .expect("public input hash");

    assert_eq!(inputs.public_input_hash.as_ref(), &expected);
    assert_eq!(inputs.private_tx_hash.as_ref(), &private_tx_hash);
    // The circuit witnesses the auditor key uncompressed and asserts the SEC1
    // prefix; the compressed form only enters through the hash chain.
    assert_eq!(
        *inputs.tx_viewing_key.secret_bytes(),
        hex_bytes::<32>(TX_SK)
    );
    assert_eq!(inputs.auditor_key, auditor_pk);
}

/// `(ephemeral, auditor_pk)` fixes the AES-256-CTR keystream, so two encryptions
/// of the same viewing key under one ephemeral scalar would publish their XOR.
/// Every call must therefore mint a new ephemeral key, which also changes the
/// ciphertext and the public input.
#[test]
fn every_call_mints_a_fresh_ephemeral_key() {
    let auditor_pk = auditor().pubkey();
    let private_tx_hash = hex_bytes::<32>(PRIVATE_TX_HASH);

    let EncryptedAudit {
        pending: first_pending,
        message: first,
    } = encrypt(auditor_pk);
    let EncryptedAudit {
        pending: second_pending,
        message: second,
    } = encrypt(auditor_pk);
    let first_inputs = first_pending
        .finish(private_tx_hash.try_into().expect("canonical field"))
        .expect("proof inputs");
    let second_inputs = second_pending
        .finish(private_tx_hash.try_into().expect("canonical field"))
        .expect("proof inputs");

    assert_ne!(first.ephemeral_pubkey(), second.ephemeral_pubkey());
    assert_ne!(first.ciphertext(), second.ciphertext());
    assert_ne!(
        first_inputs.ephemeral_key.secret_bytes(),
        second_inputs.ephemeral_key.secret_bytes()
    );
    // Same plaintext both times, so a repeated keystream would show up as equal
    // ciphertexts above.
    assert_ne!(
        first_inputs.public_input_hash.as_ref(),
        second_inputs.public_input_hash.as_ref()
    );
    assert_eq!(
        first_inputs.tx_viewing_key.secret_bytes(),
        second_inputs.tx_viewing_key.secret_bytes()
    );
}

/// The message the caller must push into `messages` before proving SPP has to be
/// the one the auditor can actually open with its own key alone.
#[test]
fn the_returned_message_opens_with_the_auditor_key() {
    let auditor = auditor();
    let EncryptedAudit { message, .. } = encrypt(auditor.pubkey());

    let recovered = message.decrypt(&auditor).expect("auditor decrypt");
    assert_eq!(*recovered, hex_bytes::<32>(TX_SK));

    // The message round-trips through the on-chain encoding under the auditor's
    // view tag.
    let data = message.to_message_data(&auditor.pubkey());
    assert_eq!(
        AuditorMessage::parse(&data, &auditor.pubkey()).expect("parse"),
        message
    );
}

/// The prover and the program hold structurally identical proofs in unrelated
/// types; the conversion must not permute the five points.
#[test]
fn instruction_proof_conversion_requires_the_commitment() {
    let proof = Proof {
        a: [0; 64],
        b: [0; 128],
        c: [0; 64],
        commitment: None,
    };

    assert!(matches!(
        to_instruction_proof(proof),
        Err(AuditProofError::MissingCommitment)
    ));
}
