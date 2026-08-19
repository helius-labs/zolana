//! `AuditProofParams::encrypt` + `PendingAuditProof::finish` is the only place the
//! sdk turns domain values into a witness, so what is pinned here is that it lands
//! on the public input the program recomputes, that it never reuses an AES-CTR
//! keystream, and that the split across the two calls puts `private_tx_hash` on
//! the `finish` side alone.

use custom_ring_program::instructions::transact::AuditPublicInput;
use custom_ring_sdk::{
    encryption::{decrypt_tx_viewing_sk, AuditorMessage},
    to_instruction_proof, AuditProof, AuditProofParams, PendingAuditProof,
};
use zeroize::Zeroizing;
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

fn encrypt(auditor_pk: P256Pubkey) -> (PendingAuditProof, AuditorMessage) {
    AuditProofParams {
        tx_viewing_sk: Zeroizing::new(hex_bytes::<32>(TX_SK)),
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

    let (pending, message) = encrypt(auditor_pk);
    let inputs = pending.finish(&private_tx_hash).expect("proof inputs");

    let tx_viewing_pk = ViewingKey::from_bytes(&hex_bytes::<32>(TX_SK))
        .expect("valid P-256 scalar")
        .pubkey();
    let expected = AuditPublicInput {
        private_tx_hash: &private_tx_hash,
        tx_viewing_pk: tx_viewing_pk.as_bytes(),
        auditor_pk: auditor_pk.as_bytes(),
        eph_pk: &message.eph_pk,
        ciphertext: &message.ciphertext,
    }
    .hash()
    .expect("public input hash");

    assert_eq!(inputs.public_input_hash, expected);
    assert_eq!(inputs.private_tx_hash, private_tx_hash);
    assert_eq!(inputs.tx_viewing_sk, hex_bytes::<32>(TX_SK));
    // The circuit witnesses the auditor key uncompressed and asserts the SEC1
    // prefix; the compressed form only enters through the hash chain.
    assert_eq!(inputs.auditor_pk.first(), Some(&4u8));
    assert_eq!(
        inputs.auditor_pk.get(1..33).expect("x coordinate"),
        auditor_pk.x().as_slice()
    );
}

/// `(ephemeral, auditor_pk)` fixes the AES-256-CTR keystream, so two encryptions
/// of the same viewing key under one ephemeral scalar would publish their XOR.
/// Every call must therefore mint a new ephemeral key, which also changes the
/// ciphertext and the public input.
#[test]
fn every_call_mints_a_fresh_ephemeral_key() {
    let auditor_pk = auditor().pubkey();
    let private_tx_hash = hex_bytes::<32>(PRIVATE_TX_HASH);

    let (first_pending, first) = encrypt(auditor_pk);
    let (second_pending, second) = encrypt(auditor_pk);
    let first_inputs = first_pending
        .finish(&private_tx_hash)
        .expect("proof inputs");
    let second_inputs = second_pending
        .finish(&private_tx_hash)
        .expect("proof inputs");

    assert_ne!(first.eph_pk, second.eph_pk);
    assert_ne!(first.ciphertext, second.ciphertext);
    assert_ne!(first_inputs.eph_sk, second_inputs.eph_sk);
    assert_ne!(
        first_inputs.public_input_hash,
        second_inputs.public_input_hash
    );
    // Same plaintext both times, so a repeated keystream would show up as equal
    // ciphertexts above.
    assert_eq!(first_inputs.tx_viewing_sk, second_inputs.tx_viewing_sk);
}

/// The whole point of splitting `encrypt` from `finish`: the ciphertext and the
/// ephemeral scalar are fixed before the SPP proof exists, and `private_tx_hash`
/// -- which only that proof produces -- moves the public input alone. If finishing
/// one encryption against two hashes changed anything else, the message published
/// in `external_data.messages` before the SPP proof could not be the message the
/// audit proof commits to.
#[test]
fn finish_binds_the_private_tx_hash_and_nothing_else() {
    let auditor_pk = auditor().pubkey();
    let (pending, message) = encrypt(auditor_pk);

    let first = pending
        .finish(&hex_bytes::<32>(PRIVATE_TX_HASH))
        .expect("proof inputs");
    let second_hash = [9u8; 32];
    let second = pending.finish(&second_hash).expect("proof inputs");

    assert_ne!(first.public_input_hash, second.public_input_hash);
    assert_eq!(first.private_tx_hash, hex_bytes::<32>(PRIVATE_TX_HASH));
    assert_eq!(second.private_tx_hash, second_hash);

    // The encryption is untouched: same witnessed plaintext, same witnessed
    // ephemeral scalar, and both witnesses still describe the one published
    // ciphertext.
    assert_eq!(first.tx_viewing_sk, second.tx_viewing_sk);
    assert_eq!(first.eph_sk, second.eph_sk);
    assert_eq!(first.auditor_pk, second.auditor_pk);
    assert_eq!(
        message
            .ephemeral_pubkey()
            .expect("published eph pk is valid"),
        ViewingKey::from_bytes(&first.eph_sk)
            .expect("witnessed ephemeral scalar")
            .pubkey(),
        "the witnessed ephemeral scalar is the one the published message carries"
    );
}

/// The message the caller must push into `messages` before proving SPP has to be
/// the one the auditor can actually open with its own key alone.
#[test]
fn the_returned_message_opens_with_the_auditor_key() {
    let auditor = auditor();
    let (_pending, message) = encrypt(auditor.pubkey());

    let eph_pk = message
        .ephemeral_pubkey()
        .expect("published eph pk is valid");
    let recovered =
        decrypt_tx_viewing_sk(&auditor, &eph_pk, &message.ciphertext).expect("auditor decrypt");
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
fn instruction_proof_conversion_preserves_every_point() {
    let prover_proof = custom_ring_prover::AuditProof {
        proof_a: [1; 32],
        proof_b: [2; 64],
        proof_c: [3; 32],
        commitment: [4; 32],
        commitment_pok: [5; 32],
    };

    assert_eq!(
        to_instruction_proof(&prover_proof),
        AuditProof {
            proof_a: [1; 32],
            proof_b: [2; 64],
            proof_c: [3; 32],
            commitment: [4; 32],
            commitment_pok: [5; 32],
        }
    );
}
