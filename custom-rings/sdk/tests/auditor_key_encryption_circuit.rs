//! The cross-language consistency gate for the `auditor_key_encryption` circuit.
//!
//! Every other test in this crate checks one side of the statement. This one
//! closes the loop: the sdk's own encryption and proof-input path produces a
//! witness the compiled Go circuit solves, the resulting proof verifies under the
//! verifying key the program has committed AND under the one on disk next to the
//! proving key, and the public input the whole chain lands on is the exact value
//! the Go circuit test solves against.
//!
//! Two verifying keys are checked on purpose. The committed
//! `verifying_keys::auditor_key_encryption::VERIFYINGKEY` is what the on-chain
//! program uses; `build/gnark/auditor_key_encryption/vk.bin` is what the proving
//! key was generated with. gnark's setup is randomized, so a regenerated proving
//! key silently stops matching the committed constant -- verifying against both is
//! what catches that drift here instead of on-chain.

use std::{sync::Once, time::Instant};

use custom_ring_program::{
    instructions::{
        transact::AuditPublicInput,
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    verifying_keys::auditor_key_encryption::VERIFYINGKEY,
};
use custom_ring_prover::{ffi, AuditProof, AuditorKeyEncryptionProofInputs, CircuitId};
use custom_ring_sdk::{
    encryption::{decrypt_tx_viewing_sk, encrypt_tx_viewing_sk},
    AuditProofParams,
};
use groth16_solana::vk::gnark::{parse_gnark_vk_bytes, Groth16VerifyingkeyOwned};
use zeroize::Zeroizing;
use zolana_keypair::{P256Pubkey, ViewingKey};

/// The `sdk/tests/go_vectors.rs` fixture, which is also the Go circuit test's
/// (`prover/circuits/auditor_key_encryption/circuit_test.go`, scalars 0x11 / 0x22
/// / 0x33).
const TX_SK: &str = "011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e";
const EPH_SK: &str = "01232021262724252a2b28292e2f2c2d32333031363734353a3b38393e3f3c3d";
const AUDITOR_SK: &str = "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c";
const AUDITOR_PK: &str = "039dc51b59006b13f143944d4e432db7c032241ceb3698a6cc0cdabadf29b71dec";

/// `big.NewInt(0xabcdef)` right-aligned, the Go fixture's `PrivateTxHash`.
const PRIVATE_TX_HASH: &str = "0000000000000000000000000000000000000000000000000000000000abcdef";

/// The public input the compiled circuit is known to solve for that fixture. It
/// is pinned identically in `program/src/instructions/transact.rs` and in
/// `prover/tests/auditor_key_encryption.rs`; reproducing it from the sdk's own
/// encryption path is what proves all three agree on the eight-element chain.
const PINNED_PUBLIC_INPUT_HASH: &str =
    "18bf7563a64675c110ae7d408b973c98005afac6d06b8ae177f4435d7e6e020b";

fn hex_bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    let decoded = hex::decode(hex_str).expect("valid hex");
    <[u8; N]>::try_from(decoded.as_slice()).expect("expected byte length")
}

fn viewing_key(hex_str: &str) -> ViewingKey {
    ViewingKey::from_bytes(&hex_bytes::<32>(hex_str)).expect("valid P-256 scalar")
}

fn auditor_pubkey() -> P256Pubkey {
    P256Pubkey::from_bytes(hex_bytes::<33>(AUDITOR_PK)).expect("valid compressed key")
}

/// Generates the keys into their canonical build directory only if they are not
/// there. Never overwrites: gnark's setup is randomized, so replacing an existing
/// `pk.bin` would invalidate the committed verifying key. `Once` also serializes
/// concurrent callers, two of which would otherwise write the same file.
fn ensure_keys() {
    static KEYS: Once = Once::new();
    KEYS.call_once(|| {
        let circuit = CircuitId::AuditorKeyEncryption;
        let dir = ffi::build_dir(circuit);
        if !dir.join("pk.bin").exists() || !dir.join("vk.bin").exists() {
            ffi::setup(circuit, &dir).expect("gnark setup");
        }
    });
}

/// The verifying key that was generated together with the proving key on disk.
fn generated_vk() -> Groth16VerifyingkeyOwned {
    let path = ffi::build_dir(CircuitId::AuditorKeyEncryption).join("vk.bin");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    parse_gnark_vk_bytes(&bytes).expect("parse vk.bin")
}

/// Runs the program's own verifier, so what is exercised is the on-chain code
/// path and not a test-local reimplementation of it.
fn verify(
    proof: &AuditProof,
    public_input_hash: [u8; 32],
    verifying_key: &groth16_solana::groth16::Groth16Verifyingkey,
) -> bool {
    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: Some((&proof.commitment, &proof.commitment_pok)),
        },
        public_input_hash,
        verifying_key,
    )
    .is_ok()
}

/// The Go fixture's witness, rebuilt through the sdk's encryption and the
/// program's canonical hashing. Unlike [`AuditProofParams::encrypt`] this pins the
/// ephemeral scalar, which is the only way to reproduce a fixed public input.
fn fixture_inputs() -> AuditorKeyEncryptionProofInputs {
    let tx_viewing_sk = hex_bytes::<32>(TX_SK);
    let auditor_pk = auditor_pubkey();
    let eph_pk = viewing_key(EPH_SK).pubkey();
    let ciphertext = encrypt_tx_viewing_sk(&tx_viewing_sk, viewing_key(EPH_SK), &auditor_pk)
        .expect("encrypt to the auditor");
    let private_tx_hash = hex_bytes::<32>(PRIVATE_TX_HASH);

    let public_input_hash = AuditPublicInput {
        private_tx_hash: &private_tx_hash,
        tx_viewing_pk: viewing_key(TX_SK).pubkey().as_bytes(),
        auditor_pk: auditor_pk.as_bytes(),
        eph_pk: eph_pk.as_bytes(),
        ciphertext: &ciphertext,
    }
    .hash()
    .expect("public input hash");

    AuditorKeyEncryptionProofInputs {
        public_input_hash,
        private_tx_hash,
        tx_viewing_sk,
        eph_sk: hex_bytes::<32>(EPH_SK),
        auditor_pk: uncompressed(&auditor_pk),
    }
}

fn uncompressed(pubkey: &P256Pubkey) -> [u8; 65] {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let point = pubkey.to_p256().expect("valid curve point");
    <[u8; 65]>::try_from(point.to_encoded_point(false).as_bytes()).expect("uncompressed SEC1")
}

/// Cheap half of the gate: the sdk reproduces the pinned public input without
/// touching the proving key, so a chain reordering or a packing change fails here
/// in milliseconds rather than after a proof.
#[test]
fn the_sdk_reproduces_the_pinned_go_public_input() {
    assert_eq!(
        fixture_inputs().public_input_hash,
        hex_bytes::<32>(PINNED_PUBLIC_INPUT_HASH)
    );
}

/// The committed key must describe this circuit's shape: one public input plus a
/// BSB22 commitment from the emulated-P256 gadget, hence `vk_ic.len() == 3`.
#[test]
fn the_committed_verifying_key_carries_a_bsb22_commitment() {
    assert_eq!(VERIFYINGKEY.nr_pubinputs, 1);
    assert!(VERIFYINGKEY.vk_commitment.is_some());
    assert_eq!(VERIFYINGKEY.vk_ic.len(), 3);
}

/// The auditor is the only party that can open the published ciphertext, and it
/// must recover the scalar byte for byte -- a truncated or reduced recovery would
/// give it a viewing key that decrypts nothing.
#[test]
fn the_auditor_recovers_the_exact_scalar() {
    let auditor = viewing_key(AUDITOR_SK);
    let ciphertext = encrypt_tx_viewing_sk(
        &hex_bytes::<32>(TX_SK),
        viewing_key(EPH_SK),
        &auditor.pubkey(),
    )
    .expect("encrypt to the auditor");

    let recovered = decrypt_tx_viewing_sk(&auditor, &viewing_key(EPH_SK).pubkey(), &ciphertext)
        .expect("auditor decrypt");
    assert_eq!(*recovered, hex_bytes::<32>(TX_SK));
}

/// The expensive half: two real proofs against the loaded proving key.
///
/// Both live in one test on purpose. Nextest runs each test in its own process,
/// and loading the ~74 MB proving key costs several seconds while proving costs
/// well under one, so splitting them would pay the load twice for no extra
/// coverage.
///
/// The two witnesses are complementary: the fixture witness is the one the Go
/// circuit test is known to solve, and the `AuditProofParams` witness is what the
/// sdk API actually hands callers -- fresh ephemeral scalar and all.
#[test]
fn prove_and_double_verify_both_witnesses() {
    ensure_keys();
    let generated_owned = generated_vk();
    let generated = generated_owned.as_borrowed();

    let started = Instant::now();
    let fixture = fixture_inputs();
    let proof = fixture.prove().expect("prove the Go fixture witness");
    eprintln!("fixture prove: {:?} (includes key load)", started.elapsed());

    assert!(
        verify(&proof, fixture.public_input_hash, &VERIFYINGKEY),
        "the proof must verify under the verifying key the program committed"
    );
    assert!(
        verify(&proof, fixture.public_input_hash, &generated),
        "the proof must verify under the vk.bin the proving key was generated with; a mismatch \
         means the committed VERIFYINGKEY and build/gnark/auditor_key_encryption/ have drifted"
    );

    // Negative 1: the verifier is bound to the public input, not just to the
    // proof. One flipped bit of the hash the program recomputes is enough.
    let mut tampered = fixture.public_input_hash;
    if let Some(byte) = tampered.last_mut() {
        *byte ^= 0x01;
    }
    assert!(
        !verify(&proof, tampered, &VERIFYINGKEY),
        "a tampered public input must not verify"
    );

    // Negative 2: what an attacker would actually swap -- the published
    // ciphertext. The program recomputes the chain from the message it sees, so a
    // flipped ciphertext byte lands on a different public input and the proof for
    // the original ciphertext no longer verifies.
    let mut ciphertext = encrypt_tx_viewing_sk(
        &hex_bytes::<32>(TX_SK),
        viewing_key(EPH_SK),
        &auditor_pubkey(),
    )
    .expect("encrypt to the auditor");
    if let Some(byte) = ciphertext.first_mut() {
        *byte ^= 0x01;
    }
    let flipped_public_input = AuditPublicInput {
        private_tx_hash: &hex_bytes::<32>(PRIVATE_TX_HASH),
        tx_viewing_pk: viewing_key(TX_SK).pubkey().as_bytes(),
        auditor_pk: auditor_pubkey().as_bytes(),
        eph_pk: viewing_key(EPH_SK).pubkey().as_bytes(),
        ciphertext: &ciphertext,
    }
    .hash()
    .expect("public input hash");
    assert_ne!(flipped_public_input, fixture.public_input_hash);
    assert!(
        !verify(&proof, flipped_public_input, &VERIFYINGKEY),
        "a flipped ciphertext byte must not verify against the original proof"
    );

    // The witness the sdk API produces must solve the same circuit. Its ephemeral
    // scalar is fresh, so its public input differs from the fixture's every run.
    let (pending, message) = AuditProofParams {
        tx_viewing_sk: Zeroizing::new(hex_bytes::<32>(TX_SK)),
        auditor_pk: auditor_pubkey(),
    }
    .encrypt()
    .expect("sdk encryption");
    let sdk_inputs = pending
        .finish(&hex_bytes::<32>(PRIVATE_TX_HASH))
        .expect("sdk proof inputs");
    assert_ne!(sdk_inputs.public_input_hash, fixture.public_input_hash);

    let started = Instant::now();
    let sdk_proof = sdk_inputs.prove().expect("prove the sdk witness");
    eprintln!("sdk prove: {:?} (key already loaded)", started.elapsed());

    assert!(
        verify(&sdk_proof, sdk_inputs.public_input_hash, &VERIFYINGKEY),
        "the witness AuditProofParams produces must solve the circuit"
    );
    assert!(
        verify(&sdk_proof, sdk_inputs.public_input_hash, &generated),
        "the sdk witness's proof must verify under vk.bin too"
    );

    // The message the caller publishes is the ciphertext the proof commits to.
    let recovered = decrypt_tx_viewing_sk(
        &viewing_key(AUDITOR_SK),
        &message.ephemeral_pubkey().expect("published eph pk"),
        &message.ciphertext,
    )
    .expect("auditor decrypt");
    assert_eq!(*recovered, hex_bytes::<32>(TX_SK));
}
