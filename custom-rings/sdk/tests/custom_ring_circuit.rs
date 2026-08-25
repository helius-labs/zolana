//! The cross-language consistency gate for the custom-ring circuit.
//!
//! Every other test in this crate checks one side of the statement. This one
//! closes the loop, the sdk's own encryption and proof-input path produces a
//! witness the compiled Go circuit solves, the resulting proof verifies under
//! the committed `verifying_key::VERIFYINGKEY` the on-chain program uses, and the
//! public input the whole chain lands on is the exact value the Go circuit
//! test solves against. gnark's setup is randomized, a regenerated proving
//! key stops proving under the committed constant, and the proof-then-verify
//! round trip here catches that drift before it reaches the chain.

use std::sync::OnceLock;

use custom_ring_interface::verifying_key::VERIFYINGKEY;
use custom_ring_interface::{CustomRingProof, CustomRingPublicInput};
use custom_ring_sdk::CustomRingProofRequest;
use custom_ring_sdk::{
    to_instruction_proof, AuditorMessage, CustomRingProofParams, EncryptedAudit,
};
use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::Groth16Verifier,
};
use zolana_client::ProverClient;
use zolana_keypair::{P256Pubkey, ViewingKey};

/// The `sdk/tests/go_vectors.rs` fixture, which is also the Go circuit test's
/// (`prover/server/circuits/custom_ring/circuit_test.go`, scalars 0x11 / 0x22
/// / 0x33).
const TX_SK: &str = "011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e";
const EPH_SK: &str = "01232021262724252a2b28292e2f2c2d32333031363734353a3b38393e3f3c3d";
const AUDITOR_SK: &str = "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c";
const AUDITOR_PK: &str = "039dc51b59006b13f143944d4e432db7c032241ceb3698a6cc0cdabadf29b71dec";

/// `big.NewInt(0xabcdef)` right-aligned, the Go fixture's `PrivateTxHash`.
const PRIVATE_TX_HASH: &str = "0000000000000000000000000000000000000000000000000000000000abcdef";

/// The public input the compiled circuit is known to solve for that fixture. It
/// is pinned identically in `program/src/instructions/transact.rs` and in
/// `sdk-libs/ts/test/ring-audit.test.ts`; reproducing it from the sdk's own
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

fn prover() -> ProverClient {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        zolana_client::spawn_prover_with_artifacts(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/zolana"),
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../prover/server/proving-keys"
            ),
        )
        .expect("start or reuse prover with workspace key cache");
    });
    ProverClient::local()
}

/// The committed verifier must match the verifier in the native Prover key.
/// Runs the program's own verifier, so what is exercised is the on-chain code
/// path and not a test-local reimplementation of it.
fn verify(proof: &CustomRingProof, public_input_hash: [u8; 32]) -> bool {
    let Ok(proof_a) = decompress_g1(&proof.proof_a) else {
        return false;
    };
    let Ok(proof_b) = decompress_g2(&proof.proof_b) else {
        return false;
    };
    let Ok(proof_c) = decompress_g1(&proof.proof_c) else {
        return false;
    };
    let Ok(commitment) = decompress_g1(&proof.commitment) else {
        return false;
    };
    let Ok(commitment_pok) = decompress_g1(&proof.commitment_pok) else {
        return false;
    };
    let public_inputs = [public_input_hash];
    Groth16Verifier::new_with_commitment(
        &proof_a,
        &proof_b,
        &proof_c,
        &commitment,
        &commitment_pok,
        &public_inputs,
        &VERIFYINGKEY,
    )
    .and_then(|mut verifier| verifier.verify())
    .is_ok()
}

fn fixture_ciphertext() -> [u8; 32] {
    hex_bytes::<32>("6de7c18c3c3676ca517647a25df33a7150ace3e07b410bc296fac11b1355382b")
}
/// The Go fixture's witness, rebuilt through the sdk's encryption and the
/// program's canonical hashing. Unlike [`CustomRingProofParams::encrypt`] this pins the
/// ephemeral scalar, which is the only way to reproduce a fixed public input.
fn fixture_public_input(ciphertext: &[u8; 32]) -> [u8; 32] {
    CustomRingPublicInput {
        private_tx_hash: &hex_bytes::<32>(PRIVATE_TX_HASH),
        tx_viewing_pk: viewing_key(TX_SK).pubkey().as_bytes(),
        auditor_pk: auditor_pubkey().as_bytes(),
        eph_pk: viewing_key(EPH_SK).pubkey().as_bytes(),
        ciphertext,
    }
    .hash()
    .expect("public input hash")
}

fn fixture_inputs() -> CustomRingProofRequest {
    let auditor_pk = auditor_pubkey();
    CustomRingProofRequest {
        public_input_hash: fixture_public_input(&fixture_ciphertext())
            .try_into()
            .expect("canonical field"),
        private_tx_hash: hex_bytes::<32>(PRIVATE_TX_HASH)
            .try_into()
            .expect("canonical field"),
        tx_viewing_key: viewing_key(TX_SK),
        ephemeral_key: viewing_key(EPH_SK),
        auditor_key: auditor_pk,
    }
}

/// Cheap half of the gate: the sdk reproduces the pinned public input without
/// touching the proving key, so a chain reordering or a packing change fails here
/// in milliseconds rather than after a proof.
#[test]
fn the_sdk_reproduces_the_pinned_go_public_input() {
    assert_eq!(
        fixture_inputs().public_input_hash.as_ref(),
        &hex_bytes::<32>(PINNED_PUBLIC_INPUT_HASH)
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
    let recovered = AuditorMessage::new(viewing_key(EPH_SK).pubkey(), fixture_ciphertext())
        .decrypt(&viewing_key(AUDITOR_SK))
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
/// circuit test is known to solve, and the `CustomRingProofParams` witness is what the
/// sdk API actually hands callers -- fresh ephemeral scalar and all.
#[test]
#[ignore = "requires Redis and the published custom-ring proving key"]
fn prove_and_verify_both_witnesses() {
    let prover = prover();

    let fixture = fixture_inputs();
    let proof = to_instruction_proof(
        prover
            .prove(&fixture)
            .expect("prove the Go fixture witness"),
    )
    .expect("compress the fixture proof");
    assert!(verify(&proof, *fixture.public_input_hash.as_ref()));

    let mut tampered = *fixture.public_input_hash.as_ref();
    // Negative 1: the verifier is bound to the public input, not just to the
    // proof. One flipped bit of the hash the program recomputes is enough.
    if let Some(byte) = tampered.last_mut() {
        *byte ^= 0x01;
    }
    assert!(!verify(&proof, tampered));

    let mut ciphertext = fixture_ciphertext();
    // Negative 2: what an attacker would actually swap -- the published
    // ciphertext. The program recomputes the chain from the message it sees, so a
    // flipped ciphertext byte lands on a different public input and the proof for
    // the original ciphertext no longer verifies.
    if let Some(byte) = ciphertext.first_mut() {
        *byte ^= 0x01;
    }
    let flipped_public_input = fixture_public_input(&ciphertext);
    assert_ne!(&flipped_public_input, fixture.public_input_hash.as_ref());
    assert!(!verify(&proof, flipped_public_input));

    let EncryptedAudit { pending, message } = CustomRingProofParams {
        tx_viewing_key: viewing_key(TX_SK),
        // The witness the sdk API produces must solve the same circuit. Its ephemeral
        // scalar is fresh, so its public input differs from the fixture's every run.
        auditor_pk: auditor_pubkey(),
    }
    .encrypt()
    .expect("sdk encryption");
    let sdk_inputs = pending
        .finish(
            hex_bytes::<32>(PRIVATE_TX_HASH)
                .try_into()
                .expect("canonical field"),
        )
        .expect("sdk proof inputs");
    assert_ne!(
        sdk_inputs.public_input_hash.as_ref(),
        fixture.public_input_hash.as_ref()
    );

    let sdk_proof = to_instruction_proof(
        prover.prove(&sdk_inputs).expect("prove the sdk witness"),
        // The message the caller publishes is the ciphertext the proof commits to.
    )
    .expect("compress the sdk proof");
    assert!(verify(&sdk_proof, *sdk_inputs.public_input_hash.as_ref()));

    let recovered = message
        .decrypt(&viewing_key(AUDITOR_SK))
        .expect("auditor decrypt");
    assert_eq!(*recovered, hex_bytes::<32>(TX_SK));
}

#[test]
#[ignore = "requires Redis and the published custom-ring proving key"]
fn a_tampered_witness_does_not_prove() {
    let prover = prover();
    let mut inputs = fixture_inputs();
    inputs.private_tx_hash = [7u8; 32].try_into().expect("canonical field");
    assert!(prover.prove(&inputs).is_err());
}
