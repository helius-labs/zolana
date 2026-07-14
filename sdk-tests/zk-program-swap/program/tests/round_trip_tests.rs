//! Round-trip tests that de-risk the program-side public-input (and fill's
//! `ctHash`) recomputation against real proofs from the swap prover, without a full
//! e2e. For each circuit: generate a proof, recompute the public input with the
//! program's verify helpers, assert it equals the prover's, and verify the proof
//! through the program's `Groth16Verifier` decompress path against the matching
//! verifying key. The program `VERIFYINGKEY` const is only exercised when it is
//! in sync with the freshly generated key (mirroring the prover tests).

use groth16_solana::{
    gnark_vk_parser::{parse_gnark_vk_bytes, Groth16VerifyingkeyOwned},
    groth16::Groth16Verifyingkey,
};
use swap_program::instructions::{
    cancel::{verify as cancel_verify, CancelProof},
    create_swap::{verify as create_verify, CreateProof},
    fill_verifiable_encryption::{verify as fill_verify, FillVerifiableEncryptionProof},
    verifier::{ciphertext_hash, verify_groth16, CompressedGroth16Proof},
};
use swap_prover::{
    CancelProofInputs, CircuitId, CreateProofInputs, FillVerifiableEncryptionProofInputs,
    OrderProof as ProverProof,
};

fn build_dir(circuit_name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../build/gnark")
        .join(circuit_name)
}

fn ensure_keys(circuit: CircuitId, circuit_name: &str) {
    let dir = build_dir(circuit_name);
    if !dir.join("pk.bin").exists() || !dir.join("vk.bin").exists() {
        swap_prover::setup(circuit, &dir).expect("setup failed");
    }
}

fn generated_vk(circuit_name: &str) -> Groth16VerifyingkeyOwned {
    let bytes = std::fs::read(build_dir(circuit_name).join("vk.bin")).expect("read vk.bin");
    parse_gnark_vk_bytes(&bytes).expect("parse vk.bin")
}

fn create_proof(proof: &ProverProof) -> CreateProof {
    CreateProof {
        proof_a: proof.proof_a,
        proof_b: proof.proof_b,
        proof_c: proof.proof_c,
    }
}

fn cancel_proof(proof: &ProverProof) -> CancelProof {
    CancelProof {
        proof_a: proof.proof_a,
        proof_b: proof.proof_b,
        proof_c: proof.proof_c,
    }
}

fn fill_proof(proof: &ProverProof) -> FillVerifiableEncryptionProof {
    let (commitment, commitment_pok) = proof.commitment.expect("fill proof carries commitment");
    FillVerifiableEncryptionProof {
        proof_a: proof.proof_a,
        proof_b: proof.proof_b,
        proof_c: proof.proof_c,
        commitment,
        commitment_pok,
    }
}

fn verify_with_vk(
    proof: CompressedGroth16Proof<'_>,
    public_input: [u8; 32],
    vk: &Groth16Verifyingkey,
) -> bool {
    verify_groth16(proof, public_input, vk).is_ok()
}

fn keys_in_sync(generated_vk: &Groth16VerifyingkeyOwned, program_vk: &Groth16Verifyingkey) -> bool {
    let borrowed = generated_vk.as_borrowed();
    borrowed.vk_ic.len() == program_vk.vk_ic.len() && borrowed.vk_alpha_g1 == program_vk.vk_alpha_g1
}

fn create_inputs() -> CreateProofInputs {
    let mut escrow_authority = [0u8; 32];
    escrow_authority[31] = 42;
    let mut escrow_blinding = [0u8; 32];
    escrow_blinding[31] = 7;
    let mut maker_owner_hash = [0u8; 32];
    maker_owner_hash[31] = 99;
    let mut maker_viewing_pk = [0u8; 33];
    maker_viewing_pk[0] = 2;
    maker_viewing_pk[32] = 55;
    let mut taker_pk_fe = [0u8; 32];
    taker_pk_fe[31] = 123;
    let mut source_input_hash = [0u8; 32];
    source_input_hash[31] = 5;
    let mut change_blinding = [0u8; 32];
    change_blinding[31] = 6;
    let mut external_data_hash = [0u8; 32];
    external_data_hash[31] = 8;

    CreateProofInputs {
        source_mint: [1u8; 32],
        source_amount: 1_000,
        escrow_authority,
        escrow_blinding,
        destination_mint: [2u8; 32],
        destination_amount: 250,
        maker_owner_hash,
        maker_viewing_pk,
        expiry: 1_700_000_000,
        taker_pk_fe,
        fill_mode: swap_prover::FILL_MODE_DERIVED,
        external_data_hash,
        source_input_hash,
        change_amount: 750,
        change_blinding,
    }
}

fn cancel_inputs() -> CancelProofInputs {
    let mut escrow_authority = [0u8; 32];
    escrow_authority[31] = 42;
    let mut escrow_blinding = [0u8; 32];
    escrow_blinding[31] = 7;
    let mut maker_owner_pk_field = [0u8; 32];
    maker_owner_pk_field[31] = 71;
    let mut maker_nullifier_pk = [0u8; 32];
    maker_nullifier_pk[31] = 88;
    let maker_owner_hash =
        swap_prover::owner_hash(&maker_owner_pk_field, &maker_nullifier_pk).expect("owner hash");
    let mut maker_viewing_pk = [0u8; 33];
    maker_viewing_pk[0] = 2;
    maker_viewing_pk[32] = 55;
    let mut taker_pk_fe = [0u8; 32];
    taker_pk_fe[31] = 123;
    let mut source_output_blinding = [0u8; 32];
    source_output_blinding[31] = 11;
    let mut external_data_hash = [0u8; 32];
    external_data_hash[31] = 8;

    CancelProofInputs {
        source_mint: [1u8; 32],
        source_amount: 1_000,
        escrow_authority,
        escrow_blinding,
        destination_mint: [2u8; 32],
        destination_amount: 250,
        maker_owner_hash,
        maker_owner_pk_field,
        maker_nullifier_pk,
        maker_viewing_pk,
        expiry: 1_700_000_000,
        taker_pk_fe,
        fill_mode: swap_prover::FILL_MODE_DERIVED,
        source_output_blinding,
        external_data_hash,
    }
}

fn fill_inputs() -> FillVerifiableEncryptionProofInputs {
    let mut escrow_authority = [0u8; 32];
    escrow_authority[31] = 42;
    let mut escrow_blinding = [0u8; 32];
    escrow_blinding[31] = 7;
    let mut maker_owner_hash = [0u8; 32];
    maker_owner_hash[31] = 99;
    let mut maker_viewing_pk = [0u8; 33];
    maker_viewing_pk[0] = 2;
    maker_viewing_pk[32] = 55;
    let mut taker_pk_fe = [0u8; 32];
    taker_pk_fe[31] = 123;
    let mut taker_nullifier_pk = [0u8; 32];
    taker_nullifier_pk[31] = 200;
    let mut taker_in_blinding = [0u8; 32];
    taker_in_blinding[31] = 13;
    let mut destination_output_blinding = [0u8; 32];
    destination_output_blinding[31] = 21;
    let mut source_output_blinding = [0u8; 32];
    source_output_blinding[31] = 31;
    let mut external_data_hash = [0u8; 32];
    external_data_hash[31] = 8;

    FillVerifiableEncryptionProofInputs {
        source_mint: [1u8; 32],
        destination_mint: [2u8; 32],
        source_amount: 1_000,
        escrow_authority,
        escrow_blinding,
        destination_amount: 250,
        maker_owner_hash,
        maker_viewing_pk,
        expiry: 1_700_000_000,
        taker_pk_fe,
        taker_nullifier_pk,
        taker_in_blinding,
        destination_output_blinding,
        source_output_blinding,
        external_data_hash,
    }
}

#[test]
fn create_public_input_and_proof_round_trip() {
    ensure_keys(CircuitId::Create, "create");
    let inputs = create_inputs();
    let prover_output = inputs.prove().expect("create prove");

    assert_eq!(
        prover_output.public_input_hash, prover_output.private_tx_hash,
        "create's sole public input must be the private tx hash"
    );

    let proof = create_proof(&prover_output.proof);
    let vk = generated_vk("create");
    assert!(
        verify_with_vk(
            CompressedGroth16Proof {
                a: &proof.proof_a,
                b: &proof.proof_b,
                c: &proof.proof_c,
                commitment: None,
            },
            prover_output.private_tx_hash,
            &vk.as_borrowed(),
        ),
        "create proof must verify against the generated verifying key"
    );

    if keys_in_sync(&vk, &swap_program::verifying_keys::create::VERIFYINGKEY) {
        create_verify::verify_create_zk_proof(&proof, prover_output.private_tx_hash)
            .expect("program verify_create_proof must accept a valid proof");
    }
}

#[test]
fn cancel_public_input_and_proof_round_trip() {
    ensure_keys(CircuitId::Cancel, "cancel");
    let inputs = cancel_inputs();
    let prover_output = inputs.prove().expect("cancel prove");

    let cancel_input = cancel_verify::CancelPublicInput {
        private_tx_hash: &prover_output.private_tx_hash,
        expiry: inputs.expiry,
        maker_owner_pk_field: &inputs.maker_owner_pk_field,
    };
    let recomputed = cancel_input
        .hash()
        .expect("program-side cancel public input");
    assert_eq!(
        recomputed, prover_output.public_input_hash,
        "program-side cancel public input must match the prover"
    );

    let proof = cancel_proof(&prover_output.proof);
    let vk = generated_vk("cancel");
    assert!(
        verify_with_vk(
            CompressedGroth16Proof {
                a: &proof.proof_a,
                b: &proof.proof_b,
                c: &proof.proof_c,
                commitment: None,
            },
            recomputed,
            &vk.as_borrowed(),
        ),
        "cancel proof must verify against the generated verifying key"
    );

    if keys_in_sync(&vk, &swap_program::verifying_keys::cancel::VERIFYINGKEY) {
        cancel_input
            .verify(&proof)
            .expect("program verify_cancel_proof must accept a valid proof");
    }
}

#[test]
fn fill_ct_hash_and_public_input_round_trip() {
    ensure_keys(
        CircuitId::FillVerifiableEncryption,
        "fill_verifiable_encryption",
    );
    let inputs = fill_inputs();
    let prover_output = inputs.prove().expect("fill prove");

    let program_ct_hash =
        ciphertext_hash(&prover_output.ciphertext).expect("program-side fill ciphertext hash");
    assert_eq!(
        program_ct_hash, prover_output.ct_hash,
        "program-side ctHash must match the prover's destination ciphertext hash"
    );

    let fill_input = fill_verify::FillVerifiableEncryptionPublicInput {
        private_tx_hash: &prover_output.private_tx_hash,
        expiry: inputs.expiry,
        destination_ciphertext: &prover_output.ciphertext,
    };
    let recomputed = fill_input.hash().expect("program-side fill public input");
    assert_eq!(
        recomputed, prover_output.public_input_hash,
        "program-side fill public input must match the prover"
    );

    let proof = fill_proof(&prover_output.proof);
    let vk = generated_vk("fill_verifiable_encryption");
    assert!(
        verify_with_vk(
            CompressedGroth16Proof {
                a: &proof.proof_a,
                b: &proof.proof_b,
                c: &proof.proof_c,
                commitment: Some((&proof.commitment, &proof.commitment_pok)),
            },
            recomputed,
            &vk.as_borrowed(),
        ),
        "fill proof must verify with new_with_commitment against the generated verifying key"
    );

    if keys_in_sync(
        &vk,
        &swap_program::verifying_keys::fill_verifiable_encryption::VERIFYINGKEY,
    ) {
        fill_input
            .verify(&proof)
            .expect("program verify_fill_proof must accept a valid proof");
    }
}
