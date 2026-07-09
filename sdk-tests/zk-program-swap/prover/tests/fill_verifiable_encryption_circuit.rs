use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    gnark_vk_parser::{parse_gnark_vk_bytes, Groth16VerifyingkeyOwned},
    groth16::Groth16Verifier,
};
use swap_program::verifying_keys::fill_verifiable_encryption::VERIFYINGKEY;
use swap_prover::{CircuitId, FillVerifiableEncryptionProofInputs, OrderProof};

fn build_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../build/gnark/fill_verifiable_encryption")
}

fn ensure_keys() {
    let dir = build_dir();
    if !dir.join("pk.bin").exists() || !dir.join("vk.bin").exists() {
        swap_prover::setup(CircuitId::FillVerifiableEncryption, &dir).expect("setup failed");
    }
}

fn generated_vk() -> Groth16VerifyingkeyOwned {
    let bytes = std::fs::read(build_dir().join("vk.bin")).expect("read vk.bin");
    parse_gnark_vk_bytes(&bytes).expect("parse vk.bin")
}

fn sample_inputs() -> FillVerifiableEncryptionProofInputs {
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

struct DecompressedProof {
    a: [u8; 64],
    b: [u8; 128],
    c: [u8; 64],
    commitment: [u8; 64],
    commitment_pok: [u8; 64],
}

fn decompress_proof(proof: &OrderProof) -> Option<DecompressedProof> {
    let a = decompress_g1(&proof.proof_a).ok()?;
    let b = decompress_g2(&proof.proof_b).ok()?;
    let c = decompress_g1(&proof.proof_c).ok()?;
    let (commitment, commitment_pok) = proof.commitment?;
    let commitment = decompress_g1(&commitment).ok()?;
    let commitment_pok = decompress_g1(&commitment_pok).ok()?;
    Some(DecompressedProof {
        a,
        b,
        c,
        commitment,
        commitment_pok,
    })
}

fn verify_with_generated_vk(
    vk: &Groth16VerifyingkeyOwned,
    proof: &OrderProof,
    public_input: [u8; 32],
) -> bool {
    let DecompressedProof {
        a,
        b,
        c,
        commitment,
        commitment_pok,
    } = match decompress_proof(proof) {
        Some(v) => v,
        None => return false,
    };
    let public_inputs = [public_input];
    let borrowed = vk.as_borrowed();
    let mut verifier = match Groth16Verifier::new_with_commitment(
        &a,
        &b,
        &c,
        &commitment,
        &commitment_pok,
        &public_inputs,
        &borrowed,
    ) {
        Ok(v) => v,
        Err(_) => return false,
    };
    verifier.verify().is_ok()
}

fn verify_against_program_vk(proof: &OrderProof, public_input: [u8; 32]) -> bool {
    let DecompressedProof {
        a,
        b,
        c,
        commitment,
        commitment_pok,
    } = match decompress_proof(proof) {
        Some(v) => v,
        None => return false,
    };
    let public_inputs = [public_input];
    let mut verifier = match Groth16Verifier::new_with_commitment(
        &a,
        &b,
        &c,
        &commitment,
        &commitment_pok,
        &public_inputs,
        &VERIFYINGKEY,
    ) {
        Ok(v) => v,
        Err(_) => return false,
    };
    verifier.verify().is_ok()
}

#[test]
fn program_vk_has_bsb22_commitment() {
    assert_eq!(VERIFYINGKEY.nr_pubinputs, 1);
    assert!(
        VERIFYINGKEY.vk_commitment_g2.is_some(),
        "fill circuit carries a BSB22 commitment"
    );
    assert_eq!(
        VERIFYINGKEY.vk_ic.len(),
        3,
        "program vk_ic length must be public_inputs + 2"
    );
}

#[test]
fn fill_prove_verify_and_round_trip() {
    ensure_keys();
    let vk = generated_vk();

    let inputs = sample_inputs();
    let expected_public_input_hash = inputs.public_input_hash().expect("public input hash");

    let result = inputs.prove().expect("prove failed");

    assert_eq!(
        result.public_input_hash, expected_public_input_hash,
        "rust-side expected_public_input_hash PublicInputHash must match the proof witness"
    );

    let proof_a_zero = result.proof.proof_a.iter().all(|byte| *byte == 0);
    assert!(!proof_a_zero, "proof_a must not be all zero");
    assert!(
        result.proof.commitment.is_some(),
        "fill proof must carry a BSB22 commitment"
    );

    assert!(
        verify_with_generated_vk(&vk, &result.proof, result.public_input_hash),
        "groth16 proof must verify with new_with_commitment against the fill verifying key"
    );

    if vk.as_borrowed().vk_ic.len() == VERIFYINGKEY.vk_ic.len()
        && vk.as_borrowed().vk_alpha_g1 == VERIFYINGKEY.vk_alpha_g1
    {
        assert!(
            verify_against_program_vk(&result.proof, result.public_input_hash),
            "proof must verify against the program fill VERIFYINGKEY when keys are in sync"
        );
    }

    let (asset, amount) = inputs
        .decrypt_destination(&result.ciphertext)
        .expect("decrypt destination ciphertext");
    let expected_asset =
        swap_prover::asset_field(&inputs.destination_mint).expect("destination asset field");
    assert_eq!(
        (asset, amount),
        (expected_asset, inputs.destination_amount),
        "the maker recovers (destination_asset, destination_amount) by decrypting with the escrow blinding"
    );
}

#[test]
fn fill_rejects_tampered_public_input() {
    ensure_keys();
    let vk = generated_vk();

    let inputs = sample_inputs();
    let result = inputs.prove().expect("prove failed");

    let mut tampered = result.public_input_hash;
    tampered[31] ^= 0x01;

    assert!(
        !verify_with_generated_vk(&vk, &result.proof, tampered),
        "verification must fail for a tampered public input"
    );
}

#[test]
fn fill_rejects_wrong_taker_address() {
    ensure_keys();

    let inputs = sample_inputs();
    let mut wrong_taker_address = inputs.taker_pk_fe;
    wrong_taker_address[31] ^= 0x01;

    assert!(
        inputs.prove_with_taker_address(&wrong_taker_address).is_err(),
        "proving must fail when the taker input owner is not Poseidon(taker_pk_fe, taker_nullifier_pk)"
    );
}

#[test]
fn fill_rejects_wrong_destination_output_owner() {
    ensure_keys();

    let inputs = sample_inputs();
    let mut wrong_owner = inputs.maker_owner_hash;
    wrong_owner[31] ^= 0x01;

    assert!(
        inputs
            .prove_with_destination_output_owner(&wrong_owner)
            .is_err(),
        "proving must fail when the destination output owner differs from maker_address"
    );
}

#[test]
fn fill_rejects_wrong_destination_output_amount() {
    ensure_keys();

    let inputs = sample_inputs();

    assert!(
        inputs
            .prove_with_destination_output_amount(inputs.destination_amount + 1)
            .is_err(),
        "proving must fail when the destination output amount differs from the committed destination_amount"
    );
}
