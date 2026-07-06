use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    gnark_vk_parser::{parse_gnark_vk_bytes, Groth16VerifyingkeyOwned},
    groth16::Groth16Verifier,
};
use swap_program::verifying_keys::create::VERIFYINGKEY;
use swap_prover::{CircuitId, CreateProofInputs};

fn build_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../build/gnark/create")
}

fn ensure_keys() {
    let dir = build_dir();
    if !dir.join("pk.bin").exists() || !dir.join("vk.bin").exists() {
        swap_prover::setup(CircuitId::Create, &dir).expect("setup failed");
    }
}

fn generated_vk() -> Groth16VerifyingkeyOwned {
    let bytes = std::fs::read(build_dir().join("vk.bin")).expect("read vk.bin");
    parse_gnark_vk_bytes(&bytes).expect("parse vk.bin")
}

fn sample_inputs() -> CreateProofInputs {
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
    let mut marker_output_hash = [0u8; 32];
    marker_output_hash[31] = 9;
    let mut external_data_hash = [0u8; 32];
    external_data_hash[31] = 8;

    CreateProofInputs {
        source_asset_id: 1,
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
        marker_output_hash,
    }
}

fn verify_with_generated_vk(
    vk: &Groth16VerifyingkeyOwned,
    proof_a: &[u8; 32],
    proof_b: &[u8; 64],
    proof_c: &[u8; 32],
    public_input: [u8; 32],
) -> bool {
    let a = match decompress_g1(proof_a) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let b = match decompress_g2(proof_b) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let c = match decompress_g1(proof_c) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let public_inputs = [public_input];
    let borrowed = vk.as_borrowed();
    let mut verifier = match Groth16Verifier::new(&a, &b, &c, &public_inputs, &borrowed) {
        Ok(v) => v,
        Err(_) => return false,
    };
    verifier.verify().is_ok()
}

fn verify_against_program_vk(
    proof_a: &[u8; 32],
    proof_b: &[u8; 64],
    proof_c: &[u8; 32],
    public_input: [u8; 32],
) -> bool {
    let a = match decompress_g1(proof_a) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let b = match decompress_g2(proof_b) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let c = match decompress_g1(proof_c) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let public_inputs = [public_input];
    let mut verifier = match Groth16Verifier::new(&a, &b, &c, &public_inputs, &VERIFYINGKEY) {
        Ok(v) => v,
        Err(_) => return false,
    };
    verifier.verify().is_ok()
}

#[test]
fn program_vk_has_no_commitment() {
    assert_eq!(VERIFYINGKEY.nr_pubinputs, 1);
    assert!(
        VERIFYINGKEY.vk_commitment_g2.is_none(),
        "create circuit is standard Groth16: no BSB22 commitment"
    );
    assert_eq!(
        VERIFYINGKEY.vk_ic.len(),
        2,
        "standard Groth16 vk_ic length must be public_inputs + 1"
    );
}

#[test]
fn create_prove_verify() {
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
        verify_with_generated_vk(
            &vk,
            &result.proof.proof_a,
            &result.proof.proof_b,
            &result.proof.proof_c,
            result.public_input_hash,
        ),
        "groth16 proof must verify against the create verifying key"
    );

    if vk.as_borrowed().vk_ic.len() == VERIFYINGKEY.vk_ic.len()
        && vk.as_borrowed().vk_alpha_g1 == VERIFYINGKEY.vk_alpha_g1
    {
        assert!(
            verify_against_program_vk(
                &result.proof.proof_a,
                &result.proof.proof_b,
                &result.proof.proof_c,
                result.public_input_hash,
            ),
            "proof must verify against the program create VERIFYINGKEY when keys are in sync"
        );
    }
}

#[test]
fn create_rejects_tampered_public_input() {
    ensure_keys();
    let vk = generated_vk();

    let inputs = sample_inputs();
    let result = inputs.prove().expect("prove failed");

    let mut tampered = result.public_input_hash;
    tampered[31] ^= 0x01;

    assert!(
        !verify_with_generated_vk(
            &vk,
            &result.proof.proof_a,
            &result.proof.proof_b,
            &result.proof.proof_c,
            tampered,
        ),
        "verification must fail for a tampered public input"
    );
}

#[test]
fn create_rejects_tampered_order_term() {
    ensure_keys();

    let mut inputs = sample_inputs();
    inputs.destination_amount = 0;

    assert!(
        inputs.prove().is_err(),
        "proving must fail when destination_amount is zero (constraint violation)"
    );
}

#[test]
fn create_zero_change_proves() {
    ensure_keys();
    let vk = generated_vk();

    let mut inputs = sample_inputs();
    inputs.change_amount = 0;
    let result = inputs.prove().expect("prove failed");

    assert!(
        verify_with_generated_vk(
            &vk,
            &result.proof.proof_a,
            &result.proof.proof_b,
            &result.proof.proof_c,
            result.public_input_hash,
        ),
        "zero-change (dummy change output) must prove and verify"
    );
}
