use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::Groth16Verifier,
    vk::gnark::{parse_gnark_vk_bytes, Groth16VerifyingkeyOwned},
};
use solana_address::Address;
use timelock_escrow_program::{
    instructions::{
        escrow::EscrowProof,
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    verifying_keys::escrow::VERIFYINGKEY,
};
use timelock_escrow_prover::{CircuitId, EscrowProofInputs, EscrowTermsProofInput};
use timelock_escrow_sdk::state::DataHash;
use zolana_transaction::{instructions::transact::PrivateTxHash, utxo::Blinding, ProofInputUtxo};

mod shared;
use shared::escrow_utxo_owner_hash;

fn build_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../build/gnark/escrow")
}

fn ensure_keys() {
    let dir = build_dir();
    if !dir.join("pk.bin").exists() || !dir.join("vk.bin").exists() {
        timelock_escrow_prover::setup(CircuitId::Escrow, &dir).expect("setup failed");
    }
}

fn generated_vk() -> Groth16VerifyingkeyOwned {
    let bytes = std::fs::read(build_dir().join("vk.bin")).expect("read vk.bin");
    parse_gnark_vk_bytes(&bytes).expect("parse vk.bin")
}

fn fe(byte: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = byte;
    out
}

fn blinding(byte: u8) -> Blinding {
    let mut out = [0u8; 31];
    out[30] = byte;
    out
}

fn sample_terms() -> EscrowTermsProofInput {
    EscrowTermsProofInput {
        owner_hash: fe(99),
        unlock: 1_700_000_000,
    }
}

fn build_inputs(escrow_amount: u64, change_amount: u64) -> EscrowProofInputs {
    let terms = sample_terms();
    let source_mint = Address::new_from_array([1u8; 32]);
    let escrow_utxo = ProofInputUtxo::new(
        escrow_utxo_owner_hash(&fe(42)),
        &source_mint,
        escrow_amount,
        &blinding(7),
    )
    .expect("escrow utxo")
    .with_data_hash(terms.data_hash().expect("terms data hash"));
    let change = ProofInputUtxo::new(terms.owner_hash, &source_mint, change_amount, &blinding(6))
        .expect("change utxo");
    let source_input_hash = fe(5);
    let external_data_hash = fe(8);
    let private_tx_hash = PrivateTxHash::new(
        &[source_input_hash, [0u8; 32]],
        &[
            change.hash().expect("change hash"),
            escrow_utxo.hash().expect("escrow utxo hash"),
        ],
        &external_data_hash,
    )
    .hash()
    .expect("private tx hash");
    EscrowProofInputs {
        private_tx_hash,
        terms,
        escrow_utxo,
        change,
        source_input_hash,
        external_data_hash,
    }
}

fn sample_inputs() -> EscrowProofInputs {
    build_inputs(250, 750)
}

fn verify_with_generated_vk(
    vk: &Groth16VerifyingkeyOwned,
    proof_a: &[u8; 32],
    proof_b: &[u8; 64],
    proof_c: &[u8; 32],
    public_input: [u8; 32],
) -> bool {
    let a = match decompress_g1(proof_a) {
        Ok(g1) => g1,
        Err(_) => return false,
    };
    let b = match decompress_g2(proof_b) {
        Ok(g2) => g2,
        Err(_) => return false,
    };
    let c = match decompress_g1(proof_c) {
        Ok(g1) => g1,
        Err(_) => return false,
    };
    let public_inputs = [public_input];
    let borrowed = vk.as_borrowed();
    let mut verifier = match Groth16Verifier::new(&a, &b, &c, &public_inputs, &borrowed) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    verifier.verify().is_ok()
}

fn keys_in_sync(vk: &Groth16VerifyingkeyOwned) -> bool {
    let borrowed = vk.as_borrowed();
    borrowed.vk_ic.len() == VERIFYINGKEY.vk_ic.len()
        && borrowed.vk_alpha_g1 == VERIFYINGKEY.vk_alpha_g1
}

#[test]
fn program_vk_has_no_commitment() {
    assert_eq!(VERIFYINGKEY.nr_pubinputs, 1);
    assert!(
        VERIFYINGKEY.vk_commitment.is_none(),
        "escrow circuit is standard Groth16: no BSB22 commitment"
    );
    assert_eq!(
        VERIFYINGKEY.vk_ic.len(),
        2,
        "standard Groth16 vk_ic length must be public_inputs + 1"
    );
}

#[test]
fn escrow_prove_verify() {
    ensure_keys();
    let vk = generated_vk();

    let inputs = sample_inputs();
    let proof = inputs.prove().expect("prove failed");

    let proof_a_zero = proof.proof_a.iter().all(|byte| *byte == 0);
    assert!(!proof_a_zero, "proof_a must not be all zero");

    assert!(
        verify_with_generated_vk(
            &vk,
            &proof.proof_a,
            &proof.proof_b,
            &proof.proof_c,
            inputs.private_tx_hash,
        ),
        "groth16 proof must verify against the escrow verifying key with private_tx_hash as the sole public input"
    );

    if keys_in_sync(&vk) {
        let proof: EscrowProof = proof.into();
        verify_groth16(
            CompressedGroth16Proof {
                a: &proof.proof_a,
                b: &proof.proof_b,
                c: &proof.proof_c,
                commitment: None,
            },
            inputs.private_tx_hash,
            &VERIFYINGKEY,
        )
        .expect("program verify_groth16 must accept a valid proof");
    } else {
        eprintln!(
            "SKIP: committed escrow VERIFYINGKEY does not match the locally generated \
             build/gnark/escrow/vk.bin (keys are gitignored and groth16 setup is randomized), \
             so the on-chain verify_groth16 path was not exercised. Regenerate the keys with \
             timelock-escrow-prover-setup to run it."
        );
    }
}

#[test]
fn escrow_rejects_tampered_public_input() {
    ensure_keys();
    let vk = generated_vk();

    let inputs = sample_inputs();
    let proof = inputs.prove().expect("prove failed");

    let mut tampered = inputs.private_tx_hash;
    tampered[31] ^= 0x01;

    assert!(
        !verify_with_generated_vk(
            &vk,
            &proof.proof_a,
            &proof.proof_b,
            &proof.proof_c,
            tampered
        ),
        "verification must fail for a tampered public input"
    );
}

#[test]
fn escrow_rejects_zero_amount() {
    ensure_keys();

    let inputs = build_inputs(0, 750);

    assert!(
        inputs.prove().is_err(),
        "proving must fail when the escrow amount is zero (constraint violation)"
    );
}

#[test]
fn escrow_zero_change_proves() {
    ensure_keys();
    let vk = generated_vk();

    let inputs = build_inputs(250, 0);
    let proof = inputs.prove().expect("prove failed");

    assert!(
        verify_with_generated_vk(
            &vk,
            &proof.proof_a,
            &proof.proof_b,
            &proof.proof_c,
            inputs.private_tx_hash,
        ),
        "a zero-value change output is non-dummy: its real utxo hash enters private_tx_hash and the proof must verify, matching SPP"
    );
}
