use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    gnark_vk_parser::{parse_gnark_vk_bytes, Groth16VerifyingkeyOwned},
    groth16::Groth16Verifier,
};
use solana_address::Address;
use swap_program::{
    instructions::{
        fill::{FillProof, FillPublicInput},
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    verifying_keys::fill::VERIFYINGKEY,
};
use swap_prover::{CircuitId, FillProofInputs, OrderTermsProofInput, FILL_MODE_DERIVED};
use swap_sdk::{
    instructions::fill::derive_destination_blinding,
    order::{escrow_owner_hash, DataHash},
};
use zolana_keypair::{hash::hash_field, ViewingKey};
use zolana_transaction::{instructions::transact::PrivateTxHash, utxo::Blinding, ProofInputUtxo};

fn build_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../build/gnark/fill")
}

fn ensure_keys() {
    let dir = build_dir();
    if !dir.join("pk.bin").exists() || !dir.join("vk.bin").exists() {
        swap_prover::setup(CircuitId::Fill, &dir).expect("setup failed");
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

fn build_inputs(destination_output_blinding: Blinding) -> FillProofInputs {
    let maker_viewing_pk = *ViewingKey::new().pubkey().as_bytes();
    let order = OrderTermsProofInput {
        destination_asset: hash_field(&[2u8; 32]).expect("destination asset"),
        destination_amount: 250,
        maker_owner_hash: fe(99),
        maker_viewing_pk,
        expiry: 1_700_000_000,
        taker_pk_fe: fe(123),
        fill_mode: FILL_MODE_DERIVED,
    };
    let source_mint = Address::new_from_array([1u8; 32]);
    let destination_mint = Address::new_from_array([2u8; 32]);
    let taker_owner_hash = fe(77);
    let escrow = ProofInputUtxo::new(
        escrow_owner_hash(&fe(42)).expect("escrow owner hash"),
        &source_mint,
        1_000,
        &blinding(7),
    )
    .expect("escrow utxo")
    .with_data_hash(order.data_hash().expect("order data hash"));
    let taker_in = ProofInputUtxo::new(
        taker_owner_hash,
        &destination_mint,
        order.destination_amount,
        &blinding(13),
    )
    .expect("taker input utxo");
    let source_output = ProofInputUtxo::new(taker_owner_hash, &source_mint, 1_000, &blinding(31))
        .expect("source output utxo");
    let destination_output = ProofInputUtxo::new(
        order.maker_owner_hash,
        &destination_mint,
        order.destination_amount,
        &destination_output_blinding,
    )
    .expect("destination output utxo");
    let external_data_hash = fe(8);
    let private_tx_hash = PrivateTxHash::new(
        &[
            escrow.hash().expect("escrow hash"),
            taker_in.hash().expect("taker input hash"),
        ],
        &[
            source_output.hash().expect("source output hash"),
            destination_output.hash().expect("destination output hash"),
        ],
        &external_data_hash,
    )
    .hash()
    .expect("private tx hash");
    let public_input_hash = FillPublicInput {
        private_tx_hash: &private_tx_hash,
        expiry: order.expiry,
    }
    .hash()
    .expect("public input hash");
    FillProofInputs {
        public_input_hash,
        private_tx_hash,
        order,
        escrow,
        taker_in,
        source_output,
        destination_output,
        external_data_hash,
    }
}

fn sample_inputs() -> FillProofInputs {
    let derived = derive_destination_blinding(&blinding(7)).expect("derive destination blinding");
    build_inputs(derived)
}

fn verify_with_vk(
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

fn keys_in_sync(vk: &Groth16VerifyingkeyOwned) -> bool {
    let borrowed = vk.as_borrowed();
    borrowed.vk_ic.len() == VERIFYINGKEY.vk_ic.len()
        && borrowed.vk_alpha_g1 == VERIFYINGKEY.vk_alpha_g1
}

#[test]
fn program_vk_has_no_commitment() {
    assert_eq!(VERIFYINGKEY.nr_pubinputs, 1);
    assert!(
        VERIFYINGKEY.vk_commitment_g2.is_none(),
        "derived fill circuit is standard Groth16: no BSB22 commitment"
    );
    assert_eq!(
        VERIFYINGKEY.vk_ic.len(),
        2,
        "standard Groth16 vk_ic length must be public_inputs + 1"
    );
}

#[test]
fn fill_prove_verify() {
    ensure_keys();
    let vk = generated_vk();

    let inputs = sample_inputs();
    let proof = inputs.prove().expect("prove failed");

    let proof_a_zero = proof.proof_a.iter().all(|byte| *byte == 0);
    assert!(!proof_a_zero, "proof_a must not be all zero");
    assert!(
        proof.commitment.is_none(),
        "derived fill proof must not carry a BSB22 commitment"
    );

    assert!(
        verify_with_vk(
            &vk,
            &proof.proof_a,
            &proof.proof_b,
            &proof.proof_c,
            inputs.public_input_hash,
        ),
        "groth16 proof must verify against the generated fill verifying key"
    );

    if keys_in_sync(&vk) {
        let public_input_hash = FillPublicInput {
            private_tx_hash: &inputs.private_tx_hash,
            expiry: inputs.order.expiry,
        }
        .hash()
        .expect("program fill public input hash");
        let proof: FillProof = proof.into();
        verify_groth16(
            CompressedGroth16Proof {
                a: &proof.proof_a,
                b: &proof.proof_b,
                c: &proof.proof_c,
                commitment: None,
            },
            public_input_hash,
            &VERIFYINGKEY,
        )
        .expect("program fill verify must accept a valid proof");
    }
}

#[test]
fn fill_rejects_tampered_public_input() {
    ensure_keys();
    let vk = generated_vk();

    let inputs = sample_inputs();
    let proof = inputs.prove().expect("prove failed");

    let mut tampered = inputs.public_input_hash;
    tampered[31] ^= 0x01;

    assert!(
        !verify_with_vk(
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
fn fill_rejects_wrong_destination_blinding() {
    ensure_keys();

    let mut wrong_blinding =
        derive_destination_blinding(&blinding(7)).expect("derive destination blinding");
    wrong_blinding[30] ^= 0x01;
    let inputs = build_inputs(wrong_blinding);

    assert!(
        inputs.prove().is_err(),
        "proving must fail when the destination output blinding is not derived from the escrow blinding"
    );
}
