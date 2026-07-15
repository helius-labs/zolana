use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    gnark_vk_parser::{parse_gnark_vk_bytes, Groth16VerifyingkeyOwned},
    groth16::Groth16Verifier,
};
use solana_address::Address;
use swap_program::{
    instructions::cancel::verify::CancelPublicInput, verifying_keys::cancel::VERIFYINGKEY,
};
use swap_prover::{CancelProofInputs, CircuitId, OrderTermsFieldElements, FILL_MODE_DERIVED};
use swap_sdk::witness::{escrow_owner_hash, order_data_hash, PlainUtxo};
use zolana_keypair::hash::{hash_field, poseidon};
use zolana_transaction::{instructions::transact::PrivateTxHash, utxo::Blinding};

fn build_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../build/gnark/cancel")
}

fn ensure_keys() {
    let dir = build_dir();
    if !dir.join("pk.bin").exists() || !dir.join("vk.bin").exists() {
        swap_prover::setup(CircuitId::Cancel, &dir).expect("setup failed");
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

fn build_inputs(source_output_owner: [u8; 32]) -> CancelProofInputs {
    let maker_owner_pk_field = fe(71);
    let maker_nullifier_pk = fe(88);
    let maker_owner_hash =
        poseidon(&[&maker_owner_pk_field, &maker_nullifier_pk]).expect("owner hash");
    let mut maker_viewing_pk = [0u8; 33];
    maker_viewing_pk[0] = 2;
    maker_viewing_pk[32] = 55;
    let order = OrderTermsFieldElements {
        destination_asset: hash_field(&[2u8; 32]).expect("destination asset"),
        destination_amount: 250,
        maker_owner_hash,
        maker_viewing_pk,
        expiry: 1_700_000_000,
        taker_pk_fe: fe(123),
        fill_mode: FILL_MODE_DERIVED,
    };
    let source_mint = Address::new_from_array([1u8; 32]);
    let escrow = PlainUtxo {
        owner_hash: escrow_owner_hash(&fe(42)).expect("escrow owner hash"),
        mint: source_mint,
        amount: 1_000,
        blinding: blinding(7),
        data_hash: order_data_hash(&order).expect("order data hash"),
    };
    let source_output = PlainUtxo {
        owner_hash: source_output_owner,
        mint: source_mint,
        amount: 1_000,
        blinding: blinding(11),
        data_hash: [0u8; 32],
    };
    let external_data_hash = fe(8);
    let private_tx_hash = PrivateTxHash::new(
        &[escrow.hash().expect("escrow hash")],
        &[source_output.hash().expect("source output hash")],
        &external_data_hash,
    )
    .hash()
    .expect("private tx hash");
    let public_input_hash = CancelPublicInput {
        private_tx_hash: &private_tx_hash,
        expiry: order.expiry,
        maker_owner_pk_field: &maker_owner_pk_field,
    }
    .hash()
    .expect("public input hash");
    CancelProofInputs {
        public_input_hash,
        private_tx_hash,
        order,
        maker_owner_pk_field,
        maker_nullifier_pk,
        escrow: escrow.field_elements().expect("escrow fields"),
        source_output: source_output.field_elements().expect("source output fields"),
        external_data_hash,
    }
}

fn sample_inputs() -> CancelProofInputs {
    let maker_owner_hash = poseidon(&[&fe(71), &fe(88)]).expect("owner hash");
    build_inputs(maker_owner_hash)
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
        "cancel circuit is standard Groth16: no BSB22 commitment"
    );
    assert_eq!(
        VERIFYINGKEY.vk_ic.len(),
        2,
        "standard Groth16 vk_ic length must be public_inputs + 1"
    );
}

#[test]
fn cancel_prove_verify() {
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
            inputs.public_input_hash,
        ),
        "groth16 proof must verify against the cancel verifying key"
    );

    if keys_in_sync(&vk) {
        CancelPublicInput {
            private_tx_hash: &inputs.private_tx_hash,
            expiry: inputs.order.expiry,
            maker_owner_pk_field: &inputs.maker_owner_pk_field,
        }
        .verify(&proof.into())
        .expect("program cancel verify must accept a valid proof");
    }
}

#[test]
fn cancel_rejects_tampered_public_input() {
    ensure_keys();
    let vk = generated_vk();

    let inputs = sample_inputs();
    let proof = inputs.prove().expect("prove failed");

    let mut tampered = inputs.public_input_hash;
    tampered[31] ^= 0x01;

    assert!(
        !verify_with_generated_vk(&vk, &proof.proof_a, &proof.proof_b, &proof.proof_c, tampered),
        "verification must fail for a tampered public input"
    );
}

#[test]
fn cancel_rejects_wrong_source_output_owner() {
    ensure_keys();

    let mut wrong_owner = poseidon(&[&fe(71), &fe(88)]).expect("owner hash");
    wrong_owner[31] ^= 0x01;
    let inputs = build_inputs(wrong_owner);

    assert!(
        inputs.prove().is_err(),
        "proving must fail when the source output is sent to an owner other than maker_address"
    );
}
