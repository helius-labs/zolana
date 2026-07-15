use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    gnark_vk_parser::{parse_gnark_vk_bytes, Groth16VerifyingkeyOwned},
    groth16::Groth16Verifier,
};
use solana_address::Address;
use swap_program::{
    instructions::{
        create_swap::CreateProof,
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    verifying_keys::create::VERIFYINGKEY,
};
use swap_prover::{
    CircuitId, CreateProofInputs, OrderTermsFieldElements, FILL_MODE_DERIVED,
};
use swap_sdk::witness::{escrow_owner_hash, order_data_hash, PlainUtxo};
use zolana_keypair::hash::hash_field;
use zolana_transaction::{instructions::transact::PrivateTxHash, utxo::Blinding};

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

fn sample_order() -> OrderTermsFieldElements {
    let mut maker_viewing_pk = [0u8; 33];
    maker_viewing_pk[0] = 2;
    maker_viewing_pk[32] = 55;
    OrderTermsFieldElements {
        destination_asset: hash_field(&[2u8; 32]).expect("destination asset"),
        destination_amount: 250,
        maker_owner_hash: fe(99),
        maker_viewing_pk,
        expiry: 1_700_000_000,
        taker_pk_fe: fe(123),
        fill_mode: FILL_MODE_DERIVED,
    }
}

fn build_inputs(destination_amount: u64, change_amount: u64) -> CreateProofInputs {
    let mut order = sample_order();
    order.destination_amount = destination_amount;
    let source_mint = Address::new_from_array([1u8; 32]);
    let escrow = PlainUtxo {
        owner_hash: escrow_owner_hash(&fe(42)).expect("escrow owner hash"),
        mint: source_mint,
        amount: 1_000,
        blinding: blinding(7),
        data_hash: order_data_hash(&order).expect("order data hash"),
    };
    let change = PlainUtxo {
        owner_hash: order.maker_owner_hash,
        mint: source_mint,
        amount: change_amount,
        blinding: blinding(6),
        data_hash: [0u8; 32],
    };
    let source_input_hash = fe(5);
    let external_data_hash = fe(8);
    let change_output_hash = if change.amount == 0 {
        [0u8; 32]
    } else {
        change.hash().expect("change hash")
    };
    let private_tx_hash = PrivateTxHash::new(
        &[source_input_hash, [0u8; 32]],
        &[change_output_hash, escrow.hash().expect("escrow hash")],
        &external_data_hash,
    )
    .hash()
    .expect("private tx hash");
    CreateProofInputs {
        private_tx_hash,
        order,
        escrow: escrow.field_elements().expect("escrow fields"),
        change: change.field_elements().expect("change fields"),
        source_input_hash,
        external_data_hash,
    }
}

fn sample_inputs() -> CreateProofInputs {
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
        "groth16 proof must verify against the create verifying key with private_tx_hash as the sole public input"
    );

    if keys_in_sync(&vk) {
        let proof: CreateProof = proof.into();
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
    }
}

#[test]
fn create_rejects_tampered_public_input() {
    ensure_keys();
    let vk = generated_vk();

    let inputs = sample_inputs();
    let proof = inputs.prove().expect("prove failed");

    let mut tampered = inputs.private_tx_hash;
    tampered[31] ^= 0x01;

    assert!(
        !verify_with_generated_vk(&vk, &proof.proof_a, &proof.proof_b, &proof.proof_c, tampered),
        "verification must fail for a tampered public input"
    );
}

#[test]
fn create_rejects_tampered_order_term() {
    ensure_keys();

    let inputs = build_inputs(0, 750);

    assert!(
        inputs.prove().is_err(),
        "proving must fail when destination_amount is zero (constraint violation)"
    );
}

#[test]
fn create_zero_change_proves() {
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
        "zero-change (dummy change output) must prove and verify"
    );
}
