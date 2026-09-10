use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::Groth16Verifier,
    vk::gnark::{parse_gnark_vk_bytes, Groth16VerifyingkeyOwned},
};
use solana_address::Address;
use swap_program::{
    instructions::{
        take::{TakeProof, TakePublicInput},
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    verifying_keys::take::VERIFYINGKEY,
};
use swap_prover::{CircuitId, TakeProofInputs, TAKE_MODE_DERIVED};
use swap_sdk::{
    instructions::take::{take_blinding_seed, TakeProofInputParams},
    state::{OrderTerms, OrderUtxo},
};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    instructions::transact::{assign_output_blindings, PrivateTxHash},
    utxo::{derive_output_blinding_seed, derive_private_tx_blinding},
};

fn build_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../build/gnark/take")
}

fn ensure_keys() {
    let dir = build_dir();
    if !dir.join("pk.bin").exists() || !dir.join("vk.bin").exists() {
        swap_prover::setup(CircuitId::Take, &dir).expect("setup failed");
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

/// Nonzero, different trees catch dropped or swapped IDs in the commitments.
const INPUT_TREE_ID: u16 = 3;
const OUTPUT_TREE_ID: u16 = 7;

fn sample_params() -> TakeProofInputParams {
    let maker = ShieldedKeypair::new_ed25519()
        .unwrap()
        .shielded_address()
        .unwrap();
    let taker = ShieldedKeypair::new_ed25519()
        .unwrap()
        .shielded_address()
        .unwrap();
    let order_utxo = OrderUtxo {
        terms: OrderTerms {
            destination_mint: Address::new_from_array([2; 32]),
            destination_amount: 250,
            destination: maker,
            taker: taker.solana_address().unwrap(),
            expiry: 1_700_000_000,
            take_mode: TAKE_MODE_DERIVED,
        },
        blinding: fe(7),
        source_mint: Address::new_from_array([1; 32]),
        source_amount: 1_000,
        destination_asset_id: 2,
    };
    let first_nullifier = order_utxo
        .to_input_utxo()
        .unwrap()
        .in_tree(INPUT_TREE_ID)
        .nullifier()
        .unwrap();
    let blinding_seed = take_blinding_seed(&order_utxo.blinding).unwrap();
    let seed = derive_output_blinding_seed(&first_nullifier, &blinding_seed).unwrap();
    let mut outputs = [
        order_utxo.source_output(taker, fe(0)),
        order_utxo.destination_output(maker, fe(0)),
    ];
    assign_output_blindings(&mut outputs, &first_nullifier, &seed).unwrap();
    let [source_output, destination_output] = outputs;
    TakeProofInputParams {
        taker_in: order_utxo.destination_output(taker, fe(13)),
        order_utxo,
        source_output,
        destination_output,
        external_data_hash: fe(8),
        private_tx_blinding: derive_private_tx_blinding(&first_nullifier, &blinding_seed).unwrap(),
        input_tree_id: INPUT_TREE_ID,
        output_tree_id: OUTPUT_TREE_ID,
    }
}

fn sample_inputs() -> TakeProofInputs {
    sample_params().to_proof_inputs().unwrap()
}

// Refresh both commitments after mutations, so negative proofs fail on the
// recovery constraint rather than on stale public hashes.
fn refresh_hashes(inputs: &mut TakeProofInputs) {
    inputs.private_tx_hash = PrivateTxHash::new(
        &[
            inputs.order_utxo.hash().unwrap(),
            inputs.taker_in.hash().unwrap(),
        ],
        &[
            inputs.source_output.hash().unwrap(),
            inputs.destination_output.hash().unwrap(),
        ],
        &inputs.external_data_hash,
        &inputs.private_tx_blinding,
    )
    .hash()
    .unwrap();
    inputs.public_input_hash = TakePublicInput {
        private_tx_hash: &inputs.private_tx_hash,
        expiry: inputs.order.expiry,
        first_nullifier: &inputs.first_nullifier,
    }
    .hash()
    .unwrap();
}

fn verify_with_vk(
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

#[test]
fn program_vk_has_no_commitment() {
    assert_eq!(VERIFYINGKEY.nr_pubinputs, 1);
    assert!(
        VERIFYINGKEY.vk_commitment.is_none(),
        "derived take circuit is standard Groth16: no BSB22 commitment"
    );
    assert_eq!(
        VERIFYINGKEY.vk_ic.len(),
        2,
        "standard Groth16 vk_ic length must be public_inputs + 1"
    );
}

#[test]
fn take_prove_verify() {
    ensure_keys();
    let vk = generated_vk();

    let inputs = sample_inputs();
    let proof = inputs.prove().expect("prove failed");

    let proof_a_zero = proof.proof_a.iter().all(|byte| *byte == 0);
    assert!(!proof_a_zero, "proof_a must not be all zero");
    assert!(
        proof.commitment.is_none(),
        "derived take proof must not carry a BSB22 commitment"
    );

    assert!(
        verify_with_vk(
            &vk,
            &proof.proof_a,
            &proof.proof_b,
            &proof.proof_c,
            inputs.public_input_hash,
        ),
        "groth16 proof must verify against the generated take verifying key"
    );

    let public_input_hash = TakePublicInput {
        private_tx_hash: &inputs.private_tx_hash,
        expiry: inputs.order.expiry,
        first_nullifier: &inputs.first_nullifier,
    }
    .hash()
    .expect("program take public input hash");
    let proof: TakeProof = proof.into();
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
    .expect("program take verify must accept a valid proof");
}

#[test]
fn take_rejects_tampered_public_input() {
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
fn take_rejects_unrecoverable_payouts_and_transaction_blinding() {
    ensure_keys();
    let good = sample_inputs();
    good.prove().expect("positive control");
    for attack in 0..4 {
        let mut inputs = good.clone();
        match attack {
            0 => inputs.destination_output.blinding = fe(29),
            1 => inputs.source_output.blinding = fe(29),
            2 => inputs.private_tx_blinding = fe(29),
            _ => {
                let blinding_seed = fe(29);
                let seed =
                    derive_output_blinding_seed(&inputs.first_nullifier, &blinding_seed).unwrap();
                inputs.private_tx_blinding =
                    derive_private_tx_blinding(&inputs.first_nullifier, &blinding_seed).unwrap();
                for (index, output) in [&mut inputs.source_output, &mut inputs.destination_output]
                    .into_iter()
                    .enumerate()
                {
                    output.blinding = zolana_transaction::utxo::derive_transact_output_blinding(
                        &inputs.first_nullifier,
                        &seed,
                        index as u32,
                    )
                    .unwrap();
                }
            }
        }
        refresh_hashes(&mut inputs);
        assert!(inputs.prove().is_err(), "accepted recovery attack {attack}");
    }
}

#[test]
fn maker_recovers_payout_without_settlement_ciphertext() {
    let params = sample_params();
    let inputs = params.to_proof_inputs().unwrap();
    let recovered = params
        .order_utxo
        .derived_destination_output(&inputs.first_nullifier)
        .unwrap();
    assert_eq!(
        recovered.hash(OUTPUT_TREE_ID).unwrap(),
        inputs.destination_output.hash().unwrap()
    );
    let wrong_first = params
        .order_utxo
        .derived_destination_output(&fe(17))
        .unwrap();
    assert_ne!(
        wrong_first.hash(OUTPUT_TREE_ID).unwrap(),
        inputs.destination_output.hash().unwrap()
    );
}

#[test]
fn sdk_rejects_a_taker_selected_blinding_seed_or_payout() {
    let mut params = sample_params();
    params.destination_output.blinding = fe(29);
    assert!(params
        .to_proof_inputs()
        .unwrap_err()
        .to_string()
        .contains("output 1 blinding"));
    let mut params = sample_params();
    params.private_tx_blinding = fe(29);
    assert!(params
        .to_proof_inputs()
        .unwrap_err()
        .to_string()
        .contains("blinding seed"));
}

#[test]
fn take_proof_binds_the_published_first_nullifier() {
    ensure_keys();
    let inputs = sample_inputs();
    let proof = inputs.prove().unwrap();
    let wrong_hash = TakePublicInput {
        private_tx_hash: &inputs.private_tx_hash,
        expiry: inputs.order.expiry,
        first_nullifier: &fe(17),
    }
    .hash()
    .unwrap();
    assert!(!verify_with_vk(
        &generated_vk(),
        &proof.proof_a,
        &proof.proof_b,
        &proof.proof_c,
        wrong_hash
    ));
}
