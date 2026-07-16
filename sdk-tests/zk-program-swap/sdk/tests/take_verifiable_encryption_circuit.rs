use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::Groth16Verifier,
    vk::gnark::{parse_gnark_vk_bytes, Groth16VerifyingkeyOwned},
};
use solana_address::Address;
use swap_program::{
    instructions::{
        take_verifiable_encryption::{
            TakeVerifiableEncryptionProof, TakeVerifiableEncryptionPublicInput,
        },
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    verifying_keys::take_verifiable_encryption::VERIFYINGKEY,
};
use swap_prover::{
    CircuitId, OrderProof, OrderTermsProofInput, TakeVerifiableEncryptionProofInputs,
    TAKE_MODE_VERIFIABLE,
};
use swap_sdk::{
    instructions::take_verifiable_encryption::{
        decrypt_destination, destination_ciphertext_with_hash,
    },
    state::DataHash,
};
use zolana_interface::merge_utils::ciphertext_hash;
use zolana_keypair::{
    hash::{hash_field, poseidon},
    ViewingKey,
};
use zolana_transaction::{instructions::transact::PrivateTxHash, utxo::Blinding, ProofInputUtxo};

mod shared;
use shared::order_utxo_owner_hash;

fn build_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../build/gnark/take_verifiable_encryption")
}

fn ensure_keys() {
    let dir = build_dir();
    if !dir.join("pk.bin").exists() || !dir.join("vk.bin").exists() {
        swap_prover::setup(CircuitId::TakeVerifiableEncryption, &dir).expect("setup failed");
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

fn sample_order() -> OrderTermsProofInput {
    let maker_viewing_pk = *ViewingKey::new().pubkey().as_bytes();
    OrderTermsProofInput {
        destination_asset: hash_field(&[2u8; 32]).expect("destination asset"),
        destination_amount: 250,
        maker_owner_hash: fe(99),
        maker_viewing_pk,
        expiry: 1_700_000_000,
        taker_pk_fe: fe(123),
        take_mode: TAKE_MODE_VERIFIABLE,
    }
}

fn taker_owner_hash(order: &OrderTermsProofInput) -> [u8; 32] {
    poseidon(&[&order.taker_pk_fe, &fe(200)]).expect("taker owner hash")
}

#[derive(Default)]
struct SampleOverrides {
    taker_owner: Option<[u8; 32]>,
    destination_owner: Option<[u8; 32]>,
    destination_amount: Option<u64>,
}

fn build_inputs(overrides: SampleOverrides) -> TakeVerifiableEncryptionProofInputs {
    let order = sample_order();
    let source_mint = Address::new_from_array([1u8; 32]);
    let destination_mint = Address::new_from_array([2u8; 32]);
    let taker_owner = overrides
        .taker_owner
        .unwrap_or_else(|| taker_owner_hash(&order));
    let destination_owner = overrides
        .destination_owner
        .unwrap_or(order.maker_owner_hash);
    let destination_amount = overrides
        .destination_amount
        .unwrap_or(order.destination_amount);
    let order_utxo = ProofInputUtxo::new(
        order_utxo_owner_hash(&fe(42)),
        &source_mint,
        1_000,
        &blinding(7),
    )
    .expect("order utxo")
    .with_data_hash(order.data_hash().expect("order data hash"));
    let taker_in = ProofInputUtxo::new(
        taker_owner,
        &destination_mint,
        order.destination_amount,
        &blinding(13),
    )
    .expect("taker input utxo");
    let source_output = ProofInputUtxo::new(taker_owner, &source_mint, 1_000, &blinding(31))
        .expect("source output utxo");
    let destination_output = ProofInputUtxo::new(
        destination_owner,
        &destination_mint,
        destination_amount,
        &blinding(21),
    )
    .expect("destination output utxo");
    let external_data_hash = fe(8);
    let private_tx_hash = PrivateTxHash::new(
        &[
            order_utxo.hash().expect("order utxo hash"),
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
    let (ciphertext, _) = sample_ciphertext(&order);
    let public_input_hash = TakeVerifiableEncryptionPublicInput {
        private_tx_hash: &private_tx_hash,
        expiry: order.expiry,
        destination_ciphertext: &ciphertext,
    }
    .hash()
    .expect("public input hash");
    TakeVerifiableEncryptionProofInputs {
        public_input_hash,
        private_tx_hash,
        order,
        taker_nullifier_pk: fe(200),
        order_utxo,
        taker_in,
        source_output,
        destination_output,
        external_data_hash,
    }
}

fn sample_ciphertext(order: &OrderTermsProofInput) -> (Vec<u8>, [u8; 32]) {
    destination_ciphertext_with_hash(
        &blinding(7),
        &Address::new_from_array([2u8; 32]),
        order.destination_amount,
        &blinding(21),
    )
    .expect("destination ciphertext")
}

fn sample_inputs() -> TakeVerifiableEncryptionProofInputs {
    build_inputs(SampleOverrides::default())
}

fn verify_with_generated_vk(
    vk: &Groth16VerifyingkeyOwned,
    proof: &OrderProof,
    public_input: [u8; 32],
) -> bool {
    let a = match decompress_g1(&proof.proof_a) {
        Ok(g1) => g1,
        Err(_) => return false,
    };
    let b = match decompress_g2(&proof.proof_b) {
        Ok(g2) => g2,
        Err(_) => return false,
    };
    let c = match decompress_g1(&proof.proof_c) {
        Ok(g1) => g1,
        Err(_) => return false,
    };
    let (commitment, commitment_pok) = match proof.commitment {
        Some(pair) => pair,
        None => return false,
    };
    let commitment = match decompress_g1(&commitment) {
        Ok(g1) => g1,
        Err(_) => return false,
    };
    let commitment_pok = match decompress_g1(&commitment_pok) {
        Ok(g1) => g1,
        Err(_) => return false,
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
fn program_vk_has_bsb22_commitment() {
    assert_eq!(VERIFYINGKEY.nr_pubinputs, 1);
    assert!(
        VERIFYINGKEY.vk_commitment.is_some(),
        "take circuit carries a BSB22 commitment"
    );
    assert_eq!(
        VERIFYINGKEY.vk_ic.len(),
        3,
        "program vk_ic length must be public_inputs + 2"
    );
}

#[test]
fn take_prove_verify_and_round_trip() {
    ensure_keys();
    let vk = generated_vk();

    let inputs = sample_inputs();
    let proof = inputs.prove().expect("prove failed");

    let proof_a_zero = proof.proof_a.iter().all(|byte| *byte == 0);
    assert!(!proof_a_zero, "proof_a must not be all zero");
    assert!(
        proof.commitment.is_some(),
        "take proof must carry a BSB22 commitment"
    );

    assert!(
        verify_with_generated_vk(&vk, &proof, inputs.public_input_hash),
        "groth16 proof must verify with new_with_commitment against the take verifying key"
    );

    let (ciphertext, ct_hash) = sample_ciphertext(&inputs.order);
    assert_eq!(
        ciphertext_hash(&ciphertext).expect("program-side take ciphertext hash"),
        ct_hash,
        "program-side ctHash must match the sdk's destination ciphertext hash"
    );

    if keys_in_sync(&vk) {
        let public_input_hash = TakeVerifiableEncryptionPublicInput {
            private_tx_hash: &inputs.private_tx_hash,
            expiry: inputs.order.expiry,
            destination_ciphertext: &ciphertext,
        }
        .hash()
        .expect("program take public input hash");
        let proof: TakeVerifiableEncryptionProof = proof
            .try_into()
            .expect("tve proof carries a BSB22 commitment");
        verify_groth16(
            CompressedGroth16Proof {
                a: &proof.proof_a,
                b: &proof.proof_b,
                c: &proof.proof_c,
                commitment: Some((&proof.commitment, &proof.commitment_pok)),
            },
            public_input_hash,
            &VERIFYINGKEY,
        )
        .expect("program take verify must accept a valid proof");
    } else {
        eprintln!(
            "SKIP: committed take_verifiable_encryption VERIFYINGKEY does not match the locally \
             generated build/gnark/take_verifiable_encryption/vk.bin (keys are gitignored and \
             groth16 setup is randomized), so the on-chain verify_groth16 path was not exercised. \
             Download the pinned keys matching swap-keys.CHECKSUM to run it."
        );
    }

    let (asset, amount) =
        decrypt_destination(&blinding(7), &ciphertext).expect("decrypt destination ciphertext");
    assert_eq!(
        (asset, amount),
        (
            hash_field(&[2u8; 32]).expect("destination asset"),
            inputs.order.destination_amount
        ),
        "the maker recovers (destination_asset, destination_amount) by decrypting with the order utxo blinding"
    );
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
        !verify_with_generated_vk(&vk, &proof, tampered),
        "verification must fail for a tampered public input"
    );
}

#[test]
fn take_rejects_wrong_taker_address() {
    ensure_keys();

    let order = sample_order();
    let mut wrong_taker_owner = taker_owner_hash(&order);
    wrong_taker_owner[31] ^= 0x01;
    let inputs = build_inputs(SampleOverrides {
        taker_owner: Some(wrong_taker_owner),
        ..Default::default()
    });

    assert!(
        inputs.prove().is_err(),
        "proving must fail when the taker input owner is not Poseidon(taker_pk_fe, taker_nullifier_pk)"
    );
}

#[test]
fn take_rejects_wrong_destination_output_owner() {
    ensure_keys();

    let order = sample_order();
    let mut wrong_owner = order.maker_owner_hash;
    wrong_owner[31] ^= 0x01;
    let inputs = build_inputs(SampleOverrides {
        destination_owner: Some(wrong_owner),
        ..Default::default()
    });

    assert!(
        inputs.prove().is_err(),
        "proving must fail when the destination output owner differs from maker_address"
    );
}

#[test]
fn take_rejects_wrong_destination_output_amount() {
    ensure_keys();

    let order = sample_order();
    let inputs = build_inputs(SampleOverrides {
        destination_amount: Some(order.destination_amount + 1),
        ..Default::default()
    });

    assert!(
        inputs.prove().is_err(),
        "proving must fail when the destination output amount differs from the committed destination_amount"
    );
}
