use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::Groth16Verifier,
    vk::gnark::{parse_gnark_vk_bytes, Groth16VerifyingkeyOwned},
};
use solana_address::Address;
use timelock_escrow_program::{
    instructions::{
        verifier::{verify_groth16, CompressedGroth16Proof},
        withdraw::{WithdrawProof, WithdrawPublicInput},
    },
    verifying_keys::withdraw::VERIFYINGKEY,
};
use timelock_escrow_prover::{CircuitId, EscrowTermsProofInput, WithdrawProofInputs};
use timelock_escrow_sdk::state::DataHash;
use zolana_keypair::hash::poseidon;
use zolana_transaction::{instructions::transact::PrivateTxHash, utxo::Blinding, ProofInputUtxo};

mod shared;
use shared::escrow_utxo_owner_hash;

fn build_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../build/gnark/withdraw")
}

fn ensure_keys() {
    let dir = build_dir();
    if !dir.join("pk.bin").exists() || !dir.join("vk.bin").exists() {
        timelock_escrow_prover::setup(CircuitId::Withdraw, &dir).expect("setup failed");
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

fn build_inputs(source_output_owner: [u8; 32]) -> WithdrawProofInputs {
    let owner_pk_field = fe(71);
    let nullifier_pk = fe(88);
    let owner_hash = poseidon(&[&owner_pk_field, &nullifier_pk]).expect("owner hash");
    let terms = EscrowTermsProofInput {
        owner_hash,
        unlock: 1_700_000_000,
    };
    let source_mint = Address::new_from_array([1u8; 32]);
    let escrow_utxo = ProofInputUtxo::new(
        escrow_utxo_owner_hash(&fe(42)),
        &source_mint,
        1_000,
        &blinding(7),
    )
    .expect("escrow utxo")
    .with_data_hash(terms.data_hash().expect("terms data hash"));
    let source_output =
        ProofInputUtxo::new(source_output_owner, &source_mint, 1_000, &blinding(11))
            .expect("source output utxo");
    let external_data_hash = fe(8);
    let private_tx_hash = PrivateTxHash::new(
        &[escrow_utxo.hash().expect("escrow utxo hash")],
        &[source_output.hash().expect("source output hash")],
        &external_data_hash,
    )
    .hash()
    .expect("private tx hash");
    let public_input_hash = WithdrawPublicInput {
        private_tx_hash: &private_tx_hash,
        unlock: terms.unlock,
        owner_pk_field: &owner_pk_field,
    }
    .hash()
    .expect("public input hash");
    WithdrawProofInputs {
        public_input_hash,
        private_tx_hash,
        terms,
        owner_pk_field,
        nullifier_pk,
        escrow_utxo,
        source_output,
        external_data_hash,
    }
}

fn sample_inputs() -> WithdrawProofInputs {
    let owner_hash = poseidon(&[&fe(71), &fe(88)]).expect("owner hash");
    build_inputs(owner_hash)
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
        "withdraw circuit is standard Groth16: no BSB22 commitment"
    );
    assert_eq!(
        VERIFYINGKEY.vk_ic.len(),
        2,
        "standard Groth16 vk_ic length must be public_inputs + 1"
    );
}

#[test]
fn withdraw_prove_verify() {
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
        "groth16 proof must verify against the withdraw verifying key"
    );

    if keys_in_sync(&vk) {
        let public_input_hash = WithdrawPublicInput {
            private_tx_hash: &inputs.private_tx_hash,
            unlock: inputs.terms.unlock,
            owner_pk_field: &inputs.owner_pk_field,
        }
        .hash()
        .expect("program withdraw public input hash");
        let proof: WithdrawProof = proof.into();
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
        .expect("program withdraw verify must accept a valid proof");
    } else {
        eprintln!(
            "SKIP: committed withdraw VERIFYINGKEY does not match the locally generated \
             build/gnark/withdraw/vk.bin (keys are gitignored and groth16 setup is randomized), \
             so the on-chain verify_groth16 path was not exercised. Regenerate the keys with \
             timelock-escrow-prover-setup to run it."
        );
    }
}

#[test]
fn withdraw_rejects_tampered_public_input() {
    ensure_keys();
    let vk = generated_vk();

    let inputs = sample_inputs();
    let proof = inputs.prove().expect("prove failed");

    let mut tampered = inputs.public_input_hash;
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
fn withdraw_rejects_wrong_source_output_owner() {
    ensure_keys();

    let mut wrong_owner = poseidon(&[&fe(71), &fe(88)]).expect("owner hash");
    wrong_owner[31] ^= 0x01;
    let inputs = build_inputs(wrong_owner);

    assert!(
        inputs.prove().is_err(),
        "proving must fail when the source output is sent to an owner other than owner_hash"
    );
}
