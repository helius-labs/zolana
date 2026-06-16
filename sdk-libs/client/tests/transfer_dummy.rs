//! Generate and verify a (2,3) transfer proof built from only dummy UTXOs.
//!
//! Unlike `transfer_2_3.rs`, this does not go through the `Transaction` builder
//! (which needs at least one real input to seed the encryption nonce). It
//! constructs an all-dummy `TransferProver` directly: empty input/output lists
//! plus an explicit (2,3) shape, so `build` pads every slot with
//! `TransferInput::new_dummy()` / `TransferOutput::new_dummy()`. The witness has
//! zero value, zero roots, and zero nullifiers, which selects the vanilla
//! Solana-only eddsa rail (`transfer_2_3`). The proof is produced on the prover
//! server and verified against the committed verifying key.
//!
//! Requires a reachable prover server (started via `spawn_prover`) with the
//! `transfer-eddsa_2_3.key` proving key available.
//!
//! Run with: `cargo test -p zolana-client --test transfer_dummy`

use groth16_solana::groth16::Groth16Verifier;
use solana_address::Address;
use zolana_client::{spawn_prover, ProverClient, PublicAmounts, Shape, TransferProver};
use zolana_interface::verifying_keys::transfer_2_3;
use zolana_transaction::ExternalData;

fn start_prover() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::env::set_var(
            "ZOLANA_PROVER_KEYS_DIR",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../prover/server/proving-keys"
            ),
        );
    });
    spawn_prover().expect("start prover");
}

fn dummy_external_data() -> ExternalData {
    ExternalData {
        instruction_discriminator: 0,
        expiry_unix_ts: 0,
        sender_view_tag: [0u8; 32],
        relayer_fee: 0,
        public_sol_amount: 0,
        public_spl_amount: 0,
        user_sol_account: Address::default(),
        user_spl_token: Address::default(),
        spl_token_interface: Address::default(),
        encrypted_utxos: Vec::new(),
    }
}

#[test]
fn dummy_transfer_2_3_proof_verifies() {
    start_prover();

    let prover = TransferProver {
        inputs: Vec::new(),
        outputs: Vec::new(),
        external_data: dummy_external_data(),
        public_amounts: PublicAmounts {
            sol: [0u8; 32],
            spl: [0u8; 32],
            asset: [0u8; 32],
        },
        payer_pubkey_hash: [0u8; 32],
        shape: Some(Shape::new(2, 3)),
    };

    let result = prover.build().expect("build all-dummy witness");

    let proof = ProverClient::local()
        .prove_transfer(&result.inputs)
        .expect("prove transfer-eddsa");

    let public_inputs: [[u8; 32]; 1] = [result.public_input_hash];
    let mut verifier = Groth16Verifier::new(
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs,
        &transfer_2_3::VERIFYINGKEY,
    )
    .expect("construct verifier");
    verifier.verify().expect("groth16 proof verifies");
}
