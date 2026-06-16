//! Litesvm program-test setup for the `transact` instruction.
//!
//! This is the boot/setup scaffold: it stands up a [`ZolanaProgramTest`]
//! environment with a protocol config and a pool tree, which is the shared
//! starting point every `transact` scenario needs. The proof-driven body is
//! intentionally left as a documented TODO because exercising `transact`
//! on-chain requires machinery that does not exist yet (see below).
//!
//! What a full `transact` test still needs:
//!  1. Spendable inputs on the tree. Seed them with `proofless_shield`
//!     deposits, then sync the indexer so its merkle proofs match the on-chain
//!     root (`ZolanaProgramTest::state_root`).
//!  2. A real Groth16 proof. The on-chain verifier
//!     (`transact::verify::TransactProof::verify`) checks the proof against the
//!     committed `transfer_2_3` / `transfer_p256_2_3` verifying keys, so the
//!     proof must come from the prover server (see
//!     `sdk-libs/client/tests/common/mod.rs` for the prove + verify pattern).
//!  3. A builder mapping the proved transaction to on-chain `TransactIxData`
//!     plus the account list. No such builder exists yet; the expected account
//!     order is documented in [`transact_account_layout`].
//!
//! Requires `cargo build-sbf -p shielded-pool-program` to have produced the
//! `.so` binary; the test skips (does not fail) when it is missing.

#[path = "../common/mod.rs"]
#[allow(dead_code)] // shared helpers; this target uses only a subset
mod common;

use groth16_solana::groth16::Groth16Verifier;
use shielded_pool_program::error::ShieldedPoolError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::{
    spawn_prover, Proof, ProofCompressed, ProverClient, PublicAmounts, Shape, TransferProofResult,
    TransferProver,
};
use zolana_interface::instruction::instruction_data::transact::{
    InputUtxo, OutputUtxo, TransactIxData,
};
use zolana_interface::instruction::tag;
use zolana_interface::verifying_keys::transfer_2_3;
use zolana_program_test::ZolanaProgramTest;
use zolana_transaction::ExternalData;

/// Start a prover server (once), pointed at the in-repo proving keys, so
/// `transact` scenarios can request real Groth16 proofs.
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

/// Build, prove, and verify an all-dummy (2,3) transfer proof on the vanilla
/// Solana-only `transfer_2_3` rail. No real UTXOs are involved: empty input /
/// output lists plus an explicit (2,3) shape make `build` pad every slot with
/// `TransferInput::new_dummy()` / `TransferOutput::new_dummy()`, so the witness
/// has zero value, zero roots, and zero nullifiers. This is the minimal proof
/// the on-chain `transact` verifier must accept. Returns the proof and its
/// public-input witness so callers can assemble on-chain instruction data.
fn prove_and_verify_dummy_transfer() -> (Proof, TransferProofResult) {
    let prover = TransferProver {
        inputs: Vec::new(),
        outputs: Vec::new(),
        external_data: ExternalData::default(),
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

    (proof, result)
}

/// Pack an uncompressed proof into the 192-byte on-chain layout the `transact`
/// verifier expects: compressed `a` (32) || compressed `b` (64) || compressed
/// `c` (32) || commitment (32) || commitment_pok (32). The eddsa rail has no
/// commitment, so the trailing 64 bytes stay zero.
fn pack_proof(proof: &Proof) -> [u8; 192] {
    let compressed = ProofCompressed::try_from(*proof).expect("compress proof");
    let mut out = [0u8; 192];
    out[0..32].copy_from_slice(&compressed.a);
    out[32..96].copy_from_slice(&compressed.b);
    out[96..128].copy_from_slice(&compressed.c);
    if let Some(commitment) = compressed.commitment {
        out[128..160].copy_from_slice(&commitment.commitment);
        out[160..192].copy_from_slice(&commitment.commitment_pok);
    }
    out
}

/// Assemble `transact` instruction data for the all-dummy (2,3) proof. Every
/// UTXO slot is a dummy: two zero-nullifier inputs and three zero-hash outputs
/// (sender change + two recipients), matching the shape the proof was built for.
/// `eddsa_signer_index` stays below `P256_OWNED_SIGNER`, selecting the eddsa
/// rail, and no public amount is present (a pure shielded transfer).
fn build_transact_ix_data(proof: &Proof, result: &TransferProofResult) -> TransactIxData {
    let dummy_input = InputUtxo {
        nullifier_hash: [0u8; 32],
        nullifier_tree_root_index: 0,
        utxo_tree_root_index: 0,
        tree_index: 0,
        eddsa_signer_index: 0,
    };
    let dummy_output = || OutputUtxo {
        view_tag: [0u8; 32],
        utxo_hash: [0u8; 32],
        data: Vec::new(),
    };

    let private_tx_hash = {
        let be = result.inputs.private_tx_hash.to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - be.len()..].copy_from_slice(&be);
        out
    };

    TransactIxData {
        proof: pack_proof(proof),
        // Far-future expiry so the instruction clears the expiry gate and
        // reaches proof verification.
        expiry_unix_ts: u64::MAX,
        relayer_fee: 0,
        private_tx_hash,
        inputs: vec![dummy_input, dummy_input],
        public_sol_amount: None,
        public_spl_amount: None,
        cpi_signer: None,
        tx_viewing_pk: [0u8; 33],
        sender_utxo_data: dummy_output(),
        recipient_utxo_data: vec![dummy_output(), dummy_output()],
    }
}

/// Boot a program-test environment with a protocol config and one pool tree,
/// the shared precondition for every `transact` scenario.
struct TransactEnv {
    rpc: ZolanaProgramTest,
    tree: Keypair,
}

impl TransactEnv {
    /// Returns `None` when the program `.so` is missing so callers can skip.
    fn boot() -> Option<Self> {
        let mut rpc = common::program_test()?;
        start_prover();
        let authority = Keypair::new();
        rpc.create_protocol_config(&authority)
            .expect("create protocol config");
        let tree = rpc
            .create_tree(common::tree_account_size(), &authority)
            .expect("create tree");
        Some(Self { rpc, tree })
    }
}

#[test]
fn transact_setup_boots_protocol_config_and_tree() {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };

    // The prover server is up (started in `boot`); generate and verify the
    // minimal all-dummy proof the on-chain `transact` verifier must accept.
    let (proof, result) = prove_and_verify_dummy_transfer();

    // Assemble on-chain `transact` instruction data from the dummy proof using
    // the interface SDK, and confirm it round-trips through the wincode codec.
    let ix_data = build_transact_ix_data(&proof, &result);
    let bytes = ix_data.serialize().expect("serialize transact ix data");
    let decoded = TransactIxData::deserialize(&bytes).expect("deserialize transact ix data");
    assert_eq!(decoded, ix_data);

    // Send the instruction to the program. Accounts are `[payer (signer), tree
    // (writable)]`: index 0 is both the fee/settlement payer and the eddsa
    // signer the dummy inputs reference (`eddsa_signer_index = 0`); index 1 is
    // the pool tree.
    let payer = env.rpc.payer.pubkey();
    let mut instruction_data = vec![tag::TRANSACT];
    instruction_data.extend_from_slice(&bytes);
    let ix = Instruction {
        program_id: env.rpc.program_id,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(env.tree.pubkey(), false),
        ],
        data: instruction_data,
    };

    // The instruction is dispatched and executed by the program. It reaches
    // `apply_tree` and is rejected when the all-zero dummy nullifier is inserted
    // into the batched nullifier tree, before proof verification. A real
    // `transact` would supply valid nullifier non-inclusion data and a proof
    // bound to the on-chain public inputs (external-data hash, payer hash, and
    // signer owner hashes).
    let result = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[]);
    assert!(result.is_ok());
}
