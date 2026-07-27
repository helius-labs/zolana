//! Zone-transfer step definitions: build a zone-owned state transition over a
//! chosen shape, prove it on the `zone_transact` circuit, and verify against the
//! committed verifying key. The ed25519 rail (`ZoneTransferProver`) is vanilla
//! Groth16; the P256 rail is removed (its SDK types remain as unimplemented
//! placeholders). Every real input is zone-owned (`zone_program_id = ZONE`), as
//! the strict zone binding requires.

use std::sync::Once;

use cucumber::{given, then};
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use solana_address::Address;
use zolana_client::{
    spawn_prover, InputUtxoContext, ProverClient, PublicMovements, Rpc, Shape, TransferSpendInput,
    ZoneTransferProver,
};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{OwnerTag, TransactOutput},
        tag::ZONE_TRANSACT,
    },
    verifying_keys::{
        transfer_zone_1_1, transfer_zone_1_2, transfer_zone_1_8, transfer_zone_2_2,
        transfer_zone_2_3, transfer_zone_3_3, transfer_zone_4_3, transfer_zone_4_4,
        transfer_zone_5_3, transfer_zone_5_4,
    },
};
use zolana_keypair::{random_blinding, NullifierKey, PublicKey, ShieldedKeypair, ViewingKey};
use zolana_transaction::{
    instructions::types::SppProofInputUtxo, Data, ExternalData, SppProofOutputUtxo, Utxo, SOL_MINT,
};

use crate::{
    test_indexer::TestIndexer,
    world::{Mode, Plan, ZoneTransferWorld},
};

// ---- given steps --------------------------------------------------------------

#[given(expr = "a {int}x{int} eddsa zone transfer")]
fn given_eddsa_shape(world: &mut ZoneTransferWorld, n_in: usize, n_out: usize) {
    world.plan = Plan {
        n_inputs: n_in,
        n_outputs: n_out,
        mode: Mode::Eddsa,
    };
}

#[given("a 3x3 eddsa zone transfer consolidating 2 real inputs")]
fn given_eddsa_multi_real(world: &mut ZoneTransferWorld) {
    world.plan = Plan {
        n_inputs: 3,
        n_outputs: 3,
        mode: Mode::EddsaMultiReal,
    };
}

#[then("the zone-transfer proof verifies")]
fn then_verifies(world: &mut ZoneTransferWorld) {
    start_prover();
    let (n_in, n_out, mode) = (world.plan.n_inputs, world.plan.n_outputs, world.plan.mode);
    match mode {
        Mode::Eddsa => prove_and_verify_eddsa(eddsa_prover(n_in, n_out), n_in, n_out),
        Mode::EddsaMultiReal => prove_and_verify_eddsa(eddsa_multi_real(), n_in, n_out),
    }
}

// ---- scenario builders --------------------------------------------------------

/// One real zero-value Solana-owned zone input + dummy padding, dummy outputs. The
/// real input balances at zero so the witness selects the eddsa (Solana-only) rail.
fn eddsa_prover(n_in: usize, n_out: usize) -> ZoneTransferProver {
    let mut indexer = TestIndexer::new();
    let signer = eddsa_keypair();
    let mut inputs = build_real_inputs(&mut indexer, &[(signer.clone(), 0)]);
    for _ in 1..n_in {
        inputs.push(dummy_input());
    }
    let outputs = (0..n_out).map(|_| dummy_output(&signer)).collect();
    ZoneTransferProver {
        inputs,
        outputs,
        external_data: zone_external_data(n_out),
        public_movements: zero_public_movements(),
        payer_pubkey_hash: [0u8; 32],
        allow_dummy_inputs: true,
        zone_program_id: Some(zone_program()),
        shape: Some(Shape::new(n_in, n_out)),
    }
}

/// Shape 3x3: two real nonzero Solana-owned zone inputs (100 + 150) consolidated
/// into one real zone-owned recipient output (250) plus dummy padding. Exercises
/// multiple real inputs, a real recipient, and value conservation on the eddsa rail.
fn eddsa_multi_real() -> ZoneTransferProver {
    let mut indexer = TestIndexer::new();
    let first_signer = eddsa_keypair();
    let second_signer = eddsa_keypair();
    let mut inputs = build_real_inputs(
        &mut indexer,
        &[(first_signer.clone(), 100), (second_signer, 150)],
    );
    inputs.push(dummy_input());
    let recipient = eddsa_keypair();
    let outputs = vec![
        real_output(&recipient, 250),
        dummy_output(&first_signer),
        dummy_output(&first_signer),
    ];
    ZoneTransferProver {
        inputs,
        outputs,
        external_data: zone_external_data(3),
        public_movements: zero_public_movements(),
        payer_pubkey_hash: [0u8; 32],
        allow_dummy_inputs: true,
        zone_program_id: Some(zone_program()),
        shape: Some(Shape::new(3, 3)),
    }
}

// ---- shared helpers -----------------------------------------------------------

fn prove_and_verify_eddsa(prover: ZoneTransferProver, n_in: usize, n_out: usize) {
    let result = prover.build().expect("build zone-transfer witness");
    let proof = ProverClient::local()
        .prove_transfer_zone(&result.inputs)
        .expect("prove zone-transfer");
    let public_inputs: [[u8; 32]; 1] = [result.public_input_hash];
    let mut verifier = Groth16Verifier::new(
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs,
        eddsa_zone_vk(n_in, n_out),
    )
    .expect("construct verifier");
    verifier
        .verify()
        .expect("zone-transfer eddsa groth16 proof verifies");
}

/// Build the real (proof-backed) inputs for `specs` (owner keypair + amount),
/// indexing every UTXO into one shared tree so all inclusion / non-inclusion proofs
/// share a single root. Each real input is zone-owned (`zone_program_id = ZONE`).
fn build_real_inputs(
    indexer: &mut TestIndexer,
    specs: &[(ShieldedKeypair, u64)],
) -> Vec<TransferSpendInput> {
    let zone = zone_program();
    let mut utxos = Vec::with_capacity(specs.len());
    let mut keys = Vec::with_capacity(specs.len());
    let mut commitments = Vec::with_capacity(specs.len());
    for (index, (kp, amount)) in specs.iter().enumerate() {
        let utxo = Utxo {
            owner: kp.signing_pubkey(),
            asset: SOL_MINT,
            amount: *amount,
            blinding: random_blinding(),
            zone_program_id: Some(zone),
            data: Data::default(),
        };
        let nullifier_pk = kp.nullifier_key.pubkey().expect("nullifier pubkey");
        let utxo_hash = utxo
            .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
            .expect("utxo hash");
        let nullifier = utxo
            .nullifier(&utxo_hash, &kp.nullifier_key)
            .expect("nullifier");
        indexer.add_utxo(utxo_hash);
        commitments.push(InputUtxoContext {
            index,
            utxo_hash,
            nullifier,
        });
        utxos.push(utxo);
        keys.push(kp.nullifier_key.clone());
    }
    let proofs = indexer
        .get_input_merkle_proofs(&commitments, None)
        .expect("merkle proofs");
    utxos
        .into_iter()
        .zip(keys)
        .zip(proofs)
        .map(|((utxo, nullifier_key), proof)| TransferSpendInput {
            utxo,
            nullifier_key,
            data_hash: None,
            zone_data_hash: None,
            proof: Some(proof),
            nullifier_proof: None,
        })
        .collect()
}

/// A real zone-owned recipient output: the recipient owns it via its
/// `owner_hash`, which the confidential zone circuit binds to the public owner
/// tag, and the shared zone program.
fn real_output(recipient: &ShieldedKeypair, amount: u64) -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        owner_address: Some(recipient.shielded_address().expect("shielded address")),
        asset: SOL_MINT,
        amount,
        blinding: random_blinding(),
        zone_program_id: Some(zone_program()),
        zone_data_hash: None,
        data_hash: None,
        owner_tag: None,
        data: Data::default(),
    }
}

/// A padding output: zero owner hash and a public tag naming an input signer.
fn dummy_output(signer: &ShieldedKeypair) -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        blinding: random_blinding(),
        owner_tag: Some(
            signer
                .signing_pubkey()
                .confidential_view_tag()
                .expect("dummy owner tag"),
        ),
        ..Default::default()
    }
}

/// A padding input: zero owner, random blinding, no state proof. The prover
/// mirrors the first real input's state root onto it; the non-inclusion witness
/// for its own nullifier comes from a fresh tree (the circuit checks
/// non-inclusion per slot against the slot's own root).
fn dummy_input() -> TransferSpendInput {
    let blinding = random_blinding();
    let utxo = Utxo {
        owner: PublicKey::zeroed(),
        asset: SOL_MINT,
        amount: 0,
        blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let mut spend = SppProofInputUtxo::new_dummy();
    spend.utxo.blinding = blinding;
    let nullifier = spend.nullifier().expect("dummy nullifier");
    let nullifier_proof = TestIndexer::new().dummy_nullifier_proof(nullifier);
    TransferSpendInput {
        utxo,
        nullifier_key: NullifierKey::from_secret([0u8; 31]),
        data_hash: None,
        zone_data_hash: None,
        proof: None,
        nullifier_proof: Some(nullifier_proof),
    }
}

/// Transaction-level data with the zone-transact discriminator. `external_data_hash`
/// is opaque to the circuit, so the output vectors are zero-filled (the witness and
/// public input use the same value, which is all the proof binds).
fn zone_external_data(n_out: usize) -> ExternalData {
    ExternalData {
        instruction_discriminator: ZONE_TRANSACT,
        expiry_unix_ts: 0,
        interface_transfers: Vec::new(),
        data_hash: None,
        zone_data_hash: None,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        outputs: (0..n_out)
            .map(|_| TransactOutput {
                utxo_hash: [0u8; 32],
                owner_tag: OwnerTag::Inline([0u8; 32]),
                data: None,
            })
            .collect(),
        resolved_owner_tags: vec![[0u8; 32]; n_out],
        messages: Vec::new(),
    }
}

fn zero_public_movements() -> PublicMovements {
    PublicMovements::default()
}

/// Fixed test zone program id; every input/output UTXO carries it and the prover
/// binds it as the public `zone_program_id`.
fn zone_program() -> Address {
    Address::new_from_array([9u8; 32])
}

fn eddsa_keypair() -> ShieldedKeypair {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&random_blinding());
    ShieldedKeypair::from_ed25519(&seed, ViewingKey::new()).expect("eddsa keypair")
}

fn eddsa_zone_vk(n_in: usize, n_out: usize) -> &'static Groth16Verifyingkey<'static> {
    match (n_in, n_out) {
        (1, 1) => &transfer_zone_1_1::VERIFYINGKEY,
        (1, 2) => &transfer_zone_1_2::VERIFYINGKEY,
        (2, 2) => &transfer_zone_2_2::VERIFYINGKEY,
        (2, 3) => &transfer_zone_2_3::VERIFYINGKEY,
        (3, 3) => &transfer_zone_3_3::VERIFYINGKEY,
        (4, 3) => &transfer_zone_4_3::VERIFYINGKEY,
        (4, 4) => &transfer_zone_4_4::VERIFYINGKEY,
        (5, 3) => &transfer_zone_5_3::VERIFYINGKEY,
        (5, 4) => &transfer_zone_5_4::VERIFYINGKEY,
        (1, 8) => &transfer_zone_1_8::VERIFYINGKEY,
        _ => panic!("unsupported zone-transfer shape {n_in}x{n_out}"),
    }
}

fn start_prover() {
    static INIT: Once = Once::new();
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
