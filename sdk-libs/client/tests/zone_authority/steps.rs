//! Zone-authority step definitions: build a zone-owned state transition (owners do
//! not sign), prove it on the `transfer-zone-authority` circuit, and verify against
//! the committed `transfer_zone_authority_<shape>` verifying key (vanilla Groth16).

use std::sync::Once;

use cucumber::{given, then};
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use solana_address::Address;
use zolana_client::{
    spawn_prover, InputUtxoContext, PreparedZoneAuthority, ProverClient, PublicAmounts, Rpc, Shape,
    SppProofInputUtxo, TransferSpendInput, ZoneAuthorityProver, ZoneAuthorityWitness,
};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{OwnerTag, TransactOutput},
        tag::ZONE_AUTHORITY_TRANSACT,
    },
    verifying_keys::{
        transfer_zone_authority_1_1, transfer_zone_authority_2_2, transfer_zone_authority_3_3,
        transfer_zone_authority_4_4,
    },
};
use zolana_keypair::{random_blinding, NullifierKey, PublicKey, ShieldedKeypair, ViewingKey};
use zolana_transaction::{
    instructions::transact::{shape::Shape as TxShape, PublicAmounts as TxPublicAmounts},
    Data, ExternalData, SppProofOutputUtxo, Utxo, SOL_MINT,
};

use crate::{
    test_indexer::TestIndexer,
    world::{Mode, Plan, ZoneAuthorityWorld},
};

// ---- given steps --------------------------------------------------------------

#[given(expr = "a {int}x{int} zone-authority transfer")]
fn given_shape(world: &mut ZoneAuthorityWorld, n_in: usize, n_out: usize) {
    world.plan = Plan {
        n_inputs: n_in,
        n_outputs: n_out,
        mode: Mode::ShapeSweep,
    };
}

#[given("a zone-authority consolidation of 2 real inputs at shape 3x3")]
fn given_multi(world: &mut ZoneAuthorityWorld) {
    world.plan = Plan {
        n_inputs: 3,
        n_outputs: 3,
        mode: Mode::MultiReal,
    };
}

#[given("a 1x1 zone-authority transfer with a P256-owned input")]
fn given_p256(world: &mut ZoneAuthorityWorld) {
    world.plan = Plan {
        n_inputs: 1,
        n_outputs: 1,
        mode: Mode::P256Input,
    };
}

#[given("a 2x2 zone-authority transfer with mixed owners")]
fn given_mixed(world: &mut ZoneAuthorityWorld) {
    world.plan = Plan {
        n_inputs: 2,
        n_outputs: 2,
        mode: Mode::MixedOwners,
    };
}

#[given("a 2x2 zone-authority transfer built via the prepared boundary")]
fn given_boundary(world: &mut ZoneAuthorityWorld) {
    world.plan = Plan {
        n_inputs: 2,
        n_outputs: 2,
        mode: Mode::Boundary,
    };
}

#[then("the zone-authority proof verifies")]
fn then_verifies(world: &mut ZoneAuthorityWorld) {
    start_prover();
    let (n_in, n_out, mode) = (world.plan.n_inputs, world.plan.n_outputs, world.plan.mode);
    match mode {
        Mode::ShapeSweep => prove_and_verify(shape_sweep(n_in), n_in, n_out),
        Mode::MultiReal => prove_and_verify(multi_real(), 3, 3),
        Mode::P256Input => prove_and_verify(p256_input(), 1, 1),
        Mode::MixedOwners => prove_and_verify(mixed_owners(), 2, 2),
        Mode::Boundary => prove_and_verify(boundary_prover(), 2, 2),
    }
}

// ---- scenario builders --------------------------------------------------------

/// #1: one real zero-value Solana-owned zone input + dummy padding, dummy outputs.
fn shape_sweep(n: usize) -> ZoneAuthorityProver {
    let mut indexer = TestIndexer::new();
    let mut inputs = build_real_inputs(&mut indexer, &[(eddsa_keypair(), 0)]);
    for _ in 1..n {
        inputs.push(dummy_input());
    }
    let outputs = (0..n).map(|_| dummy_output()).collect();
    assemble_prover(inputs, outputs, n, n)
}

/// #2: 2 real nonzero Solana-owned zone inputs consolidated into 1 real zone-owned
/// output, with dummy input/output padding (shape 3x3).
fn multi_real() -> ZoneAuthorityProver {
    let mut indexer = TestIndexer::new();
    let mut inputs = build_real_inputs(
        &mut indexer,
        &[(eddsa_keypair(), 100), (eddsa_keypair(), 150)],
    );
    inputs.push(dummy_input());
    let recipient = eddsa_keypair();
    let outputs = vec![real_output(&recipient, 250), dummy_output(), dummy_output()];
    assemble_prover(inputs, outputs, 3, 3)
}

/// #3: one real P256-owned zone input + dummy output (shape 1x1). Exercises the
/// pubkey-agnostic owner mode (no signature).
fn p256_input() -> ZoneAuthorityProver {
    let mut indexer = TestIndexer::new();
    let inputs = build_real_inputs(&mut indexer, &[(p256_keypair(), 0)]);
    assemble_prover(inputs, vec![dummy_output()], 1, 1)
}

/// #4: one Solana-owned and one P256-owned real input, dummy outputs (shape 2x2).
fn mixed_owners() -> ZoneAuthorityProver {
    let mut indexer = TestIndexer::new();
    let inputs = build_real_inputs(&mut indexer, &[(eddsa_keypair(), 0), (p256_keypair(), 0)]);
    assemble_prover(inputs, vec![dummy_output(), dummy_output()], 2, 2)
}

/// #5: build through the transaction-crate boundary: `PreparedZoneAuthority` ->
/// `ZoneAuthorityWitness` -> `ZoneAuthorityProver` (shape 2x2).
fn boundary_prover() -> ZoneAuthorityProver {
    let zone = zone_program();
    let mut indexer = TestIndexer::new();
    let kp = eddsa_keypair();
    let utxo = Utxo {
        owner: kp.signing_pubkey(),
        asset: SOL_MINT,
        amount: 0,
        blinding: random_blinding(),
        zone_program_id: Some(zone),
        data: Data::default(),
    };
    let nullifier_pk = kp.nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo_hash = utxo
        .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
        .expect("utxo hash");
    indexer.add_utxo(utxo_hash);

    let prepared = PreparedZoneAuthority {
        inputs: vec![
            SppProofInputUtxo::new(utxo, &kp),
            SppProofInputUtxo::new_dummy(),
        ],
        outputs: vec![dummy_output(), dummy_output()],
        public_amounts: TxPublicAmounts {
            sol: [0u8; 32],
            spl: [0u8; 32],
            asset: [0u8; 32],
        },
        external_data: zone_external_data(2),
        payer_pubkey_hash: [0u8; 32],
        zone_program_id: Some(zone),
        shape: TxShape::IN2_OUT2,
    };
    let commitments = prepared.input_utxo_hashes().expect("input commitments");
    let proofs = indexer
        .get_input_merkle_proofs(Address::default(), &commitments, None)
        .expect("merkle proofs");
    ZoneAuthorityProver::try_from(ZoneAuthorityWitness { prepared, proofs })
        .expect("zone-authority prover")
}

// ---- shared helpers -----------------------------------------------------------

fn prove_and_verify(prover: ZoneAuthorityProver, n_in: usize, n_out: usize) {
    let result = prover.build().expect("build zone-authority witness");
    let proof = ProverClient::local()
        .prove_zone_authority(&result.inputs)
        .expect("prove zone-authority");
    let public_inputs: [[u8; 32]; 1] = [result.public_input_hash];
    let mut verifier = Groth16Verifier::new(
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs,
        zone_authority_vk(n_in, n_out),
    )
    .expect("construct verifier");
    verifier
        .verify()
        .expect("zone-authority groth16 proof verifies");
}

fn assemble_prover(
    inputs: Vec<TransferSpendInput>,
    outputs: Vec<SppProofOutputUtxo>,
    n_in: usize,
    n_out: usize,
) -> ZoneAuthorityProver {
    ZoneAuthorityProver {
        inputs,
        outputs,
        external_data: zone_external_data(n_out),
        public_amounts: PublicAmounts {
            sol: [0u8; 32],
            spl: [0u8; 32],
            asset: [0u8; 32],
        },
        payer_pubkey_hash: [0u8; 32],
        zone_program_id: Some(zone_program()),
        shape: Some(Shape::new(n_in, n_out)),
    }
}

/// Build the real (proof-backed) inputs for `specs` (owner keypair + amount),
/// indexing every UTXO into one shared tree so all inclusion / non-inclusion proofs
/// share a single root. Each real input is zone-owned (`zone_program_id = ZONE`),
/// as the strict zone binding requires.
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
        .get_input_merkle_proofs(Address::default(), &commitments, None)
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
        })
        .collect()
}

/// A zone-owned real output to a recipient (used in the consolidation scenario).
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

/// A padding output: zero owner hash, random blinding (the circuit leaves it free).
fn dummy_output() -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        blinding: random_blinding(),
        ..Default::default()
    }
}

/// A padding input: zero owner, random blinding, no proof. The prover mirrors the
/// first real input's roots onto it; the circuit skips its checks.
fn dummy_input() -> TransferSpendInput {
    let utxo = Utxo {
        owner: PublicKey::zeroed(),
        asset: SOL_MINT,
        amount: 0,
        blinding: random_blinding(),
        zone_program_id: None,
        data: Data::default(),
    };
    TransferSpendInput {
        utxo,
        nullifier_key: NullifierKey::from_secret([0u8; 31]),
        data_hash: None,
        zone_data_hash: None,
        proof: None,
    }
}

/// Transaction-level data with the zone-authority discriminator. `external_data_hash`
/// is opaque to the circuit, so the output vectors are zero-filled (the witness and
/// public input use the same value, which is all the proof binds).
fn zone_external_data(n_out: usize) -> ExternalData {
    ExternalData {
        instruction_discriminator: ZONE_AUTHORITY_TRANSACT,
        expiry_unix_ts: 0,
        relayer_fee: 0,
        public_sol_amount: None,
        public_spl_amount: None,
        user_sol_account: Address::default(),
        user_spl_token: Address::default(),
        spl_token_interface: Address::default(),
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

/// Fixed test zone program id; every input/output UTXO carries it and the prover
/// binds it as the public `zone_program_id`.
fn zone_program() -> Address {
    Address::new_from_array([9u8; 32])
}

fn eddsa_keypair() -> ShieldedKeypair {
    let mut seed = [0u8; 32];
    seed[1..].copy_from_slice(&random_blinding());
    ShieldedKeypair::from_ed25519(&seed, ViewingKey::new()).expect("eddsa keypair")
}

fn p256_keypair() -> ShieldedKeypair {
    ShieldedKeypair::new().expect("p256 keypair")
}

fn zone_authority_vk(n_in: usize, n_out: usize) -> &'static Groth16Verifyingkey<'static> {
    match (n_in, n_out) {
        (1, 1) => &transfer_zone_authority_1_1::VERIFYINGKEY,
        (2, 2) => &transfer_zone_authority_2_2::VERIFYINGKEY,
        (3, 3) => &transfer_zone_authority_3_3::VERIFYINGKEY,
        (4, 4) => &transfer_zone_authority_4_4::VERIFYINGKEY,
        _ => panic!("unsupported zone-authority shape {n_in}x{n_out}"),
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
