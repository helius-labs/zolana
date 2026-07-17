//! Zone-transfer step definitions: build a zone-owned state transition over a
//! chosen shape, prove it on the `zone_transact` circuit, and verify against the
//! committed verifying key. The ed25519 rail (`ZoneTransferProver`) is vanilla
//! Groth16; the P256 rail (`ZoneTransferP256Prover`) carries a BSB22 commitment and
//! is verified with `new_with_commitment`. Both bind a shared `zone_program_id` and
//! every real input is zone-owned (`zone_program_id = ZONE`), as the strict zone
//! binding requires.

use std::sync::Once;

use cucumber::{given, then};
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use solana_address::Address;
use zolana_client::{
    spawn_prover, InputUtxoContext, P256Owner, ProverClient, PublicAmounts, Rpc, Shape,
    TransferSpendInput, ZoneTransferP256Prover, ZoneTransferProver,
};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{OwnerTag, TransactOutput},
        tag::ZONE_TRANSACT,
    },
    verifying_keys::{
        transfer_p256_zone_1_1, transfer_p256_zone_1_2, transfer_p256_zone_1_8,
        transfer_p256_zone_2_2, transfer_p256_zone_2_3, transfer_p256_zone_3_3,
        transfer_p256_zone_4_3, transfer_p256_zone_4_4, transfer_p256_zone_5_3,
        transfer_p256_zone_5_4, transfer_zone_1_1, transfer_zone_1_2, transfer_zone_1_8,
        transfer_zone_2_2, transfer_zone_2_3, transfer_zone_3_3, transfer_zone_4_3,
        transfer_zone_4_4, transfer_zone_5_3, transfer_zone_5_4,
    },
};
use zolana_keypair::{
    hash::sha256, random_blinding, NullifierKey, PublicKey, ShieldedKeypair, ViewingKey,
};
use zolana_transaction::{Data, ExternalData, SppProofOutputUtxo, Utxo, SOL_MINT};

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

#[given(expr = "a {int}x{int} P256 zone transfer")]
fn given_p256_shape(world: &mut ZoneTransferWorld, n_in: usize, n_out: usize) {
    world.plan = Plan {
        n_inputs: n_in,
        n_outputs: n_out,
        mode: Mode::P256,
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

#[given("a 3x3 P256 zone transfer consolidating 2 real inputs")]
fn given_p256_multi_real(world: &mut ZoneTransferWorld) {
    world.plan = Plan {
        n_inputs: 3,
        n_outputs: 3,
        mode: Mode::P256MultiReal,
    };
}

#[then("the zone-transfer proof verifies")]
fn then_verifies(world: &mut ZoneTransferWorld) {
    start_prover();
    let (n_in, n_out, mode) = (world.plan.n_inputs, world.plan.n_outputs, world.plan.mode);
    match mode {
        Mode::Eddsa => prove_and_verify_eddsa(eddsa_prover(n_in, n_out), n_in, n_out),
        Mode::P256 => prove_and_verify_p256(p256_prover(n_in, n_out), n_in, n_out),
        Mode::EddsaMultiReal => prove_and_verify_eddsa(eddsa_multi_real(), n_in, n_out),
        Mode::P256MultiReal => prove_and_verify_p256(p256_multi_real(), n_in, n_out),
    }
}

// ---- scenario builders --------------------------------------------------------

/// One real zero-value Solana-owned zone input + dummy padding, dummy outputs. The
/// real input balances at zero so the witness selects the eddsa (Solana-only) rail.
fn eddsa_prover(n_in: usize, n_out: usize) -> ZoneTransferProver {
    let mut indexer = TestIndexer::new();
    let mut inputs = build_real_inputs(&mut indexer, &[(eddsa_keypair(), 0)]);
    for _ in 1..n_in {
        inputs.push(dummy_input());
    }
    let outputs = (0..n_out).map(|_| dummy_output()).collect();
    ZoneTransferProver {
        inputs,
        outputs,
        external_data: zone_external_data(n_out),
        public_amounts: zero_public_amounts(),
        payer_pubkey_hash: [0u8; 32],
        zone_program_id: Some(zone_program()),
        shape: Some(Shape::new(n_in, n_out)),
    }
}

/// Shape 3x3: two real nonzero Solana-owned zone inputs (100 + 150) consolidated
/// into one real zone-owned recipient output (250) plus dummy padding. Exercises
/// multiple real inputs, a real recipient, and value conservation on the eddsa rail.
fn eddsa_multi_real() -> ZoneTransferProver {
    let mut indexer = TestIndexer::new();
    let mut inputs = build_real_inputs(
        &mut indexer,
        &[(eddsa_keypair(), 100), (eddsa_keypair(), 150)],
    );
    inputs.push(dummy_input());
    let recipient = eddsa_keypair();
    let outputs = vec![real_output(&recipient, 250), dummy_output(), dummy_output()];
    ZoneTransferProver {
        inputs,
        outputs,
        external_data: zone_external_data(3),
        public_amounts: zero_public_amounts(),
        payer_pubkey_hash: [0u8; 32],
        zone_program_id: Some(zone_program()),
        shape: Some(Shape::new(3, 3)),
    }
}

/// Shape 3x3 P256 analog of [`eddsa_multi_real`]: two real inputs sharing one P256
/// owner (the shared signature) consolidated into one real recipient output. The
/// real inputs and output are built once and reused across the two signing passes
/// (only they feed `private_tx_hash`).
fn p256_multi_real() -> ZoneTransferP256Prover {
    let owner = p256_keypair();
    let mut indexer = TestIndexer::new();
    let reals = build_real_inputs(&mut indexer, &[(owner.clone(), 100), (owner.clone(), 150)]);
    let recipient = p256_keypair();
    let output = real_output(&recipient, 250);

    let make = |p256_owner: P256Owner| -> ZoneTransferP256Prover {
        let mut inputs: Vec<TransferSpendInput> = reals.to_vec();
        inputs.push(dummy_input());
        let outputs = vec![output.clone(), dummy_output(), dummy_output()];
        ZoneTransferP256Prover {
            inputs,
            outputs,
            external_data: zone_external_data(3),
            public_amounts: zero_public_amounts(),
            payer_pubkey_hash: [0u8; 32],
            p256_owner,
            zone_program_id: Some(zone_program()),
            shape: Some(Shape::new(3, 3)),
        }
    };

    let private_tx_hash = make(placeholder_p256_owner(&owner))
        .build()
        .expect("build p256 multi-real zone transfer (probe)")
        .private_tx_hash;

    let signature = owner.sign(&sha256(&private_tx_hash));
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&signature[..32]);
    sig_s.copy_from_slice(&signature[32..]);
    let signed_owner = P256Owner {
        pubkey: owner.signing_pubkey().as_p256().expect("p256 pubkey"),
        sig_r,
        sig_s,
    };

    make(signed_owner)
}

/// One real zero-value P256-owned zone input + dummy padding, dummy outputs. The
/// shared P256 owner signs `sha256(private_tx_hash)`, so the proof carries the
/// BSB22 commitment over the in-circuit P256 witness.
fn p256_prover(n_in: usize, n_out: usize) -> ZoneTransferP256Prover {
    let owner = p256_keypair();

    // Build the single real input ONCE and reuse it across both signing passes:
    // only the real input and external_data feed `private_tx_hash` (dummies and tree
    // roots do not), so a stable real input keeps the signed hash and the final
    // witness consistent. (Re-deriving inputs per pass would use fresh random
    // blindings and change `private_tx_hash`, invalidating the signature.)
    let mut indexer = TestIndexer::new();
    let real = build_real_inputs(&mut indexer, &[(owner.clone(), 0)])
        .pop()
        .expect("one real input");

    let make = |p256_owner: P256Owner| -> ZoneTransferP256Prover {
        let mut inputs = vec![real.clone()];
        for _ in 1..n_in {
            inputs.push(dummy_input());
        }
        let outputs = (0..n_out).map(|_| dummy_output()).collect();
        ZoneTransferP256Prover {
            inputs,
            outputs,
            external_data: zone_external_data(n_out),
            public_amounts: zero_public_amounts(),
            payer_pubkey_hash: [0u8; 32],
            p256_owner,
            zone_program_id: Some(zone_program()),
            shape: Some(Shape::new(n_in, n_out)),
        }
    };

    // The P256 signature is over `sha256(private_tx_hash)` and is independent of the
    // signature itself: probe with a placeholder owner to recover the hash, sign it,
    // then build the final prover with the real signature over the same inputs.
    let private_tx_hash = make(placeholder_p256_owner(&owner))
        .build()
        .expect("build p256 zone transfer (probe)")
        .private_tx_hash;

    let signature = owner.sign(&sha256(&private_tx_hash));
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&signature[..32]);
    sig_s.copy_from_slice(&signature[32..]);
    let signed_owner = P256Owner {
        pubkey: owner.signing_pubkey().as_p256().expect("p256 pubkey"),
        sig_r,
        sig_s,
    };

    make(signed_owner)
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

fn prove_and_verify_p256(prover: ZoneTransferP256Prover, n_in: usize, n_out: usize) {
    let result = prover.build().expect("build p256 zone-transfer witness");
    let proof = ProverClient::local()
        .prove_transfer_p256_zone(&result.inputs)
        .expect("prove p256 zone-transfer");
    let commitment = proof
        .commitment
        .expect("p256 zone-transfer proof must carry a BSB22 commitment");
    let public_inputs: [[u8; 32]; 1] = [result.public_input_hash];
    let mut verifier = Groth16Verifier::new_with_commitment(
        &proof.a,
        &proof.b,
        &proof.c,
        &commitment.commitment,
        &commitment.commitment_pok,
        &public_inputs,
        p256_zone_vk(n_in, n_out),
    )
    .expect("construct verifier");
    verifier
        .verify()
        .expect("zone-transfer p256 groth16 proof verifies");
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

/// A real zone-owned recipient output: the recipient owns it via its `owner_hash`
/// (the zone circuit leaves the output owner unconstrained / anonymous), bound to
/// the shared zone program.
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

/// Transaction-level data with the zone-transact discriminator. `external_data_hash`
/// is opaque to the circuit, so the output vectors are zero-filled (the witness and
/// public input use the same value, which is all the proof binds).
fn zone_external_data(n_out: usize) -> ExternalData {
    ExternalData {
        instruction_discriminator: ZONE_TRANSACT,
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

fn zero_public_amounts() -> PublicAmounts {
    PublicAmounts {
        sol: [0u8; 32],
        spl: [0u8; 32],
        asset: [0u8; 32],
    }
}

/// A placeholder owner used only to recover `private_tx_hash` (independent of the
/// signature) before the real signature is computed and the prover is rebuilt.
fn placeholder_p256_owner(owner: &ShieldedKeypair) -> P256Owner {
    P256Owner {
        pubkey: owner.signing_pubkey().as_p256().expect("p256 pubkey"),
        sig_r: [0u8; 32],
        sig_s: [0u8; 32],
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

fn p256_zone_vk(n_in: usize, n_out: usize) -> &'static Groth16Verifyingkey<'static> {
    match (n_in, n_out) {
        (1, 1) => &transfer_p256_zone_1_1::VERIFYINGKEY,
        (1, 2) => &transfer_p256_zone_1_2::VERIFYINGKEY,
        (2, 2) => &transfer_p256_zone_2_2::VERIFYINGKEY,
        (2, 3) => &transfer_p256_zone_2_3::VERIFYINGKEY,
        (3, 3) => &transfer_p256_zone_3_3::VERIFYINGKEY,
        (4, 3) => &transfer_p256_zone_4_3::VERIFYINGKEY,
        (4, 4) => &transfer_p256_zone_4_4::VERIFYINGKEY,
        (5, 3) => &transfer_p256_zone_5_3::VERIFYINGKEY,
        (5, 4) => &transfer_p256_zone_5_4::VERIFYINGKEY,
        (1, 8) => &transfer_p256_zone_1_8::VERIFYINGKEY,
        _ => panic!("unsupported p256 zone-transfer shape {n_in}x{n_out}"),
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
