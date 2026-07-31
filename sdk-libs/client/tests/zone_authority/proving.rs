//! Ring-authority proof construction and verification cases.

use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use solana_address::Address;
use zolana_client::{
    InputUtxoContext, PreparedRingAuthority, ProverClient, PublicTransfers, Rpc, Shape,
    SppProofInputUtxo, TransferSpendInput, RingAuthorityProver, RingAuthorityWitness,
};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{OwnerTag, TransactOutput},
        tag::RING_AUTHORITY_TRANSACT,
    },
    verifying_keys::{
        transfer_ring_authority_1_1, transfer_ring_authority_2_2, transfer_ring_authority_3_3,
        transfer_ring_authority_4_4,
    },
};
use zolana_keypair::{random_blinding, NullifierKey, PublicKey, ShieldedKeypair, ViewingKey};
use zolana_transaction::{
    instructions::transact::shape::Shape as TxShape, Data, ExternalData, SppProofOutputUtxo, Utxo,
    SOL_MINT,
};

use crate::{
    harness::{Mode, RingAuthorityHarness},
    prover_bootstrap::start_prover,
    test_indexer::TestIndexer,
};

impl RingAuthorityHarness {
    pub(crate) fn prove_and_verify(&self) {
        start_prover();
        let (n_in, n_out, mode) = (self.plan.n_inputs, self.plan.n_outputs, self.plan.mode);
        match mode {
            Mode::ShapeSweep => prove_and_verify(shape_sweep(n_in), n_in, n_out),
            Mode::MultiReal => prove_and_verify(multi_real(), 3, 3),
            Mode::P256Input => prove_and_verify(p256_input(), 1, 1),
            Mode::MixedOwners => prove_and_verify(mixed_owners(), 2, 2),
            Mode::Boundary => prove_and_verify(boundary_prover(), 2, 2),
        }
    }
}

// ---- scenario builders --------------------------------------------------------

/// #1: one real zero-value Solana-owned ring input + dummy padding, dummy outputs.
fn shape_sweep(n: usize) -> RingAuthorityProver {
    let mut indexer = TestIndexer::new();
    let mut inputs = build_real_inputs(&mut indexer, &[(eddsa_keypair(), 0)]);
    for _ in 1..n {
        inputs.push(dummy_input());
    }
    let outputs = (0..n).map(|_| dummy_output()).collect();
    assemble_prover(inputs, outputs, n, n)
}

/// #2: 2 real nonzero Solana-owned ring inputs consolidated into 1 real ring-owned
/// output, with dummy input/output padding (shape 3x3).
fn multi_real() -> RingAuthorityProver {
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

/// #3: one real P256-owned ring input + dummy output (shape 1x1). Exercises the
/// pubkey-agnostic owner mode (no signature).
fn p256_input() -> RingAuthorityProver {
    let mut indexer = TestIndexer::new();
    let inputs = build_real_inputs(&mut indexer, &[(p256_keypair(), 0)]);
    assemble_prover(inputs, vec![dummy_output()], 1, 1)
}

/// #4: one Solana-owned and one P256-owned real input, dummy outputs (shape 2x2).
fn mixed_owners() -> RingAuthorityProver {
    let mut indexer = TestIndexer::new();
    let inputs = build_real_inputs(&mut indexer, &[(eddsa_keypair(), 0), (p256_keypair(), 0)]);
    assemble_prover(inputs, vec![dummy_output(), dummy_output()], 2, 2)
}

/// #5: build through the transaction-crate boundary: `PreparedRingAuthority` ->
/// `RingAuthorityWitness` -> `RingAuthorityProver` (shape 2x2).
fn boundary_prover() -> RingAuthorityProver {
    let ring = ring_program();
    let mut indexer = TestIndexer::new();
    let kp = eddsa_keypair();
    let utxo = Utxo {
        owner: kp.signing_pubkey(),
        asset: SOL_MINT,
        amount: 0,
        blinding: random_blinding(),
        ring_program_id: Some(ring),
        data: Data::default(),
    };
    let nullifier_pk = kp.nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo_hash = utxo
        .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
        .expect("utxo hash");
    indexer.add_utxo(utxo_hash);

    let prepared = PreparedRingAuthority {
        inputs: vec![
            SppProofInputUtxo::new(utxo, &kp),
            SppProofInputUtxo::new_dummy(),
        ],
        outputs: vec![dummy_output(), dummy_output()],
        public_transfers: PublicTransfers::default(),
        external_data: ring_external_data(2),
        payer: Address::new_from_array([0u8; 32]),
        ring_program_id: Some(ring),
        shape: TxShape::IN2_OUT2,
    };
    let commitments = prepared.input_utxo_hashes().expect("input commitments");
    let proofs = indexer
        .get_input_merkle_proofs(&commitments, None)
        .expect("merkle proofs");
    let dummy_nullifier_proofs = prepared
        .inputs
        .iter()
        .filter(|input| input.is_dummy())
        .map(|input| {
            let nullifier = input.nullifier().expect("dummy nullifier");
            TestIndexer::new().dummy_nullifier_proof(nullifier)
        })
        .collect();
    RingAuthorityProver::try_from(RingAuthorityWitness {
        prepared,
        proofs,
        dummy_nullifier_proofs,
    })
    .expect("ring-authority prover")
}

// ---- shared helpers -----------------------------------------------------------

fn prove_and_verify(prover: RingAuthorityProver, n_in: usize, n_out: usize) {
    let result = prover.build().expect("build ring-authority witness");
    let proof = ProverClient::local()
        .prove_ring_authority(&result.inputs)
        .expect("prove ring-authority");
    let public_inputs: [[u8; 32]; 1] = [result.public_input_hash];
    let mut verifier = Groth16Verifier::new(
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs,
        ring_authority_vk(n_in, n_out),
    )
    .expect("construct verifier");
    verifier
        .verify()
        .expect("ring-authority groth16 proof verifies");
}

fn assemble_prover(
    inputs: Vec<TransferSpendInput>,
    outputs: Vec<SppProofOutputUtxo>,
    n_in: usize,
    n_out: usize,
) -> RingAuthorityProver {
    RingAuthorityProver {
        inputs,
        outputs,
        external_data: ring_external_data(n_out),
        public_transfers: PublicTransfers::default(),
        payer: Address::new_from_array([0u8; 32]),
        allow_dummy_inputs: true,
        ring_program_id: Some(ring_program()),
        shape: Some(Shape::new(n_in, n_out)),
    }
}

/// Build the real (proof-backed) inputs for `specs` (owner keypair + amount),
/// indexing every UTXO into one shared tree so all inclusion / non-inclusion proofs
/// share a single root. Each real input is ring-owned (`ring_program_id = RING`),
/// as the strict ring binding requires.
fn build_real_inputs(
    indexer: &mut TestIndexer,
    specs: &[(ShieldedKeypair, u64)],
) -> Vec<TransferSpendInput> {
    let ring = ring_program();
    let mut utxos = Vec::with_capacity(specs.len());
    let mut keys = Vec::with_capacity(specs.len());
    let mut commitments = Vec::with_capacity(specs.len());
    for (index, (kp, amount)) in specs.iter().enumerate() {
        let utxo = Utxo {
            owner: kp.signing_pubkey(),
            asset: SOL_MINT,
            amount: *amount,
            blinding: random_blinding(),
            ring_program_id: Some(ring),
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
            ring_data_hash: None,
            proof: Some(proof),
            nullifier_proof: None,
        })
        .collect()
}

/// A ring-owned real output to a recipient (used in the consolidation scenario).
fn real_output(recipient: &ShieldedKeypair, amount: u64) -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        owner_address: Some(recipient.shielded_address().expect("shielded address")),
        asset: SOL_MINT,
        amount,
        blinding: random_blinding(),
        ring_program_id: Some(ring_program()),
        ring_data_hash: None,
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
        ring_program_id: None,
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
        ring_data_hash: None,
        proof: None,
        nullifier_proof: Some(nullifier_proof),
    }
}

/// Transaction-level data with the ring-authority discriminator. `external_data_hash`
/// is opaque to the circuit, so the output vectors are zero-filled (the witness and
/// public input use the same value, which is all the proof binds).
fn ring_external_data(n_out: usize) -> ExternalData {
    ExternalData {
        instruction_discriminator: RING_AUTHORITY_TRANSACT,
        expiry_unix_ts: 0,
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
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

/// Fixed test ring program id; every input/output UTXO carries it and the prover
/// binds it as the public `ring_program_id`.
fn ring_program() -> Address {
    Address::new_from_array([9u8; 32])
}

fn eddsa_keypair() -> ShieldedKeypair {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&random_blinding());
    ShieldedKeypair::from_ed25519(&seed, ViewingKey::new()).expect("eddsa keypair")
}

fn p256_keypair() -> ShieldedKeypair {
    ShieldedKeypair::new().expect("p256 keypair")
}

fn ring_authority_vk(n_in: usize, n_out: usize) -> &'static Groth16Verifyingkey<'static> {
    match (n_in, n_out) {
        (1, 1) => &transfer_ring_authority_1_1::VERIFYINGKEY,
        (2, 2) => &transfer_ring_authority_2_2::VERIFYINGKEY,
        (3, 3) => &transfer_ring_authority_3_3::VERIFYINGKEY,
        (4, 4) => &transfer_ring_authority_4_4::VERIFYINGKEY,
        _ => panic!("unsupported ring-authority shape {n_in}x{n_out}"),
    }
}
