//! Ring-transfer proof construction and verification cases.

use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use solana_address::Address;
use zolana_client::{
    InputUtxoContext, ProverClient, PublicTransfers, RingTransferProver, Rpc, Shape,
    TransferSpendInput,
};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{OwnerTag, TransactOutput},
        tag::RING_TRANSACT,
    },
    verifying_keys::{
        transfer_ring_1_1, transfer_ring_1_2, transfer_ring_1_8, transfer_ring_2_2,
        transfer_ring_2_3, transfer_ring_36_2, transfer_ring_3_3, transfer_ring_4_3,
        transfer_ring_4_4, transfer_ring_5_3, transfer_ring_5_4,
    },
};
use zolana_keypair::{random_blinding, NullifierKey, PublicKey, ShieldedKeypair, SigningKey};
use zolana_transaction::{
    instructions::types::SppProofInputUtxo, Data, ExternalData, SppProofOutputUtxo, TransactTrees,
    Utxo, SOL_MINT,
};

use crate::{
    harness::{Mode, RingTransferHarness},
    prover_bootstrap::start_prover,
    test_indexer::TestIndexer,
};

impl RingTransferHarness {
    pub(crate) fn prove_and_verify(&self) {
        start_prover();
        let (n_in, n_out, mode) = (self.plan.n_inputs, self.plan.n_outputs, self.plan.mode);
        match mode {
            Mode::Eddsa => prove_and_verify_eddsa(eddsa_prover(n_in, n_out), n_in, n_out),
            Mode::EddsaMultiReal => prove_and_verify_eddsa(eddsa_multi_real(), n_in, n_out),
            // NOTE(pr164): PR164 removed the P256 rail (`RingTransferP256Prover`,
            // `transfer_p256_ring_*` VKs are gone); the P256 modes were dropped here.
        }
    }
}

// ---- scenario builders --------------------------------------------------------

/// One real zero-value Solana-owned ring input + dummy padding, dummy outputs. The
/// real input balances at zero so the witness selects the eddsa (Solana-only) rail.
fn eddsa_prover(n_in: usize, n_out: usize) -> RingTransferProver {
    let mut indexer = TestIndexer::new();
    let signer = eddsa_keypair();
    let mut inputs = build_real_inputs(&mut indexer, &[(signer.clone(), 0)]);
    for _ in 1..n_in {
        inputs.push(dummy_input());
    }
    let outputs = (0..n_out).map(|_| dummy_output(&signer)).collect();
    // The authorized signer vector must contain every real input's owner
    // pk-field (payer-first on-chain; any placement satisfies Contains).
    let mut signer_pk_hashes = vec![owner_pk_hash(&signer)];
    signer_pk_hashes.resize(n_in + 1, [0u8; 32]);
    RingTransferProver {
        inputs,
        outputs,
        external_data: ring_external_data(n_out),
        public_transfers: PublicTransfers::default(),
        signer_pk_hashes,
        allow_dummy_inputs: true,
        ring_program_id: Some(ring_program()),
        shape: Some(Shape::new(n_in, n_out)),
    }
}

/// Shape 3x3: two real nonzero Solana-owned ring inputs (100 + 150) consolidated
/// into one real ring-owned recipient output (250) plus dummy padding. Exercises
/// multiple real inputs, a real recipient, and value conservation on the eddsa rail.
fn eddsa_multi_real() -> RingTransferProver {
    let mut indexer = TestIndexer::new();
    let first_signer = eddsa_keypair();
    let second_signer = eddsa_keypair();
    let mut inputs = build_real_inputs(
        &mut indexer,
        &[(first_signer.clone(), 100), (second_signer.clone(), 150)],
    );
    inputs.push(dummy_input());
    let recipient = eddsa_keypair();
    let outputs = vec![
        real_output(&recipient, 250),
        dummy_output(&first_signer),
        dummy_output(&first_signer),
    ];
    RingTransferProver {
        inputs,
        outputs,
        external_data: ring_external_data(3),
        public_transfers: PublicTransfers::default(),
        signer_pk_hashes: vec![
            owner_pk_hash(&first_signer),
            owner_pk_hash(&second_signer),
            [0u8; 32],
            [0u8; 32],
        ],
        allow_dummy_inputs: true,
        ring_program_id: Some(ring_program()),
        shape: Some(Shape::new(3, 3)),
    }
}

// ---- shared helpers -----------------------------------------------------------

/// The owner pk-field the circuit checks each content-bearing input against
/// (`hash_bytes` of the signing pubkey's confidential view tag).
fn owner_pk_hash(keypair: &ShieldedKeypair) -> [u8; 32] {
    keypair
        .signing_pubkey()
        .owner_proof_input_hash()
        .expect("owner pk hash")
}

fn prove_and_verify_eddsa(prover: RingTransferProver, n_in: usize, n_out: usize) {
    let result = prover.build().expect("build ring-transfer witness");
    let proof = ProverClient::local()
        .prove_transfer_ring(&result.inputs)
        .expect("prove ring-transfer");
    let public_inputs: [[u8; 32]; 1] = [result.public_input_hash];
    let mut verifier = Groth16Verifier::new(
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs,
        eddsa_ring_vk(n_in, n_out),
    )
    .expect("construct verifier");
    verifier
        .verify()
        .expect("ring-transfer eddsa groth16 proof verifies");
}

/// Build the real (proof-backed) inputs for `specs` (owner keypair + amount),
/// indexing every UTXO into one shared tree so all inclusion / non-inclusion proofs
/// share a single root. Each real input is ring-owned (`ring_program_id = RING`).
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

/// A real ring-owned recipient output: the recipient owns it via its
/// `owner_hash`, which the confidential ring circuit binds to the public owner
/// tag, and the shared ring program.
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

/// Transaction-level data with the ring-transact discriminator. `external_data_hash`
/// is opaque to the circuit, so the output vectors are zero-filled (the witness and
/// public input use the same value, which is all the proof binds).
fn ring_external_data(n_out: usize) -> ExternalData {
    ExternalData {
        instruction_discriminator: RING_TRANSACT,
        trees: Some(TransactTrees {
            input_tree: Address::new_from_array([11u8; 32]),
            output_tree: Address::new_from_array([12u8; 32]),
        }),
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
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&seed)).expect("eddsa keypair")
}

fn eddsa_ring_vk(n_in: usize, n_out: usize) -> &'static Groth16Verifyingkey<'static> {
    match (n_in, n_out) {
        (1, 1) => &transfer_ring_1_1::VERIFYINGKEY,
        (1, 2) => &transfer_ring_1_2::VERIFYINGKEY,
        (2, 2) => &transfer_ring_2_2::VERIFYINGKEY,
        (2, 3) => &transfer_ring_2_3::VERIFYINGKEY,
        (3, 3) => &transfer_ring_3_3::VERIFYINGKEY,
        (4, 3) => &transfer_ring_4_3::VERIFYINGKEY,
        (4, 4) => &transfer_ring_4_4::VERIFYINGKEY,
        (5, 3) => &transfer_ring_5_3::VERIFYINGKEY,
        (5, 4) => &transfer_ring_5_4::VERIFYINGKEY,
        (1, 8) => &transfer_ring_1_8::VERIFYINGKEY,
        (36, 2) => &transfer_ring_36_2::VERIFYINGKEY,
        _ => panic!("unsupported ring-transfer shape {n_in}x{n_out}"),
    }
}
