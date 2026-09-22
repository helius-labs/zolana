//! Ring-authority proof construction and verification cases.

use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use solana_address::Address;
use zolana_client::{
    ProverClient, PublicTransfers, RingAuthorityProver, RingAuthorityWitness, Rpc, Shape,
    TransferInputUtxo,
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
use zolana_keypair::{random_blinding, NullifierKey, ShieldedKeypair, SigningKey};
use zolana_transaction::{
    instructions::{ring_authority::RingAuthorityProofInputs, transact::shape::Shape as TxShape},
    utxo::SppProofInputUtxo,
    Data, ExternalData, Mint, SppProofOutputUtxo, Utxo,
};

use crate::{
    authority_fixture::complete_inputs, input_fixture::wallet_utxo,
    output_blindings::assign_output_blindings,
};

use crate::{
    harness::{Mode, RingAuthorityHarness},
    prover_bootstrap::start_prover,
    test_indexer::TestIndexer,
};

/// Test fixtures live in the first localnet tree.
// TODO(tree-id): resolve the tree id from the tree account.
const TEST_TREE_ID: u16 = 0;

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
fn shape_sweep(n: usize) -> (RingAuthorityProver, Vec<NullifierKey>) {
    let mut indexer = TestIndexer::new();
    let (mut inputs, keys) = build_real_inputs(&mut indexer, &[(eddsa_keypair(), 0)]);
    for _ in 1..n {
        inputs.push(dummy_input());
    }
    let outputs = (0..n).map(|_| dummy_output()).collect();
    (assemble_prover(inputs, outputs, n, n), keys)
}

/// #2: 2 real nonzero Solana-owned ring inputs consolidated into 1 real ring-owned
/// output, with dummy input/output padding (shape 3x3).
fn multi_real() -> (RingAuthorityProver, Vec<NullifierKey>) {
    let mut indexer = TestIndexer::new();
    let (mut inputs, keys) = build_real_inputs(
        &mut indexer,
        &[(eddsa_keypair(), 100), (eddsa_keypair(), 150)],
    );
    inputs.push(dummy_input());
    let recipient = eddsa_keypair();
    let outputs = vec![real_output(&recipient, 250), dummy_output(), dummy_output()];
    (assemble_prover(inputs, outputs, 3, 3), keys)
}

/// #3: one real P256-owned ring input + dummy output (shape 1x1). Exercises the
/// pubkey-agnostic owner mode (no signature).
fn p256_input() -> (RingAuthorityProver, Vec<NullifierKey>) {
    let mut indexer = TestIndexer::new();
    let (inputs, keys) = build_real_inputs(&mut indexer, &[(p256_keypair(), 0)]);
    (assemble_prover(inputs, vec![dummy_output()], 1, 1), keys)
}

/// #4: one Solana-owned and one P256-owned real input, dummy outputs (shape 2x2).
fn mixed_owners() -> (RingAuthorityProver, Vec<NullifierKey>) {
    let mut indexer = TestIndexer::new();
    let (inputs, keys) =
        build_real_inputs(&mut indexer, &[(eddsa_keypair(), 0), (p256_keypair(), 0)]);
    (
        assemble_prover(inputs, vec![dummy_output(), dummy_output()], 2, 2),
        keys,
    )
}

/// #5: build through the transaction-crate boundary: `PreparedRingAuthority` ->
/// `RingAuthorityWitness` -> `RingAuthorityProver` (shape 2x2).
fn boundary_prover() -> (RingAuthorityProver, Vec<NullifierKey>) {
    let mut indexer = TestIndexer::new();
    let owner = eddsa_keypair();
    let (mut inputs, keys) = build_real_inputs(&mut indexer, &[(owner, 0)]);
    inputs.push(dummy_input());
    let mut outputs = vec![dummy_output(), dummy_output()];
    let blinding_seed = [46; 32];
    assign_output_blindings(&inputs[0].utxo.nullifier, &mut outputs, &blinding_seed);
    let proofs = inputs
        .iter()
        .filter_map(|input| input.proof.clone())
        .collect();
    let dummy_nullifier_proofs = inputs
        .iter()
        .filter_map(|input| input.nullifier_proof.clone())
        .collect();
    let prepared = RingAuthorityProofInputs {
        input_utxos: inputs.into_iter().map(|input| input.utxo).collect(),
        output_utxos: outputs,
        blinding_seed,
        output_tree_id: TEST_TREE_ID,
        public_transfers: PublicTransfers::default(),
        external_data: ring_external_data(2),
        payer: Address::default(),
        ring_program_id: Some(ring_program()),
        shape: TxShape::IN2_OUT2,
    };
    (
        RingAuthorityProver::try_from(RingAuthorityWitness {
            prepared,
            proofs,
            dummy_nullifier_proofs,
        })
        .unwrap(),
        keys,
    )
}

// ---- shared helpers -----------------------------------------------------------

fn prove_and_verify(
    (prover, keys): (RingAuthorityProver, Vec<NullifierKey>),
    n_in: usize,
    n_out: usize,
) {
    let mut result = prover.build().expect("build ring-authority witness");
    complete_inputs(&mut result.inputs.inputs, &keys);
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
    inputs: Vec<TransferInputUtxo>,
    mut outputs: Vec<SppProofOutputUtxo>,
    n_in: usize,
    n_out: usize,
) -> RingAuthorityProver {
    let blinding_seed = [46u8; 32];
    assign_output_blindings(&inputs[0].utxo.nullifier, &mut outputs, &blinding_seed);
    RingAuthorityProver {
        blinding_seed,
        output_tree_id: TEST_TREE_ID,
        inputs,
        outputs,
        external_data: ring_external_data(n_out),
        public_transfers: PublicTransfers::default(),
        payer: Address::new_from_array([0u8; 32]),
        allow_dummy_inputs: true,
        ring_program_id: Some(ring_program()),
        shape: Shape::new(n_in, n_out),
    }
}

/// Build the real (proof-backed) inputs for `specs` (owner keypair + amount),
/// indexing every UTXO into one shared tree so all inclusion / non-inclusion proofs
/// share a single root. Each real input is ring-owned (`ring_program_id = RING`),
/// as the strict ring binding requires.
fn build_real_inputs(
    indexer: &mut TestIndexer,
    specs: &[(ShieldedKeypair, u64)],
) -> (Vec<TransferInputUtxo>, Vec<NullifierKey>) {
    let mut utxos: Vec<SppProofInputUtxo> = Vec::new();
    let keys = specs
        .iter()
        .map(|(owner, _)| owner.nullifier_key.clone())
        .collect();
    for (owner, amount) in specs {
        let mut wallet = wallet_utxo(
            Utxo {
                owner: owner.signing_pubkey(),
                asset: Mint::SOL,
                amount: *amount,
                blinding: random_blinding(),
                ring_program_id: Some(ring_program()),
                data: Data::default(),
            },
            &owner.nullifier_key,
            TEST_TREE_ID,
            0,
            None,
            None,
        );
        wallet.leaf_index = indexer.add_utxo(wallet.utxo_hash);
        utxos.push(wallet.into());
    }
    let proofs = indexer
        .get_input_merkle_proofs(&utxos.iter().collect::<Vec<_>>(), None)
        .unwrap();
    let inputs = utxos
        .into_iter()
        .zip(proofs)
        .map(|(utxo, proof)| TransferInputUtxo {
            utxo,
            proof: Some(proof),
            nullifier_proof: None,
        })
        .collect();
    (inputs, keys)
}

/// A ring-owned real output to a recipient (used in the consolidation scenario).
fn real_output(recipient: &ShieldedKeypair, amount: u64) -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        owner_address: Some(recipient.shielded_address().expect("shielded address")),
        asset: Mint::SOL,
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

/// A padding input: zero owner, random blinding, no state proof. It sits in
/// tree slot 0 with the real inputs; the non-inclusion witness for its own
/// nullifier comes from an equally empty nullifier tree, so it shares the one
/// published nullifier root.
fn dummy_input() -> TransferInputUtxo {
    let utxo = SppProofInputUtxo::dummy(TEST_TREE_ID).unwrap();
    let nullifier_proof = Some(TestIndexer::new().dummy_nullifier_proof(utxo.nullifier));
    TransferInputUtxo {
        utxo,
        proof: None,
        nullifier_proof,
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
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&seed)).expect("eddsa keypair")
}

fn p256_keypair() -> ShieldedKeypair {
    ShieldedKeypair::new_p256().expect("p256 keypair")
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
