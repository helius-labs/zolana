//! Batch guards for `aggregate_transact`, all of which fire before any pairing.
//!
//! The selector alone names the outer verifying key, so a batch that disagrees
//! with it must be rejected rather than verified against the wrong key.

use shielded_pool_tests::support::fixtures::Pool;
use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g2_compress_be};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::{
            aggregate_transact::{AggregateTransactIxData, EMPTY_LEG_COMMITMENT, EMPTY_LEG_PROOF},
            transact::{CircuitId, RingP256ProofData, TransactIxData, TransactProof},
        },
        AggregateTransact,
    },
    verifying_keys::{AggregateCircuitId, Bsb22Commitment, InnerCircuitKind},
    N_PUBLIC_SLOTS,
};
use zolana_program_test::Rejection;
use zolana_test_utils::transact::{eddsa_input_utxo, fe, inline_output};

const SLOTS: u8 = N_PUBLIC_SLOTS as u8;

fn ring_leg() -> TransactIxData {
    TransactIxData {
        proof: EMPTY_LEG_PROOF,
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit: CircuitId::RingEddsa(2, 3, SLOTS),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        inputs: (1..=2).map(|n| eddsa_input_utxo(fe(n), 0)).collect(),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: (11..14).map(|n| inline_output(fe(n), fe(n))).collect(),
        messages: Vec::new(),
    }
}

fn selector(batch: u8) -> AggregateCircuitId {
    AggregateCircuitId {
        kind: InnerCircuitKind::RingEddsa,
        num_inputs: 2,
        num_outputs: 3,
        num_public_asset_slots: SLOTS,
        batch,
    }
}

fn batch(circuit: AggregateCircuitId, legs: Vec<TransactIxData>) -> AggregateTransactIxData {
    AggregateTransactIxData {
        circuit,
        proof: TransactProof::zeroed(),
        bsb22_commitment: EMPTY_LEG_COMMITMENT,
        legs,
        leg_account_counts: Vec::new(),
    }
}

#[track_caller]
fn expect_rejection(env: &mut Pool, data: AggregateTransactIxData, expected: ShieldedPoolError) {
    let ring_program_ids = vec![
        Pubkey::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID);
        data.legs.len().max(1)
    ];
    let ix = AggregateTransact {
        payer: env.rpc.payer.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        ring_program_ids,
        owner_signers: vec![Vec::new(); data.legs.len().max(1)],
        interface_transfer_accounts: vec![Vec::new(); data.legs.len().max(1)],
        data,
    }
    .cpi_instruction();
    let payer = env.rpc.payer.pubkey();
    expect_ix_rejection(env, without_pda_signers(ix, payer), expected);
}

/// The batch guards fire before any account is read, so the run does not need
/// the ring PDA signature the settled path requires.
fn without_pda_signers(mut ix: Instruction, payer: Pubkey) -> Instruction {
    for meta in &mut ix.accounts {
        meta.is_signer = meta.pubkey == payer;
    }
    ix
}

#[track_caller]
fn expect_ix_rejection(env: &mut Pool, ix: Instruction, expected: ShieldedPoolError) {
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .expect_err("guarded aggregate must be rejected");
    Rejection::pool(expected).at(1).assert_litesvm(error);
}

#[test]
fn aggregate_rejects_a_batch_size_with_no_key() {
    let mut env = Pool::initialized();
    for size in [1u8, 4, 5] {
        let legs = vec![ring_leg(); size as usize];
        expect_rejection(
            &mut env,
            batch(selector(size), legs),
            ShieldedPoolError::InvalidAggregateBatch,
        );
    }
}

/// The declared batch and the leg count must agree, or the chain the outer
/// proof commits to is not the chain the program builds.
#[test]
fn aggregate_rejects_a_leg_count_that_disagrees_with_the_selector() {
    let mut env = Pool::initialized();
    expect_rejection(
        &mut env,
        batch(selector(3), vec![ring_leg(); 2]),
        ShieldedPoolError::InvalidAggregateBatch,
    );
}

/// A leg of another rail would be settled against a key that never proved it.
#[test]
fn aggregate_rejects_a_leg_from_another_rail() {
    let mut env = Pool::initialized();
    let mut legs = vec![ring_leg(); 2];
    legs[1].circuit = CircuitId::ConfidentialEddsa(2, 3, SLOTS);
    expect_rejection(
        &mut env,
        batch(selector(2), legs),
        ShieldedPoolError::MismatchedCircuitType,
    );
}

#[test]
fn aggregate_rejects_a_leg_of_another_shape() {
    let mut env = Pool::initialized();
    let mut legs = vec![ring_leg(); 2];
    legs[1].circuit = CircuitId::RingEddsa(1, 3, SLOTS);
    expect_rejection(
        &mut env,
        batch(selector(2), legs),
        ShieldedPoolError::MismatchedCircuitType,
    );
}

/// A leg's proof is not part of the statement, so any value there is
/// unconstrained instruction data.
#[test]
fn aggregate_rejects_a_leg_that_carries_a_proof() {
    let mut env = Pool::initialized();
    let mut legs = vec![ring_leg(); 2];
    legs[1].proof = TransactProof {
        a: [0xFF; 32],
        b: [0xFF; 64],
        c: [0xFF; 32],
    };
    expect_rejection(
        &mut env,
        batch(selector(2), legs),
        ShieldedPoolError::AggregateLegCarriesProof,
    );
}

/// The inner commitment lives in the outer witness, so a leg carrying one is
/// unconstrained as well.
#[test]
fn aggregate_rejects_a_leg_that_carries_a_commitment() {
    let mut env = Pool::initialized();
    let p256_selector = AggregateCircuitId {
        kind: InnerCircuitKind::RingP256,
        ..selector(2)
    };
    let mut legs = vec![ring_leg(); 2];
    for leg in &mut legs {
        leg.circuit = CircuitId::RingP256(
            2,
            3,
            SLOTS,
            RingP256ProofData {
                bsb22_commitment: EMPTY_LEG_COMMITMENT,
                default_owner_tag: None,
            },
        );
    }
    legs[1].circuit = CircuitId::RingP256(
        2,
        3,
        SLOTS,
        RingP256ProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: [0xFF; 32],
                commitment_pok: [0xFF; 32],
            },
            default_owner_tag: None,
        },
    );
    expect_rejection(
        &mut env,
        batch(p256_selector, legs),
        ShieldedPoolError::AggregateLegCarriesProof,
    );
}

/// The account list is split by a fixed per-leg run, so a short list must not
/// let one leg read another's accounts.
#[test]
fn aggregate_rejects_an_account_list_that_does_not_split() {
    let mut env = Pool::initialized();
    let data = batch(selector(2), vec![ring_leg(); 2]);
    let mut ix = AggregateTransact {
        payer: env.rpc.payer.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        ring_program_ids: vec![
            Pubkey::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID);
            2
        ],
        owner_signers: vec![Vec::new(); 2],
        interface_transfer_accounts: vec![Vec::new(); 2],
        data,
    }
    .cpi_instruction();
    ix.accounts.pop();
    let ix = without_pda_signers(ix, env.rpc.payer.pubkey());
    expect_ix_rejection(&mut env, ix, ShieldedPoolError::InvalidAggregateBatch);
}

/// A batch whose legs all settle, so the run reaches the outer pairing. The
/// legs carry no proof of their own, so nothing but the outer proof stands
/// between the batch and the state it just wrote.
fn settling_batch(
    env: &mut Pool,
    proof: TransactProof,
    commitment: Bsb22Commitment,
) -> Instruction {
    let legs: Vec<TransactIxData> = (0..2u64)
        .map(|leg| {
            let mut data = ring_leg();
            // Distinct nullifiers per leg, or the queue rejects the repeat.
            data.inputs = (1..=2)
                .map(|n| eddsa_input_utxo(fe(10 * (leg + 1) + n), 0))
                .collect();
            data.outputs = (1..=3)
                .map(|n| {
                    let value = fe(100 * (leg + 1) + n);
                    inline_output(value, value)
                })
                .collect();
            data
        })
        .collect();

    let mut data = batch(selector(2), legs);
    data.proof = proof;
    data.bsb22_commitment = commitment;
    AggregateTransact {
        payer: env.rpc.payer.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        ring_program_ids: vec![
            Pubkey::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID);
            2
        ],
        owner_signers: vec![Vec::new(); 2],
        interface_transfer_accounts: vec![Vec::new(); 2],
        data,
    }
    .instruction()
}

/// A well-formed G1/G2 point that no honest prover produced, taken from the
/// named batch's own outer key so it decompresses and only the pairing can
/// reject it.
fn wrong_proof(batch: u8) -> (TransactProof, Bsb22Commitment) {
    let vk = selector(batch)
        .verifying_key()
        .expect("outer verifying key");
    let a = alt_bn128_g1_compress_be(&vk.vk_alpha_g1).expect("compress alpha");
    let b = alt_bn128_g2_compress_be(&vk.vk_beta_g2).expect("compress beta");
    (
        TransactProof { a, b, c: a },
        Bsb22Commitment {
            commitment: a,
            commitment_pok: a,
        },
    )
}

/// The outer proof is the only thing binding the chained leg hashes, and its
/// failure has to be its own error rather than a shape complaint.
#[test]
fn aggregate_rejects_a_tampered_outer_proof() {
    let mut env = Pool::initialized();
    env.rpc
        .load_ring_test_program()
        .expect("load ring test program");
    let authority = env.authority.insecure_clone();
    env.rpc
        .create_ring_config(&authority, &authority.pubkey(), true)
        .expect("create ring config");

    let (proof, commitment) = wrong_proof(2);
    let ix = settling_batch(&mut env, proof, commitment);
    expect_ix_rejection(
        &mut env,
        ix,
        ShieldedPoolError::AggregateProofVerificationFailed,
    );
}

/// The selector alone names the outer key, so a two-leg batch is settled
/// against the two-leg key and a proof aimed at another batch size fails the
/// pairing rather than selecting the key it was made for.
#[test]
fn aggregate_rejects_a_proof_for_another_batch_size() {
    let mut env = Pool::initialized();
    env.rpc
        .load_ring_test_program()
        .expect("load ring test program");
    let authority = env.authority.insecure_clone();
    env.rpc
        .create_ring_config(&authority, &authority.pubkey(), true)
        .expect("create ring config");

    let (proof, commitment) = wrong_proof(3);
    let ix = settling_batch(&mut env, proof, commitment);
    expect_ix_rejection(
        &mut env,
        ix,
        ShieldedPoolError::AggregateProofVerificationFailed,
    );
}
