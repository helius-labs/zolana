use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use swap_program::{
    error::SwapError,
    instructions::{take::TakeProof, take_batch::TakeBatchIxData},
    tag,
};
use zolana_interface::{
    instruction::instruction_data::{
        aggregate_transact::AggregateTransactIxData, transact::TransactProof,
    },
    verifying_keys::{AggregateCircuitId, Bsb22Commitment, InnerCircuitKind},
    N_PUBLIC_SLOTS,
};
use zolana_test_utils::mollusk::expect_err_exact;

use crate::common::{account, setup_mollusk, transact};

#[test]
fn fewer_take_proofs_than_legs_is_rejected_exactly() {
    let (mollusk, program_id) = setup_mollusk();
    let payer = Pubkey::new_from_array([21; 32]);

    let body = wincode::serialize(&TakeBatchIxData {
        take_proofs: vec![TakeProof {
            proof_a: [10; 32],
            proof_b: [11; 64],
            proof_c: [12; 32],
        }],
        aggregate: AggregateTransactIxData {
            circuit: AggregateCircuitId {
                kind: InnerCircuitKind::ConfidentialEddsa,
                num_inputs: 2,
                num_outputs: 2,
                num_public_asset_slots: N_PUBLIC_SLOTS as u8,
                batch: 2,
            },
            proof: TransactProof::zeroed(),
            bsb22_commitment: Bsb22Commitment {
                commitment: [0; 32],
                commitment_pok: [0; 32],
            },
            legs: vec![transact(Vec::new()), transact(Vec::new())],
            leg_account_counts: vec![6, 6],
        },
    })
    .expect("serialize take batch");
    let mut data = vec![tag::TAKE_BATCH];
    data.extend_from_slice(&body);

    let instruction = Instruction {
        program_id,
        accounts: vec![AccountMeta::new(payer, true)],
        data,
    };
    expect_err_exact(
        &mollusk,
        &instruction,
        &[(payer, account(1_000_000_000))],
        ProgramError::Custom(SwapError::TakeProofCountMismatch as u32),
    );
}
