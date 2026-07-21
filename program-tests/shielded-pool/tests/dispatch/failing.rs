use solana_instruction::{error::InstructionError, Instruction};
use solana_signer::Signer;
use zolana_interface::{error::ShieldedPoolError, instruction::tag};
use zolana_test_utils::litesvm_asserts::{assert_instruction_error, assert_pool_error};

use crate::{
    common::program_test,
    support::{sol_deposit_accounts, Pool},
};

#[test]
fn dispatch_rejects_empty_instruction_data() {
    let mut rpc = program_test();
    let err = rpc
        .create_and_send_default_payer_transaction(
            &[Instruction {
                program_id: rpc.program_id,
                accounts: vec![],
                data: Vec::new(),
            }],
            &[],
        )
        .expect_err("invalid dispatch data must fail");
    assert_instruction_error(err, InstructionError::InvalidInstructionData);
}

#[test]
fn dispatch_rejects_unknown_instruction_tag() {
    let mut rpc = program_test();
    let err = rpc
        .create_and_send_default_payer_transaction(
            &[Instruction {
                program_id: rpc.program_id,
                accounts: vec![],
                data: vec![u8::MAX],
            }],
            &[],
        )
        .expect_err("invalid dispatch data must fail");
    assert_instruction_error(err, InstructionError::InvalidInstructionData);
}

#[test]
fn dispatch_rejects_truncated_deposit_data() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(1_000_000_000);
    let accounts = sol_deposit_accounts(&pool.rpc, pool.tree.pubkey(), depositor.pubkey());
    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(
            &[Instruction {
                program_id: pool.rpc.program_id,
                accounts,
                data: vec![tag::DEPOSIT, 1, 2, 3],
            }],
            &[&depositor],
        )
        .expect_err("truncated deposit must fail");
    assert_pool_error(err, ShieldedPoolError::InvalidInstructionData);
}
