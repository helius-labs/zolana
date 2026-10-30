//! The standalone fixture's verifier program, built by `zolana build-zk-program`
//! from a crate on the zk DSL alone, verifies a proof of its circuit on-chain
//! through the generated verifier module.

use litesvm::LiteSVM;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use spr_client::{compile_message, sign_transaction, ComputeBudgetConfig};
use spr_program::{to_bytes, proof::compressed_proof};
use spr_zk_standalone_fixture::{
    instruction::withdrawal_data, verifier::withdrawal, WithdrawalInputs,
};

/// A pairing check with four public inputs needs more than the 200,000 units
/// a single instruction gets by default.
const COMPUTE_UNITS: u32 = 400_000;

fn program_so() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/deploy/spr_zk_standalone_fixture.so");
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{}: {error}; build it with `just build-zk-standalone`",
            path.display()
        )
    })
}

fn send(svm: &mut LiteSVM, payer: &Keypair, program: &Keypair, data: Vec<u8>) -> bool {
    let instruction = Instruction {
        program_id: program.pubkey(),
        accounts: vec![],
        data,
    };
    let message = compile_message(
        &payer.pubkey(),
        &[instruction],
        svm.latest_blockhash(),
        ComputeBudgetConfig::new(COMPUTE_UNITS),
    )
    .expect("compile the v1 message");
    let transaction = sign_transaction(message, &[payer]).expect("sign the v1 transaction");
    let sent = svm.send_transaction(transaction);
    svm.expire_blockhash();
    sent.is_ok()
}

#[test]
fn the_verifier_program_accepts_only_the_proven_payout() {
    let mut svm = LiteSVM::new();
    let program = Keypair::new();
    svm.add_program(program.pubkey(), &program_so())
        .expect("load the verifier program");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund the payer");

    let inputs = WithdrawalInputs::example();
    let artifacts = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/zk/spr-zk-standalone-fixture");
    let result = xark::prover::circuit_at(artifacts).prove(inputs).expect("standalone Xark proof");
    let proof = compressed_proof(&result.proof).expect("compressed proof");
    let inputs = WithdrawalInputs::example();
    let public_inputs = withdrawal::PublicInputs {
        commitment: to_bytes(&inputs.public.commitment),
        amount: inputs.public.amount,
        destination: inputs.public.destination(),
    };
    let other_amount = withdrawal::PublicInputs {
        amount: public_inputs.amount + 1,
        ..public_inputs
    };

    assert_eq!(
        (
            send(
                &mut svm,
                &payer,
                &program,
                withdrawal_data(&proof, &public_inputs).to_vec()
            ),
            send(
                &mut svm,
                &payer,
                &program,
                withdrawal_data(&proof, &other_amount).to_vec()
            ),
            send(&mut svm, &payer, &program, vec![0u8; 3]),
        ),
        (true, false, false)
    );
}
