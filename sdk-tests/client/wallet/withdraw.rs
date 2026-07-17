use anyhow::Result;
use client_example::{client, prover, select_inputs, setup, DEPOSIT_AMOUNT, WITHDRAW_AMOUNT};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_interface::instruction::{Transact, TransactSolWithdrawal, TransactWithdrawal};
use zolana_transaction::{
    instructions::transact::{ConfidentialTransfer, WithdrawalTarget},
    SOL_MINT,
};

fn main() -> Result<()> {
    let mut ctx = setup()?;
    let client = client(&ctx);
    ctx.alice.deposit(&client, DEPOSIT_AMOUNT)?;

    let recipient = Keypair::new();

    let inputs = select_inputs(
        &ctx.alice.wallet,
        &ctx.alice.keypair,
        SOL_MINT,
        WITHDRAW_AMOUNT,
    )?;
    let funding = ctx.alice.funding()?;

    let mut transfer = ConfidentialTransfer::new(ctx.alice.address()?, inputs, funding.pubkey());
    transfer.withdraw(
        SOL_MINT,
        WITHDRAW_AMOUNT,
        WithdrawalTarget::Sol {
            user_sol_account: recipient.pubkey(),
        },
    )?;
    let proof_inputs = transfer.sign(&ctx.alice.keypair, &ctx.alice.wallet.registry)?;

    let commitments = proof_inputs.input_utxo_hashes()?;
    let spend_proofs = client.get_input_merkle_proofs(&commitments, None)?;
    let data = prover(&ctx).prove_transact(proof_inputs, &spend_proofs)?;

    let before = client.get_balance(recipient.pubkey())?;

    let withdraw_ix = Transact {
        payer: funding.pubkey(),
        tree: ctx.tree,
        withdrawal: Some(TransactWithdrawal::Sol(TransactSolWithdrawal {
            recipient: recipient.pubkey(),
        })),
        data,
    }
    .instruction();
    let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let signature = client.create_and_send_transaction(
        &[compute_budget, withdraw_ix],
        funding.pubkey(),
        &[&funding],
    )?;
    client.confirm_private_transaction_sync(signature)?;

    let after = client.get_balance(recipient.pubkey())?;
    println!(
        "withdraw recipient={} credited={} tx={signature}",
        recipient.pubkey(),
        after - before
    );
    Ok(())
}
