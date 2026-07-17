use anyhow::Result;
use client_example::{
    client, prover, select_inputs, setup, shield, sync_until, SHIELD_AMOUNT, TRANSFER_AMOUNT,
};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signer::Signer;
use zolana_client::{Rpc, SppProofInputUtxo};
use zolana_interface::instruction::Transact;
use zolana_transaction::{instructions::transact::ConfidentialTransfer, Filter, SOL_MINT};

fn main() -> Result<()> {
    let mut ctx = setup()?;
    shield(
        &ctx.rpc,
        &ctx.indexer,
        ctx.tree,
        &mut ctx.alice,
        SHIELD_AMOUNT,
    )?;
    let alice = ctx.alice.wallet;
    let alice_balance = alice.balance(SOL_MINT, None).unwrap();

    if alice_balance.amount < TRANSFER_AMOUNT {
        panic!("Insufficient sol balance");
    }
    let input_utxo = alice_balance.utxos[0];
    let spp_proof_input_utxos = SppProofInputUtxo::new(input_utxo, alice.identity.);
/*
    let mut transfer = ConfidentialTransfer::new(ctx.alice.address()?, inputs, funding.pubkey());
    transfer.send(&ctx.bob.address()?, SOL_MINT, TRANSFER_AMOUNT)?;
    let proof_inputs = transfer.sign(&ctx.alice.keypair, &ctx.alice.wallet.registry)?;

    let client = client(&ctx);
    let commitments = proof_inputs.input_utxo_hashes()?;
    let spend_proofs = client.get_input_merkle_proofs(&commitments)?;
    let data = prover(&ctx).prove_transact(proof_inputs, &spend_proofs)?;

    let transfer_ix = Transact {
        payer: funding.pubkey(),
        tree: ctx.tree,
        withdrawal: None,
        data,
    }
    .instruction();
    let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let signature = client.create_and_send_transaction(
        &[compute_budget, transfer_ix],
        funding.pubkey(),
        &[&funding],
    )?;
    client.confirm_private_transaction_sync(signature)?;

    sync_until(&ctx.indexer, &mut ctx.bob, |wallet| {
        Ok(wallet
            .balance(SOL_MINT, Some(Filter::MinAmount(TRANSFER_AMOUNT)))?
            .amount
            >= TRANSFER_AMOUNT)
    })?;

    let balance = ctx.bob.balance(SOL_MINT, None)?.amount;
    println!("transfer bob_balance={balance} tx={signature}");*/
    Ok(())
}
