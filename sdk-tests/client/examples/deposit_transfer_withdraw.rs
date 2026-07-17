use anyhow::{anyhow, Result};
use client_example::{setup, SetupContext, DEPOSIT_AMOUNT, TRANSFER_AMOUNT, WITHDRAW_AMOUNT};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signer::Signer;
use zolana_client::{IndexerRpcConfig, Rpc, SolanaRpc, ZolanaClient};
use zolana_interface::instruction::{Deposit, Transact, TransactSolWithdrawal, TransactWithdrawal};
use zolana_keypair::random_blinding;
use zolana_transaction::{
    decrypt_transactions,
    instructions::{
        transact::{ConfidentialTransfer, WithdrawalTarget},
        types::SppProofInputUtxo,
    },
    AssetRegistry, SOL_MINT,
};

// 1. Alice deposits SOL into her confidential balance.
// 2. Alice transfers SOL to Bob's confidential balance.
// 3. Alice withdraws the remaining SOL back to her own Solana account.
fn main() -> Result<()> {
    let SetupContext {
        rpc_url,
        indexer_url,
        prover_url,
        tree,
        alice: alice_keypair,
        bob: bob_keypair,
    } = setup()?;

    let client = ZolanaClient::from_urls(SolanaRpc::new(rpc_url), &indexer_url, prover_url, tree);
    let assets = AssetRegistry::default();

    let alice_funding = alice_keypair.to_solana_keypair()?;
    let alice_address = alice_keypair.shielded_address()?;

    // 1. Alice deposits DEPOSIT_AMOUNT SOL to her confidential balance.
    let confidential_balances = {
        let deposit_ix = Deposit {
            tree,
            depositor: alice_funding.pubkey(),
            spl: None,
            view_tag: alice_address.signing_pubkey.confidential_view_tag()?,
            owner: alice_address.owner_hash()?,
            blinding: random_blinding(),
            public_amount: Some(DEPOSIT_AMOUNT),
            utxo_data: None,
            memo: None,
        }
        .instruction();
        client.create_and_send_transaction(
            &[deposit_ix],
            alice_funding.pubkey(),
            &[&alice_funding],
        )?;

        let alice_tag = alice_address.signing_pubkey.confidential_view_tag()?;
        let response = client.get_shielded_transactions_by_tags(
            vec![alice_tag],
            None,
            Some(50),
            Some(IndexerRpcConfig::wait()),
        )?;

        decrypt_transactions(&alice_keypair, &response.transactions, &assets)
            .map_err(|e| anyhow!("decrypt bob transactions: {e:?}"))?
    };

    // 2. Alice transfers TRANSFER_AMOUNT SOL to Bob's confidential balance.

    // 2.1. Fetch and deserialize (deposits are not encrypted).
    let utxo = confidential_balances
        .get_balance(SOL_MINT)
        .expect("failed to fetch deposited utxo")
        .utxos[0]
        .clone();

    // 2.2. Build the confidential transfer to Bob and sign it.
    let input = SppProofInputUtxo::new(utxo, &alice_keypair);
    let bob_address = bob_keypair.shielded_address()?;
    let mut transfer =
        ConfidentialTransfer::new(alice_address, vec![input], alice_funding.pubkey());
    transfer.send(&bob_address, SOL_MINT, TRANSFER_AMOUNT)?;
    let proof_inputs = transfer.sign(&alice_keypair, &assets)?;

    // 2.3. Prove the transaction and send the transact instruction.
    let data = client.prove_transact(proof_inputs, Some(IndexerRpcConfig::wait()))?;

    let transfer_ix = Transact {
        payer: alice_funding.pubkey(),
        tree,
        withdrawal: None,
        data,
    }
    .instruction();
    let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let signature = client.create_and_send_transaction(
        &[compute_budget, transfer_ix],
        alice_funding.pubkey(),
        &[&alice_funding],
    )?;
    client.confirm_private_transaction_sync(signature)?;

    // 2.4. Fetch and decrypt Bob's balance to confirm the transfer landed.
    let bob_tag = bob_address.signing_pubkey.confidential_view_tag()?;
    let response = client.get_shielded_transactions_by_tags(
        vec![bob_tag],
        None,
        None,
        Some(IndexerRpcConfig::wait()),
    )?;

    let balances = decrypt_transactions(&bob_keypair, &response.transactions, &assets)
        .map_err(|e| anyhow!("decrypt bob transactions: {e:?}"))?;
    let balance = balances
        .get_balance(SOL_MINT)
        .map(|b| b.amount)
        .unwrap_or(0);
    println!("transfer bob_balance={balance} tx={signature}");

    // 3. Alice withdraws WITHDRAW_AMOUNT SOL from her confidential balance back
    // to her own Solana account.

    // 3.1. Fetch and decrypt Alice's SOL change UTXO left over from the transfer.
    let alice_tag = alice_address.signing_pubkey.confidential_view_tag()?;
    let response = client.get_shielded_transactions_by_tags(
        vec![alice_tag],
        None,
        Some(50),
        Some(IndexerRpcConfig::wait()),
    )?;
    let alice_balances = decrypt_transactions(&alice_keypair, &response.transactions, &assets)
        .map_err(|e| anyhow!("decrypt alice transactions: {e:?}"))?;
    let change_utxo = alice_balances
        .get_balance(SOL_MINT)
        .and_then(|b| b.utxos.first())
        .expect("failed to fetch alice's change utxo")
        .clone();

    // 3.2. Build the withdrawal to Alice's own Solana account and sign it.
    let withdraw_input = SppProofInputUtxo::new(change_utxo, &alice_keypair);

    let mut withdrawal =
        ConfidentialTransfer::new(alice_address, vec![withdraw_input], alice_funding.pubkey());
    withdrawal.withdraw(
        SOL_MINT,
        WITHDRAW_AMOUNT,
        WithdrawalTarget::Sol {
            user_sol_account: alice_funding.pubkey(),
        },
    )?;
    let proof_inputs = withdrawal.sign(&alice_keypair, &assets)?;

    // 3.3. Prove the transaction and send the transact instruction, this time
    // with the withdrawal accounts attached.
    let data = client.prove_transact(proof_inputs, Some(IndexerRpcConfig::wait()))?;

    let withdraw_ix = Transact {
        payer: alice_funding.pubkey(),
        tree,
        withdrawal: Some(TransactWithdrawal::Sol(TransactSolWithdrawal {
            recipient: alice_funding.pubkey(),
        })),
        data,
    }
    .instruction();
    let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let signature = client.create_and_send_transaction(
        &[compute_budget, withdraw_ix],
        alice_funding.pubkey(),
        &[&alice_funding],
    )?;
    client.confirm_private_transaction_sync(signature)?;

    // 3.4. Confirm the withdrawn amount landed in Alice's Solana balance.
    let solana_balance = client.get_balance(alice_funding.pubkey())?;
    println!("withdraw solana_balance={solana_balance} tx={signature}");
    Ok(())
}
