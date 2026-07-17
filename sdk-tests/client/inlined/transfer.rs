use anyhow::{anyhow, Result};
use client_example::{setup, SetupContext, TestWallet, DEPOSIT_AMOUNT, TRANSFER_AMOUNT};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signer::Signer;
use zolana_client::{IndexerRpcConfig, Rpc, SolanaRpc, ZolanaClient};
use zolana_interface::instruction::{Deposit, Transact};
use zolana_keypair::random_blinding;
use zolana_transaction::{
    decrypt_transactions,
    instructions::{transact::ConfidentialTransfer, types::SppProofInputUtxo},
    AssetRegistry, SOL_MINT,
};

fn main() -> Result<()> {
    let SetupContext {
        rpc_url,
        indexer_url,
        prover_url,
        tree,
        alice: TestWallet {
            keypair: alice_keypair,
            ..
        },
        bob: TestWallet {
            keypair: bob_keypair,
            ..
        },
        ..
    } = setup()?;

    let client = ZolanaClient::from_urls(SolanaRpc::new(rpc_url), &indexer_url, prover_url, tree);
    let assets = AssetRegistry::default();

    let alice_funding = alice_keypair.to_solana_keypair()?;
    let alice_address = alice_keypair.shielded_address()?;

    {
        let deposit_ix = Deposit {
            tree,
            depositor: alice_funding.pubkey(),
            spl: None,
            view_tag: alice_address.viewing_pubkey.x(),
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
    }

    let alice_tag = alice_address.signing_pubkey.confidential_view_tag()?;
    let response = client.get_shielded_transactions_by_tags(
        vec![alice_tag],
        None,
        Some(50),
        Some(IndexerRpcConfig::wait()),
    )?;

    let balances = decrypt_transactions(&alice_keypair, &response.transactions, &assets)
        .map_err(|e| anyhow!("decrypt bob transactions: {e:?}"))?;
    let utxo = balances
        .get_balance(SOL_MINT)
        .expect("failed to fetch deposited utxo")
        .utxos[0]
        .clone();

    let input = SppProofInputUtxo::new(utxo, &alice_keypair);

    let bob_address = bob_keypair.shielded_address()?;
    let mut transfer =
        ConfidentialTransfer::new(alice_address, vec![input], alice_funding.pubkey());
    transfer.send(&bob_address, SOL_MINT, TRANSFER_AMOUNT)?;
    let proof_inputs = transfer.sign(&alice_keypair, &assets)?;

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
    Ok(())
}
