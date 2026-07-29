use anyhow::{anyhow, Result};
use client_example::{setup, SetupContext};
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::{
    plan_batch_transact, BatchTransactAccounts, BatchTransactPlan, IndexerRpcConfig, Rpc,
    SolanaRpc, ZolanaClient, PACKET_DATA_SIZE,
};
use zolana_interface::instruction::{AssetDeposit, Deposit, DepositAsset};
use zolana_keypair::{random_blinding, ShieldedKeypair};
use zolana_transaction::{
    decrypt_transactions,
    instructions::{transact::ConfidentialTransfer, types::SppProofInputUtxo},
    AssetRegistry, SOL_MINT,
};

const DEPOSIT_AMOUNT: u64 = 500_000_000;

// Batch payout: Alice pays Bob and Carol in one submission.
// 1. Alice deposits two SOL UTXOs.
// 2. Alice builds one transfer per recipient and proves each entry.
// 3. plan_batch_transact measures the combined transaction. It returns one
//    BatchTransact when the size fits a packet. It returns solo instructions
//    when the size does not fit. The caller is never worse off.
// 4. Bob and Carol decrypt their balances.
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

    let alice_solana_keypair = alice_keypair.to_solana_keypair()?;
    let alice_shielded_address = alice_keypair.shielded_address()?;
    // Carol only receives; her wallet needs no funds.
    let carol_keypair = ShieldedKeypair::from_solana_keypair(&Keypair::new())?;

    // 1. One deposit instruction carries both UTXOs. Each batch entry later
    // spends its own UTXO, because entry inputs must not overlap.
    let alice_balances = {
        let deposit = |_| -> Result<AssetDeposit> {
            Ok(AssetDeposit {
                asset: DepositAsset::Sol,
                view_tag: alice_shielded_address.confidential_view_tag()?,
                owner: alice_shielded_address.owner_hash()?,
                blinding: random_blinding(),
                amount: DEPOSIT_AMOUNT,
                utxo_data: None,
                memo: None,
            })
        };
        let deposit_ix = Deposit {
            tree,
            depositor: alice_solana_keypair.pubkey(),
            deposits: vec![deposit(0)?, deposit(1)?],
        }
        .instruction()?;
        client.create_and_send_transaction(
            &[deposit_ix],
            alice_solana_keypair.pubkey(),
            &[&alice_solana_keypair],
        )?;

        let alice_tag = alice_shielded_address.confidential_view_tag()?;
        let response = client.get_shielded_transactions_by_tags(
            vec![alice_tag],
            None,
            Some(50),
            Some(IndexerRpcConfig::wait()),
        )?;
        let balances = decrypt_transactions(&alice_keypair, &response.transactions, &assets)
            .map_err(|e| anyhow!("decrypt alice transactions: {e:?}"))?;
        let balance = balances
            .get_balance(SOL_MINT)
            .expect("alice deposit balance");
        assert_eq!(balance.amount, 2 * DEPOSIT_AMOUNT);
        assert_eq!(balance.utxos.len(), 2);
        balances
    };

    // 2. One entry per recipient. Each entry sends a full UTXO, so both
    // entries resolve to the same compact circuit shape.
    let utxos = &alice_balances
        .get_balance(SOL_MINT)
        .expect("alice utxos")
        .utxos;
    let recipients = [
        bob_keypair.shielded_address()?,
        carol_keypair.shielded_address()?,
    ];
    let mut entries = Vec::with_capacity(recipients.len());
    for (utxo, recipient) in utxos.iter().zip(recipients.iter()) {
        let input = SppProofInputUtxo::new(utxo.clone(), &alice_keypair);
        let mut transfer = ConfidentialTransfer::new(
            alice_shielded_address,
            vec![input],
            alice_solana_keypair.pubkey(),
        );
        transfer.send(recipient, SOL_MINT, DEPOSIT_AMOUNT)?;
        let proof_inputs = transfer.sign(&alice_keypair, &assets)?;
        let entry = client.prove_transact(tree, proof_inputs, Some(IndexerRpcConfig::wait()))?;
        println!(
            "entry: circuit {:?}, {} bytes",
            entry.circuit,
            entry.serialize()?.len()
        );
        entries.push(entry);
    }

    // 3. Plan first to show the size decision, then submit through the same
    // plan logic in the client.
    let plan = plan_batch_transact(
        BatchTransactAccounts {
            payer: alice_solana_keypair.pubkey(),
            input_tree: tree,
            output_tree: tree,
            signers: vec![],
        },
        entries.clone(),
    )?;
    match &plan {
        BatchTransactPlan::Batched { tx_bytes, .. } => {
            println!("plan: one BatchTransact, {tx_bytes} of {PACKET_DATA_SIZE} bytes");
        }
        BatchTransactPlan::Solo {
            batched_tx_bytes, ..
        } => {
            println!(
                "plan: solo fallback, batch would need {batched_tx_bytes} of {PACKET_DATA_SIZE} bytes"
            );
        }
    }
    let signatures = client.send_batch_transact_sync(
        alice_solana_keypair.pubkey(),
        &[&alice_solana_keypair],
        tree,
        entries,
    )?;
    assert_eq!(signatures.len(), if plan.is_batched() { 1 } else { 2 });
    for signature in &signatures {
        client.confirm_private_transaction_sync(*signature)?;
    }
    println!("submitted {} transaction(s)", signatures.len());

    // 4. Both recipients see their funds.
    for (keypair, name) in [(&bob_keypair, "bob"), (&carol_keypair, "carol")] {
        let tag = keypair.shielded_address()?.confidential_view_tag()?;
        let response = client.get_shielded_transactions_by_tags(
            vec![tag],
            None,
            None,
            Some(IndexerRpcConfig::wait()),
        )?;
        let balances = decrypt_transactions(keypair, &response.transactions, &assets)
            .map_err(|e| anyhow!("decrypt {name} transactions: {e:?}"))?;
        let balance = balances
            .get_balance(SOL_MINT)
            .unwrap_or_else(|| panic!("{name} balance"));
        assert_eq!(balance.amount, DEPOSIT_AMOUNT);
        println!("{name} received {}", balance.amount);
    }
    Ok(())
}
