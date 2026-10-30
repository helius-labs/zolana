#[test]
#[ignore = "requires built localnet programs, CLI, Photon, and prover with proving keys"]
fn test_merge_submission() -> anyhow::Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    use anyhow::anyhow;
    use client_example::{setup_merge_scenario, MergeScenario};
    use solana_signer::Signer;
    use spr_client::{
        sign_transaction, IndexerRpcConfig, MergeProofRequest, Rpc, UtxoScan, ZolanaClient,
    };
    use spr_transaction::{instructions::merge::MergeTransaction, AssetRegistry, SOL_MINT};

    // Setup: register a merge-enabled owner with two notes and a separate fee payer.
    let note_count = 2;
    let note_amount = 100_000_000;
    let MergeScenario {
        rpc_url,
        indexer_url,
        prover_url,
        tree_id,
        sender,
        rent_sponsor: fee_payer,
        utxos,
        ..
    } = setup_merge_scenario(note_count, note_amount)?;
    let client = ZolanaClient::from_urls(rpc_url, indexer_url, prover_url, None)?;
    let assets = AssetRegistry::default();
    let expected_amount: u64 = utxos.iter().map(|utxo| utxo.utxo.amount).sum();

    // 1–2. Consolidate the notes on their tree and encrypt the merged output.
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .saturating_add(600);
    let merge = MergeTransaction::new(utxos)?
        .with_output_tree_id(tree_id)
        .with_expiry(expiry)
        .encrypt(&sender)?;

    // 3–4. The owner's registry record authorizes the merge; its key proves it.
    let submission = MergeProofRequest::new(merge.clone(), &sender)?;

    // 5–7. Check the record, fetch proofs, prove and verify, then build the message.
    let proved = submission.prove_sync(&client)?;
    let (blockhash, last_valid_block_height) = client.get_latest_blockhash()?;
    let unsigned = proved.build_solana_message(
        fee_payer.pubkey(),
        blockhash,
        last_valid_block_height,
        spr_client::ComputeBudgetConfig::new(spr_client::MERGE_CU_LIMIT),
    )?;

    // 8. Only the fee payer signs; the owner does not sign a merge.
    assert!(client.get_block_height()? <= unsigned.last_valid_block_height);
    let transaction = sign_transaction(unsigned.message, &[&fee_payer])?;

    // 9. Submit the signed Solana transaction.
    let signature = client.process_transaction(transaction)?;

    // 10. Wait for confirmation and indexing, then verify the two notes became one.
    client.confirm_private_transaction_sync(signature)?;
    let scan = UtxoScan::new(&sender)
        .with_indexer_config(IndexerRpcConfig::at_slot(client.get_slot()?))
        .fetch(&client, &assets)?;
    let balance = scan
        .spendable
        .balances
        .get_balance(SOL_MINT)
        .ok_or_else(|| anyhow!("the merged SOL note was not indexed"))?;
    assert_eq!(
        (balance.amount, balance.utxos.len()),
        (expected_amount, 1),
        "merging must consolidate the notes without changing their total value",
    );
    Ok(())
}
