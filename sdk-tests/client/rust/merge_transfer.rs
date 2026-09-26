use anyhow::Result;
use client_example::{
    merge::{
        assert_balance_needs_merging, assert_balances_after_transfer,
        assert_merge_needs_no_padding, assert_merge_output_is_predicted, landed_slot,
        locate_merged_note, proof_data_source, MergeRequest, MergedNote, Timeline,
    },
    setup_merge_scenario, MergeScenario,
};
use solana_signer::Signer;
use zolana_client::{
    AsyncProverClient, AsyncZolanaIndexer, ComputeBudgetConfig, IndexerRpcConfig, ProverClient,
    Rpc, SolanaRpc, ZolanaClient, ZolanaIndexer,
};
use zolana_program::instruction::{MergeTransact, Transact};
use zolana_transaction::{
    instructions::{
        merge::MergeTransaction,
        transact::{ConfidentialTransaction, Shape},
    },
    AssetRegistry,
};
use zolana_user_registry_interface::user_record_pda;

/// One merge spends exactly `MAX_MERGE_INPUTS` inputs.
const UTXO_COUNT: usize = 36;
const DEPOSIT_AMOUNT: u64 = 100_000;
const TRANSFER_AMOUNT: u64 = 500_000;
/// A 36-input merge costs about 250,000 compute units, most of it the 36
/// nullifier PDAs.
const MERGE_CU_LIMIT: u32 = 400_000;

/// Spends a balance spread over more UTXOs than one transaction can take, the
/// direct way: merge, then transfer the merged output.
///
/// This is the baseline [`optimized_merge_transfer`] improves on. The transfer
/// proves its input against a Merkle path, so it cannot be built until the
/// merge has landed, the merged output has been appended to the tree, and the
/// indexer has served a proof for it. That wait sits between the two
/// transactions and neither proof can overlap it.
///
/// Two actors, the same as in the optimized flow:
///
/// - **Sender** owns the UTXOs and signs the transfer.
/// - **Merge payer** pays for and sends the merge, covering the nullifier PDAs
///   and the forester fee. It holds no spending key: a record that has opted
///   into merging can be merged by any caller.
///
/// The run prints each stage as it ends, then a table of every stage and of
/// every prover request with the spans the prover reports.
///
/// The critical path is the sum of every step, and the indexer round trip
/// between the merge and the transfer proof is the part the cache removes.
///
/// [`optimized_merge_transfer`]: ../optimized_merge_transfer.rs
fn main() -> Result<()> {
    // A registered sender whose private balance sits in 36 separate UTXOs. The
    // rent sponsor funds no cache here; it only pays for the merge.
    let MergeScenario {
        cluster,
        rpc_url,
        indexer_url,
        prover_url,
        tree,
        tree_id,
        sender,
        recipient,
        rent_sponsor: merge_payer,
        utxos,
    } = setup_merge_scenario(UTXO_COUNT, DEPOSIT_AMOUNT)?;
    let _refund = cluster.refund_on_exit(&rpc_url, vec![&sender, &merge_payer]);

    let source = proof_data_source()?;
    let timeline = Timeline::start();
    let merge_prover =
        ProverClient::new(prover_url.clone()).with_timing(timeline.prover_sink("merge"));
    let client = ZolanaClient::new(
        SolanaRpc::new(rpc_url.clone()),
        ZolanaIndexer::new(&indexer_url),
        ProverClient::new(prover_url.clone()).with_timing(timeline.prover_sink("transfer")),
        AsyncZolanaIndexer::new(&indexer_url),
        AsyncProverClient::new(prover_url),
    )
    .with_proof_data_source(source);
    let indexer = ZolanaIndexer::new(&indexer_url);
    let assets = AssetRegistry::default();
    let sender_address = sender.shielded_address()?;
    let recipient_address = recipient.shielded_address()?;

    // 1. The balance cannot be spent in one transfer, so it has to be merged.
    assert_balance_needs_merging(&utxos, UTXO_COUNT);
    let total: u64 = utxos.iter().map(|utxo| utxo.utxo.amount).sum();

    // 2. Merge proof inputs. Without a cache the merge binds to nothing but its
    // own inputs and output, so `MergeRequest::cache` stays `None` and the
    // instruction takes no trailing cache account.
    let transaction = MergeTransaction::new(utxos.clone())?
        .with_output_tree_id(tree_id)
        .encrypt(&sender)?;
    assert_merge_needs_no_padding(&transaction)?;
    let merged_note = MergedNote {
        owner: &sender,
        blinding: transaction.output_utxo.blinding,
        amount: total,
        tree_id,
    }
    .predict()?;
    let merge = timeline.stage("merge inputs", || {
        MergeRequest {
            transaction,
            owner: &sender,
            cache: None,
        }
        .prepare(source, &indexer)
    })?;

    // 3. Prove and send the merge. Nothing else can start: the transfer's
    // Merkle proof does not exist until this output is in the tree.
    let merge_data = timeline.stage("merge proof", || merge.prove(&merge_prover))?;

    let merge_ix = MergeTransact {
        input_tree: tree,
        output_tree: tree,
        payer: merge_payer.pubkey(),
        user_record: user_record_pda(&sender.pubkey()).0,
        data: merge_data.clone(),
        cache: None,
    }
    .instruction();
    let merge_slot = timeline.stage("merge send and confirm", || {
        let signature = client.create_and_send_transaction(
            &[merge_ix],
            merge_payer.pubkey(),
            &[&merge_payer],
            ComputeBudgetConfig::new(MERGE_CU_LIMIT),
        )?;
        landed_slot(&client, signature)
    })?;

    // 4. Build the transfer over the merged output. Its commitment is known
    // from the merge, but its Merkle path is not, so the sender has to sync
    // the merged note back from the indexer before it can be spent.
    assert_merge_output_is_predicted(&merged_note, &merge_data)?;
    let merged_note = timeline.stage("merged note sync", || {
        let response = client.get_shielded_transactions_by_tags(
            vec![sender_address.confidential_view_tag()?],
            None,
            Some(50),
            Some(IndexerRpcConfig::at_slot(merge_slot)),
        )?;
        locate_merged_note(merged_note, &response.transactions)
    })?;

    let mut transfer = ConfidentialTransaction::new(vec![merged_note], sender.pubkey())?
        .with_output_tree_id(tree_id)?;
    transfer.transfer_sol(&recipient_address, TRANSFER_AMOUNT)?;
    transfer.pad_utxos(Shape::IN2_OUT3, &sender_address)?;
    let transfer_inputs = transfer.encrypt(&sender)?;
    let transfer_data = timeline.stage("transfer proof", || {
        client.prove_transact(
            transfer_inputs,
            Some(IndexerRpcConfig::at_slot(merge_slot)),
            &sender,
        )
    })?;

    // 5. Send the transfer.
    let transfer_ix = Transact {
        payer: sender.pubkey(),
        input_trees: vec![tree],
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transfer_data,
    }
    .instruction();
    let slot = timeline.stage("transfer send and confirm", || {
        let signature = client.create_and_send_transaction(
            &[transfer_ix],
            sender.pubkey(),
            &[&sender],
            client.compute_budget(),
        )?;
        landed_slot(&client, signature)
    })?;

    assert_balances_after_transfer(
        &client,
        &sender,
        &recipient,
        &assets,
        slot,
        TRANSFER_AMOUNT,
        total - TRANSFER_AMOUNT,
    )?;
    timeline.print_summary();

    Ok(())
}
