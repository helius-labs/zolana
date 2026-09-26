use anyhow::{Context, Result};
use client_example::{
    cached_merge::{
        assemble_cached_transfer, assert_cache_closed_and_refunded, wait_for_cache_commitment,
    },
    merge::{
        assert_balance_needs_merging, assert_balances_after_transfer,
        assert_merge_needs_no_padding, assert_merge_output_is_predicted, landed_slot, log,
        merge_instruction_data,
    },
    setup_merge_scenario, MergeScenario,
};
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    prover::MergeCacheTarget, ComputeBudgetConfig, MergeProver, ProofAuthority, ProofCompressed,
    ProverClient, Rpc, SolanaRpc, WitnessReader, ZolanaClient, ZolanaIndexer,
};
use zolana_interface::instruction::instruction_data::CreateCacheData;
use zolana_program::instruction::{
    CacheWriteAccounts, CloseCache, CreateCache, MergeTransact, Transact,
};
use zolana_transaction::{
    instructions::{
        merge::MergeTransaction,
        transact::{ConfidentialTransaction, Shape},
    },
    AssetRegistry, Data, Mint, Utxo, WalletUtxo,
};
use zolana_user_registry_interface::user_record_pda;

/// One merge spends exactly `MAX_MERGE_INPUTS` inputs.
const UTXO_COUNT: usize = 36;
const DEPOSIT_AMOUNT: u64 = 100_000_000;
const TRANSFER_AMOUNT: u64 = 500_000_000;
/// Distinguishes this cache from any other the sponsor holds; the address is
/// derived from the sponsor and this value.
const CACHE_NONCE: u64 = 0;
/// The sponsor's rent sits in the cache until it is closed. After the expiry
/// anyone may close it and return that rent.
const CACHE_EXPIRES_AT: i64 = 2_000_000_000;
/// The slot this merge writes its output commitment into. With several merges
/// each takes its own slot of the same cache.
const CACHE_SLOT: u8 = 0;
/// A 36-input merge costs about 250,000 compute units, most of it the 36
/// nullifier PDAs.
const MERGE_CU_LIMIT: u32 = 400_000;

/// Spends a balance spread over more UTXOs than one transaction can take,
/// without the round trip that normally separates the merge from the transfer.
///
/// A wallet that has received many small payments holds more UTXOs than the
/// widest transfer shape accepts, so spending the balance means merging first.
/// Running the two in sequence is slow for a reason unrelated to proving: the
/// transfer needs a Merkle inclusion proof for the merged output, so it cannot
/// start until the merge has landed, been appended to the tree, and been
/// indexed.
///
/// A cache account removes that dependency. The merge writes its output
/// commitment into a slot of a cache PDA, and a transfer may prove an input
/// against that commitment instead of against a Merkle path. The merged
/// output's blinding is derived rather than random, so the client knows the
/// commitment before the merge is submitted, and both proofs can be requested
/// at once.
///
/// Two actors:
///
/// - **Sender** owns the UTXOs. It signs the transfer, which proves it owns
///   every input the transfer draws from the cache.
/// - **Rent sponsor** funds the cache account and is its write authority. It
///   creates the cache and sends the merge, paying the nullifier PDAs and the
///   forester fee, and is refunded when the cache closes. It holds no spending
///   key: a record that has opted into merging can be merged by any caller.
///
/// The run prints its own timeline. The order it shows is the point:
///
/// ```text
/// t+  0.000s  merge and transfer proofs requested
/// t+  0.061s  transfer proof ready
/// t+  1.131s  merge proof ready
/// t+  1.652s  merge transaction confirmed
/// t+  1.652s  cache slot 0 holds the merge output
/// t+  2.168s  transfer transaction confirmed
/// ```
///
/// The critical path is `max(merge proof + merge lands, transfer proof)`
/// instead of `merge proof + merge lands + indexing + transfer proof`.
fn main() -> Result<()> {
    // A registered sender whose private balance sits in 36 separate UTXOs, plus
    // a rent sponsor for the cache account.
    let MergeScenario {
        rpc_url,
        indexer_url,
        prover_url,
        tree,
        tree_id,
        sender,
        recipient,
        rent_sponsor,
        utxos,
    } = setup_merge_scenario(UTXO_COUNT, DEPOSIT_AMOUNT)?;

    let client =
        ZolanaClient::from_urls(SolanaRpc::new(rpc_url), &indexer_url, prover_url.clone())?;
    let indexer = ZolanaIndexer::new(&indexer_url);
    let prover = ProverClient::new(prover_url);
    let assets = AssetRegistry::default();
    let sender_address = sender.shielded_address()?;
    let recipient_address = recipient.shielded_address()?;

    // 1. The balance cannot be spent in one transfer, so it has to be merged.
    assert_balance_needs_merging(&utxos, UTXO_COUNT);
    let total: u64 = utxos.iter().map(|utxo| utxo.utxo.amount).sum();

    // 2.1. Merge proof inputs, for one slot of one cache.
    //
    // The cache address is derived from the rent sponsor and a nonce, so it is
    // known before the account exists, which is why the merge proof can commit
    // to it here and the create instruction can ride along with the merge
    // below. The merge's `external_data_hash` includes that address and slot,
    // so a proven merge cannot be replayed into a different cache.
    let create_cache = CreateCache {
        payer: rent_sponsor.pubkey(),
        data: CreateCacheData {
            // Every merge that writes a slot must be authorized by this key,
            // and it alone decides what the slots hold. Here that is the
            // sponsor, which also sends the merge; the field is separate from
            // `rent_sponsor` so a third party can fund a cache it is not
            // allowed to write.
            write_authority: rent_sponsor.pubkey(),
            nonce: CACHE_NONCE,
            tree_id,
            expires_at: CACHE_EXPIRES_AT,
        },
    };
    let cache = create_cache.cache();

    let (merge, merged_output) = {
        let transaction = MergeTransaction::new(utxos.clone())?
            .with_output_tree_id(tree_id)
            .encrypt(&sender)?;
        assert_merge_needs_no_padding(&transaction)?;

        // Every input of one merge is proven against the same pair of roots, so
        // the proofs come from one indexer call.
        let commitments = transaction.input_utxo_hashes()?;
        let witnesses =
            indexer.input_witnesses(&commitments, &transaction.dummy_nullifiers(), None)?;

        let output = transaction.output_utxo.clone();
        let result = MergeProver {
            transaction,
            nullifier_key: sender.nullifier_key.clone(),
            proofs: witnesses.spend_proofs,
            dummy_nullifier_proofs: witnesses.dummy_nullifier_proofs,
            cache: Some(MergeCacheTarget {
                address: cache,
                slot: CACHE_SLOT,
            }),
        }
        .build()?;
        (result, output)
    };

    // 2.2. Transfer proof inputs, from the merge's predicted output.
    //
    // Nothing here waits for the merge. The merged output's blinding is derived
    // from the owner's nullifier secret and the first input's nullifier rather
    // than drawn at random, so the client knows the output commitment exactly,
    // and a cached input is proven against that commitment instead of against a
    // Merkle path.
    let merged_utxo = Utxo {
        owner: sender_address.signing_pubkey,
        asset: Mint::SOL,
        amount: total,
        blinding: merged_output.blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    let nullifier_pubkey = sender.nullifier_key.pubkey()?;
    let utxo_hash = merged_utxo.hash(&nullifier_pubkey, &[0; 32], &[0; 32], tree_id)?;
    // The note exists only as a prediction, so it carries no leaf index or
    // publication slot: a cached input is proven against the commitment the
    // cache holds, never against a path into the tree.
    let transfer_input = WalletUtxo {
        nullifier: sender
            .nullifier_key
            .nullifier(&utxo_hash, &merged_utxo.blinding)?,
        utxo: merged_utxo,
        nullifier_pubkey,
        utxo_hash,
        data_hash: None,
        ring_data_hash: None,
        tree_id,
        leaf_index: 0,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    };
    assert_merge_output_is_predicted(&transfer_input, &merge)?;

    let mut transfer = ConfidentialTransaction::new(vec![transfer_input], sender.pubkey())?
        .with_output_tree_id(tree_id)?;
    transfer.transfer_sol(&recipient_address, TRANSFER_AMOUNT)?;
    transfer.pad_utxos(Shape::IN2_OUT3, &sender_address)?;
    let mut proof_inputs = transfer.encrypt(&sender)?.with_read_cache(cache);
    for input in proof_inputs
        .input_utxos
        .iter_mut()
        .filter(|input| !input.is_dummy())
    {
        *input = input.clone().with_cache_slot(CACHE_SLOT)?;
    }
    let mut transfer = assemble_cached_transfer(&client, tree, proof_inputs)?;
    sender.complete_inputs(&mut transfer.prover_inputs.inputs)?;

    // 3. Both proofs are requested at once, and the merge is sent the moment its
    // own proof is ready. Neither proof is an input to the other, so the
    // transfer's runs on its own thread while the merge proves, lands, and
    // writes the cache. Both proof calls take `&self` on one shared prover
    // client, and the SDK's proving path is synchronous, so this needs threads
    // rather than an async runtime.
    let started = std::time::Instant::now();
    log(started, "merge and transfer proofs requested");
    let transfer_proof = std::thread::scope(|scope| {
        let transfer = scope.spawn(|| {
            let proof = prover.prove_transfer(&transfer.prover_inputs);
            log(started, "transfer proof ready");
            proof
        });

        let merge_proof = prover.prove_merge(&merge.inputs).context("merge proof")?;
        log(started, "merge proof ready");

        // 4. The rent sponsor sends the merge. Cache creation is permissionless
        // and idempotent, so every merge includes it: with several merges in
        // flight the first to land creates the account and the rest are no-ops
        // that can neither clear the commitments nor extend the expiry. The
        // sender signs nothing here. Its record opted into merging, and only
        // the cache's write authority decides what the slot receives.
        let merge_ix = MergeTransact {
            input_tree: tree,
            output_tree: tree,
            payer: rent_sponsor.pubkey(),
            user_record: user_record_pda(&sender.pubkey()).0,
            data: merge_instruction_data(&merge, merge_proof)?,
            cache: Some(CacheWriteAccounts {
                cache,
                writer: rent_sponsor.pubkey(),
            }),
        }
        .instruction();
        client.create_and_send_transaction(
            &[create_cache.instruction(), merge_ix],
            rent_sponsor.pubkey(),
            &[&rent_sponsor],
            ComputeBudgetConfig::new(MERGE_CU_LIMIT),
        )?;
        log(started, "merge transaction confirmed");

        let transfer_proof = transfer.join().expect("transfer proving thread");
        transfer_proof.context("transfer proof")
    })?;

    // 5. Wait for the commitment to appear in the slot the transfer's proof
    // committed to.
    wait_for_cache_commitment(&client, cache, CACHE_SLOT, &merge.output_hash)?;
    log(
        started,
        &format!("cache slot {CACHE_SLOT} holds the merge output"),
    );

    // 6. Send the transfer and close the cache account.
    let sponsor_before = client.get_balance(rent_sponsor.pubkey())?;
    let transfer_ix = Transact {
        payer: sender.pubkey(),
        input_trees: vec![tree],
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transfer.with_proof(ProofCompressed::try_from(transfer_proof)?.to_transact_proof()),
    }
    .instruction_with_cache_read(cache);
    let close_cache_ix = CloseCache {
        cache,
        rent_recipient: rent_sponsor.pubkey(),
        writer: Some(rent_sponsor.pubkey()),
    }
    .instruction();
    let signature = client.create_and_send_transaction(
        &[transfer_ix, close_cache_ix],
        sender.pubkey(),
        &[&sender, &rent_sponsor],
        client.compute_budget(),
    )?;
    let slot = landed_slot(&client, signature)?;
    log(started, "transfer transaction confirmed");

    assert_cache_closed_and_refunded(&client, cache, rent_sponsor.pubkey(), sponsor_before)?;
    assert_balances_after_transfer(
        &client,
        &sender,
        &recipient,
        &assets,
        slot,
        TRANSFER_AMOUNT,
        total - TRANSFER_AMOUNT,
    )?;

    Ok(())
}
