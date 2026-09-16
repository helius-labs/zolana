use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, ensure, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::{
    prover::transact::witness::assemble_cached_with_dummy_proofs, ComputeBudgetConfig,
    ConfidentialTransfer, MerkleProof, ProverClient, ProverInputs, Rpc, SpendProof,
    SppProofInputUtxo, STATE_TREE_HEIGHT,
};
use zolana_interface::{
    instruction::{tag, CreateCacheData, MergeTransact, Transact},
    shape::Shape,
    state::cache::{CacheAccount, CACHE_OWNER_REGISTRY, CACHE_SEED},
    PROGRAM_ID_PUBKEY,
};
use zolana_keypair::random_blinding;
use zolana_smart_account_client::execute_sync_ix;
use zolana_transaction::{Data, Utxo, SOL_MINT};
use zolana_user_registry_interface::user_record_pda;

use super::{transfer::decode_output_blinding, LifecycleHarness};
use crate::{
    benchmark::{deposit_notes, BenchmarkConfig, NOTE_AMOUNT},
    localnet::{pack_merge_proof, ZERO},
    nullifier_pda::assert_nullifier_pdas,
    test_validator_asserts::{
        assert_transaction_compute_units, wait_for_indexed_transaction, wait_for_merkle_proofs,
        wait_for_non_inclusion_proofs,
    },
    transact::pack_transact_proof,
};

impl LifecycleHarness {
    pub fn cached_merge_spend_benchmark(
        &mut self,
        config: &BenchmarkConfig,
        run: usize,
        phase: &str,
        warmup_ms: u128,
    ) -> Result<u128> {
        let inputs = config.inputs;
        let setup = Instant::now();
        let owner = self.register_merge_owner("cached-sender", true)?;
        self.ensure_fresh_actor("cached-recipient")?;
        let sender = self.actor("cached-sender").keypair.clone();
        let recipient = self.actor("cached-recipient").keypair.clone();
        let payer = self.payer.insecure_clone();
        let tree = self.tree;
        let deposits = deposit_notes(
            &mut self.rpc,
            &payer,
            tree,
            sender.shielded_address()?.owner_hash()?,
            inputs,
            config.interleaved,
        )?;
        let source = deposits
            .into_iter()
            .map(|output| Utxo {
                owner: sender.signing_pubkey(),
                asset: SOL_MINT,
                amount: output.output.amount,
                blinding: output.output.blinding,
                ring_program_id: None,
                data: Data::default(),
            })
            .collect::<Vec<_>>();
        self.actor_mut("cached-sender").spendable = source.clone();
        let setup_ms = setup.elapsed().as_millis();
        let witness_start = Instant::now();
        let merge_key = self.merge_key.insecure_clone();
        let budget = ComputeBudgetConfig::new(1_400_000).with_heap_size(256 * 1024);
        let operation_id = random_blinding();
        let (cache, _) = solana_address::Address::find_program_address(
            &[CACHE_SEED, owner.pubkey().as_ref(), &operation_id],
            &PROGRAM_ID_PUBKEY,
        );
        let mut data = vec![tag::CREATE_CACHE];
        data.extend(wincode::serialize(&CreateCacheData {
            owner_kind: 0,
            operation_id,
            tree_id: self.tree_id,
            close_authority: owner.pubkey().to_bytes(),
        })?);
        let create = Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new_readonly(owner.pubkey(), true),
                AccountMeta::new(cache, false),
                AccountMeta::new_readonly(Default::default(), false),
            ],
            data,
        };

        let mut batches = Vec::new();
        let mut merged_notes = Vec::new();
        let mut membership_fetch_ms = 0;
        let mut nullifier_fetch_ms = 0;
        for (slot, chunk) in source.chunks(36).enumerate() {
            let ((proof, output), timing) = self.prepare_merge_timed(
                "cached-sender",
                SOL_MINT,
                chunk,
                Some((cache.to_bytes(), slot as u8)),
            )?;
            membership_fetch_ms += timing.membership_fetch_ms;
            nullifier_fetch_ms += timing.nullifier_fetch_ms;
            merged_notes.push(Utxo {
                owner: sender.signing_pubkey(),
                asset: SOL_MINT,
                amount: output.amount,
                blinding: output.blinding,
                ring_program_id: None,
                data: Data::default(),
            });
            batches.push(proof);
        }
        let spends = merged_notes
            .iter()
            .cloned()
            .map(|utxo| SppProofInputUtxo::new(utxo, &sender).in_tree(self.tree_id))
            .collect();
        let mut transfer =
            ConfidentialTransfer::new(sender.shielded_address()?, spends, owner.pubkey())
                .with_output_tree_id(self.tree_id);
        let compact = batches.len() > 5;
        if compact {
            transfer = transfer.with_compact_change().with_shape(Shape::IN36_OUT2);
        }
        transfer.send(
            &recipient.shielded_address()?,
            SOL_MINT,
            inputs as u64 * NOTE_AMOUNT,
        )?;
        let prepared = transfer.sign(&sender, &self.assets)?;
        let commitments = prepared.input_utxo_hashes()?;
        let dummy_nullifiers = prepared.dummy_nullifiers()?;
        let mut nullifiers: Vec<_> = commitments.iter().map(|input| input.nullifier).collect();
        nullifiers.extend_from_slice(&dummy_nullifiers);
        let fetch_start = Instant::now();
        let mut nips = wait_for_non_inclusion_proofs(&self.indexer, self.tree_address, &nullifiers);
        nullifier_fetch_ms += fetch_start.elapsed().as_millis();
        let dummy_nips = nips.split_off(commitments.len());
        let state_root = if dummy_nips.is_empty() {
            None
        } else {
            let first =
                source[0].hash(&sender.nullifier_key.pubkey()?, &ZERO, &ZERO, self.tree_id)?;
            let fetch_start = Instant::now();
            let proof =
                wait_for_merkle_proofs(&self.indexer, self.tree_address, &[first]).remove(0);
            membership_fetch_ms += fetch_start.elapsed().as_millis();
            Some(proof)
        };
        let spends: Vec<_> = commitments
            .iter()
            .zip(nips)
            .map(|(commitment, nullifier)| SpendProof {
                state: MerkleProof {
                    leaf: commitment.utxo_hash,
                    merkle_context: nullifier.merkle_context.clone(),
                    path: vec![ZERO; STATE_TREE_HEIGHT],
                    leaf_index: 0,
                    root: state_root.as_ref().map_or(ZERO, |proof| proof.root),
                    root_seq: state_root.as_ref().map_or(0, |proof| proof.root_seq),
                    root_index: state_root.as_ref().map_or(0, |proof| proof.root_index),
                },
                nullifier,
            })
            .collect();
        let assembled = assemble_cached_with_dummy_proofs(prepared, &spends, &dummy_nips)?;
        let witness_ms = witness_start.elapsed().as_millis();
        let proving = Instant::now();
        let overlap = std::env::var("E2E_BENCH_OVERLAP").as_deref() != Ok("0");
        let packed = std::env::var("E2E_BENCH_PACKED").as_deref() != Ok("0");
        let poll_ms = std::env::var("E2E_BENCH_POLL_MS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()?;
        ensure!(
            poll_ms != Some(0),
            "confirmation poll interval must be positive"
        );
        let mut submitter = CacheSubmitter {
            rpc: &self.rpc,
            owner: &owner,
            merge_key: &merge_key,
            budget,
            poll_ms,
            packed,
            pending: vec![create],
            signatures: Vec::new(),
            send_ms: 0,
        };
        let mut deferred = Vec::new();
        let mut prove_ms = 0;
        let mut transfer_proof = None;
        let next = AtomicUsize::new(0);
        thread::scope(|scope| -> Result<()> {
            let (sender, receiver) = mpsc::channel();
            let mut workers = Vec::new();
            for _ in 0..config.concurrency.min(batches.len() + 1) {
                let sender = sender.clone();
                let batches = &batches;
                let assembled = &assembled;
                let next = &next;
                workers.push(scope.spawn(move || loop {
                    let job = next.fetch_add(1, Ordering::Relaxed);
                    if job > batches.len() {
                        break;
                    }
                    let index = if job == 0 { batches.len() } else { job - 1 };
                    let prover = ProverClient::local();
                    let result = if let Some(batch) = batches.get(index) {
                        prover.prove_merge(&batch.inputs)
                    } else {
                        let ProverInputs::Eddsa(inputs) = &assembled.prover_inputs;
                        prover.prove_cached_transfer(
                            inputs,
                            assembled.cached_inputs.as_ref().unwrap(),
                        )
                    };
                    if sender
                        .send((index, result, proving.elapsed().as_millis()))
                        .is_err()
                    {
                        break;
                    }
                }));
            }
            drop(sender);
            for _ in 0..=batches.len() {
                let (index, proof, elapsed) = receiver
                    .recv()
                    .map_err(|_| anyhow!("cached proof worker stopped"))?;
                let proof = proof?;
                prove_ms = prove_ms.max(elapsed);
                let Some(batch) = batches.get(index) else {
                    transfer_proof = Some(proof);
                    continue;
                };
                let mut merge = MergeTransact {
                    input_tree: self.tree,
                    output_tree: self.tree,
                    payer: self.merge_vault,
                    user_record: user_record_pda(&owner.pubkey()).0,
                    data: batch.instruction_data(pack_merge_proof(&proof)?),
                }
                .instruction();
                merge.accounts.push(AccountMeta::new(cache, false));
                let wrapped =
                    execute_sync_ix(&self.merge_settings, 0, &[merge_key.pubkey()], &[merge]);
                if overlap {
                    submitter.append(wrapped)?;
                } else {
                    deferred.push(wrapped);
                }
            }
            for worker in workers {
                worker
                    .join()
                    .map_err(|_| anyhow!("cached proof worker panicked"))?;
            }
            Ok(())
        })?;
        let sending = Instant::now();
        let mut transfer = Transact {
            payer: owner.pubkey(),
            input_trees: vec![self.tree],
            output_tree: self.tree,
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            data: assembled.with_proof(pack_transact_proof(&transfer_proof.unwrap())?),
        }
        .instruction();
        transfer.accounts.push(AccountMeta::new(cache, false));
        deferred.push(transfer);
        for instruction in deferred {
            submitter.append(instruction)?;
        }
        let (signatures, chain_send_ms) = submitter.finish()?;
        let signature = *signatures.last().unwrap();
        let send_ms = sending.elapsed().as_millis();
        let confirmed_ms = witness_start.elapsed().as_millis();
        let indexer_start = Instant::now();
        let indexed = wait_for_indexed_transaction(
            &self.indexer,
            recipient.signing_pubkey().confidential_view_tag()?,
            signature,
        );
        let recipient_indexer_ms = indexer_start.elapsed().as_millis();
        let decrypt_start = Instant::now();
        let balances = zolana_transaction::decrypt_transactions(
            &recipient,
            std::slice::from_ref(&indexed),
            &self.assets,
        )?;
        assert_eq!(
            balances.get_balance(SOL_MINT).map(|balance| balance.amount),
            Some(inputs as u64 * NOTE_AMOUNT)
        );
        let recipient_decrypt_ms = decrypt_start.elapsed().as_millis();
        let visible_ms = witness_start.elapsed().as_millis();
        let cache_account = self
            .rpc
            .get_account(cache)?
            .ok_or_else(|| anyhow!("cache account missing"))?;
        assert_eq!(cache_account.owner, PROGRAM_ID_PUBKEY);
        assert_eq!(cache_account.data.len(), CacheAccount::SIZE);
        let cache_state = bytemuck::from_bytes::<CacheAccount>(&cache_account.data);
        assert!(cache_state.has_discriminator());
        assert_eq!(cache_state.owner_kind, CACHE_OWNER_REGISTRY);
        assert_eq!(cache_state.owner, owner.pubkey().to_bytes());
        assert_eq!(cache_state.operation_id, operation_id);
        assert_eq!(cache_state.tree_id, self.tree_id.to_le_bytes());
        assert_eq!(cache_state.frozen, 1);
        for (slot, batch) in batches.iter().enumerate() {
            assert_eq!(cache_state.commitments[slot], batch.output_hash);
        }
        assert!(cache_state.commitments[batches.len()..]
            .iter()
            .all(|hash| *hash == ZERO));
        let spent_nullifiers = batches
            .iter()
            .flat_map(|batch| batch.nullifiers.iter().copied())
            .chain(nullifiers.iter().copied())
            .collect::<Vec<_>>();
        assert_nullifier_pdas(&self.rpc, &self.tree, &spent_nullifiers)?;
        let expected = self.build_expected(
            "cached-recipient",
            recipient.signing_pubkey(),
            SOL_MINT,
            inputs as u64 * NOTE_AMOUNT,
            decode_output_blinding(&sender.viewing_key, &indexed, if compact { 0 } else { 2 })?,
            &indexed,
        )?;
        self.actor_mut("cached-recipient").expected.push(expected);
        self.indexed.push(indexed);
        self.sync("cached-recipient")?;
        self.assert_utxos("cached-recipient")?;
        let mut total_cu = 0;
        for signature in &signatures {
            total_cu +=
                assert_transaction_compute_units(&self.rpc, signature, "cached spend", 1_400_000)?;
        }
        let proofs = batches.len() + 1;
        let transactions = signatures.len();
        println!(
            "E2E_PIPELINE {}",
            serde_json::json!({
                "variant": "cached", "run": run, "phase": phase, "inputs": inputs,
                "concurrency": config.concurrency, "gomaxprocs": config.gomaxprocs,
                "prover_concurrency": config.prover_concurrency, "layout": config.layout(),
                "key_state": if config.warm_keys && phase == "measured" { "warm" } else { "cold" },
                "warm_keys": config.warm_keys && phase == "measured", "warmup_ms": warmup_ms,
                "proofs": proofs, "transactions": transactions, "packed": packed, "poll_ms": poll_ms,
                "indexer_poll_ms": std::env::var("E2E_BENCH_INDEXER_POLL_MS").ok(),
                "overlap": overlap, "proof_schedule": "transfer-first-work-conserving",
                "total_cu": total_cu, "setup_ms": setup_ms, "witness_ms": witness_ms,
                "membership_fetch_ms": membership_fetch_ms, "nullifier_fetch_ms": nullifier_fetch_ms,
                "witness_local_ms": witness_ms.saturating_sub(membership_fetch_ms + nullifier_fetch_ms),
                "prove_ms": prove_ms, "submit_ms": send_ms, "chain_send_ms": chain_send_ms,
                "confirmed_ms": confirmed_ms, "total_ms": visible_ms,
                "recipient_indexer_ms": recipient_indexer_ms, "recipient_decrypt_ms": recipient_decrypt_ms,
                "output_slots": if compact { 2 } else { 3 },
            })
        );
        Ok(setup_ms + visible_ms)
    }
}

struct CacheSubmitter<'a> {
    rpc: &'a zolana_client::SolanaRpc,
    owner: &'a Keypair,
    merge_key: &'a Keypair,
    budget: ComputeBudgetConfig,
    poll_ms: Option<u64>,
    packed: bool,
    pending: Vec<Instruction>,
    signatures: Vec<solana_signature::Signature>,
    send_ms: u128,
}

impl CacheSubmitter<'_> {
    fn append(&mut self, instruction: Instruction) -> Result<()> {
        ensure!(
            zolana_client::transaction_size(
                &self.owner.pubkey(),
                std::slice::from_ref(&instruction),
                self.budget
            )?
            .fits(),
            "instruction exceeds transaction limits"
        );
        let mut candidate = self.pending.clone();
        candidate.push(instruction.clone());
        if !self.pending.is_empty()
            && (!self.packed
                || !zolana_client::transaction_size(&self.owner.pubkey(), &candidate, self.budget)?
                    .fits())
        {
            self.flush()?;
        }
        self.pending.push(instruction);
        Ok(())
    }

    fn finish(mut self) -> Result<(Vec<solana_signature::Signature>, u128)> {
        self.flush()?;
        Ok((self.signatures, self.send_ms))
    }

    fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let start = Instant::now();
        let mut signers: Vec<&dyn Signer> = vec![self.owner];
        if self
            .pending
            .iter()
            .flat_map(|ix| &ix.accounts)
            .any(|account| account.is_signer && account.pubkey == self.merge_key.pubkey())
        {
            signers.push(self.merge_key);
        }
        let size =
            zolana_client::transaction_size(&self.owner.pubkey(), &self.pending, self.budget)?;
        println!(
            "cached transaction: {} bytes, {} addresses",
            size.bytes, size.addresses
        );
        let signature = if let Some(interval) = self.poll_ms {
            let (blockhash, _) = self.rpc.get_latest_blockhash()?;
            let transaction = zolana_client::sign_transaction(
                zolana_client::compile_message(
                    &self.owner.pubkey(),
                    &self.pending,
                    blockhash,
                    self.budget,
                )?,
                &signers,
            )?;
            let signature = self.rpc.send_transaction_with_config(
                &transaction,
                zolana_client::RpcSendTransactionConfig {
                    preflight_commitment: Some(self.rpc.client().commitment().commitment),
                    ..Default::default()
                },
            )?;
            self.rpc
                .wait_for_signature_with_interval(&signature, Duration::from_millis(interval))?;
            signature
        } else {
            self.rpc.create_and_send_transaction(
                &self.pending,
                self.owner.pubkey(),
                &signers,
                self.budget,
            )?
        };
        self.signatures.push(signature);
        self.send_ms += start.elapsed().as_millis();
        self.pending.clear();
        Ok(())
    }
}
