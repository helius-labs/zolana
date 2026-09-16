use std::{thread, time::Instant};

use anyhow::{anyhow, ensure, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_signer::Signer;
use zolana_client::{
    prover::transact::witness::assemble_cached, ComputeBudgetConfig, ConfidentialTransfer,
    MerkleProof, ProverClient, ProverInputs, Rpc, SpendProof, SppProofInputUtxo, STATE_TREE_HEIGHT,
};
use zolana_interface::{
    instruction::{tag, CreateCacheData, MergeTransact, Transact},
    state::cache::CACHE_SEED,
    PROGRAM_ID_PUBKEY,
};
use zolana_keypair::random_blinding;
use zolana_smart_account_client::execute_sync_ix;
use zolana_transaction::{Data, Utxo, SOL_MINT};
use zolana_user_registry_interface::user_record_pda;

use super::{transfer::decode_output_blinding, LifecycleHarness};
use crate::{
    localnet::{pack_merge_proof, ZERO},
    test_validator_asserts::{
        assert_transaction_compute_units, wait_for_indexed_transaction,
        wait_for_non_inclusion_proofs,
    },
    transact::pack_transact_proof,
};

impl LifecycleHarness {
    pub fn cached_merge_spend_benchmark(&mut self, inputs: usize) -> Result<()> {
        ensure!(
            inputs == 144,
            "this benchmark uses the local cached 4x3 key and requires 144 inputs"
        );
        let setup = Instant::now();
        let owner = self.register_merge_owner("cached-sender", true)?;
        self.ensure_fresh_actor("cached-recipient")?;
        for _ in 0..inputs {
            self.deposit_sol("cached-sender", 1_000_000_000)?;
        }
        let setup_ms = setup.elapsed().as_millis();
        let source = self.actor("cached-sender").spendable.clone();
        let sender = self.actor("cached-sender").keypair.clone();
        let recipient = self.actor("cached-recipient").keypair.clone();
        let merge_key = self.merge_key.insecure_clone();
        let budget = ComputeBudgetConfig::new(1_400_000).with_heap_size(256 * 1024);
        let operation_id = random_blinding();
        let (cache, _) = solana_address::Address::find_program_address(
            &[CACHE_SEED, owner.pubkey().as_ref(), &operation_id],
            &PROGRAM_ID_PUBKEY,
        );
        let witness_start = Instant::now();
        let mut signatures = Vec::new();
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
        let mut instructions = vec![create];

        let mut batches = Vec::new();
        let mut merged_notes = Vec::new();
        for (slot, chunk) in source.chunks(36).enumerate() {
            let (proof, output) = self.prepare_merge(
                "cached-sender",
                SOL_MINT,
                chunk,
                Some((cache.to_bytes(), slot as u8)),
            )?;
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
        transfer.send(
            &recipient.shielded_address()?,
            SOL_MINT,
            inputs as u64 * 1_000_000_000,
        )?;
        let prepared = transfer.sign(&sender, &self.assets)?;
        let commitments = prepared.input_utxo_hashes()?;
        let nullifiers: Vec<_> = commitments.iter().map(|input| input.nullifier).collect();
        let nips = wait_for_non_inclusion_proofs(&self.indexer, self.tree_address, &nullifiers);
        let spends: Vec<_> = commitments
            .iter()
            .zip(nips)
            .map(|(commitment, nullifier)| SpendProof {
                state: MerkleProof {
                    leaf: commitment.utxo_hash,
                    merkle_context: nullifier.merkle_context.clone(),
                    path: vec![ZERO; STATE_TREE_HEIGHT],
                    leaf_index: 0,
                    root: ZERO,
                    root_seq: 0,
                    root_index: 0,
                },
                nullifier,
            })
            .collect();
        let assembled = assemble_cached(prepared, &spends)?;
        let witness_ms = witness_start.elapsed().as_millis();
        let warm_keys = std::env::var("E2E_BENCH_WARM_KEYS").as_deref() == Ok("1");
        let warmup_ms = if warm_keys {
            let warmup = Instant::now();
            let prover = ProverClient::local();
            prover.prove_merge(&batches[0].inputs)?;
            let ProverInputs::Eddsa(inputs) = &assembled.prover_inputs;
            prover.prove_cached_transfer(inputs, assembled.cached_inputs.as_ref().unwrap())?;
            warmup.elapsed().as_millis()
        } else {
            0
        };
        let start = Instant::now();
        let proving = Instant::now();
        let (merge_proofs, transfer_proof) = thread::scope(|scope| -> Result<_> {
            let merge_jobs: Vec<_> = batches
                .iter()
                .map(|batch| scope.spawn(move || ProverClient::local().prove_merge(&batch.inputs)))
                .collect();
            let transfer_job = scope.spawn(|| {
                let ProverInputs::Eddsa(inputs) = &assembled.prover_inputs;
                ProverClient::local()
                    .prove_cached_transfer(inputs, assembled.cached_inputs.as_ref().unwrap())
            });
            let mut merge_proofs = Vec::new();
            for job in merge_jobs {
                merge_proofs.push(
                    job.join()
                        .map_err(|_| anyhow!("merge proof worker panicked"))??,
                );
            }
            Ok((
                merge_proofs,
                transfer_job
                    .join()
                    .map_err(|_| anyhow!("transfer proof worker panicked"))??,
            ))
        })?;
        let prove_ms = proving.elapsed().as_millis();
        let sending = Instant::now();
        for (batch, proof) in batches.iter().zip(merge_proofs) {
            let mut merge = MergeTransact {
                input_tree: self.tree,
                output_tree: self.tree,
                payer: self.merge_vault,
                user_record: user_record_pda(&owner.pubkey()).0,
                data: batch.instruction_data(pack_merge_proof(&proof)?),
            }
            .instruction();
            merge.accounts.push(AccountMeta::new(cache, false));
            let wrapped = execute_sync_ix(&self.merge_settings, 0, &[merge_key.pubkey()], &[merge]);
            instructions.push(wrapped);
        }
        let mut transfer = Transact {
            payer: owner.pubkey(),
            input_trees: vec![self.tree],
            output_tree: self.tree,
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            data: assembled.with_proof(pack_transact_proof(&transfer_proof)?),
        }
        .instruction();
        transfer.accounts.push(AccountMeta::new(cache, false));
        instructions.push(transfer);
        let packed = std::env::var("E2E_BENCH_PACKED").as_deref() != Ok("0");
        let mut groups: Vec<Vec<Instruction>> = Vec::new();
        for instruction in instructions {
            let mut candidate = groups.last().cloned().unwrap_or_default();
            candidate.push(instruction.clone());
            if packed
                && !groups.is_empty()
                && zolana_client::transaction_size(&owner.pubkey(), &candidate, budget)?.fits()
            {
                *groups.last_mut().unwrap() = candidate;
            } else {
                ensure!(
                    zolana_client::transaction_size(
                        &owner.pubkey(),
                        std::slice::from_ref(&instruction),
                        budget
                    )?
                    .fits(),
                    "instruction exceeds transaction limits"
                );
                groups.push(vec![instruction]);
            }
        }
        for group in groups {
            let mut signers: Vec<&dyn Signer> = vec![&owner];
            if group
                .iter()
                .flat_map(|ix| &ix.accounts)
                .any(|account| account.is_signer && account.pubkey == merge_key.pubkey())
            {
                signers.push(&merge_key);
            }
            let size = zolana_client::transaction_size(&owner.pubkey(), &group, budget)?;
            println!(
                "cached transaction: {} bytes, {} addresses",
                size.bytes, size.addresses
            );
            signatures.push(self.rpc.create_and_send_transaction(
                &group,
                owner.pubkey(),
                &signers,
                budget,
            )?);
        }
        let signature = *signatures.last().unwrap();
        let send_ms = sending.elapsed().as_millis();
        let confirmed_ms = witness_ms + start.elapsed().as_millis();
        let indexed = wait_for_indexed_transaction(
            &self.indexer,
            recipient.signing_pubkey().confidential_view_tag()?,
            signature,
        );
        let expected = self.build_expected(
            "cached-recipient",
            recipient.signing_pubkey(),
            SOL_MINT,
            inputs as u64 * 1_000_000_000,
            decode_output_blinding(&sender.viewing_key, &indexed, 2)?,
            &indexed,
        )?;
        self.actor_mut("cached-recipient").expected.push(expected);
        self.indexed.push(indexed);
        self.sync("cached-recipient")?;
        self.assert_utxos("cached-recipient")?;
        let visible_ms = witness_ms + start.elapsed().as_millis();
        let mut total_cu = 0;
        for signature in &signatures {
            total_cu +=
                assert_transaction_compute_units(&self.rpc, signature, "cached spend", 1_400_000)?;
        }
        println!("E2E_BENCH variant=cached inputs={inputs} proofs={} transactions={} packed={packed} total_cu={total_cu} setup_ms={setup_ms} warm_keys={warm_keys} warmup_ms={warmup_ms} witness_ms={witness_ms} prove_ms={prove_ms} send_ms={send_ms} confirmed_ms={confirmed_ms} visible_ms={visible_ms}", batches.len() + 1, signatures.len());
        Ok(())
    }
}
