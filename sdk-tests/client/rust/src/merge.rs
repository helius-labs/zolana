//! Helpers shared by the two merge examples: the run timeline, proving a merge
//! by either proof data route, and the assertions both flows make.

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use solana_signature::Signature;
use zolana_client::{
    prover::{
        indexed::{IndexedMergePreparation, PreparedIndexedMerge, ProvenIndexedMerge},
        MergeCacheTarget,
    },
    timing::{ProverTiming, ProverTimingSink},
    IndexerRpcConfig, MergeProofResult, MergeProver, ProofCompressed, ProofDataSource,
    ProverClient, Rpc, ShieldedTransaction, WitnessReader, ZolanaClient, ZolanaIndexer,
};
use zolana_interface::instruction::instruction_data::MergeTransactIxData;
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    decrypt_spendable,
    instructions::{merge::MergeProofInputs, transact::canonical_shape},
    AssetRegistry, Data, Mint, Utxo, WalletUtxo, SOL_MINT,
};

/// `ZOLANA_PROOF_DATA_SOURCE=client` fetches Merkle data in the example, unset or `prover`
/// leaves it to the prover.
pub fn proof_data_source() -> Result<ProofDataSource> {
    match std::env::var("ZOLANA_PROOF_DATA_SOURCE").as_deref() {
        Ok("client") => Ok(ProofDataSource::Client),
        Ok("prover") | Err(_) => Ok(ProofDataSource::Prover),
        Ok(other) => Err(anyhow!("unknown ZOLANA_PROOF_DATA_SOURCE {other:?}")),
    }
}

pub struct Timeline {
    started: Instant,
    stages: Mutex<Vec<Stage>>,
    requests: Arc<Mutex<Vec<Request>>>,
}

struct Stage {
    name: &'static str,
    start: Duration,
    end: Duration,
}

struct Request {
    label: &'static str,
    start: Duration,
    timing: ProverTiming,
}

impl Timeline {
    pub fn start() -> Self {
        Self {
            started: Instant::now(),
            stages: Mutex::default(),
            requests: Arc::default(),
        }
    }

    /// Runs `step` as one stage and prints when it ends.
    pub fn stage<T>(&self, name: &'static str, step: impl FnOnce() -> T) -> T {
        let start = self.started.elapsed();
        let output = step();
        let end = self.started.elapsed();
        println!("t+{:>7.3}s  {name} done", end.as_secs_f64());
        self.stages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Stage { name, start, end });
        output
    }

    pub fn prover_sink(&self, label: &'static str) -> ProverTimingSink {
        let started = self.started;
        let requests = Arc::clone(&self.requests);
        Arc::new(move |timing: ProverTiming| {
            let start = started.elapsed().saturating_sub(timing.elapsed);
            requests
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Request {
                    label,
                    start,
                    timing,
                });
        })
    }

    pub fn print_summary(&self) {
        let ms = |duration: Duration| duration.as_secs_f64() * 1000.0;
        println!(
            "\n{:<24}{:>10}{:>10}{:>10}",
            "stage", "start ms", "end ms", "ms"
        );
        for stage in self
            .stages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            println!(
                "{:<24}{:>10.0}{:>10.0}{:>10.0}",
                stage.name,
                ms(stage.start),
                ms(stage.end),
                ms(stage.end - stage.start)
            );
        }
        println!(
            "\n{:<10}{:<28}{:>8}{:>10}  server spans ms",
            "prover", "path", "status", "rtt ms"
        );
        for request in self
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            let spans: Vec<String> = request
                .timing
                .spans
                .iter()
                .map(|span| {
                    let open = if span.complete { "" } else { " open" };
                    format!("{} {:.1}{open}", span.name, span.duration_ms)
                })
                .collect();
            println!(
                "{:<10}{:<28}{:>8}{:>10.0}  starts {:.0}, {}",
                request.label,
                request.timing.path,
                request.timing.status,
                ms(request.timing.elapsed),
                ms(request.start),
                if spans.is_empty() {
                    "not reported".to_string()
                } else {
                    spans.join(", ")
                }
            );
        }
    }
}

pub struct MergeRequest<'a> {
    pub transaction: MergeProofInputs,
    pub owner: &'a ShieldedKeypair,
    pub cache: Option<MergeCacheTarget>,
}

pub enum PreparedMerge {
    Client(Box<MergeProofResult>),
    Prover(Box<PreparedIndexedMerge>),
}

impl MergeRequest<'_> {
    pub fn prepare(
        self,
        source: ProofDataSource,
        indexer: &ZolanaIndexer,
    ) -> Result<PreparedMerge> {
        let nullifier_key = self.owner.nullifier_key.clone();
        if source == ProofDataSource::Prover {
            let preparation = IndexedMergePreparation {
                merge: self.transaction,
                nullifier_key,
            };
            return Ok(PreparedMerge::Prover(Box::new(match self.cache {
                Some(cache) => preparation.prepare_for_cache(cache)?,
                None => preparation.prepare()?,
            })));
        }
        let commitments = self.transaction.input_utxo_hashes()?;
        let witnesses =
            indexer.input_witnesses(&commitments, &self.transaction.dummy_nullifiers(), None)?;
        Ok(PreparedMerge::Client(Box::new(
            MergeProver {
                transaction: self.transaction,
                nullifier_key,
                proofs: witnesses.spend_proofs,
                dummy_nullifier_proofs: witnesses.dummy_nullifier_proofs,
                cache: self.cache,
            }
            .build()?,
        )))
    }
}

impl PreparedMerge {
    pub fn prove(self, prover: &ProverClient) -> Result<MergeTransactIxData> {
        match self {
            Self::Client(merge) => {
                let proof = prover.prove_merge(&merge.inputs)?;
                Ok(merge.instruction_data(ProofCompressed::try_from(proof)?.to_merge_proof()?))
            }
            Self::Prover(prepared) => match prover.prove_indexed(prepared.as_ref())? {
                ProvenIndexedMerge::Merge(data) => Ok(data),
                ProvenIndexedMerge::Ring(_) => {
                    Err(anyhow!("a plain merge came back as a ring merge"))
                }
            },
        }
    }
}

pub fn landed_slot<R: Rpc>(client: &ZolanaClient<R>, signature: Signature) -> Result<u64> {
    client
        .get_signature_statuses(vec![signature])?
        .first()
        .and_then(|status| status.as_ref())
        .map(|status| status.slot)
        .ok_or_else(|| anyhow!("transaction {signature} has no confirmed slot"))
}

/// The balance is too wide for one transfer: shape selection reaches five
/// inputs on its own, so these UTXOs have to be consolidated by a merge first.
pub fn assert_balance_needs_merging(utxos: &[WalletUtxo], expected: usize) {
    assert_eq!(
        utxos.len(),
        expected,
        "the wallet should hold {expected} utxos"
    );
    assert!(
        canonical_shape(utxos.len(), 2).is_err(),
        "{} utxos should not fit any auto-selected transfer shape",
        utxos.len()
    );
}

/// A merge at the widest supported input count leaves no padding slot, so no
/// dummy nullifier proofs have to be fetched.
pub fn assert_merge_needs_no_padding(prepared: &MergeProofInputs) -> Result<()> {
    assert!(
        prepared.dummy_nullifiers().is_empty(),
        "a full-width merge should need no padding"
    );
    Ok(())
}

/// Known before the merge lands, since its blinding is derived.
pub struct MergedNote<'a> {
    pub owner: &'a ShieldedKeypair,
    pub blinding: [u8; 32],
    pub amount: u64,
    pub tree_id: u16,
}

impl MergedNote<'_> {
    /// No leaf index or slot yet, [`locate_merged_note`] takes them from the indexer.
    pub fn predict(self) -> Result<WalletUtxo> {
        let utxo = Utxo {
            owner: self.owner.shielded_address()?.signing_pubkey,
            asset: Mint::SOL,
            amount: self.amount,
            blinding: self.blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        let nullifier_pubkey = self.owner.nullifier_key.pubkey()?;
        let utxo_hash = utxo.hash(&nullifier_pubkey, &[0; 32], &[0; 32], self.tree_id)?;
        Ok(WalletUtxo {
            nullifier: self
                .owner
                .nullifier_key
                .nullifier(&utxo_hash, &utxo.blinding)?,
            utxo,
            nullifier_pubkey,
            utxo_hash,
            data_hash: None,
            ring_data_hash: None,
            tree_id: self.tree_id,
            leaf_index: 0,
            slot: 0,
            tx_signature: Signature::default(),
            slot_index: 0,
        })
    }
}

/// A merge publishes no ciphertext, so decryption never yields its output.
pub fn locate_merged_note(
    note: WalletUtxo,
    transactions: &[ShieldedTransaction],
) -> Result<WalletUtxo> {
    for tx in transactions {
        for (index, slot) in tx.output_slots.iter().enumerate() {
            if slot.output_context.hash == note.utxo_hash
                && slot.output_context.tree_id == note.tree_id
            {
                return Ok(WalletUtxo {
                    leaf_index: slot.output_context.leaf_index,
                    slot: tx.slot,
                    tx_signature: tx.tx_signature,
                    slot_index: u32::try_from(index)?,
                    ..note
                });
            }
        }
    }
    Err(anyhow!("the merged output is not indexed"))
}

/// The UTXO the transfer spends is exactly the output the merge produces,
/// which is what lets the transfer be proven before the merge is sent.
pub fn assert_merge_output_is_predicted(
    transfer_input: &WalletUtxo,
    merge: &MergeTransactIxData,
) -> Result<()> {
    assert_eq!(
        transfer_input.utxo_hash, merge.output_utxo_hash,
        "the predicted merge output should match the commitment the merge proves"
    );
    Ok(())
}

/// The recipient received the transfer and the sender kept the change.
pub fn assert_balances_after_transfer<R: Rpc>(
    client: &ZolanaClient<R>,
    sender: &ShieldedKeypair,
    recipient: &ShieldedKeypair,
    assets: &AssetRegistry,
    slot: u64,
    sent: u64,
    kept: u64,
) -> Result<()> {
    let response = client.get_shielded_transactions_by_tags(
        vec![
            sender.shielded_address()?.confidential_view_tag()?,
            recipient.shielded_address()?.confidential_view_tag()?,
        ],
        None,
        Some(50),
        Some(IndexerRpcConfig::at_slot(slot)),
    )?;
    assert_eq!(balance(sender, &response.transactions, assets)?, kept);
    assert_eq!(balance(recipient, &response.transactions, assets)?, sent);
    Ok(())
}

fn balance(
    keypair: &ShieldedKeypair,
    transactions: &[ShieldedTransaction],
    assets: &AssetRegistry,
) -> Result<u64> {
    Ok(decrypt_spendable(keypair, transactions, assets)
        .map_err(|e| anyhow!("decrypt transactions: {e:?}"))?
        .balances
        .get_balance(SOL_MINT)
        .map(|balance| balance.amount)
        .unwrap_or_default())
}
