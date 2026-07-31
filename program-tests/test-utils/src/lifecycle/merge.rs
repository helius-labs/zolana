//! Merge-service operations and wallet assertions.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::{MergeProver, ProverClient, SpendProof, TransferSpendInput};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{instruction_data::merge_transact::MERGE_INPUT_COUNT, MergeTransact},
};
use zolana_keypair::{
    merge::{merge_dummy_nullifier, merge_output_blinding},
    random_blinding,
};
use zolana_program_test::Rejection;
use zolana_smart_account_client::execute_sync_ix;
use zolana_transaction::{Data, OutputContext, SppProofOutputUtxo, Utxo, WalletUtxo};
use zolana_user_registry_interface::{
    instruction::{register, set_merging_enabled, RegisterData},
    user_record_pda,
};

use super::LifecycleHarness;
use crate::{
    localnet::{pack_merge_proof, send_transaction, ZERO},
    test_validator_asserts::{
        assert_account_unchanged, fetch_account, wait_for_indexed_transaction,
        wait_for_merkle_proof, wait_for_non_inclusion_proof,
    },
};

/// What the consolidated-output assert needs after a merge: the actor that owns
/// the appended output and the output's hash (for the inclusion-proof check).
pub(crate) struct MergeRecord {
    pub(crate) actor: String,
    pub(crate) output_hash: [u8; 32],
}

impl LifecycleHarness {
    /// Register `name` on the user-registry under a fresh Solana keypair and opt the
    /// record into merging. Returns the registering Solana keypair so the merge helper
    /// can derive the `user_record` PDA the program reads. `enable_merge` gates the
    /// `set_merging_enabled` opt-in so the disabled path can be exercised.
    pub fn register_merge_owner(&mut self, name: &str, enable_merge: bool) -> Result<Keypair> {
        self.ensure_fresh_actor(name)?;
        let keypair = self.actor(name).keypair.clone();

        // Every actor is eddsa-owned: it registers under its own ed25519 signing
        // key (so `record.owner` is the identity merge derives `signing_pk_field`
        // from) with no `owner_p256`.
        let owner = self.actor(name).solana_signer.as_ref().expect("lifecycle actors are eddsa-owned").insecure_clone();
        self.rpc.airdrop(&owner.pubkey(), 1_000_000_000)?;

        let register_data = RegisterData {
            owner_p256: None,
            nullifier_pubkey: keypair.nullifier_key.pubkey()?,
            viewing_pubkey: *keypair.viewing_pubkey().as_bytes(),
        };
        let user_record = user_record_pda(&owner.pubkey()).0;
        let register_ix = register(user_record, owner.pubkey(), register_data);
        send_transaction(&mut self.rpc, &[register_ix], &owner.pubkey(), &[&owner])?;

        // Opt the record into merging. When enabled, any caller may run
        // `merge_transact`; the disabled path leaves it `false`, which the program
        // rejects with `MergeDisabled`.
        let set_enabled_ix = set_merging_enabled(user_record, owner.pubkey(), enable_merge);
        send_transaction(&mut self.rpc, &[set_enabled_ix], &owner.pubkey(), &[&owner])?;
        Ok(owner)
    }

    /// Build, prove, and submit a merge of `count` of `name`'s spendable `asset`
    /// UTXOs into one consolidated output, run by the configured merge authority for
    /// the registered owner `owner_solana`. Returns the transaction send result so
    /// the caller can assert success or the `MergeDisabled` failure.
    pub fn merge(
        &mut self,
        name: &str,
        owner_solana: &Keypair,
        asset: Address,
        count: usize,
    ) -> Result<solana_signature::Signature> {
        self.ensure_fresh_actor(name)?;
        let keypair = self.actor(name).keypair.clone();

        let (inputs, input_positions): (Vec<Utxo>, Vec<usize>) = {
            let actor = self.actor(name);
            let selected = actor
                .spendable
                .iter()
                .enumerate()
                .filter(|(_, utxo)| utxo.asset == asset)
                .take(count)
                .map(|(index, utxo)| (utxo.clone(), index))
                .collect::<Vec<_>>();
            if selected.len() != count {
                return Err(anyhow!("{name} needs {count} spendable UTXOs of {asset}"));
            }
            selected.into_iter().unzip()
        };

        // Per-input SpendProof, exactly as the transfer path fetches them. The
        // proof's root indices flow through `MergeProofResult` (real slots from the
        // SpendProofs, dummy slots mirroring the first real input).
        let nullifier_pk = keypair.nullifier_key.pubkey()?;
        let mut spend_inputs: Vec<TransferSpendInput> = Vec::with_capacity(MERGE_INPUT_COUNT);
        let mut total: u64 = 0;
        for utxo in &inputs {
            total += utxo.amount;
            let utxo_hash = utxo.hash(&nullifier_pk, &ZERO, &ZERO)?;
            let nullifier = keypair
                .nullifier_key
                .nullifier(&utxo_hash, &utxo.blinding)?;
            let state = wait_for_merkle_proof(&self.indexer, self.tree_address, utxo_hash);
            let nf = wait_for_non_inclusion_proof(&self.indexer, self.tree_address, nullifier);
            spend_inputs.push(TransferSpendInput {
                utxo: utxo.clone(),
                nullifier_key: keypair.nullifier_key.clone(),
                data_hash: None,
                zone_data_hash: None,
                proof: Some(SpendProof {
                    state,
                    nullifier: nf,
                }),
                nullifier_proof: None,
            });
        }

        let first_hash = inputs[0].hash(&nullifier_pk, &ZERO, &ZERO)?;
        let first_nullifier = keypair
            .nullifier_key
            .nullifier(&first_hash, &inputs[0].blinding)?;

        // Pad to the 8-input shape with dummies. A dummy mirrors the first real
        // input's UTXO root but carries a non-inclusion proof for its own
        // deterministic nullifier.
        let owner = keypair.signing_pubkey();
        while spend_inputs.len() < MERGE_INPUT_COUNT {
            let slot = spend_inputs.len();
            let dummy_nullifier =
                merge_dummy_nullifier(&keypair.nullifier_key, &first_nullifier, slot as u8)?;
            let dummy_nullifier_proof =
                wait_for_non_inclusion_proof(&self.indexer, self.tree_address, dummy_nullifier);
            let utxo = Utxo {
                owner,
                asset,
                amount: 0,
                blinding: random_blinding(),
                zone_program_id: None,
                data: Data::default(),
            };
            spend_inputs.push(TransferSpendInput {
                utxo,
                nullifier_key: keypair.nullifier_key.clone(),
                data_hash: None,
                zone_data_hash: None,
                proof: None,
                nullifier_proof: Some(dummy_nullifier_proof),
            });
        }

        // The circuit derives the consolidated output blinding from the first
        // real input and its published nullifier.
        let output_blinding = merge_output_blinding(&keypair.nullifier_key, &first_nullifier)?;
        let output = SppProofOutputUtxo {
            owner_address: Some(keypair.shielded_address()?),
            asset,
            amount: total,
            blinding: output_blinding,
            zone_program_id: None,
            zone_data_hash: None,
            data_hash: None,
            owner_tag: None,
            data: Data::default(),
        };

        let expiry_unix_ts = u64::MAX;

        let result = MergeProver {
            inputs: spend_inputs,
            output: output.clone(),
            expiry_unix_ts,
            signing_pubkey: owner,
            nullifier_key: keypair.nullifier_key.clone(),
        }
        .build()?;

        let proof = ProverClient::local().prove_merge(&result.inputs)?;

        // The client assembles the instruction data (incl. the encrypted_utxo blob)
        // the same way the prover bound `external_data_hash`, so they agree on-chain.
        let data = result.instruction_data(pack_merge_proof(&proof)?);

        let user_record = user_record_pda(&owner_solana.pubkey()).0;
        let payer_before = fetch_account(&self.rpc, &self.merge_vault)?;
        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let user_record_before = fetch_account(&self.rpc, &user_record)?;
        let merge_ix = MergeTransact {
            input_tree: self.tree,
            output_tree: self.tree,
            payer: self.merge_vault,
            user_record,
            data,
        }
        .instruction();
        let sync_ix = execute_sync_ix(
            &self.merge_settings,
            0,
            &[self.merge_key.pubkey()],
            &[merge_ix],
        );
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let merge_key = self.merge_key.insecure_clone();
        let sig = send_transaction(
            &mut self.rpc,
            &[compute_budget, sync_ix],
            &merge_key.pubkey(),
            &[&merge_key],
        )?;
        // A successful merge collects the forester fee from the inner payer: one
        // 20-lamport share per inserted nullifier, transferred into the tree.
        let forester_fee = MERGE_INPUT_COUNT as u64 * 20;
        let payer_after = fetch_account(&self.rpc, &self.merge_vault)?;
        assert_eq!(
            payer_before.lamports - payer_after.lamports,
            forester_fee,
            "merge must charge the payer one forester share per nullifier"
        );
        let tree_after = fetch_account(&self.rpc, &self.tree)?;
        assert_eq!(
            tree_after.lamports - tree_before.lamports,
            forester_fee,
            "merge forester fee must accrue to the tree"
        );
        assert_account_unchanged(&self.rpc, &user_record, &user_record_before)?;

        // Only commit the fixture's spendable set after the validator accepted the
        // transaction. Rejected merges leave both chain and harness state intact.
        for index in input_positions.into_iter().rev() {
            self.actor_mut(name).spendable.remove(index);
        }

        // The merged output carries the owner's signing-pubkey view tag (the
        // confidential default-zone tag), so the indexed transaction is located by
        // that tag and added to the synced stream; the owner's `Wallet::sync` then
        // rediscovers the consolidated output and marks the consumed inputs spent
        // from the transaction's nullifiers.
        let owner_tag = keypair.signing_pubkey().confidential_view_tag()?;
        let indexed = wait_for_indexed_transaction(&self.indexer, owner_tag, sig);

        // A real wallet would already have discovered the deposits it selected
        // for this merge. This local lifecycle harness keeps deposits only in its
        // spendable list, so seed any missing input notes before replaying the
        // merge event; reconstruction needs their amounts, assets, and first
        // blinding.
        for input in &inputs {
            let input_hash = input.hash(&nullifier_pk, &ZERO, &ZERO)?;
            if self
                .actor(name)
                .wallet
                .utxos
                .iter()
                .any(|note| note.output_context.hash == input_hash)
            {
                continue;
            }
            let proof = wait_for_merkle_proof(&self.indexer, self.tree_address, input_hash);
            let note = WalletUtxo {
                utxo: input.clone(),
                output_context: OutputContext {
                    hash: input_hash,
                    tree: proof.merkle_context.tree,
                    leaf_index: proof.leaf_index,
                },
                nullifier: input.nullifier(&input_hash, &keypair.nullifier_key)?,
                data_hash: None,
                zone_data_hash: None,
                spent: true,
            };
            let actor = self.actor_mut(name);
            actor.wallet.utxos.push(note.clone());
            actor.expected.push(note);
        }

        // The consolidated output owned by the actor, tracked like a transfer
        // recipient UTXO so `assert_utxos` matches the synced wallet.
        let merged_utxo = self.build_expected(
            name,
            keypair.signing_pubkey(),
            asset,
            total,
            output_blinding,
            &indexed,
        )?;
        self.actor_mut(name).expected.push(merged_utxo);

        // Mark consumed inputs spent if they were decrypted (tracked) UTXOs.
        for input in &inputs {
            let consumed_hash = input.hash(&nullifier_pk, &ZERO, &ZERO)?;
            if let Some(utxo) = self
                .actor_mut(name)
                .expected
                .iter_mut()
                .find(|n| n.output_context.hash == consumed_hash)
            {
                utxo.spent = true;
            }
        }

        self.indexed.push(indexed);

        // Record what the inclusion-proof assert needs: the appended output hash.
        self.last_merge = Some(MergeRecord {
            actor: name.to_string(),
            output_hash: result.output_hash,
        });
        Ok(sig)
    }

    /// Functional assert for the consolidated output, the standard
    /// "syncs / UTXOs match" path: the owner's `Wallet::sync` rediscovers the merged
    /// output by its bootstrap view tag and marks the consumed inputs spent, and the
    /// synced wallet must match the tracked expected set. Also confirms the indexer
    /// serves an inclusion proof for the appended output.
    pub fn assert_merged(&mut self, name: &str) -> Result<()> {
        let output_hash = {
            let record = self
                .last_merge
                .as_ref()
                .ok_or_else(|| anyhow!("no merge recorded"))?;
            if record.actor != name {
                return Err(anyhow!("last merge was for {}, not {name}", record.actor));
            }
            record.output_hash
        };

        self.sync(name)?;
        let merged_present = self
            .actor(name)
            .wallet
            .utxos
            .iter()
            .any(|w| w.output_context.hash == output_hash);
        assert!(
            merged_present,
            "{name}'s synced wallet should hold the consolidated output"
        );
        self.assert_utxos(name)?;

        // The output was appended to the tree (inclusion proof is served).
        let _ = wait_for_merkle_proof(&self.indexer, self.tree_address, output_hash);
        Ok(())
    }

    /// Attempt a merge expecting it to fail with `MergeDisabled`; the owner is
    /// registered but never enabled merging.
    pub fn merge_expect_disabled(
        &mut self,
        name: &str,
        owner_solana: &Keypair,
        asset: Address,
        count: usize,
    ) -> Result<()> {
        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let spendable_before = self.actor(name).spendable.clone();
        match self.merge(name, owner_solana, asset, count) {
            Ok(_) => Err(anyhow!(
                "merge unexpectedly succeeded for a disabled service"
            )),
            Err(error) => {
                let client_error = error
                    .downcast_ref::<zolana_client::ClientError>()
                    .unwrap_or_else(|| panic!("expected typed client error, got {error:?}"));
                Rejection::pool(ShieldedPoolError::MergeDisabled)
                    .at(1)
                    .assert_client(client_error);
                assert_account_unchanged(&self.rpc, &self.tree, &tree_before)?;
                assert_eq!(
                    self.actor(name).spendable,
                    spendable_before,
                    "rejected merge changed fixture spendable UTXOs"
                );
                Ok(())
            }
        }
    }

    /// Prove a merge bound to `name`'s registered signing / viewing keys but
    /// submit it with `record_owner`'s `user_record`. The program derives the
    /// owner public inputs from the passed record, so the recomputed
    /// public-input hash no longer matches the proof and verification fails.
    /// Asserts the exact `TransactProofVerificationFailed` rejection with the
    /// tree account and the fixture's spendable set left unchanged.
    pub fn merge_expect_foreign_record_rejected(
        &mut self,
        name: &str,
        record_owner: &Keypair,
        asset: Address,
        count: usize,
    ) -> Result<()> {
        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let spendable_before = self.actor(name).spendable.clone();
        match self.merge(name, record_owner, asset, count) {
            Ok(_) => Err(anyhow!(
                "merge unexpectedly succeeded with a foreign user_record"
            )),
            Err(error) => {
                let client_error = error
                    .downcast_ref::<zolana_client::ClientError>()
                    .unwrap_or_else(|| panic!("expected typed client error, got {error:?}"));
                Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed)
                    .at(1)
                    .assert_client(client_error);
                assert_account_unchanged(&self.rpc, &self.tree, &tree_before)?;
                assert_eq!(
                    self.actor(name).spendable,
                    spendable_before,
                    "rejected merge changed fixture spendable UTXOs"
                );
                Ok(())
            }
        }
    }
}
