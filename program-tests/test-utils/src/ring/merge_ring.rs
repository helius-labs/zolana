//! Ring merge operations and wallet assertions.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signer::Signer;
use zolana_client::{
    prover::merge_ring::MergeRingProver, MergeProver, ProverClient, SpendProof, TransferSpendInput,
};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::merge_transact::{MergeProof, MERGE_INPUT_COUNT},
        MergeRing,
    },
};
use zolana_keypair::random_blinding;
use zolana_program_test::Rejection;
use zolana_transaction::{
    instructions::merge::{merge_dummy_nullifier, merge_output_blinding},
    Data, SppProofOutputUtxo, Utxo,
};

use super::{MergeRingRecord, RingHarness, SECOND_RING_TEST_PROGRAM_ID};
use crate::{
    localnet::{pack_merge_proof, send_transaction, ZERO},
    test_validator_asserts::{
        assert_account_unchanged, assert_merge_ring, fetch_account, wait_for_indexed_transaction,
        wait_for_merkle_proof, wait_for_non_inclusion_proof, MergeRingAssertArgs,
    },
};

/// Behavioral switches for [`RingHarness::merge_ring_inner`]: the happy path
/// uses the defaults; each rejection scenario flips exactly the flags it needs.
#[derive(Default)]
struct MergeRingOptions {
    /// After a successful merge, replay the exact SPP instruction and assert
    /// the nullifier-tree rejection.
    assert_replay: bool,
    /// Submit through this ring program instead of the harness's own (the
    /// foreign-program rejection).
    submit_ring: Option<solana_pubkey::Pubkey>,
    /// Expect SPP to reject the transaction on proof verification (7008),
    /// leaving the tree untouched.
    expect_proof_rejection: bool,
    /// Build the proof on the default merge rail (tag 13) and submit it
    /// unchanged through `merge_ring` (tag 16); see
    /// [`Self::merge_transact_proof_replayed_as_ring_rejected`].
    prove_for_default_merge: bool,
}

impl RingHarness {
    /// Build, prove, and submit a `merge_ring` of `count` of `name`'s spendable
    /// `asset` ring UTXOs into one consolidated output. The fixture program signs
    /// the ring's `ring_auth` PDA on the CPI into SPP. Records `last_merge` and
    /// tracks the merged output (consumed inputs marked spent) so
    /// `assert_merged_ring` matches the synced wallet.
    pub fn merge_ring(
        &mut self,
        name: &str,
        asset: Address,
        count: usize,
    ) -> Result<solana_signature::Signature> {
        self.merge_ring_inner(name, asset, count, MergeRingOptions::default())?
            .ok_or_else(|| anyhow!("ring merge unexpectedly rejected"))
    }

    /// Execute a valid ring merge and then replay its exact SPP instruction.
    /// The second transaction uses a distinct compute-budget instruction so it
    /// has a fresh signature while reusing the same (now queued) proof-bound
    /// input nullifiers.
    pub fn merge_ring_replay_rejected(
        &mut self,
        name: &str,
        asset: Address,
        count: usize,
    ) -> Result<()> {
        self.merge_ring_inner(
            name,
            asset,
            count,
            MergeRingOptions {
                assert_replay: true,
                ..Default::default()
            },
        )?;
        Ok(())
    }

    pub fn merge_ring_foreign_program_rejected(
        &mut self,
        name: &str,
        asset: Address,
        count: usize,
    ) -> Result<()> {
        let foreign = solana_pubkey::Pubkey::new_from_array(SECOND_RING_TEST_PROGRAM_ID);
        let authority = self.payer.pubkey().to_bytes().into();
        let (_, _) = self.create_ring_config_for(foreign, &authority, true)?;
        self.merge_ring_inner(
            name,
            asset,
            count,
            MergeRingOptions {
                submit_ring: Some(foreign),
                expect_proof_rejection: true,
                ..Default::default()
            },
        )?;
        Ok(())
    }

    /// INV-RING-MERGE-11: build a real default-rail merge proof
    /// (`merge_transact`, instruction tag 13) from default-shielded (non-ring)
    /// UTXOs and submit it unchanged through `merge_ring` (tag 16). SPP
    /// recomputes `external_data_hash` with the ring-merge tag, so the proof
    /// no longer matches and the instruction fails on-chain with
    /// `TransactProofVerificationFailed` (7008), leaving the tree untouched.
    pub fn merge_transact_proof_replayed_as_ring_rejected(
        &mut self,
        name: &str,
        asset: Address,
        count: usize,
    ) -> Result<()> {
        self.merge_ring_inner(
            name,
            asset,
            count,
            MergeRingOptions {
                expect_proof_rejection: true,
                prove_for_default_merge: true,
                ..Default::default()
            },
        )?;
        Ok(())
    }

    fn merge_ring_inner(
        &mut self,
        name: &str,
        asset: Address,
        count: usize,
        options: MergeRingOptions,
    ) -> Result<Option<solana_signature::Signature>> {
        let MergeRingOptions {
            assert_replay,
            submit_ring,
            expect_proof_rejection,
            prove_for_default_merge,
        } = options;
        // Cross-rail replay mechanics: see the canonical rationale on
        // [`Self::merge_transact_proof_replayed_as_ring_rejected`].
        if self.ring_config.is_none() {
            self.create_enabled_ring_config()?;
        }
        self.ensure_fresh_actor(name)?;
        let keypair = self.actor(name).keypair.clone();
        let ring = Address::new_from_array(self.ring_program_id.to_bytes());

        let inputs: Vec<Utxo> = {
            let actor = self.actor_mut(name);
            let mut taken = Vec::with_capacity(count);
            for _ in 0..count {
                let pos = actor
                    .spendable
                    .iter()
                    .position(|u| u.asset == asset)
                    .ok_or_else(|| anyhow!("{name} needs {count} spendable UTXOs of {asset}"))?;
                taken.push(actor.spendable.remove(pos));
            }
            taken
        };

        // Per-input SpendProof, fetched exactly as the transfer path does. The
        // proof's root indices flow through `MergeProofResult` (real slots from
        // the SpendProofs, dummy slots mirroring the first real input). The ring is
        // stamped on each real input by `MergeRingProver::build`, so the
        // SpendProofs must be taken against the UTXO hash carrying that ring.
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
                ring_data_hash: None,
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
                ring_program_id: None,
                data: Data::default(),
            };
            spend_inputs.push(TransferSpendInput {
                utxo,
                nullifier_key: keypair.nullifier_key.clone(),
                data_hash: None,
                ring_data_hash: None,
                proof: None,
                nullifier_proof: Some(dummy_nullifier_proof),
            });
        }

        // The single consolidated ring-owned output is reconstructed from the
        // first real input and its published nullifier.
        let output_blinding = merge_output_blinding(&keypair.nullifier_key, &first_nullifier)?;
        let output = SppProofOutputUtxo {
            owner_address: Some(keypair.shielded_address()?),
            asset,
            amount: total,
            blinding: output_blinding,
            ring_program_id: None,
            ring_data_hash: None,
            data_hash: None,
            owner_tag: None,
            data: Data::default(),
        };

        let expiry_unix_ts = u64::MAX;

        // Both rails share the 8-in/1-out merge witness (see
        // [`Self::merge_transact_proof_replayed_as_ring_rejected`]). For the
        // cross-rail replay the proof is built by the default `MergeProver`
        // (tag 13), then wrapped in the `merge_ring` instruction data
        // (tag 16) unchanged.
        let (data, output_hash, input_nullifiers) = if prove_for_default_merge {
            let result = MergeProver {
                inputs: spend_inputs,
                output,
                expiry_unix_ts,
                signing_pubkey: owner,
                nullifier_key: keypair.nullifier_key.clone(),
            }
            .build()?;
            let proof = ProverClient::local().prove_merge(&result.inputs)?;
            (
                result.ring_instruction_data(pack_merge_proof(&proof)?, ZERO),
                result.output_hash,
                result.nullifiers,
            )
        } else {
            let result = MergeRingProver {
                inputs: spend_inputs,
                output,
                expiry_unix_ts,
                signing_pubkey: owner,
                nullifier_key: keypair.nullifier_key.clone(),
                ring_program_id: ring,
            }
            .build()?;
            let proof = ProverClient::local().prove_merge_ring(&result.inputs)?;
            (
                result.ring_instruction_data(pack_merge_proof(&proof)?, ZERO),
                result.output_hash,
                result.nullifiers,
            )
        };

        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let payer = self.payer.insecure_clone();
        let merge_ix = MergeRing {
            input_tree: self.tree,
            output_tree: self.tree,
            ring_program_id: submit_ring.unwrap_or(self.ring_program_id),
            payer: payer.pubkey(),
            data: data.merge.clone(),
            output_ring_data_hash: data.output_ring_data_hash,
        }
        .instruction();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let send_result = send_transaction(
            &mut self.rpc,
            &[compute_budget, merge_ix.clone()],
            &payer.pubkey(),
            &[&payer],
        );
        if expect_proof_rejection {
            match send_result {
                Ok(_) => {
                    return Err(anyhow!(
                        "merge submitted with a mismatched proof unexpectedly succeeded"
                    ))
                }
                Err(error) => {
                    // The mismatched proof must fail in the SPP instruction
                    // (index 1, after the compute-budget instruction).
                    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed)
                        .at(1)
                        .assert_client(&error);
                    assert_account_unchanged(&self.rpc, &self.tree, &tree_before)?;
                    self.actor_mut(name).spendable.extend(inputs);
                    return Ok(None);
                }
            }
        }
        let sig = send_result?;

        let indexed = wait_for_indexed_transaction(&self.indexer, first_nullifier, sig);

        // Functional assert at the action: the tree root advanced (output appended),
        // photon serves a tracking inclusion proof for the consolidated output, and
        // every spent input nullifier is now present. Run here because the spent
        // nullifiers and the pre-merge tree snapshot are in scope; `MergeRingRecord`
        // (the frozen Harness contract) carries only the output hash, so the
        // wallet-discovery assert is deferred to `assert_merged_ring`.
        assert_merge_ring(
            &self.rpc,
            &self.indexer,
            MergeRingAssertArgs {
                tree: &self.tree,
                output_hash,
                input_nullifiers: &input_nullifiers,
                tree_before: &tree_before,
            },
        )?;

        // The merged output is tagged by its first input nullifier.
        self.indexed.push(indexed);

        self.last_merge = Some(MergeRingRecord {
            actor: name.to_string(),
            output_hash,
        });

        if assert_replay {
            // The only writable instruction accounts are the fee payer and the
            // tree. Capturing the post-success tree therefore covers every
            // non-fee-payer account that a rejected replay could mutate.
            let tree_after_success = fetch_account(&self.rpc, &self.tree)?;
            let replay_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_399_999);
            match send_transaction(
                &mut self.rpc,
                &[replay_budget, merge_ix],
                &payer.pubkey(),
                &[&payer],
            ) {
                Ok(_) => return Err(anyhow!("replayed ring merge unexpectedly succeeded")),
                Err(error) => {
                    // The replay must fail in the SPP instruction (index 1,
                    // after the compute-budget instruction).
                    Rejection::pool(ShieldedPoolError::NullifierTreeUpdateFailed)
                        .at(1)
                        .assert_client(&error);
                    assert_account_unchanged(&self.rpc, &self.tree, &tree_after_success)?;
                }
            }
        }
        Ok(Some(sig))
    }

    /// Confirm the consolidated ring output is present on-chain: the inclusion +
    /// nullifier-presence check ran at the action (`merge_ring`); here we re-confirm
    /// the indexer serves an inclusion proof for the appended output recorded for
    /// `name`.
    pub fn assert_merged_ring(&mut self, name: &str) -> Result<()> {
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
        let _ = wait_for_merkle_proof(&self.indexer, self.tree_address, output_hash);
        Ok(())
    }

    /// Attempt a `merge_ring` with a zeroed 192-byte proof, expecting SPP's shared
    /// merge verifier to reject it. Builds the same instruction the happy path does
    /// (real inputs, padded dummies, a real output and ciphertext) but replaces the
    /// proof bytes with zeros, so only proof verification fails.
    pub fn merge_ring_bad_proof(&mut self, name: &str, asset: Address, count: usize) -> Result<()> {
        if self.ring_config.is_none() {
            self.create_enabled_ring_config()?;
        }
        self.ensure_fresh_actor(name)?;
        let keypair = self.actor(name).keypair.clone();
        let ring = Address::new_from_array(self.ring_program_id.to_bytes());

        // Borrow (do not consume) `count` spendable UTXOs: a rejected merge spends
        // nothing, so the inputs must remain available for any later operation.
        let inputs: Vec<Utxo> = {
            let actor = self.actor(name);
            let mut taken = Vec::with_capacity(count);
            for utxo in actor.spendable.iter().filter(|u| u.asset == asset) {
                taken.push(utxo.clone());
                if taken.len() == count {
                    break;
                }
            }
            if taken.len() < count {
                return Err(anyhow!("{name} needs {count} spendable UTXOs of {asset}"));
            }
            taken
        };

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
                ring_data_hash: None,
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
                ring_program_id: None,
                data: Data::default(),
            };
            spend_inputs.push(TransferSpendInput {
                utxo,
                nullifier_key: keypair.nullifier_key.clone(),
                data_hash: None,
                ring_data_hash: None,
                proof: None,
                nullifier_proof: Some(dummy_nullifier_proof),
            });
        }

        let output = SppProofOutputUtxo {
            owner_address: Some(keypair.shielded_address()?),
            asset,
            amount: total,
            blinding: merge_output_blinding(&keypair.nullifier_key, &first_nullifier)?,
            ring_program_id: None,
            ring_data_hash: None,
            data_hash: None,
            owner_tag: None,
            data: Data::default(),
        };

        let result = MergeRingProver {
            inputs: spend_inputs,
            output,
            expiry_unix_ts: u64::MAX,
            signing_pubkey: owner,
            nullifier_key: keypair.nullifier_key.clone(),
            ring_program_id: ring,
        }
        .build()?;

        // Assemble the instruction data exactly as the happy path does, then
        // zero the proof so verification is the only thing that fails.
        let data = result.ring_instruction_data(MergeProof::zeroed(), ZERO);

        let payer = self.payer.insecure_clone();
        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let merge_ix = MergeRing {
            input_tree: self.tree,
            output_tree: self.tree,
            ring_program_id: self.ring_program_id,
            payer: payer.pubkey(),
            data: data.merge.clone(),
            output_ring_data_hash: data.output_ring_data_hash,
        }
        .instruction();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        match send_transaction(
            &mut self.rpc,
            &[compute_budget, merge_ix],
            &payer.pubkey(),
            &[&payer],
        ) {
            Ok(_) => Err(anyhow!(
                "ring merge with an invalid proof unexpectedly succeeded"
            )),
            Err(error) => {
                Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed)
                    .at(1)
                    .assert_client(&error);
                assert_account_unchanged(&self.rpc, &self.tree, &tree_before)?;
                Ok(())
            }
        }
    }
}
