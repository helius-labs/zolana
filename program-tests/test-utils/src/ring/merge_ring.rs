//! Ring merge operations and wallet assertions.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signer::Signer;
use zolana_client::{MergeProver, ProverClient};
use zolana_interface::{
    error::ShieldedPoolError, instruction::instruction_data::merge_transact::MergeProof,
};
use zolana_keypair::ShieldedKeypair;
use zolana_program::instruction::MergeRing;
use zolana_program_test::Rejection;
use zolana_transaction::Utxo;

use super::{MergeRingRecord, RingHarness, SECOND_RING_TEST_PROGRAM_ID};
use crate::{
    localnet::{pack_merge_proof, send_transaction, ZERO},
    nullifier_pda::assert_nullifier_pdas,
    test_validator_asserts::{
        assert_account_unchanged, assert_merge_ring, fetch_account, wait_for_indexed_transaction,
        wait_for_merkle_proof, MergeRingAssertArgs,
    },
};

impl RingHarness {
    fn merge_prover(
        &self,
        keypair: &ShieldedKeypair,
        inputs: &[Utxo],
        ring: Option<Address>,
    ) -> Result<MergeProver> {
        let nullifier_pk = keypair.nullifier_key.pubkey()?;
        let hashes = inputs
            .iter()
            .map(|input| input.hash(&nullifier_pk, &ZERO, &ZERO, self.tree_id))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let states = crate::test_validator_asserts::wait_for_merkle_proofs(
            &self.indexer,
            self.tree_address,
            &hashes,
        );
        let notes = inputs
            .iter()
            .zip(&states)
            .map(|(utxo, state)| {
                crate::utxo::wallet(
                    utxo.clone(),
                    &keypair.nullifier_key,
                    self.tree_id,
                    state.leaf_index,
                    None,
                    None,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let transaction = match ring {
            Some(ring) => zolana_transaction::instructions::merge::MergeTransaction::new_with_ring(
                notes, ring, None,
            )?,
            None => zolana_transaction::instructions::merge::MergeTransaction::new(notes)?,
        }
        .with_output_tree_id(self.tree_id)
        .encrypt(keypair)?;
        let mut nullifiers: Vec<_> = transaction
            .input_utxo_hashes()?
            .iter()
            .map(|input| input.nullifier)
            .collect();
        nullifiers.extend(transaction.dummy_nullifiers());
        let mut proofs = crate::test_validator_asserts::wait_for_non_inclusion_proofs(
            &self.indexer,
            self.tree_address,
            &nullifiers,
        );
        let dummy_nullifier_proofs = proofs.split_off(inputs.len());
        let proofs = states
            .into_iter()
            .zip(proofs)
            .map(|(state, nullifier)| zolana_client::SpendProof { state, nullifier })
            .collect();
        Ok(MergeProver {
            transaction,
            nullifier_key: keypair.nullifier_key.clone(),
            proofs,
            dummy_nullifier_proofs,
            cache: None,
        })
    }
}

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
    /// The second transaction asks for a distinct compute-unit limit so it has
    /// a fresh signature while reusing the same (now queued) proof-bound input
    /// nullifiers.
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
        let (_, _) = self.create_ring_config_for(foreign, &authority)?;
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
                    .position(|u| u.asset.asset == asset)
                    .ok_or_else(|| anyhow!("{name} needs {count} spendable UTXOs of {asset}"))?;
                taken.push(actor.spendable.remove(pos));
            }
            taken
        };

        let prover = self.merge_prover(
            &keypair,
            &inputs,
            if prove_for_default_merge {
                None
            } else {
                Some(ring)
            },
        )?;
        let first_nullifier = prover.transaction.input_utxos[0].nullifier;
        let result = prover.build()?;
        let proof = if prove_for_default_merge {
            ProverClient::local().prove_merge(&result.inputs)?
        } else {
            ProverClient::local().prove_merge_ring(&result.inputs)?
        };
        let data = result.ring_instruction_data(pack_merge_proof(&proof)?);
        let output_hash = result.output_hash;
        let input_nullifiers = result.nullifiers;

        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let payer = self.payer.insecure_clone();
        let merge_ix = MergeRing {
            input_tree: self.tree,
            output_tree: self.tree,
            ring_program_id: submit_ring.unwrap_or(self.ring_program_id),
            payer: payer.pubkey(),
            data: data.merge.clone(),
            output_ring_data_hash: data.output_ring_data_hash,
            cache: None,
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
                    // The mismatched proof must fail in the SPP instruction, the
                    // only one a v1 transaction carries: its compute ceilings
                    // live in the message header.
                    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed)
                        .at(0)
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
            // The writable instruction accounts are the fee payer, the tree and
            // the nullifier PDAs. A rejected replay rolls the nullifier PDAs back to
            // their post-success state, so capturing the post-success tree covers
            // every other non-fee-payer account a replay could mutate.
            let tree_after_success = fetch_account(&self.rpc, &self.tree)?;
            // A budget one unit below the original keeps the replayed message
            // distinct from the landed one, so the runtime reaches the program
            // instead of dropping it as an already-processed signature. In a v1
            // transaction that difference sits in the message header.
            let replay_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_399_999);
            match send_transaction(
                &mut self.rpc,
                &[replay_budget, merge_ix],
                &payer.pubkey(),
                &[&payer],
            ) {
                Ok(_) => return Err(anyhow!("replayed ring merge unexpectedly succeeded")),
                Err(error) => {
                    // The replay must fail in the SPP instruction, the only one
                    // the transaction carries: every nullifier already has an
                    // initialized nullifier PDA.
                    Rejection::pool(ShieldedPoolError::NullifierAlreadyQueued)
                        .at(0)
                        .assert_client(&error);
                    assert_account_unchanged(&self.rpc, &self.tree, &tree_after_success)?;
                    assert_nullifier_pdas(&self.rpc, &self.tree, &input_nullifiers)?;
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
            for utxo in actor.spendable.iter().filter(|u| u.asset.asset == asset) {
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

        let result = self.merge_prover(&keypair, &inputs, Some(ring))?.build()?;

        // Assemble the instruction data exactly as the happy path does, then
        // zero the proof so verification is the only thing that fails.
        let data = result.ring_instruction_data(MergeProof::zeroed());

        let payer = self.payer.insecure_clone();
        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let merge_ix = MergeRing {
            input_tree: self.tree,
            output_tree: self.tree,
            ring_program_id: self.ring_program_id,
            payer: payer.pubkey(),
            data: data.merge.clone(),
            output_ring_data_hash: data.output_ring_data_hash,
            cache: None,
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
                    .at(0)
                    .assert_client(&error);
                assert_account_unchanged(&self.rpc, &self.tree, &tree_before)?;
                Ok(())
            }
        }
    }
}
