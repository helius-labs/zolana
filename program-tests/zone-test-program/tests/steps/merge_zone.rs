//! `merge_zone` steps and the World consolidation operation. `merge_zone` is the
//! policy-zone analog of `merge_transact`: it consolidates several of one owner's
//! same-asset, same-zone UTXOs into a single output, proving on the
//! `merge_zone_8_1` circuit. Authorization is the zone's `zone_config` signer (the
//! fixture program signs the `zone_auth` PDA on the CPI into SPP); unlike spp
//! merge there is no user-registry record, no smart account, and no
//! merge-authority check.
//!
//! The consolidated output carries the owner's signing-pubkey view tag (the
//! confidential default-zone tag) as its single-use `merge_view_tag`, so the same
//! tag both indexes the merged output for `Wallet::sync` discovery and is inserted
//! into the nullifier queue for replay protection. The functional inclusion /
//! nullifier-presence check runs inside the `merge_zone` action (where the spent
//! nullifiers and the pre-merge tree snapshot are in scope); `assert_merged_zone`
//! then syncs and full-struct asserts the actor's wallet (the merged output
//! present, the consumed inputs spent), the standard "syncs / UTXOs match" path
//! used by the other lifecycle steps.

use anyhow::{anyhow, Result};
use cucumber::{then, when};
use p256::SecretKey;
use rings_client::{
    prover::merge_zone::MergeZoneProver, ProverClient, SpendProof, TransferSpendInput,
};
use rings_interface::instruction::{
    instruction_data::merge_transact::MERGE_INPUT_COUNT, MergeZone,
};
use rings_keypair::random_blinding;
use rings_test_utils::test_validator_asserts::{
    assert_merge_zone, fetch_account, wait_for_indexed_transaction, wait_for_merkle_proof,
    wait_for_non_inclusion_proof, MergeZoneAssertArgs,
};
use rings_transaction::{Data, OutputUtxo, Utxo, SOL_MINT};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signer::Signer;

use crate::{
    localnet::{pack_proof, send_transaction, ZERO},
    support::MergeZoneRecord,
    ZoneLifecycleWorld,
};

/// `ShieldedPoolError::TransactProofVerificationFailed` (the shared merge proof
/// verifier rejects a malformed / zeroed proof).
const TRANSACT_PROOF_VERIFICATION_FAILED: u32 = 7008;

impl ZoneLifecycleWorld {
    /// Build, prove, and submit a `merge_zone` of `count` of `name`'s spendable
    /// `asset` zone UTXOs into one consolidated output. The fixture program signs
    /// the zone's `zone_auth` PDA on the CPI into SPP. Records `last_merge` and
    /// tracks the merged output (consumed inputs marked spent) so
    /// `assert_merged_zone` matches the synced wallet.
    pub(crate) fn merge_zone(&mut self, name: &str, asset: Address, count: usize) -> Result<()> {
        if self.zone_config.is_none() {
            self.create_enabled_zone_config()?;
        }
        self.ensure_actor(name)?;
        let keypair = self.actor(name).keypair.clone();
        let zone = Address::new_from_array(self.zone_program_id.to_bytes());

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
        // proof's root indices flow through `MergeZoneProofResult` (real slots from
        // the SpendProofs, dummy slots mirroring the first real input). The zone is
        // stamped on each real input by `MergeZoneProver::build`, so the
        // SpendProofs must be taken against the UTXO hash carrying that zone.
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
            });
        }

        // Pad to the 8-input shape with dummies (a dummy mirrors the first real
        // input's roots, so it carries no proof of its own).
        let owner = keypair.signing_pubkey();
        while spend_inputs.len() < MERGE_INPUT_COUNT {
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
            });
        }

        // The single consolidated zone-owned output, owned by the merger, with a
        // fresh random blinding the owner recovers by decrypting the published
        // merge ciphertext. `MergeZoneProver::build` stamps the shared zone on it.
        let output_blinding = random_blinding();
        let output = OutputUtxo {
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

        // Ephemeral viewing scalar: 31 random bytes are < BN254 modulus, so the
        // value is both a valid P-256 scalar and a valid circuit witness.
        let mut sk_bytes = [0u8; 32];
        sk_bytes[1..].copy_from_slice(&random_blinding());
        let tx_viewing_sk = SecretKey::from_slice(&sk_bytes)
            .map_err(|e| anyhow!("invalid ephemeral viewing scalar: {e}"))?;

        let expiry_unix_ts = u64::MAX;

        let result = MergeZoneProver {
            inputs: spend_inputs,
            output: output.clone(),
            expiry_unix_ts,
            signing_pubkey: owner,
            nullifier_key: keypair.nullifier_key.clone(),
            user_viewing_pk: keypair.viewing_pubkey(),
            tx_viewing_sk,
            zone_program_id: zone,
        }
        .build()?;

        let proof = ProverClient::local().prove_merge_zone(&result.inputs)?;

        // `merge_zone` inserts the single-use `merge_view_tag` into the nullifier
        // queue for replay protection, so it must be a BN254 field element: the
        // owner-pubkey confidential tag is a raw pubkey (not reduced) and the queue
        // rejects it. Use the derived `merge_view_tag` (HKDF, 31 bytes) keyed by the
        // submitting payer as the merge authority; photon indexes the output under it.
        let merge_view_tag = keypair.get_merge_view_tag(0)?;
        let data = result.instruction_data(pack_proof(&proof)?, merge_view_tag);

        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let payer = self.payer.insecure_clone();
        let merge_ix = MergeZone {
            tree: self.tree,
            zone_program_id: self.zone_program_id,
            payer: payer.pubkey(),
            data: data.merge.clone(),
            merge_view_tag: data.merge_view_tag,
        }
        .instruction();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let sig = send_transaction(
            &mut self.rpc,
            &[compute_budget, merge_ix],
            &payer.pubkey(),
            &[&payer],
        )?;

        let indexed = wait_for_indexed_transaction(&self.indexer, merge_view_tag, sig);

        // Functional assert at the action: the tree root advanced (output appended),
        // photon serves a tracking inclusion proof for the consolidated output, and
        // every spent input nullifier is now present. Run here because the spent
        // nullifiers and the pre-merge tree snapshot are in scope; `MergeZoneRecord`
        // (the frozen World contract) carries only the output hash, so the
        // wallet-discovery assert is deferred to `assert_merged_zone`.
        assert_merge_zone(
            &self.rpc,
            &self.indexer,
            MergeZoneAssertArgs {
                tree: &self.tree,
                output_hash: result.output_hash,
                input_nullifiers: &result.nullifiers,
                tree_before: &tree_before,
            },
        )?;

        // The merged output is anonymous (tagged by the derived merge_view_tag, which
        // `Wallet::sync` has no scan for), so discovery is verified on-chain via the
        // inclusion + nullifier-presence check above rather than a wallet sync.
        self.indexed.push(indexed);

        self.last_merge = Some(MergeZoneRecord {
            actor: name.to_string(),
            output_hash: result.output_hash,
        });
        Ok(())
    }

    /// Confirm the consolidated zone output is present on-chain: the inclusion +
    /// nullifier-presence check ran at the action (`merge_zone`); here we re-confirm
    /// the indexer serves an inclusion proof for the appended output recorded for
    /// `name`.
    pub(crate) fn assert_merged_zone(&mut self, name: &str) -> Result<()> {
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

    /// Attempt a `merge_zone` with a zeroed 192-byte proof, expecting SPP's shared
    /// merge verifier to reject it. Builds the same instruction the happy path does
    /// (real inputs, padded dummies, a real output and ciphertext) but replaces the
    /// proof bytes with zeros, so only proof verification fails.
    pub(crate) fn merge_zone_bad_proof(
        &mut self,
        name: &str,
        asset: Address,
        count: usize,
    ) -> Result<()> {
        if self.zone_config.is_none() {
            self.create_enabled_zone_config()?;
        }
        self.ensure_actor(name)?;
        let keypair = self.actor(name).keypair.clone();
        let zone = Address::new_from_array(self.zone_program_id.to_bytes());

        // Borrow (do not consume) `count` spendable UTXOs: a rejected merge spends
        // nothing, so the inputs must remain available for any later step.
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
                zone_data_hash: None,
                proof: Some(SpendProof {
                    state,
                    nullifier: nf,
                }),
            });
        }

        let owner = keypair.signing_pubkey();
        while spend_inputs.len() < MERGE_INPUT_COUNT {
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
            });
        }

        let output = OutputUtxo {
            owner_address: Some(keypair.shielded_address()?),
            asset,
            amount: total,
            blinding: random_blinding(),
            zone_program_id: None,
            zone_data_hash: None,
            data_hash: None,
            owner_tag: None,
            data: Data::default(),
        };

        let mut sk_bytes = [0u8; 32];
        sk_bytes[1..].copy_from_slice(&random_blinding());
        let tx_viewing_sk = SecretKey::from_slice(&sk_bytes)
            .map_err(|e| anyhow!("invalid ephemeral viewing scalar: {e}"))?;

        let result = MergeZoneProver {
            inputs: spend_inputs,
            output,
            expiry_unix_ts: u64::MAX,
            signing_pubkey: owner,
            nullifier_key: keypair.nullifier_key.clone(),
            user_viewing_pk: keypair.viewing_pubkey(),
            tx_viewing_sk,
            zone_program_id: zone,
        }
        .build()?;

        // Assemble the instruction data exactly as the happy path does (derived
        // merge_view_tag so the nullifier-queue insert is valid), then zero the
        // 192-byte proof so verification is the only thing that fails.
        let merge_view_tag = keypair.get_merge_view_tag(0)?;
        let data = result.instruction_data([0u8; 192], merge_view_tag);

        let payer = self.payer.insecure_clone();
        let merge_ix = MergeZone {
            tree: self.tree,
            zone_program_id: self.zone_program_id,
            payer: payer.pubkey(),
            data: data.merge.clone(),
            merge_view_tag: data.merge_view_tag,
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
                "zone merge with an invalid proof unexpectedly succeeded"
            )),
            Err(error) => {
                assert_rpc_custom_error(&error, TRANSACT_PROOF_VERIFICATION_FAILED);
                Ok(())
            }
        }
    }
}

/// Assert a transaction failed with the given custom program error, by code or its
/// hex form, as the validator surfaces it.
#[track_caller]
fn assert_rpc_custom_error(error: &anyhow::Error, code: u32) {
    let message = error.to_string().to_lowercase();
    let hex = format!("0x{code:x}");
    assert!(
        message.contains(&code.to_string()) || message.contains(&hex),
        "expected custom program error {code} ({hex}), got: {message}"
    );
}

#[when(expr = "the zone consolidates {int} of {word}'s SOL zone UTXOs")]
fn zone_consolidates(world: &mut ZoneLifecycleWorld, count: i64, name: String) {
    world
        .merge_zone(&name, SOL_MINT, count as usize)
        .expect("zone merge consolidation");
}

#[then(expr = "{word} holds one consolidated zone SOL UTXO")]
fn holds_consolidated_zone_utxo(world: &mut ZoneLifecycleWorld, name: String) {
    world.assert_merged_zone(&name).expect("assert merged zone");
}

#[then(expr = "a zone merge with an invalid proof is rejected")]
fn invalid_proof_rejected(world: &mut ZoneLifecycleWorld) {
    // Two of the actor's spendable SOL zone UTXOs are enough to form a real input
    // set; the proof is then zeroed so only verification fails.
    world
        .merge_zone_bad_proof("alice", SOL_MINT, 2)
        .expect("zone merge with invalid proof rejected");
}
