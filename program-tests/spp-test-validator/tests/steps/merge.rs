//! `merge_transact` steps and the World merge operation. The merge service
//! consolidates several of one owner's same-asset UTXOs into a single output. The
//! owner is either rail: a P256 owner registers its `owner_p256`, a Solana owner
//! registers under its ed25519 signing key (the `eddsa_owner` rail). The owner
//! registers on the user-registry and opts into the merge service; the configured
//! merge authority then runs the consolidation on the owner's behalf, proving on
//! the 8-in/1-out merge circuit.
//!
//! The consolidated output carries the owner's signing-pubkey view tag (the
//! confidential default-zone tag), so `Wallet::sync`
//! rediscovers it: `assert_merged` syncs and full-struct asserts the actor's wallet
//! (the merged output present, the consumed inputs spent), the standard
//! "syncs / UTXOs match" path used by the other lifecycle steps.

use anyhow::{anyhow, Result};
use cucumber::{given, then, when};
use p256::SecretKey;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::{MergeProver, ProverClient, SpendProof, TransferSpendInput};
use zolana_interface::instruction::{
    instruction_data::merge_transact::MERGE_INPUT_COUNT, MergeTransact,
};
use zolana_keypair::{random_blinding, SignatureType};
use zolana_smart_account_client::execute_sync_ix;
use zolana_test_utils::test_validator_asserts::{
    wait_for_indexed_transaction, wait_for_merkle_proof, wait_for_non_inclusion_proof,
};
use zolana_transaction::{Data, OutputUtxo, Utxo, SOL_MINT};
use zolana_user_registry_interface::{
    instruction::{register, set_merging_enabled, RegisterData},
    user_record_pda,
};

use crate::{
    localnet::{pack_proof, send_transaction, ZERO},
    LifecycleWorld,
};

/// What the consolidated-output assert needs after a merge: the actor that owns
/// the appended output and the output's hash (for the inclusion-proof check).
pub(crate) struct MergeRecord {
    pub(crate) actor: String,
    pub(crate) output_hash: [u8; 32],
}

impl LifecycleWorld {
    /// Register `name` on the user-registry under a fresh Solana keypair and opt the
    /// record into merging. Returns the registering Solana keypair so the merge step
    /// can derive the `user_record` PDA the program reads. `enable_merge` gates the
    /// `set_merging_enabled` opt-in so the disabled path can be exercised.
    pub(crate) fn register_merge_owner(
        &mut self,
        name: &str,
        enable_merge: bool,
    ) -> Result<Keypair> {
        self.ensure_actor(name)?;
        let keypair = self.actor(name).keypair.clone();

        // The owner identity rail follows the actor's signing key. A Solana owner
        // registers under its own ed25519 signing key (so `record.owner` is the
        // identity merge derives `signing_pk_field` from) with no `owner_p256`; a
        // P256 owner registers under a fresh account and stores its `owner_p256`.
        let (owner, owner_p256) = match keypair.signing_pubkey().signature_type()? {
            SignatureType::Ed25519 => {
                let signer = self
                    .actor(name)
                    .solana_signer
                    .as_ref()
                    .ok_or_else(|| anyhow!("eddsa actor {name} has no backing signer"))?
                    .insecure_clone();
                (signer, None)
            }
            SignatureType::P256 => (
                Keypair::new(),
                Some(*keypair.signing_pubkey().as_p256()?.as_bytes()),
            ),
        };
        self.rpc.airdrop(&owner.pubkey(), 1_000_000_000)?;

        let register_data = RegisterData {
            owner_p256,
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
    pub(crate) fn merge(
        &mut self,
        name: &str,
        owner_solana: &Keypair,
        asset: Address,
        count: usize,
    ) -> Result<()> {
        self.ensure_actor(name)?;
        let keypair = self.actor(name).keypair.clone();

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

        // The single consolidated output, owned by the merger, with a fresh random
        // blinding the owner recovers by decrypting the published merge ciphertext.
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

        // Ephemeral viewing scalar: 31 random bytes are < BN254 modulus, so the value
        // is both a valid P-256 scalar and a valid circuit witness.
        let mut sk_bytes = [0u8; 32];
        sk_bytes[1..].copy_from_slice(&random_blinding());
        let tx_viewing_sk = SecretKey::from_slice(&sk_bytes)
            .map_err(|e| anyhow!("invalid ephemeral viewing scalar: {e}"))?;

        let expiry_unix_ts = u64::MAX;

        let result = MergeProver {
            inputs: spend_inputs,
            output: output.clone(),
            expiry_unix_ts,
            signing_pubkey: owner,
            nullifier_key: keypair.nullifier_key.clone(),
            user_viewing_pk: keypair.viewing_pubkey(),
            tx_viewing_sk,
        }
        .build()?;

        let proof = ProverClient::local().prove_merge(&result.inputs)?;

        // The client assembles the instruction data (incl. the encrypted_utxo blob)
        // the same way the prover bound `external_data_hash`, so they agree on-chain.
        let data = result.instruction_data(pack_proof(&proof)?);

        let merge_ix = MergeTransact {
            tree: self.tree,
            payer: self.merge_vault,
            user_record: user_record_pda(&owner_solana.pubkey()).0,
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

        // The merged output carries the owner's signing-pubkey view tag (the
        // confidential default-zone tag), so the indexed transaction is located by
        // that tag and added to the synced stream; the owner's `Wallet::sync` then
        // rediscovers the consolidated output and marks the consumed inputs spent
        // from the transaction's nullifiers.
        let owner_tag = keypair.signing_pubkey().confidential_view_tag()?;
        let indexed = wait_for_indexed_transaction(&self.indexer, owner_tag, sig);

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
            if let Some(note) = self
                .actor_mut(name)
                .expected
                .iter_mut()
                .find(|n| n.output_context.hash == consumed_hash)
            {
                note.spent = true;
            }
        }

        self.indexed.push(indexed);

        // Record what the inclusion-proof assert needs: the appended output hash.
        self.last_merge = Some(MergeRecord {
            actor: name.to_string(),
            output_hash: result.output_hash,
        });
        Ok(())
    }

    /// Functional assert for the consolidated output, the standard
    /// "syncs / UTXOs match" path: the owner's `Wallet::sync` rediscovers the merged
    /// output by its bootstrap view tag and marks the consumed inputs spent, and the
    /// synced wallet must match the tracked expected set. Also confirms the indexer
    /// serves an inclusion proof for the appended output.
    pub(crate) fn assert_merged(&mut self, name: &str) -> Result<()> {
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
    pub(crate) fn merge_expect_disabled(
        &mut self,
        name: &str,
        owner_solana: &Keypair,
        asset: Address,
        count: usize,
    ) -> Result<()> {
        match self.merge(name, owner_solana, asset, count) {
            Ok(()) => Err(anyhow!(
                "merge unexpectedly succeeded for a disabled service"
            )),
            Err(error) => {
                assert_rpc_custom_error(&error, MERGE_DISABLED);
                Ok(())
            }
        }
    }
}

/// Custom program error code for an owner that has not enabled merging
/// (`ShieldedPoolError::MergeDisabled`).
const MERGE_DISABLED: u32 = 7017;

/// Assert a transaction failed with the given custom program error, by code (e.g.
/// `7017`) or its hex form (e.g. `0x1b69`), as the validator surfaces it.
#[track_caller]
fn assert_rpc_custom_error(error: &anyhow::Error, code: u32) {
    let message = error.to_string().to_lowercase();
    let hex = format!("0x{code:x}");
    assert!(
        message.contains(&code.to_string()) || message.contains(&hex),
        "expected custom program error {code} ({hex}), got: {message}"
    );
}

#[given(expr = "{word} registers for the merge service")]
fn registers_for_merge_service(world: &mut LifecycleWorld, name: String) {
    let owner = world
        .register_merge_owner(&name, true)
        .expect("register merge owner");
    world.merge_owners.insert(name, owner);
}

#[given(expr = "{word} registers without the merge service")]
fn registers_without_merge_service(world: &mut LifecycleWorld, name: String) {
    let owner = world
        .register_merge_owner(&name, false)
        .expect("register merge owner");
    world.merge_owners.insert(name, owner);
}

#[given(expr = "{word} deposits {int} SOL UTXOs of {int} lamports")]
fn deposits_n_sol(world: &mut LifecycleWorld, name: String, count: i64, amount: i64) {
    for _ in 0..count {
        world
            .deposit_sol(&name, amount as u64)
            .expect("deposit SOL UTXO");
    }
}

#[when(expr = "the merge service consolidates {int} of {word}'s SOL UTXOs")]
fn merge_service_consolidates(world: &mut LifecycleWorld, count: i64, name: String) {
    let owner = merge_owner(world, &name);
    world
        .merge(&name, &owner, SOL_MINT, count as usize)
        .expect("merge consolidation");
}

#[then(expr = "the merge service cannot consolidate {int} of {word}'s SOL UTXOs")]
fn merge_service_cannot_consolidate(world: &mut LifecycleWorld, count: i64, name: String) {
    let owner = merge_owner(world, &name);
    world
        .merge_expect_disabled(&name, &owner, SOL_MINT, count as usize)
        .expect("merge rejected with MergeDisabled");
}

#[then(expr = "{word} holds one consolidated SOL UTXO")]
fn holds_consolidated_utxo(world: &mut LifecycleWorld, name: String) {
    world.assert_merged(&name).expect("assert merged");
}

fn merge_owner(world: &LifecycleWorld, name: &str) -> Keypair {
    world
        .merge_owners
        .get(name)
        .expect("merge owner registered")
        .insecure_clone()
}
