//! `merge_transact` steps and the World merge operation. The merge service
//! consolidates several of one owner's same-asset UTXOs into a single output. The
//! owner is either rail: a P256 owner registers its `owner_p256`, a Solana owner
//! registers under its ed25519 signing key (the `eddsa_owner` rail). The owner
//! registers on the user-registry and opts into the merge service; the configured
//! merge authority then runs the consolidation on the owner's behalf, proving on
//! the 8-in/1-out merge circuit.
//!
//! NOTE: the consolidated output carries no transfer-style view tag, so it is not
//! discovered by `Wallet::sync` (the merge scheme is not wired into sync yet).
//! `assert_merged` therefore verifies the output by decrypting the published
//! ciphertext and reconstructing the UTXO, instead of the standard
//! "syncs / UTXOs match" path. Swap it for that path once merge sync lands.

use anyhow::{anyhow, Result};
use cucumber::{given, then, when};
use p256::SecretKey;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::{MergeProver, ProverClient, SpendProof, TransferSpendInput};
use zolana_interface::{
    instruction::{instruction_data::merge_transact::MERGE_INPUT_COUNT, MergeTransact},
    pda,
};
use zolana_keypair::{random_blinding, SignatureType};
use zolana_test_utils::test_validator_asserts::{
    wait_for_merkle_proof, wait_for_non_inclusion_proof,
};
use zolana_transaction::{Data, OutputUtxo, Utxo, SOL_MINT};
use zolana_user_registry_interface::{
    instruction::{register, set_merge_service, RegisterData},
    user_record_pda,
};

use crate::{
    localnet::{pack_proof, send_transaction, ZERO},
    LifecycleWorld,
};

/// What the consolidated-output assert needs after a merge: the appended output
/// and the ciphertext that lets the owner reconstruct it.
pub(crate) struct MergeRecord {
    pub(crate) actor: String,
    pub(crate) asset: Address,
    pub(crate) total: u64,
    pub(crate) output_hash: [u8; 32],
    pub(crate) output_blinding: [u8; 31],
    pub(crate) tx_viewing_pk: zolana_keypair::P256Pubkey,
    pub(crate) ciphertext: Vec<u8>,
}

impl LifecycleWorld {
    /// Register `name` on the user-registry under a fresh Solana keypair and opt the
    /// record into the merge service. Returns the registering Solana keypair so the
    /// merge step can derive the `user_record` PDA the program reads. `enable_merge`
    /// gates the `set_merge_service` opt-in so the disabled path can be exercised.
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

        if enable_merge {
            let enable_ix = set_merge_service(user_record, owner.pubkey(), true);
            send_transaction(&mut self.rpc, &[enable_ix], &owner.pubkey(), &[&owner])?;
        }
        Ok(owner)
    }

    /// Build, prove, and submit a merge of `count` of `name`'s spendable `asset`
    /// UTXOs into one consolidated output, run by the configured merge authority for
    /// the registered, merge-service-enabled owner `owner_solana`. Returns the
    /// transaction send result so the caller can assert success or the
    /// `MergeServiceDisabled` failure.
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
                proof: None,
            });
        }

        // The single consolidated output, owned by the merger, with a fresh random
        // blinding the owner recovers by decrypting the published merge ciphertext.
        let output_blinding = random_blinding();
        let output = OutputUtxo {
            owner_hash: keypair.owner_hash()?,
            asset,
            amount: total,
            blinding: output_blinding,
            zone_program_id: None,
            zone_data_hash: None,
            program_data_hash: None,
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
            protocol_config: pda::protocol_config(),
            payer: self.authority.pubkey(),
            user_record: user_record_pda(&owner_solana.pubkey()).0,
            data,
        }
        .instruction();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let authority = self.authority.insecure_clone();
        send_transaction(
            &mut self.rpc,
            &[compute_budget, merge_ix],
            &authority.pubkey(),
            &[&authority],
        )?;

        // Record what the consolidated-output assert needs: the appended output
        // hash and the published ciphertext the owner decrypts.
        self.last_merge = Some(MergeRecord {
            actor: name.to_string(),
            asset,
            total,
            output_hash: result.output_hash,
            output_blinding,
            tx_viewing_pk: result.tx_viewing_pk,
            ciphertext: result.ciphertext,
        });
        Ok(())
    }

    /// Functional assert for the consolidated output. The merge output carries no
    /// transfer-style view tag, so it is not discovered by `Wallet::sync`; instead
    /// the owner decrypts the published ciphertext with its viewing key, reconstructs
    /// the merged UTXO, and confirms the reconstruction hashes to the output hash the
    /// tree appended. Also confirms the indexer serves an inclusion proof for that
    /// output.
    ///
    /// NOTE: this does not go through `Wallet::sync`/`assert_utxos` because the merge
    /// scheme is not yet wired into `Wallet::sync` (D-phase, in flight). When merge
    /// sync lands, replace this with the standard "syncs / UTXOs match" assert.
    pub(crate) fn assert_merged(&self, name: &str) -> Result<()> {
        let record = self
            .last_merge
            .as_ref()
            .ok_or_else(|| anyhow!("no merge recorded"))?;
        if record.actor != name {
            return Err(anyhow!("last merge was for {}, not {name}", record.actor));
        }
        let keypair = self.actor(name).keypair.clone();

        // Owner reconstructs the merged UTXO from the published ciphertext.
        let plaintext = keypair.decrypt_merge(&record.tx_viewing_pk, &record.ciphertext)?;
        let amount = u64::from_be_bytes(
            plaintext
                .get(0..8)
                .ok_or_else(|| anyhow!("merge plaintext too short"))?
                .try_into()?,
        );
        let blinding: [u8; 31] = plaintext
            .get(40..71)
            .ok_or_else(|| anyhow!("merge plaintext too short"))?
            .try_into()?;
        assert_eq!(amount, record.total, "recovered merged amount");
        assert_eq!(
            blinding, record.output_blinding,
            "recovered merged blinding"
        );

        let reconstructed = self.build_expected(
            name,
            keypair.signing_pubkey(),
            record.asset,
            amount,
            blinding,
        )?;
        assert_eq!(
            reconstructed.hash, record.output_hash,
            "owner reconstructs the merged output from the ciphertext",
        );

        // The output was appended to the tree (inclusion proof is served).
        let _ = wait_for_merkle_proof(&self.indexer, self.tree_address, record.output_hash);
        Ok(())
    }

    /// Attempt a merge expecting it to fail with `MergeServiceDisabled`; the owner is
    /// registered but never opted into the merge service.
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
                assert_rpc_custom_error(&error, MERGE_SERVICE_DISABLED);
                Ok(())
            }
        }
    }
}

/// Custom program error code for an owner that has not enabled the merge service
/// (`ShieldedPoolError::MergeServiceDisabled`).
const MERGE_SERVICE_DISABLED: u32 = 7017;

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
        .expect("merge rejected with MergeServiceDisabled");
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
