//! Ring-authority transfer operations and assertions.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    ProverClient, PublicTransfers, RingAuthorityProver, Shape, SpendProof, TransferSpendInput,
};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{
            CircuitId, InputUtxo, OwnerTag, TransactOutput, TransactProof,
        },
        tag::RING_AUTHORITY_TRANSACT,
        RingAuthorityTransact, TransactIxData,
    },
};
use zolana_keypair::{random_blinding, random_salt, ViewingKey};
use zolana_program_test::Rejection;
use zolana_transaction::{
    serialization::confidential::{Confidential, ConfidentialEncode},
    Data, ExternalData, OwnerCx, SppProofOutputUtxo, Utxo, UtxoSerialization,
};

use super::RingHarness;
use crate::{
    localnet::{send_transaction, ZERO},
    test_validator_asserts::{
        assert_account_unchanged, assert_ring_transact, fetch_account,
        wait_for_indexed_transaction, wait_for_merkle_proof, wait_for_non_inclusion_proof,
        RingTransactAssertArgs,
    },
    transact::pack_transact_proof,
};

impl RingHarness {
    /// Run a ring-authority permanent-delegate transfer over one of `name`'s
    /// ring-owned UTXOs: re-own its full value to the TRACKED actor `recipient` as a
    /// new ring-owned output. Builds and proves the real ring-authority proof, sends
    /// the instruction through the fixture (which signs the `ring_auth` PDA on its CPI
    /// into SPP), and asserts the full state transition. The recipient slot is tagged
    /// with `recipient`'s confidential view tag, so Photon indexes the transaction
    /// under it and the recipient's `Wallet::sync` targets the slot. Requires a ring
    /// config with `ring_authority_transact_is_enabled = true`.
    pub fn ring_authority_transfer(
        &mut self,
        name: &str,
        recipient: &str,
        asset: Address,
    ) -> Result<Signature> {
        if self.ring_config.is_none() {
            self.create_enabled_ring_config()?;
        }
        self.ensure_fresh_actor(name)?;
        self.ensure_fresh_actor(recipient)?;
        self.sync(name)?;

        let (ix_data, consumed_input, consumed_hash, reowned_utxo) =
            self.build_ring_authority_transfer(name, recipient, asset)?;

        let tree = self.tree;
        let payer = self.payer.insecure_clone();
        let tree_before = fetch_account(&self.rpc, &tree)?;

        let transfer_ix = RingAuthorityTransact {
            payer: payer.pubkey(),
            input_tree: tree,
            output_tree: tree,
            ring_program_id: self.ring_program_id,
            interface_transfer_accounts: Vec::new(),
            data: ix_data.clone(),
        }
        .instruction();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let signature = send_transaction(
            &mut self.rpc,
            &[compute_budget, transfer_ix],
            &payer.pubkey(),
            &[&payer],
        )?;
        self.commit_ring_authority_spend(name, &consumed_input, consumed_hash)?;

        // The recipient actor's confidential view tag is the first output's inline
        // owner tag (ring flows resolve owner tags inline); Photon indexes the
        // transaction under it, and the confidential default-ring scan in
        // `Wallet::sync` queries exactly this tag.
        let fetch_view_tag = match ix_data.outputs.first().map(|output| output.owner_tag) {
            Some(OwnerTag::Inline(tag)) => tag,
            _ => {
                return Err(anyhow!(
                    "ring-authority transfer produced no inline-tagged output"
                ))
            }
        };
        assert_ring_transact(
            &self.rpc,
            &self.indexer,
            RingTransactAssertArgs {
                tree: &tree,
                data: &ix_data,
                signature,
                fetch_view_tag,
                tree_before: &tree_before,
            },
        )?;

        let indexed = wait_for_indexed_transaction(&self.indexer, fetch_view_tag, signature);
        // Track the re-owned ring UTXO in the recipient's expected set (locating its
        // on-chain output context in the indexed transaction) so `assert_utxos`
        // cross-checks the synced wallet after the re-own.
        let expected = self.build_expected(recipient, reowned_utxo, &indexed)?;
        self.actor_mut(recipient).expected.push(expected);
        self.indexed.push(indexed);
        self.sync(recipient)?;
        self.assert_ring_output_discovered(recipient, &ix_data)?;

        Ok(signature)
    }

    /// Assert the recipient actor's synced wallet discovered the appended ring-owned
    /// output (its leaf hash is among the synced wallet's UTXOs). The output hash is
    /// the single entry in the instruction's `outputs`.
    fn assert_ring_output_discovered(
        &self,
        recipient: &str,
        ix_data: &TransactIxData,
    ) -> Result<()> {
        let output_hash = ix_data
            .outputs
            .first()
            .ok_or_else(|| anyhow!("ring-authority transfer produced no output"))?
            .utxo_hash;
        let discovered = self
            .actor(recipient)
            .wallet
            .utxos
            .iter()
            .any(|w| w.output_context.hash == output_hash);
        assert!(
            discovered,
            "{recipient}'s synced wallet should hold the re-owned ring UTXO {output_hash:?}"
        );
        Ok(())
    }

    /// Assemble the `TransactIxData` for a 1x1 ring-authority transfer of one of
    /// `name`'s spendable ring UTXOs of `asset` to the tracked actor `recipient`,
    /// without mutating fixture state. The same `ExternalData` (the output hash and
    /// the recipient ciphertext) is fed to the prover and to the instruction, so they
    /// agree on the `external_data_hash` the program recomputes on-chain. Also
    /// returns the consumed input (with its hash) and the re-owned output plaintext,
    /// so the caller can track both in the fixture's expected sets.
    fn build_ring_authority_transfer(
        &mut self,
        name: &str,
        recipient: &str,
        asset: Address,
    ) -> Result<(TransactIxData, Utxo, [u8; 32], Utxo)> {
        let ring = Address::new_from_array(self.ring_program_id.to_bytes());
        let keypair = self.actor(name).keypair.clone();
        let recipient_keypair = self.actor(recipient).keypair.clone();
        let nullifier_pk = keypair.nullifier_key.pubkey()?;

        let input_utxo: Utxo = {
            let actor = self.actor(name);
            actor
                .spendable
                .iter()
                .find(|u| u.asset == asset && u.ring_program_id == Some(ring))
                .cloned()
                .ok_or_else(|| anyhow!("{name} needs a spendable ring UTXO of {asset}"))?
        };
        let amount = input_utxo.amount;

        // Real input: fetch its inclusion / non-inclusion proofs, exactly as the
        // transfer / merge paths do. The authority supplies the owner's nullifier key.
        let utxo_hash = input_utxo.hash(&nullifier_pk, &ZERO, &ZERO)?;
        let nullifier = keypair
            .nullifier_key
            .nullifier(&utxo_hash, &input_utxo.blinding)?;
        let state = wait_for_merkle_proof(&self.indexer, self.tree_address, utxo_hash);
        let non_inclusion =
            wait_for_non_inclusion_proof(&self.indexer, self.tree_address, nullifier);
        let spend_input = TransferSpendInput {
            utxo: input_utxo.clone(),
            nullifier_key: keypair.nullifier_key.clone(),
            data_hash: None,
            ring_data_hash: None,
            proof: Some(SpendProof {
                state,
                nullifier: non_inclusion,
            }),
            nullifier_proof: None,
        };

        // Tracked recipient actor; the re-owned output is ring-owned (bound to the
        // ring program by the circuit) and carries the recipient's address so it is a
        // real (non-dummy) output. The slot's view tag is the recipient's confidential
        // owner tag, the exact tag `Wallet::sync`'s confidential scan queries.
        let recipient_address = recipient_keypair.shielded_address()?;
        let recipient_view_tag = recipient_address.signing_pubkey.confidential_view_tag()?;
        let output = SppProofOutputUtxo {
            owner_address: Some(recipient_address),
            asset,
            amount,
            blinding: random_blinding(),
            ring_program_id: Some(ring),
            ring_data_hash: None,
            data_hash: None,
            owner_tag: None,
            data: Data::default(),
        };
        let output_hash = output.hash()?;

        // Encrypt the output to the recipient under an ephemeral transaction viewing
        // key, the same confidential-recipient encoding a transfer uses, so Photon
        // indexes the transaction by the recipient's view tag.
        let tx = ViewingKey::new();
        let salt = random_salt();
        let owner_cx = OwnerCx {
            owner: recipient_address.signing_pubkey,
            assets: &self.assets,
            ring_program_id: Some(ring),
        };
        // The recipient decrypts a plaintext `Utxo` (the on-chain leaf is the
        // `SppProofOutputUtxo` above); both carry identical fields so their hashes agree.
        let output_plaintext = Utxo {
            owner: recipient_address.signing_pubkey,
            asset,
            amount,
            blinding: output.blinding,
            ring_program_id: Some(ring),
            data: Data::default(),
        };
        let ciphertext = Confidential::encode(
            core::slice::from_ref(&output_plaintext),
            &owner_cx,
            recipient_view_tag,
            &ConfidentialEncode {
                tx: tx.clone(),
                recipient_pubkey: recipient_address.viewing_pubkey,
                salt,
                slot_index: 0,
            },
        )?;

        let external_data = ExternalData {
            instruction_discriminator: RING_AUTHORITY_TRANSACT,
            expiry_unix_ts: u64::MAX,
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            tx_viewing_pk: *tx.pubkey().as_bytes(),
            salt,
            // Ring flows resolve owner tags inline (the tag is the recipient's
            // confidential view tag, not an account or the shared P256 key), so the
            // wire tag and its resolved form are the same 32 bytes.
            outputs: vec![TransactOutput {
                utxo_hash: output_hash,
                owner_tag: OwnerTag::Inline(recipient_view_tag),
                data: Some(ciphertext.data),
            }],
            resolved_owner_tags: vec![recipient_view_tag],
            messages: vec![],
        };

        let result = RingAuthorityProver {
            inputs: vec![spend_input],
            outputs: vec![output],
            external_data: external_data.clone(),
            public_transfers: PublicTransfers::default(),
            payer: Address::new_from_array(self.payer.pubkey().to_bytes()),
            allow_dummy_inputs: true,
            ring_program_id: Some(ring),
            shape: Some(Shape::new(1, 1)),
        }
        .build()?;
        let proof = ProverClient::local().prove_ring_authority(&result.inputs)?;

        // Assemble the instruction inputs from the one prover build: the nullifier and
        // root indices are computed once and shared with the proof, so the witness and
        // the instruction commit to identical values. The authority rail carries no
        // per-input signer: the `ring_config` PDA signs on-chain instead.
        let nullifier_hash = *result
            .nullifiers
            .first()
            .ok_or_else(|| anyhow!("ring-authority witness produced no nullifier"))?;
        let &(utxo_tree_root_index, nullifier_tree_root_index) = result
            .input_root_indices
            .first()
            .ok_or_else(|| anyhow!("ring-authority witness produced no root indices"))?;
        let inputs = vec![InputUtxo {
            nullifier_hash,
            nullifier_tree_root_index,
            utxo_tree_root_index,
        }];

        let ix_data = TransactIxData {
            proof: pack_transact_proof(&proof)?,
            expiry_unix_ts: external_data.expiry_unix_ts,
            private_tx_hash: result.private_tx_hash,
            circuit: CircuitId::RingAuthority(
                inputs.len() as u8,
                external_data.outputs.len() as u8,
                zolana_interface::N_PUBLIC_SLOTS as u8,
            ),
            inputs,
            interface_transfers: external_data
                .interface_transfers
                .iter()
                .map(|transfer| transfer.interface_transfer())
                .collect(),
            data_hash: external_data.data_hash,
            ring_data_hash: external_data.ring_data_hash,
            tx_viewing_pk: external_data.tx_viewing_pk,
            salt: external_data.salt,
            outputs: external_data.outputs.clone(),
            messages: external_data.messages.clone(),
        };

        Ok((ix_data, input_utxo, utxo_hash, output_plaintext))
    }

    fn commit_ring_authority_spend(
        &mut self,
        name: &str,
        consumed: &Utxo,
        consumed_hash: [u8; 32],
    ) -> Result<()> {
        let actor = self.actor_mut(name);
        let position = actor
            .spendable
            .iter()
            .position(|utxo| {
                utxo.asset == consumed.asset
                    && utxo.amount == consumed.amount
                    && utxo.blinding == consumed.blinding
                    && utxo.ring_program_id == consumed.ring_program_id
            })
            .ok_or_else(|| anyhow!("accepted authority spend input disappeared from fixture"))?;
        actor.spendable.remove(position);
        if let Some(utxo) = actor
            .expected
            .iter_mut()
            .find(|utxo| utxo.output_context.hash == consumed_hash)
        {
            utxo.spent = true;
        }
        Ok(())
    }

    /// Attempt a ring-authority transfer after disabling the flag; SPP must reject it
    /// with `RingAuthorityTransactDisabled`. The build (prove) still runs, since the
    /// disabled check happens on-chain while parsing accounts.
    pub fn ring_authority_transfer_disabled(&mut self, name: &str, asset: Address) -> Result<()> {
        if self.ring_config.is_none() {
            self.create_enabled_ring_config()?;
        }
        // The rail is governance-owned now, so disabling it goes through
        // `set_ring_activation`; the ring itself cannot reach the flag.
        self.set_ring_activation(true, false)?;
        self.ensure_fresh_actor(name)?;
        self.sync(name)?;

        // The transition is rejected on-chain before any state change, so the
        // recipient is irrelevant; re-own back to the same actor.
        let (ix_data, _, _, _) = self.build_ring_authority_transfer(name, name, asset)?;
        let payer = self.payer.insecure_clone();
        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let transfer_ix = RingAuthorityTransact {
            payer: payer.pubkey(),
            input_tree: self.tree,
            output_tree: self.tree,
            ring_program_id: self.ring_program_id,
            interface_transfer_accounts: Vec::new(),
            data: ix_data,
        }
        .instruction();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        match send_transaction(
            &mut self.rpc,
            &[compute_budget, transfer_ix],
            &payer.pubkey(),
            &[&payer],
        ) {
            Ok(_) => Err(anyhow!(
                "disabled ring-authority transfer unexpectedly succeeded"
            )),
            Err(error) => {
                Rejection::pool(ShieldedPoolError::RingAuthorityTransactDisabled)
                    .at(1)
                    .assert_client(&error);
                assert_account_unchanged(&self.rpc, &self.tree, &tree_before)?;
                Ok(())
            }
        }
    }

    /// Attempt a ring-authority transfer whose proof bytes were corrupted; SPP must
    /// reject it with `TransactProofVerificationFailed`.
    pub fn ring_authority_transfer_bad_proof(&mut self, name: &str, asset: Address) -> Result<()> {
        if self.ring_config.is_none() {
            self.create_enabled_ring_config()?;
        }
        self.ensure_fresh_actor(name)?;
        self.sync(name)?;

        // Rejected on-chain before any state change; re-own back to the same actor.
        // Zero the proof (the ring-authority rail is vanilla eddsa) so verification
        // deterministically fails with `TransactProofVerificationFailed` -- flipping a
        // single byte can instead yield `InvalidTransactProofEncoding` depending on
        // the random proof bytes.
        let (mut ix_data, _, _, _) = self.build_ring_authority_transfer(name, name, asset)?;
        ix_data.proof = TransactProof::zeroed();

        let payer = self.payer.insecure_clone();
        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let transfer_ix = RingAuthorityTransact {
            payer: payer.pubkey(),
            input_tree: self.tree,
            output_tree: self.tree,
            ring_program_id: self.ring_program_id,
            interface_transfer_accounts: Vec::new(),
            data: ix_data,
        }
        .instruction();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        match send_transaction(
            &mut self.rpc,
            &[compute_budget, transfer_ix],
            &payer.pubkey(),
            &[&payer],
        ) {
            Ok(_) => Err(anyhow!(
                "bad-proof ring-authority transfer unexpectedly succeeded"
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
