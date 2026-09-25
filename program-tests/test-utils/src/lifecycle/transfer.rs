//! Shielded transfer and spend operations.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{assemble, ProofAuthority, ProverClient, SpendProof};
use zolana_keypair::PublicKey;
use zolana_program::instruction::Transact;
use zolana_transaction::instructions::transact::ConfidentialTransaction;
use zolana_transaction::{
    serialization::confidential::Confidential, Data, ShieldedTransaction, Utxo, WalletUtxo,
    SOL_MINT,
};

use super::LifecycleHarness;
use crate::{
    localnet::{send_transaction, ZERO},
    test_validator_asserts::{
        wait_for_indexed_transaction, wait_for_merkle_proof, wait_for_non_inclusion_proof,
    },
    transact::pack_transact_proof,
};

impl LifecycleHarness {
    /// Transfer `amount` of `asset` from `from` to `to`, consolidating two of
    /// `from`'s spendable UTXOs of `asset` into the (2, 3) shape. The single-input
    /// variant is `transfer_single`, which pads with a dummy input.
    pub fn transfer_asset(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
    ) -> Result<Signature> {
        self.ensure_fresh_actor(from)?;
        self.ensure_fresh_actor(to)?;
        let inputs: Vec<Utxo> = {
            let actor = self.actor_mut(from);
            let mut taken = Vec::new();
            for _ in 0..2 {
                let pos = actor
                    .spendable
                    .iter()
                    .position(|u| u.asset.asset == asset)
                    .ok_or_else(|| anyhow!("{from} needs two spendable UTXOs of {asset}"))?;
                taken.push(actor.spendable.remove(pos));
            }
            taken
        };
        self.execute_transfer(from, Some(to), inputs, asset, amount)
    }

    /// Transfer `amount` of the `spl_mint` SPL asset from `from` to `to`, spending
    /// one SOL UTXO and one SPL UTXO (the supported (2, 3) shape). The recipient
    /// gets SPL; `from` gets back an SPL change and a SOL change.
    pub fn transfer_mixed(
        &mut self,
        from: &str,
        to: &str,
        spl_mint: Address,
        amount: u64,
    ) -> Result<Signature> {
        self.ensure_fresh_actor(from)?;
        self.ensure_fresh_actor(to)?;
        let send_asset = spl_mint;
        let inputs: Vec<Utxo> = {
            let actor = self.actor_mut(from);
            let spl_pos = actor
                .spendable
                .iter()
                .position(|u| u.asset.asset == spl_mint)
                .ok_or_else(|| anyhow!("{from} needs a spendable {spl_mint} UTXO"))?;
            let spl = actor.spendable.remove(spl_pos);
            let sol_pos = actor
                .spendable
                .iter()
                .position(|u| u.asset.asset == SOL_MINT)
                .ok_or_else(|| anyhow!("{from} needs a spendable SOL UTXO"))?;
            let sol = actor.spendable.remove(sol_pos);
            vec![spl, sol]
        };
        self.execute_transfer(from, Some(to), inputs, send_asset, amount)
    }

    /// Transfer `amount` of `asset` from `from` to `to` spending a single UTXO. The
    /// client pads the inputs to the (2, 3) shape with a dummy, so this exercises the
    /// dummy-padding path. Picks a spendable UTXO of `asset` that covers `amount`.
    pub fn transfer_single(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
    ) -> Result<Signature> {
        self.ensure_fresh_actor(from)?;
        self.ensure_fresh_actor(to)?;
        let inputs: Vec<Utxo> = {
            let actor = self.actor_mut(from);
            let pos = actor
                .spendable
                .iter()
                .position(|u| u.asset.asset == asset && u.amount >= amount)
                .ok_or_else(|| {
                    anyhow!("{from} needs a spendable {asset} UTXO covering {amount}")
                })?;
            vec![actor.spendable.remove(pos)]
        };
        self.execute_transfer(from, Some(to), inputs, asset, amount)
    }

    /// Consolidate a single UTXO of `asset` with no recipient, so the only output is
    /// the sender's change for the full amount. Exercises the change-only output path.
    pub fn consolidate(&mut self, from: &str, asset: Address) -> Result<Signature> {
        self.ensure_fresh_actor(from)?;
        let input = {
            let actor = self.actor_mut(from);
            let pos = actor
                .spendable
                .iter()
                .position(|u| u.asset.asset == asset)
                .ok_or_else(|| anyhow!("{from} needs a spendable UTXO of {asset}"))?;
            actor.spendable.remove(pos)
        };
        self.execute_transfer(from, None, vec![input], asset, 0)
    }

    /// Build, prove, and submit a transfer of `amount` of `send_asset` from
    /// `from` to `to` (or to no one, for a change-only consolidation) spending
    /// `inputs`. Records the recipient UTXO and the per-asset sender change
    /// (decrypting each output's own ciphertext for the blinding), and marks
    /// consumed decrypted inputs spent.
    fn execute_transfer(
        &mut self,
        from: &str,
        to: Option<&str>,
        inputs: Vec<Utxo>,
        send_asset: Address,
        amount: u64,
    ) -> Result<Signature> {
        let send_input: u64 = inputs
            .iter()
            .filter(|u| u.asset.asset == send_asset)
            .map(|u| u.amount)
            .sum();
        if send_input < amount {
            return Err(anyhow!(
                "{from} has {send_input} of the sent asset, need {amount}"
            ));
        }

        let from_keypair = self.actor(from).keypair.clone();
        let to_keypair = to.map(|t| self.actor(t).keypair.clone());
        let to_address = to_keypair
            .as_ref()
            .map(|k| k.shielded_address())
            .transpose()?;
        let to_view_tag = to_keypair
            .as_ref()
            .map(|k| k.signing_pubkey().confidential_view_tag())
            .transpose()?;
        // Every actor pays and signs its own spend (the owner sits at signer index
        // 0 / the fee payer).
        let fee_payer = self
            .actor(from)
            .solana_signer
            .as_ref()
            .expect("lifecycle actors are eddsa-owned")
            .insecure_clone();
        let payer_address = Address::new_from_array(fee_payer.pubkey().to_bytes());
        let sender_view_tag = from_keypair.signing_pubkey().confidential_view_tag()?;

        let nullifier_pk = from_keypair.nullifier_key.pubkey()?;
        let hashes = inputs
            .iter()
            .map(|utxo| utxo.hash(&nullifier_pk, &[0; 32], &[0; 32], self.tree_id))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let states = crate::test_validator_asserts::wait_for_merkle_proofs(
            &self.indexer,
            self.tree_address,
            &hashes,
        );
        let indexed_inputs = inputs
            .iter()
            .zip(&states)
            .map(|(utxo, state)| {
                crate::utxo::wallet(
                    utxo.clone(),
                    &from_keypair.nullifier_key,
                    self.tree_id,
                    state.leaf_index,
                    None,
                    None,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let mut transfer = ConfidentialTransaction::new(indexed_inputs, payer_address)?;
        if let Some(addr) = &to_address {
            if send_asset == SOL_MINT {
                transfer.transfer_sol(addr, amount)?;
            } else {
                transfer.transfer(addr, send_asset, amount)?;
            }
        }
        let proof_inputs = transfer.encrypt(&from_keypair)?;
        let finalized_outputs = proof_inputs.output_utxos.clone();

        let commitments = proof_inputs.input_utxo_hashes()?;
        let mut spend_proofs = Vec::new();
        for commitment in &commitments {
            let state =
                wait_for_merkle_proof(&self.indexer, self.tree_address, commitment.utxo_hash);
            let nullifier = wait_for_non_inclusion_proof(
                &self.indexer,
                self.tree_address,
                commitment.nullifier,
            );
            spend_proofs.push(SpendProof { state, nullifier });
        }
        // The circuit checks non-inclusion for every slot, so each padding dummy
        // needs a real low-element witness for its own nullifier.
        let dummy_proofs: Vec<_> = proof_inputs
            .dummy_nullifiers()
            .into_iter()
            .map(|nullifier| {
                wait_for_non_inclusion_proof(&self.indexer, self.tree_address, nullifier)
            })
            .collect();

        // All actors are eddsa-owned since the P256 rail was removed: the owner
        // authorizes the spend by signing the transaction.
        let mut assembled = assemble(proof_inputs, &spend_proofs, &dummy_proofs)?;
        let transfer_inputs = &mut assembled.prover_inputs;
        let proof = from_keypair
            .nullifier_key
            .prove_transfer(&ProverClient::local(), transfer_inputs)?;
        let ix_data = assembled.with_proof(pack_transact_proof(&proof)?);

        let transfer_ix = Transact {
            payer: fee_payer.pubkey(),
            input_trees: vec![self.tree],
            output_tree: self.tree,
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            data: ix_data,
        }
        .instruction();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let sig = send_transaction(
            &mut self.rpc,
            &[compute_budget, transfer_ix.clone()],
            &fee_payer.pubkey(),
            &[&fee_payer],
        )?;
        self.last_transact = Some((sig, transfer_ix));

        // A change-only transfer has no recipient slot, so locate the indexed
        // transaction by the sender's view tag instead.
        let wait_tag = to_view_tag.unwrap_or(sender_view_tag);
        let indexed = wait_for_indexed_transaction(&self.indexer, wait_tag, sig);
        // Decode each committed output blinding from the sender side: the expected
        // set is rebuilt independently from the on-chain ciphertexts (not from
        // `Wallet::sync`) so `assert_utxos` is a real cross-check of the synced
        // wallet, not a comparison of sync to itself.

        let mut expected = Vec::new();
        if let (Some(to), Some(keypair)) = (to, &to_keypair) {
            expected.push((to, keypair.signing_pubkey(), send_asset, amount));
        }
        let mut assets = Vec::new();
        for input in &inputs {
            if !assets.contains(&input.asset.asset) {
                assets.push(input.asset.asset);
            }
        }
        for asset in assets {
            let total: u64 = inputs
                .iter()
                .filter(|input| input.asset.asset == asset)
                .map(|input| input.amount)
                .sum();
            let change = total - if asset == send_asset { amount } else { 0 };
            if change > 0 {
                expected.push((from, from_keypair.signing_pubkey(), asset, change));
            }
        }
        expected.resize(
            finalized_outputs.len(),
            (from, from_keypair.signing_pubkey(), SOL_MINT, 0),
        );
        assert_eq!(indexed.output_slots.len(), expected.len());
        for (position, (actor, owner, asset, amount)) in expected.into_iter().enumerate() {
            let output = &finalized_outputs[position];
            assert_eq!(
                (
                    output.owner_address.unwrap().signing_pubkey,
                    output.asset.asset,
                    output.amount
                ),
                (owner, asset, amount)
            );
            let note = self.build_expected(
                actor,
                owner,
                asset,
                amount,
                decode_output_blinding(&from_keypair.viewing_key, &indexed, position as u32)?,
                &indexed,
            )?;
            self.actor_mut(actor).expected.push(note);
        }

        self.indexed.push(indexed);
        Ok(sig)
    }

    pub fn build_expected(
        &self,
        name: &str,
        owner: PublicKey,
        asset: Address,
        amount: u64,
        blinding: [u8; 32],
        tx: &ShieldedTransaction,
    ) -> Result<WalletUtxo> {
        let keypair = &self.actor(name).keypair;
        let nullifier_pk = keypair.nullifier_key.pubkey()?;
        let utxo = Utxo {
            owner,
            asset: self.assets.mint(&asset)?,
            amount,
            blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        let utxo_hash = utxo.hash(&nullifier_pk, &ZERO, &ZERO, self.tree_id)?;
        let (position, slot) = tx
            .output_slots
            .iter()
            .enumerate()
            .find(|(_, slot)| slot.output_context.hash == utxo_hash)
            .ok_or_else(|| anyhow!("expected output not found in indexed tx"))?;
        let nullifier = utxo.nullifier(&utxo_hash, &keypair.nullifier_key)?;
        Ok(WalletUtxo {
            nullifier_pubkey: nullifier_pk,
            utxo_hash,
            nullifier,
            data_hash: None,
            ring_data_hash: None,
            tree_id: self.tree_id,
            leaf_index: slot.output_context.leaf_index,
            slot: tx.slot,
            tx_signature: tx.tx_signature,
            slot_index: u32::try_from(position)?,
            utxo,
        })
    }
}

pub(crate) fn decode_output_blinding(
    viewing_key: &zolana_keypair::ViewingKey,
    indexed: &ShieldedTransaction,
    slot_index: u32,
) -> Result<[u8; 32]> {
    let first_nullifier = indexed
        .nullifiers
        .first()
        .ok_or_else(|| anyhow!("indexed tx missing nullifier"))?;
    let salt = indexed
        .salt
        .ok_or_else(|| anyhow!("indexed tx missing salt"))?;
    let tx_key = viewing_key.get_transaction_viewing_key(first_nullifier)?;
    let slot = indexed
        .output_slots
        .get(slot_index as usize)
        .ok_or_else(|| anyhow!("indexed tx missing output slot {slot_index}"))?;
    let output_data = slot
        .output_data()
        .ok_or_else(|| anyhow!("output slot {slot_index} undecodable"))?;
    let body = match &output_data {
        zolana_event::OutputDataEncoding::Encrypted(blob) => blob
            .split_first()
            .map(|(_, body)| body)
            .ok_or_else(|| anyhow!("empty output blob"))?,
        _ => return Err(anyhow!("output slot {slot_index} not encrypted")),
    };
    let plaintext = Confidential::decrypt_with_tx_key(&tx_key, body, salt, slot_index)?;
    Ok(plaintext.blinding)
}
