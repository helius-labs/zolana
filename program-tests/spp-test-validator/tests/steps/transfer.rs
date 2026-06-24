//! `transfer` / `spend` steps and the World transfer operations. A spend is a
//! transfer to a throwaway recipient. `transfer_asset` consolidates two UTXOs of
//! one asset; `transfer_mixed` spends one SOL and one SPL UTXO in a single
//! transfer. Both feed `execute_transfer`, which tracks the recipient UTXO and the
//! per-asset sender change.

use anyhow::{anyhow, Result};
use cucumber::{then, when};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    ProverClient, ProverInputs, SpendProof, SpendUtxo, Transaction as ClientTransaction,
};
use zolana_interface::instruction::Transact;
use zolana_keypair::PublicKey;
use zolana_test_utils::test_validator_asserts::{
    wait_for_indexed_transaction, wait_for_merkle_proof, wait_for_non_inclusion_proof,
};
use zolana_transaction::{
    transfer::{OutputCiphertext, TransferEncryptedUtxos, SENDER_SLOT_COUNT},
    utxo::derive_blinding,
    Data, SyncTransaction, TransactionEncryption, Utxo, WalletUtxo, SOL_MINT, TRANSFER,
};

use crate::{
    localnet::{
        pack_proof, send_transaction, RECIPIENT_POSITION_BASE, SOL_CHANGE_POSITION,
        SPL_CHANGE_POSITION, ZERO,
    },
    world::Rail,
    LifecycleWorld,
};

impl LifecycleWorld {
    /// Transfer `amount` of `asset` from `from` to `to`, consolidating two of
    /// `from`'s spendable UTXOs of `asset` into the (2, 3) shape. The single-input
    /// variant is `transfer_single`, which pads with a dummy input.
    pub(crate) fn transfer_asset(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
    ) -> Result<Signature> {
        self.ensure_actor(from)?;
        self.ensure_actor(to)?;
        let inputs: Vec<Utxo> = {
            let actor = self.actor_mut(from);
            let mut taken = Vec::new();
            for _ in 0..2 {
                let pos = actor
                    .spendable
                    .iter()
                    .position(|u| u.asset == asset)
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
    pub(crate) fn transfer_mixed(
        &mut self,
        from: &str,
        to: &str,
        spl_mint: Address,
        amount: u64,
    ) -> Result<Signature> {
        self.ensure_actor(from)?;
        self.ensure_actor(to)?;
        let send_asset = spl_mint;
        let inputs: Vec<Utxo> = {
            let actor = self.actor_mut(from);
            let spl_pos = actor
                .spendable
                .iter()
                .position(|u| u.asset == spl_mint)
                .ok_or_else(|| anyhow!("{from} needs a spendable {spl_mint} UTXO"))?;
            let spl = actor.spendable.remove(spl_pos);
            let sol_pos = actor
                .spendable
                .iter()
                .position(|u| u.asset == SOL_MINT)
                .ok_or_else(|| anyhow!("{from} needs a spendable SOL UTXO"))?;
            let sol = actor.spendable.remove(sol_pos);
            vec![spl, sol]
        };
        self.execute_transfer(from, Some(to), inputs, send_asset, amount)
    }

    /// Transfer `amount` of `asset` from `from` to `to` spending a single UTXO. The
    /// client pads the inputs to the (2, 3) shape with a dummy, so this exercises the
    /// dummy-padding path. Picks a spendable UTXO of `asset` that covers `amount`.
    pub(crate) fn transfer_single(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
    ) -> Result<Signature> {
        self.ensure_actor(from)?;
        self.ensure_actor(to)?;
        let inputs: Vec<Utxo> = {
            let actor = self.actor_mut(from);
            let pos = actor
                .spendable
                .iter()
                .position(|u| u.asset == asset && u.amount >= amount)
                .ok_or_else(|| {
                    anyhow!("{from} needs a spendable {asset} UTXO covering {amount}")
                })?;
            vec![actor.spendable.remove(pos)]
        };
        self.execute_transfer(from, Some(to), inputs, asset, amount)
    }

    /// Consolidate a single UTXO of `asset` with no recipient, so the only output is
    /// the sender's change for the full amount. Exercises the change-only output path.
    pub(crate) fn consolidate(&mut self, from: &str, asset: Address) -> Result<Signature> {
        self.ensure_actor(from)?;
        let input = {
            let actor = self.actor_mut(from);
            let pos = actor
                .spendable
                .iter()
                .position(|u| u.asset == asset)
                .ok_or_else(|| anyhow!("{from} needs a spendable UTXO of {asset}"))?;
            actor.spendable.remove(pos)
        };
        self.execute_transfer(from, None, vec![input], asset, 0)
    }

    /// Build, prove (P256), and submit a transfer of `amount` of `send_asset` from
    /// `from` to `to` (or to no one, for a change-only consolidation) spending
    /// `inputs`. Records the recipient UTXO and the per-asset sender change
    /// (decrypting the sender bundle for the blinding seed), and marks consumed
    /// decrypted inputs spent.
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
            .filter(|u| u.asset == send_asset)
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
            .map(|k| k.recipient_bootstrap_view_tag());
        // An eddsa actor pays and signs its own spend (the owner sits at signer index
        // 0 / the fee payer); a P256 actor falls back to the global payer.
        let fee_payer = self
            .actor(from)
            .solana_signer
            .as_ref()
            .map(|k| k.insecure_clone())
            .unwrap_or_else(|| self.payer.insecure_clone());
        let payer_address = Address::new_from_array(fee_payer.pubkey().to_bytes());
        let send_index = self.actor(from).send_counter;
        let sender_view_tag = from_keypair.get_sender_view_tag(send_index)?;
        self.actor_mut(from).send_counter += 1;

        let spends: Vec<SpendUtxo> = inputs
            .iter()
            .map(|u| SpendUtxo::from((u.clone(), &from_keypair)))
            .collect();
        let mut tx =
            ClientTransaction::new(from_keypair.shielded_address()?, spends, payer_address);
        if let (Some(addr), Some(tag)) = (&to_address, to_view_tag) {
            tx.send(addr, send_asset, amount, tag)?;
        }
        let signed = tx.sign(
            Pubkey::default(),
            &from_keypair,
            &self.assets,
            sender_view_tag,
        )?;

        let commitments = signed.input_commitments()?;
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

        // The rail follows the input owner type: P256-owned inputs prove on the
        // P256 circuit, ed25519-owned inputs on the vanilla eddsa circuit (where the
        // owner authorizes the spend by signing the transaction).
        let assembled = signed.assemble(&spend_proofs)?;
        let (proof, rail) = match &assembled.prover_inputs {
            ProverInputs::P256(inputs) => (
                ProverClient::local().prove_transfer_p256(inputs)?,
                Rail::P256,
            ),
            ProverInputs::Eddsa(inputs) => {
                (ProverClient::local().prove_transfer(inputs)?, Rail::Eddsa)
            }
        };
        self.last_rail = Some(rail);
        let ix_data = assembled.with_proof(pack_proof(&proof)?);

        let transfer_ix = Transact {
            payer: fee_payer.pubkey(),
            tree: self.tree,
            cpi_signer: None,
            withdrawal: None,
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
        let tx_viewing_pk = indexed
            .tx_viewing_pk
            .ok_or_else(|| anyhow!("transfer missing tx_viewing_pk"))?;
        let salt = indexed
            .salt
            .ok_or_else(|| anyhow!("transfer missing salt"))?;
        let slots: Vec<OutputCiphertext> = indexed
            .output_slots
            .iter()
            .map(|slot| OutputCiphertext {
                view_tag: slot.view_tag,
                data: slot.payload.clone(),
            })
            .collect();
        let first_nullifier = commitments
            .first()
            .ok_or_else(|| anyhow!("no input commitment"))?
            .nullifier;
        let blob = TransferEncryptedUtxos::from_output_ciphertexts(
            tx_viewing_pk,
            salt,
            &slots,
            SENDER_SLOT_COUNT,
        )?;
        let (sender_plaintext, _) = from_keypair
            .viewing_key
            .decrypt_transfer(&first_nullifier, &blob)?;
        let seed = sender_plaintext.blinding_seed;

        let sync_tx = SyncTransaction {
            scheme: TRANSFER,
            tx_viewing_pk,
            salt,
            output_slots: slots,
            nullifiers: indexed.nullifiers.clone(),
        };
        self.indexed.push(sync_tx);

        // Expected recipient UTXO (the recipient slot sits at blinding position 2).
        if let (Some(to), Some(to_keypair)) = (to, &to_keypair) {
            let recipient_utxo = self.build_expected(
                to,
                to_keypair.signing_pubkey(),
                send_asset,
                amount,
                derive_blinding(&seed, RECIPIENT_POSITION_BASE),
            )?;
            self.actor_mut(to).expected.push(recipient_utxo);
        }

        // Mark consumed inputs spent if they were decrypted (tracked) UTXOs.
        let nullifier_pk = from_keypair.nullifier_key.pubkey()?;
        for input in &inputs {
            let consumed_hash = input.hash(&nullifier_pk, &ZERO, &ZERO)?;
            if let Some(note) = self
                .actor_mut(from)
                .expected
                .iter_mut()
                .find(|n| n.hash == consumed_hash)
            {
                note.spent = true;
            }
        }

        // Expected sender change per asset present in the inputs. Per spec the SPL
        // change sits at output position 0 and the SOL change at position 1.
        let spl_asset = inputs.iter().map(|u| u.asset).find(|a| *a != SOL_MINT);
        for (change_asset, position) in [
            (spl_asset, SPL_CHANGE_POSITION),
            (Some(SOL_MINT), SOL_CHANGE_POSITION),
        ] {
            let Some(change_asset) = change_asset else {
                continue;
            };
            let input_sum: u64 = inputs
                .iter()
                .filter(|u| u.asset == change_asset)
                .map(|u| u.amount)
                .sum();
            let sent = if change_asset == send_asset {
                amount
            } else {
                0
            };
            let change = input_sum - sent;
            if change > 0 {
                let change_utxo = self.build_expected(
                    from,
                    from_keypair.signing_pubkey(),
                    change_asset,
                    change,
                    derive_blinding(&seed, position),
                )?;
                self.actor_mut(from).expected.push(change_utxo);
            }
        }

        Ok(sig)
    }

    pub(crate) fn build_expected(
        &self,
        name: &str,
        owner: PublicKey,
        asset: Address,
        amount: u64,
        blinding: [u8; 31],
    ) -> Result<WalletUtxo> {
        let keypair = &self.actor(name).keypair;
        let nullifier_pk = keypair.nullifier_key.pubkey()?;
        let utxo = Utxo {
            owner,
            asset,
            amount,
            blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let hash = utxo.hash(&nullifier_pk, &ZERO, &ZERO)?;
        let nullifier = utxo.nullifier(&hash, &keypair.nullifier_key)?;
        Ok(WalletUtxo {
            utxo,
            hash,
            nullifier,
            spent: false,
        })
    }
}

fn spl_asset_address(world: &LifecycleWorld) -> Address {
    let mint = world.spl_asset().expect("SPL asset registered").mint;
    Address::new_from_array(mint.to_bytes())
}

#[when(expr = "{word} transfers {int} lamports of SOL to {word}")]
fn transfers(world: &mut LifecycleWorld, from: String, amount: i64, to: String) {
    world
        .transfer_asset(&from, &to, SOL_MINT, amount as u64)
        .expect("transfer");
}

#[when(expr = "{word} spends {int} lamports of SOL to {word}")]
fn spends(world: &mut LifecycleWorld, from: String, amount: i64, to: String) {
    world
        .transfer_asset(&from, &to, SOL_MINT, amount as u64)
        .expect("spend");
}

#[when(expr = "{word} transfers {int} tokens to {word}")]
fn transfers_tokens(world: &mut LifecycleWorld, from: String, amount: i64, to: String) {
    let asset = spl_asset_address(world);
    world
        .transfer_asset(&from, &to, asset, amount as u64)
        .expect("transfer tokens");
}

#[when(expr = "{word} spends {int} tokens to {word}")]
fn spends_tokens(world: &mut LifecycleWorld, from: String, amount: i64, to: String) {
    let asset = spl_asset_address(world);
    world
        .transfer_asset(&from, &to, asset, amount as u64)
        .expect("spend tokens");
}

#[when(expr = "{word} transfers {int} tokens to {word} with SOL and SPL inputs")]
fn transfers_mixed(world: &mut LifecycleWorld, from: String, amount: i64, to: String) {
    let asset = spl_asset_address(world);
    world
        .transfer_mixed(&from, &to, asset, amount as u64)
        .expect("mixed transfer");
}

#[when(expr = "{word} consolidates a SOL UTXO")]
fn consolidates_sol(world: &mut LifecycleWorld, from: String) {
    world.consolidate(&from, SOL_MINT).expect("consolidate SOL");
}

#[when(expr = "{word} consolidates a token UTXO")]
fn consolidates_spl(world: &mut LifecycleWorld, from: String) {
    let asset = spl_asset_address(world);
    world.consolidate(&from, asset).expect("consolidate token");
}

#[when(expr = "{word} transfers {int} lamports of SOL to {word} from a single UTXO")]
fn transfers_single_sol(world: &mut LifecycleWorld, from: String, amount: i64, to: String) {
    world
        .transfer_single(&from, &to, SOL_MINT, amount as u64)
        .expect("single-input SOL transfer");
}

#[when(expr = "{word} transfers {int} tokens to {word} from a single UTXO")]
fn transfers_single_spl(world: &mut LifecycleWorld, from: String, amount: i64, to: String) {
    let asset = spl_asset_address(world);
    world
        .transfer_single(&from, &to, asset, amount as u64)
        .expect("single-input SPL transfer");
}

#[then(expr = "the eddsa signer authorized the transfer")]
fn eddsa_signer_authorized(world: &mut LifecycleWorld) {
    assert_eq!(
        world.last_rail,
        Some(Rail::Eddsa),
        "transfer should take the eddsa rail (ed25519 signer authorizes the spend)"
    );
}

#[then(expr = "the proof authorized the transfer")]
fn p256_proof_authorized(world: &mut LifecycleWorld) {
    assert_eq!(
        world.last_rail,
        Some(Rail::P256),
        "transfer should take the P256 rail (ownership proven in the proof)"
    );
}
