//! `zone_transact` steps and the World zone-transfer / zone-withdraw operations.
//! `zone_transact` is the anonymous policy-zone analog of `transact`: a
//! shield/unshield/shielded transfer over zone-owned UTXOs. SPP verifies a real
//! Groth16 proof against the anonymous zone verifying keys, so the happy path
//! needs a real proof from the prover server. There is no SDK helper that emits a
//! `ZoneTransact` instruction, so the test is the zone's client: it assembles the
//! `TransactIxData` itself and sends `ZoneTransact{..}.instruction()` to the
//! fixture program, which forwards to SPP signing the zone's `zone_auth` PDA.
//!
//! Assembly mirrors `sdk-libs/client/src/prover/transact/witness.rs::assemble`:
//! the high-level `Transaction` builder produces a decryptable `SignedTransaction`
//! (outputs, ciphertexts, `external_data`) exactly as a confidential `transact`
//! would, then this module rebinds the instruction discriminator to
//! `ZONE_TRANSACT`, drives the zone prover rail, and folds the prover result and
//! the builder's `external_data` into a `TransactIxData`. Zone outputs carry
//! `zone_program_id: None` (the `zone_transact` variant exempts UTXOs whose
//! `zone_program_id` is `0` from the public-zone binding, per spec); the inputs
//! are the zone-owned UTXOs from the zone deposits, and the public
//! `zone_program_id` comes from the `ZoneConfig` the program reads.
//!
//! The eddsa rail authorizes the spend with the owner's ed25519 transaction
//! signature (the owner sits at signer index 0 / the fee payer). The P256 rail
//! proves ownership inside the proof: the shared P256 owner signs
//! `sha256(private_tx_hash)`, recovered with a probe build before the final prover
//! is constructed.

use anyhow::{anyhow, Result};
use cucumber::{then, when};
use rings_client::{
    P256Owner, ProverClient, PublicAmounts, Rpc, Shape, SignedTransaction, SpendProof, SpendUtxo,
    Transaction as ClientTransaction, TransferSpendInput, WithdrawalTarget, ZoneTransferP256Prover,
    ZoneTransferProver,
};
use rings_interface::instruction::{
    instruction_data::transact::{InputUtxo, TransactIxData, TransactProof},
    tag::ZONE_TRANSACT,
    TransactSolWithdrawal, TransactWithdrawal, ZoneTransact,
};
use rings_keypair::{hash::sha256, ShieldedKeypair, SignatureType};
use rings_test_utils::test_validator_asserts::{
    assert_zone_transact, fetch_account, wait_for_indexed_transaction, wait_for_merkle_proof,
    wait_for_non_inclusion_proof, ZoneTransactAssertArgs,
};
use rings_transaction::{utxo::derive_blinding, ShieldedTransaction, Utxo, SOL_MINT};
use solana_account::Account;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;

use crate::{
    localnet::{
        send_transaction, transact_proof, RECIPIENT_POSITION_BASE, SOL_CHANGE_POSITION,
        SPL_CHANGE_POSITION, ZERO,
    },
    support::Rail,
    world::decode_sender_seed,
    ZoneLifecycleWorld,
};

/// `ShieldedPoolError::TransactProofVerificationFailed`: SPP's shared transact
/// proof verifier rejects a malformed / zeroed proof.
const TRANSACT_PROOF_VERIFICATION_FAILED: u32 = 7008;

/// Sentinel `eddsa_signer_index` marking a P256-owned input; SPP uses it to select
/// the P256 verifying key and skip the per-input eddsa signer check. Mirrors
/// `P256_OWNED_SIGNER` in the shielded-pool program and `witness.rs`.
const P256_OWNED_SIGNER: u8 = 255;

/// Default output-tree slot for every input (`tree_index` 0), as in `witness.rs`.
const DEFAULT_TREE_INDEX: u8 = 0;

/// Default eddsa signer account index for a Solana-owned input (the fee payer).
const DEFAULT_EDDSA_SIGNER_INDEX: u8 = 0;

/// The output hashes a zone transfer produced, so the step can confirm
/// `Wallet::sync` rediscovers each one.
#[derive(Default)]
struct DiscoveredOutputs {
    /// The recipient output hash (`None` for a change-only transfer / withdrawal).
    recipient: Option<[u8; 32]>,
    /// The sender's per-asset change output hashes.
    change: Vec<[u8; 32]>,
}

/// A proved zone transfer, sent and indexed, ready to be asserted and tracked.
struct SentZoneTransfer {
    data: TransactIxData,
    fetch_view_tag: [u8; 32],
    indexed: ShieldedTransaction,
    signature: Signature,
    tree_before: Account,
}

impl ZoneLifecycleWorld {
    /// Zone-transfer `amount` of `asset` from `from` to `to` over the eddsa rail
    /// (the owner authorizes the spend with its ed25519 transaction signature),
    /// consolidating two of `from`'s spendable zone UTXOs of `asset` into the
    /// (2, 3) shape. Sets `last_rail` to [`Rail::Eddsa`].
    pub(crate) fn zone_transfer(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
    ) -> Result<Signature> {
        self.execute_zone_transfer(from, Some(to), asset, amount, None, Rail::Eddsa)
    }

    /// Zone-transfer `amount` of `asset` from `from` to `to` over the P256 rail
    /// (ownership proven inside the proof via the shared P256 owner signature).
    /// Sets `last_rail` to [`Rail::P256`].
    pub(crate) fn zone_transfer_p256(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
    ) -> Result<Signature> {
        self.execute_zone_transfer(from, Some(to), asset, amount, None, Rail::P256)
    }

    /// Zone-withdraw `amount` of SOL from `from`'s zone UTXOs to a fresh external
    /// Solana account: the public SOL amount leaves the pool while `from` keeps the
    /// change as a zone UTXO. Eddsa rail. Returns the withdrawal recipient so the
    /// step can assert the lamports landed.
    pub(crate) fn zone_withdraw(
        &mut self,
        from: &str,
        asset: Address,
        amount: u64,
    ) -> Result<(Signature, Pubkey)> {
        if asset != SOL_MINT {
            return Err(anyhow!("only SOL zone withdrawals are supported"));
        }
        let recipient = Keypair::new().pubkey();
        let sig =
            self.execute_zone_transfer(from, None, asset, amount, Some(recipient), Rail::Eddsa)?;
        Ok((sig, recipient))
    }

    /// Build, prove (`zone_transact` rail), send, and verify a zone transfer or
    /// withdrawal. `withdrawal` is `Some(recipient)` for a public-amount SOL
    /// withdrawal; `None` for a pure shielded transfer. Records `last_transact` and
    /// `last_rail`, pushes the indexed transaction, tracks the recipient / change
    /// UTXOs, and marks consumed inputs spent — mirroring the default-zone
    /// `transact` flow.
    fn execute_zone_transfer(
        &mut self,
        from: &str,
        to: Option<&str>,
        send_asset: Address,
        amount: u64,
        withdrawal: Option<Pubkey>,
        rail: Rail,
    ) -> Result<Signature> {
        if self.zone_config.is_none() {
            self.create_enabled_zone_config()?;
        }
        self.ensure_actor(from)?;
        if let Some(to) = to {
            self.ensure_actor(to)?;
        }

        let inputs = self.take_zone_inputs(from, send_asset)?;
        let sent =
            self.send_zone_transfer(from, to, &inputs, send_asset, amount, withdrawal, rail)?;
        self.last_rail = Some(rail);

        let SentZoneTransfer {
            data,
            fetch_view_tag,
            indexed,
            signature,
            tree_before,
        } = sent;

        assert_zone_transact(
            &self.rpc,
            &self.indexer,
            ZoneTransactAssertArgs {
                tree: &self.tree,
                data: &data,
                signature,
                fetch_view_tag,
                tree_before: &tree_before,
            },
        )?;

        // Rebuild the expected recipient / change UTXOs from the seed in the sender
        // bundle (decoded independently of `Wallet::sync`), then mark consumed inputs
        // spent, so `assert_utxos` is a real cross-check of the synced wallet.
        let seed = decode_sender_seed(&self.actor(from).keypair.viewing_key, &indexed)?;
        let discovered =
            self.track_outputs(from, to, &inputs, send_asset, amount, seed, &indexed)?;
        self.indexed.push(indexed);

        // Discovery via `Wallet::sync`: the confidential builder tagged the recipient
        // output by the recipient's owner-pubkey view tag and the sender change by the
        // sender's (riding the sender bundle at slot 0 / `get_sender_view_tag`), the
        // two tags `sync` scans for the default-zone path (see
        // `sdk-libs/transaction/src/wallet/sync.rs`). Sync each actor and confirm its
        // wallet now holds the new outputs by hash — no hand-asserted view tag.
        if let (Some(to), Some(recipient_hash)) = (to, discovered.recipient) {
            self.sync(to)?;
            self.assert_wallet_holds(to, recipient_hash, "recipient zone-transfer output")?;
        }
        self.sync(from)?;
        for change_hash in &discovered.change {
            self.assert_wallet_holds(from, *change_hash, "sender zone-transfer change")?;
        }

        Ok(signature)
    }

    /// Confirm `name`'s synced wallet holds an unspent UTXO with `output_hash`. Run
    /// `sync` first; this leans on `Wallet::sync` discovery (the confidential owner
    /// tag the builder attached), not on a hand-set view tag.
    fn assert_wallet_holds(&self, name: &str, output_hash: [u8; 32], what: &str) -> Result<()> {
        let found = self
            .actor(name)
            .wallet
            .utxos
            .iter()
            .any(|w| w.output_context.hash == output_hash && !w.spent);
        if !found {
            return Err(anyhow!(
                "{name}'s synced wallet did not discover the {what} (hash {})",
                hex32(&output_hash)
            ));
        }
        Ok(())
    }

    /// Take two of `from`'s spendable zone UTXOs of `asset` (the (2, 3) shape). A
    /// zone UTXO carries `zone_program_id`, so its hash binds the zone the prover
    /// stamps on the proof.
    fn take_zone_inputs(&mut self, from: &str, asset: Address) -> Result<Vec<Utxo>> {
        let actor = self.actor_mut(from);
        let mut taken = Vec::with_capacity(2);
        for _ in 0..2 {
            let pos = actor
                .spendable
                .iter()
                .position(|u| u.asset == asset)
                .ok_or_else(|| anyhow!("{from} needs two spendable zone UTXOs of {asset}"))?;
            taken.push(actor.spendable.remove(pos));
        }
        Ok(taken)
    }

    /// Assemble the proved `TransactIxData`, send the `ZoneTransact` instruction, and
    /// wait for the indexed transaction.
    #[allow(clippy::too_many_arguments)]
    fn send_zone_transfer(
        &mut self,
        from: &str,
        to: Option<&str>,
        inputs: &[Utxo],
        send_asset: Address,
        amount: u64,
        withdrawal: Option<Pubkey>,
        rail: Rail,
    ) -> Result<SentZoneTransfer> {
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
        let sender_view_tag = from_keypair.signing_pubkey().confidential_view_tag()?;

        // The eddsa rail's owner sits at signer index 0 (the fee payer), so an eddsa
        // actor pays and signs its own spend; a P256 actor falls back to the global
        // payer (ownership is proven in the proof).
        let fee_payer = self
            .actor(from)
            .solana_signer
            .as_ref()
            .map(|k| k.insecure_clone())
            .unwrap_or_else(|| self.payer.insecure_clone());
        let payer_address = Address::new_from_array(fee_payer.pubkey().to_bytes());

        // The high-level builder produces a decryptable SignedTransaction (outputs,
        // ciphertexts, external_data) exactly as a confidential transact; the zone
        // rail differs only in the prover and the instruction, plus the public
        // zone_program_id and the rebound discriminator.
        let spends: Vec<SpendUtxo> = inputs
            .iter()
            .map(|u| SpendUtxo::from_keypair(u.clone(), &from_keypair))
            .collect();
        let mut tx =
            ClientTransaction::new(from_keypair.shielded_address()?, spends, payer_address);
        match (&to_address, withdrawal) {
            (Some(addr), None) => {
                tx.send(addr, send_asset, amount)?;
            }
            (None, Some(recipient)) => {
                tx.withdraw(
                    send_asset,
                    amount,
                    WithdrawalTarget::Sol {
                        user_sol_account: Address::new_from_array(recipient.to_bytes()),
                    },
                )?;
            }
            (Some(_), Some(_)) => {
                return Err(anyhow!("a zone transfer cannot both send and withdraw"));
            }
            (None, None) => {
                return Err(anyhow!("a zone transfer needs a recipient or a withdrawal"));
            }
        }
        let mut signed = tx.sign(&from_keypair, &self.assets)?;
        // Rebind the discriminator to ZONE_TRANSACT before anything commits to
        // external_data: it is folded into external_data_hash and private_tx_hash, so
        // the proof and the on-chain recompute must agree on it.
        signed.external_data.instruction_discriminator = ZONE_TRANSACT;

        let zone = Address::new_from_array(self.zone_program_id.to_bytes());
        let data = self.prove_and_assemble(&signed, zone, rail)?;

        let withdrawal_meta = withdrawal
            .map(|recipient| TransactWithdrawal::Sol(TransactSolWithdrawal { recipient }));

        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let transfer_ix = ZoneTransact {
            payer: fee_payer.pubkey(),
            tree: self.tree,
            zone_program_id: self.zone_program_id,
            withdrawal: withdrawal_meta,
            data: data.clone(),
        }
        .instruction();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let signature = send_transaction(
            &mut self.rpc,
            &[compute_budget, transfer_ix.clone()],
            &fee_payer.pubkey(),
            &[&fee_payer],
        )?;
        self.last_transact = Some((signature, transfer_ix));

        // A change-only transfer/withdrawal has no recipient slot, so locate the
        // indexed transaction by the sender's view tag instead.
        let fetch_view_tag = to_view_tag.unwrap_or(sender_view_tag);
        let indexed = wait_for_indexed_transaction(&self.indexer, fetch_view_tag, signature);

        Ok(SentZoneTransfer {
            data,
            fetch_view_tag,
            indexed,
            signature,
            tree_before,
        })
    }

    /// Drive the zone prover rail and fold the result into a `TransactIxData`,
    /// mirroring `witness.rs::assemble`.
    fn prove_and_assemble(
        &self,
        signed: &SignedTransaction,
        zone: Address,
        rail: Rail,
    ) -> Result<TransactIxData> {
        let spend_inputs = self.zone_spend_inputs(&signed.inputs)?;
        let shape = Shape::new(signed.shape.n_inputs, signed.shape.n_outputs);

        match rail {
            Rail::Eddsa => {
                let prover = ZoneTransferProver {
                    inputs: spend_inputs,
                    outputs: signed.outputs.clone(),
                    external_data: signed.external_data.clone(),
                    public_amounts: client_public_amounts(signed.public_amounts),
                    payer_pubkey_hash: signed.payer_pubkey_hash,
                    zone_program_id: Some(zone),
                    shape: Some(shape),
                };
                let result = prover.build()?;
                let proof = ProverClient::local().prove_transfer_zone(&result.inputs)?;
                assemble_ix_data(
                    signed,
                    &result.nullifiers,
                    result.private_tx_hash,
                    &result.input_root_indices,
                    None,
                    Rail::Eddsa,
                    transact_proof(&proof)?,
                )
            }
            Rail::P256 => {
                let p256_owner = self.p256_owner(signed, zone)?;
                let prover = ZoneTransferP256Prover {
                    inputs: spend_inputs,
                    outputs: signed.outputs.clone(),
                    external_data: signed.external_data.clone(),
                    public_amounts: client_public_amounts(signed.public_amounts),
                    payer_pubkey_hash: signed.payer_pubkey_hash,
                    p256_owner,
                    zone_program_id: Some(zone),
                    shape: Some(shape),
                };
                let result = prover.build()?;
                let proof = ProverClient::local().prove_transfer_p256_zone(&result.inputs)?;
                assemble_ix_data(
                    signed,
                    &result.nullifiers,
                    result.private_tx_hash,
                    &result.input_root_indices,
                    Some(result.p256_signing_pk_field),
                    Rail::P256,
                    transact_proof(&proof)?,
                )
            }
        }
    }

    /// Recover the shared [`P256Owner`] for the P256 rail: probe-build the zone P256
    /// prover with a placeholder owner to recover `private_tx_hash` (independent of
    /// the signature), sign `sha256(private_tx_hash)` with the actor that owns the
    /// first real P256 input, then return the signed owner. The probe and the final
    /// build use identical inputs/outputs/external_data, so the hash is stable.
    fn p256_owner(&self, signed: &SignedTransaction, zone: Address) -> Result<P256Owner> {
        let signing_keypair = self.p256_signing_keypair(signed)?;
        let pubkey = signing_keypair.signing_pubkey().as_p256()?;

        let probe = ZoneTransferP256Prover {
            inputs: self.zone_spend_inputs(&signed.inputs)?,
            outputs: signed.outputs.clone(),
            external_data: signed.external_data.clone(),
            public_amounts: client_public_amounts(signed.public_amounts),
            payer_pubkey_hash: signed.payer_pubkey_hash,
            p256_owner: P256Owner {
                pubkey,
                sig_r: [0u8; 32],
                sig_s: [0u8; 32],
            },
            zone_program_id: Some(zone),
            shape: Some(Shape::new(signed.shape.n_inputs, signed.shape.n_outputs)),
        };
        let private_tx_hash = probe.build()?.private_tx_hash;

        let signature = signing_keypair.sign(&sha256(&private_tx_hash));
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(
            signature
                .get(..32)
                .ok_or_else(|| anyhow!("short P256 signature"))?,
        );
        sig_s.copy_from_slice(
            signature
                .get(32..)
                .ok_or_else(|| anyhow!("short P256 signature"))?,
        );
        Ok(P256Owner {
            pubkey,
            sig_r,
            sig_s,
        })
    }

    /// The actor keypair whose signing pubkey owns the first real P256 input, used
    /// to sign `sha256(private_tx_hash)`.
    fn p256_signing_keypair(&self, signed: &SignedTransaction) -> Result<ShieldedKeypair> {
        let owner = signed
            .inputs
            .iter()
            .filter(|spend| !spend.is_dummy())
            .map(|spend| spend.utxo.owner)
            .find(|owner| matches!(owner.signature_type(), Ok(SignatureType::P256)))
            .ok_or_else(|| anyhow!("no P256-owned input to authorize the zone transfer"))?;
        self.actors
            .values()
            .find(|actor| actor.keypair.signing_pubkey() == owner)
            .map(|actor| actor.keypair.clone())
            .ok_or_else(|| anyhow!("no tracked actor owns the P256 input"))
    }

    /// Convert the builder's padded `SpendUtxo` list into the prover's
    /// `TransferSpendInput` list, fetching a `SpendProof` for every real input
    /// against its zone-bound UTXO hash (dummies carry no proof and mirror the first
    /// real input's roots downstream).
    fn zone_spend_inputs(&self, spends: &[SpendUtxo]) -> Result<Vec<TransferSpendInput>> {
        let mut out = Vec::with_capacity(spends.len());
        for spend in spends {
            let proof = if spend.is_dummy() {
                None
            } else {
                let nullifier_pk = spend.nullifier_key.pubkey()?;
                let utxo_hash = spend.utxo.hash(&nullifier_pk, &ZERO, &ZERO)?;
                let nullifier = spend
                    .nullifier_key
                    .nullifier(&utxo_hash, &spend.utxo.blinding)?;
                let state = wait_for_merkle_proof(&self.indexer, self.tree_address, utxo_hash);
                let nf = wait_for_non_inclusion_proof(&self.indexer, self.tree_address, nullifier);
                Some(SpendProof {
                    state,
                    nullifier: nf,
                })
            };
            out.push(TransferSpendInput {
                utxo: spend.utxo.clone(),
                nullifier_key: spend.nullifier_key.clone(),
                data_hash: None,
                zone_data_hash: None,
                proof,
            });
        }
        Ok(out)
    }

    /// Track the expected recipient and per-asset sender-change UTXOs and mark the
    /// consumed inputs spent, rebuilt independently from the decoded blinding seed so
    /// `assert_utxos` cross-checks the synced wallet. Mirrors the default-zone
    /// `transact` flow; a withdrawal has no recipient slot and reduces the SOL change
    /// by the public amount.
    // All eight inputs are the independent facts a single tracked transfer needs;
    // bundling them into a struct here would only obscure the one call site.
    #[allow(clippy::too_many_arguments)]
    fn track_outputs(
        &mut self,
        from: &str,
        to: Option<&str>,
        inputs: &[Utxo],
        send_asset: Address,
        amount: u64,
        seed: [u8; 31],
        indexed: &ShieldedTransaction,
    ) -> Result<DiscoveredOutputs> {
        let from_keypair = self.actor(from).keypair.clone();
        let mut discovered = DiscoveredOutputs::default();

        if let Some(to) = to {
            let to_keypair = self.actor(to).keypair.clone();
            let recipient_utxo = self.build_expected(
                to,
                to_keypair.signing_pubkey(),
                send_asset,
                amount,
                derive_blinding(&seed, RECIPIENT_POSITION_BASE),
                indexed,
            )?;
            discovered.recipient = Some(recipient_utxo.output_context.hash);
            self.actor_mut(to).expected.push(recipient_utxo);
        }

        let nullifier_pk = from_keypair.nullifier_key.pubkey()?;
        for input in inputs {
            let consumed_hash = input.hash(&nullifier_pk, &ZERO, &ZERO)?;
            if let Some(note) = self
                .actor_mut(from)
                .expected
                .iter_mut()
                .find(|n| n.output_context.hash == consumed_hash)
            {
                note.spent = true;
            }
        }

        // Per-asset sender change: SPL change at output position 0, SOL change at
        // position 1 (the fixed-position output layout). A withdrawal (no recipient
        // slot) sends the public amount out of the pool; the rest is SOL change.
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
            let change = input_sum
                .checked_sub(sent)
                .ok_or_else(|| anyhow!("{from} change underflow: sent {sent} of {change_asset}"))?;
            if change > 0 {
                let change_utxo = self.build_expected(
                    from,
                    from_keypair.signing_pubkey(),
                    change_asset,
                    change,
                    derive_blinding(&seed, position),
                    indexed,
                )?;
                discovered.change.push(change_utxo.output_context.hash);
                self.actor_mut(from).expected.push(change_utxo);
            }
        }
        Ok(discovered)
    }

    /// Attempt a zone transfer whose proof bytes are zeroed; SPP's shared transact
    /// proof verifier must reject it. Builds the same instruction the happy path
    /// does (real inputs, padded dummies, decryptable outputs) but replaces the
    /// proof with `TransactProof::zeroed_eddsa`, so only proof verification fails.
    /// Borrows (does not consume) the inputs: a rejected transfer spends nothing.
    pub(crate) fn zone_transfer_bad_proof(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
    ) -> Result<()> {
        if self.zone_config.is_none() {
            self.create_enabled_zone_config()?;
        }
        self.ensure_actor(from)?;
        self.ensure_actor(to)?;

        let inputs: Vec<Utxo> = {
            let actor = self.actor(from);
            let mut taken = Vec::with_capacity(2);
            for utxo in actor.spendable.iter().filter(|u| u.asset == asset) {
                taken.push(utxo.clone());
                if taken.len() == 2 {
                    break;
                }
            }
            if taken.len() < 2 {
                return Err(anyhow!("{from} needs two spendable zone UTXOs of {asset}"));
            }
            taken
        };

        let from_keypair = self.actor(from).keypair.clone();
        let to_address = self.actor(to).keypair.shielded_address()?;
        let fee_payer = self
            .actor(from)
            .solana_signer
            .as_ref()
            .map(|k| k.insecure_clone())
            .unwrap_or_else(|| self.payer.insecure_clone());
        let payer_address = Address::new_from_array(fee_payer.pubkey().to_bytes());

        let spends: Vec<SpendUtxo> = inputs
            .iter()
            .map(|u| SpendUtxo::from_keypair(u.clone(), &from_keypair))
            .collect();
        let mut tx =
            ClientTransaction::new(from_keypair.shielded_address()?, spends, payer_address);
        tx.send(&to_address, asset, amount)?;
        let mut signed = tx.sign(&from_keypair, &self.assets)?;
        signed.external_data.instruction_discriminator = ZONE_TRANSACT;

        // Assemble the instruction data with real nullifiers / root indices but a
        // zeroed proof, so verification is the only thing that fails.
        let zone = Address::new_from_array(self.zone_program_id.to_bytes());
        let prover = ZoneTransferProver {
            inputs: self.zone_spend_inputs(&signed.inputs)?,
            outputs: signed.outputs.clone(),
            external_data: signed.external_data.clone(),
            public_amounts: client_public_amounts(signed.public_amounts),
            payer_pubkey_hash: signed.payer_pubkey_hash,
            zone_program_id: Some(zone),
            shape: Some(Shape::new(signed.shape.n_inputs, signed.shape.n_outputs)),
        };
        let result = prover.build()?;
        let data = assemble_ix_data(
            &signed,
            &result.nullifiers,
            result.private_tx_hash,
            &result.input_root_indices,
            None,
            Rail::Eddsa,
            TransactProof::zeroed_eddsa(),
        )?;

        let transfer_ix = ZoneTransact {
            payer: fee_payer.pubkey(),
            tree: self.tree,
            zone_program_id: self.zone_program_id,
            withdrawal: None,
            data,
        }
        .instruction();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        match send_transaction(
            &mut self.rpc,
            &[compute_budget, transfer_ix],
            &fee_payer.pubkey(),
            &[&fee_payer],
        ) {
            Ok(_) => Err(anyhow!(
                "zone transfer with an invalid proof unexpectedly succeeded"
            )),
            Err(error) => {
                assert_rpc_custom_error(&error, TRANSACT_PROOF_VERIFICATION_FAILED);
                Ok(())
            }
        }
    }
}

/// Convert the transaction crate's `PublicAmounts` into the prover client's
/// identically-shaped type (both are `{ sol, spl, asset }: [u8; 32]`).
fn client_public_amounts(
    amounts: rings_transaction::instructions::transact::PublicAmounts,
) -> PublicAmounts {
    PublicAmounts {
        sol: amounts.sol,
        spl: amounts.spl,
        asset: amounts.asset,
    }
}

/// Assemble the `TransactIxData` from the signed transaction's external data and
/// the prover result, mirroring `client::prover::transact::witness::assemble`. Each
/// padded input carries its nullifier hash, root indices, and signer index; dummies
/// inherit the first real input's signer. `external_data` fields flow through
/// unchanged (already rebound to `ZONE_TRANSACT`).
fn assemble_ix_data(
    signed: &SignedTransaction,
    nullifiers: &[[u8; 32]],
    private_tx_hash: [u8; 32],
    root_indices: &[(u16, u16)],
    p256_signing_pk_field: Option<[u8; 32]>,
    rail: Rail,
    proof: TransactProof,
) -> Result<TransactIxData> {
    let n_inputs = signed.shape.n_inputs;
    if nullifiers.len() != n_inputs || root_indices.len() != n_inputs {
        return Err(anyhow!(
            "witness input count {} / {} does not match shape {n_inputs}",
            nullifiers.len(),
            root_indices.len()
        ));
    }

    // Per-input signer index: a real P256 input uses the P256 sentinel, a real
    // eddsa input uses signer index 0 (the fee payer); dummies inherit the first
    // real input's signer.
    let mut real_signer_indices = Vec::new();
    for spend in signed.inputs.iter().filter(|spend| !spend.is_dummy()) {
        let signer = match (rail, spend.utxo.owner.signature_type()?) {
            (Rail::P256, SignatureType::P256) => P256_OWNED_SIGNER,
            _ => DEFAULT_EDDSA_SIGNER_INDEX,
        };
        real_signer_indices.push(signer);
    }
    let dummy_signer = real_signer_indices
        .first()
        .copied()
        .unwrap_or(DEFAULT_EDDSA_SIGNER_INDEX);

    let mut inputs = Vec::with_capacity(n_inputs);
    for i in 0..n_inputs {
        let nullifier_hash = *nullifiers
            .get(i)
            .ok_or_else(|| anyhow!("missing nullifier {i}"))?;
        let &(utxo_tree_root_index, nullifier_tree_root_index) = root_indices
            .get(i)
            .ok_or_else(|| anyhow!("missing root index {i}"))?;
        let eddsa_signer_index = real_signer_indices.get(i).copied().unwrap_or(dummy_signer);
        inputs.push(InputUtxo {
            nullifier_hash,
            nullifier_tree_root_index,
            utxo_tree_root_index,
            tree_index: DEFAULT_TREE_INDEX,
            eddsa_signer_index,
        });
    }

    let external = &signed.external_data;
    Ok(TransactIxData {
        proof,
        expiry_unix_ts: external.expiry_unix_ts,
        relayer_fee: external.relayer_fee,
        private_tx_hash,
        p256_signing_pk_field,
        inputs,
        public_sol_amount: external.public_sol_amount,
        public_spl_amount: external.public_spl_amount,
        data_hash: external.data_hash,
        zone_data_hash: external.zone_data_hash,
        tx_viewing_pk: external.tx_viewing_pk,
        salt: external.salt,
        output_utxo_hashes: external.output_utxo_hashes.clone(),
        output_ciphertexts: external.output_ciphertexts.clone(),
    })
}

/// Lowercase hex of a 32-byte hash for error messages.
fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
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

#[when(expr = "{word} zone-transfers {int} lamports of SOL to {word}")]
fn zone_transfers_sol(world: &mut ZoneLifecycleWorld, from: String, amount: i64, to: String) {
    world
        .zone_transfer(&from, &to, SOL_MINT, amount as u64)
        .expect("zone transfer SOL");
}

#[when(expr = "{word} zone-transfers {int} lamports of SOL to {word} over the P256 rail")]
fn zone_transfers_sol_p256(world: &mut ZoneLifecycleWorld, from: String, amount: i64, to: String) {
    world
        .zone_transfer_p256(&from, &to, SOL_MINT, amount as u64)
        .expect("zone transfer SOL (P256)");
}

#[when(expr = "{word} zone-withdraws {int} lamports of SOL")]
fn zone_withdraws_sol(world: &mut ZoneLifecycleWorld, from: String, amount: i64) {
    let (_sig, recipient) = world
        .zone_withdraw(&from, SOL_MINT, amount as u64)
        .expect("zone withdraw SOL");
    // The public amount left the pool to the fresh external account.
    let account = world
        .rpc
        .get_account(Address::new_from_array(recipient.to_bytes()))
        .expect("fetch withdrawal recipient")
        .expect("withdrawal recipient funded");
    assert_eq!(
        account.lamports, amount as u64,
        "zone withdrawal recipient should receive the public SOL amount"
    );
}

#[then(expr = "a zone transfer with an invalid proof is rejected")]
fn invalid_proof_rejected(world: &mut ZoneLifecycleWorld) {
    world
        .zone_transfer_bad_proof("alice", "bob", SOL_MINT, 1)
        .expect("zone transfer with invalid proof rejected");
}

#[then(expr = "the eddsa signer authorized the zone transfer")]
fn eddsa_signer_authorized(world: &mut ZoneLifecycleWorld) {
    assert_eq!(
        world.last_rail,
        Some(Rail::Eddsa),
        "zone transfer should take the eddsa rail (ed25519 signer authorizes the spend)"
    );
}

#[then(expr = "the proof authorized the zone transfer")]
fn p256_proof_authorized(world: &mut ZoneLifecycleWorld) {
    assert_eq!(
        world.last_rail,
        Some(Rail::P256),
        "zone transfer should take the P256 rail (ownership proven in the proof)"
    );
}
