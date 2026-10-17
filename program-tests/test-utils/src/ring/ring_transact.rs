//! Ring transfer and withdrawal operations.

use anyhow::{anyhow, Result};
use solana_account::Account;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    input_utxos_from_nullifiers, transaction_size, ComputeBudgetConfig, ProofAuthority,
    ProverClient, ProverExt, RingTransferProver, Shape, TransferInputUtxo,
};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{
            CircuitId, InputUtxo, TransactIxData, TransactProof, TreeContext,
        },
        tag::RING_TRANSACT,
    },
};
use zolana_program::instruction::{
    RingTransact, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
    TransactSplWithdrawalAccounts,
};
use zolana_program_test::Rejection;
use zolana_transaction::instructions::transact::ConfidentialTransaction;
use zolana_transaction::instructions::transact::SppProofInputs;
use zolana_transaction::utxo::SppProofInputUtxo;
use zolana_transaction::{
    instructions::transact::canonical_shape, Data, ShieldedTransaction, Utxo, SOL_MINT,
};

use super::{decode_output_blinding, RingHarness, SpendSlot};
use crate::{
    localnet::send_transaction_with_budget,
    spl::create_token_account,
    test_validator_asserts::{
        assert_account_unchanged, assert_ring_transact, fetch_account,
        wait_for_indexed_transaction, RingTransactAssertArgs,
    },
    transact::pack_transact_proof,
};

/// The output hashes a ring transfer produced, so the caller can confirm
/// `Wallet::sync` rediscovers each one.
#[derive(Default)]
struct DiscoveredOutputs {
    /// The recipient output hashes in recipient order (empty for a change-only
    /// transfer / withdrawal).
    recipients: Vec<[u8; 32]>,
    /// The sender's per-asset change output hashes.
    change: Vec<[u8; 32]>,
}

/// A proved ring transfer, sent and indexed, ready to be asserted and tracked.
struct SentRingTransfer {
    data: TransactIxData,
    fetch_view_tag: [u8; 32],
    indexed: ShieldedTransaction,
    signature: Signature,
    tree_before: Account,
}

/// The public settlement leg of a ring withdrawal.
#[derive(Clone, Copy)]
enum RingWithdrawal {
    Sol {
        recipient: Pubkey,
    },
    Spl {
        mint: Pubkey,
        recipient_token: Pubkey,
    },
}

impl RingWithdrawal {
    fn interface_accounts(&self) -> TransactInterfaceTransferAccounts {
        match self {
            Self::Sol { recipient } => {
                TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                    recipient: *recipient,
                })
            }
            Self::Spl {
                mint,
                recipient_token,
            } => TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
                mint: *mint,
                spl_interface: zolana_interface::pda::spl_interface(mint),
                user_token_account: *recipient_token,
                token_program: zolana_interface::pda::spl_token_program_id(),
            }),
        }
    }
}

struct RingTransferOperation<'a> {
    from: &'a str,
    /// Each recipient receives `amount` of `send_asset`.
    recipients: &'a [&'a str],
    inputs: &'a [Utxo],
    send_asset: Address,
    amount: u64,
    withdrawal: Option<RingWithdrawal>,
    /// Pad to this shape with compact padding instead of random dummies at
    /// the smallest shape that fits.
    compact_shape: Option<Shape>,
}

/// What a landed ring operation produced, for rebuilding the expected
/// recipient and change UTXOs. `output_ring` is the ring every output joined
/// (`None` for the default ring), which is folded into each output's hash.
struct TrackedOutputs<'a> {
    from: &'a str,
    recipients: &'a [&'a str],
    inputs: &'a [Utxo],
    send_asset: Address,
    amount: u64,
    output_ring: Option<Address>,
}

impl RingHarness {
    /// Ring-transfer `amount` of `asset` from `from` to `to` over the eddsa rail
    /// (the owner authorizes the spend with its ed25519 transaction signature),
    /// consolidating two of `from`'s spendable UTXOs of `asset` into the
    /// 2x4 shape.
    pub fn ring_transfer(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
    ) -> Result<Signature> {
        self.execute_ring_transfer(from, Some(to), [asset; 2], amount, None)
    }

    /// Ring-withdraw `amount` of `asset` from `from`'s ring UTXOs. The public
    /// amount leaves the pool while `from` keeps the change as a default-ring UTXO.
    /// Returns the settlement account the caller asserts against, a fresh
    /// system account for SOL and a fresh token account for an SPL mint.
    pub fn ring_withdraw(
        &mut self,
        from: &str,
        asset: Address,
        amount: u64,
    ) -> Result<(Signature, Pubkey)> {
        let withdrawal = if asset == SOL_MINT {
            RingWithdrawal::Sol {
                recipient: Keypair::new().pubkey(),
            }
        } else {
            let mint = Pubkey::new_from_array(asset.to_bytes());
            let owner = Keypair::new().pubkey();
            RingWithdrawal::Spl {
                mint,
                recipient_token: create_token_account(&self.rpc, &self.payer, &mint, &owner)?,
            }
        };
        let settlement_account = match withdrawal {
            RingWithdrawal::Sol { recipient } => recipient,
            RingWithdrawal::Spl {
                recipient_token, ..
            } => recipient_token,
        };
        let sig = self.execute_ring_transfer(from, None, [asset; 2], amount, Some(withdrawal))?;
        Ok((sig, settlement_account))
    }

    /// Ring-transfer `amount` of `spl_mint` funded by one SPL and one SOL ring
    /// UTXO, the SOL input returns whole as change beside the SPL change.
    pub fn ring_transfer_mixed(
        &mut self,
        from: &str,
        to: &str,
        spl_mint: Address,
        amount: u64,
    ) -> Result<Signature> {
        self.execute_ring_transfer(from, Some(to), [spl_mint, SOL_MINT], amount, None)
    }

    /// Build, prove (`ring_transact` rail), send, and verify a ring transfer or
    /// withdrawal. `withdrawal` is `Some` for a public-amount withdrawal,
    /// `None` for a pure shielded transfer. Pushes the indexed
    /// transaction, tracks the recipient / change UTXOs, and marks consumed
    /// inputs spent — mirroring the default-ring `transact` flow.
    /// `input_assets[0]` is the sent asset.
    fn execute_ring_transfer(
        &mut self,
        from: &str,
        to: Option<&str>,
        input_assets: [Address; 2],
        amount: u64,
        withdrawal: Option<RingWithdrawal>,
    ) -> Result<Signature> {
        if self.ring_config.is_none() {
            self.create_enabled_ring_config()?;
        }
        self.ensure_fresh_actor(from)?;
        if let Some(to) = to {
            self.ensure_fresh_actor(to)?;
        }

        let send_asset = input_assets[0];
        let inputs = self.take_ring_inputs(from, input_assets)?;
        self.execute_ring_operation(RingTransferOperation {
            from,
            recipients: to.as_slice(),
            inputs: &inputs,
            send_asset,
            amount,
            withdrawal,
            compact_shape: None,
        })
    }

    /// Ring-transfer `amount` of SOL from `from` to each of `recipients` on
    /// the runtime Ed25519 rail, spending `input_count` of `from`'s SOL ring UTXOs at
    /// `shape` with compact padding. Every output is real: one per recipient
    /// plus the sender's change.
    pub fn ring_transfer_to_many(
        &mut self,
        from: &str,
        recipients: &[&str],
        input_count: usize,
        amount: u64,
        shape: Shape,
    ) -> Result<Signature> {
        if self.ring_config.is_none() {
            self.create_enabled_ring_config()?;
        }
        self.ensure_fresh_actor(from)?;
        for recipient in recipients {
            self.ensure_fresh_actor(recipient)?;
        }
        let inputs: Vec<Utxo> = {
            let actor = self.actor_mut(from);
            let mut taken = Vec::with_capacity(input_count);
            for _ in 0..input_count {
                let pos = actor
                    .spendable
                    .iter()
                    .position(|u| u.asset.asset == SOL_MINT)
                    .ok_or_else(|| anyhow!("{from} needs {input_count} spendable SOL UTXOs"))?;
                taken.push(actor.spendable.remove(pos));
            }
            taken
        };
        self.execute_ring_operation(RingTransferOperation {
            from,
            recipients,
            inputs: &inputs,
            send_asset: SOL_MINT,
            amount,
            withdrawal: None,
            compact_shape: Some(shape),
        })
    }

    /// Send, assert, and track one prepared ring operation.
    fn execute_ring_operation(
        &mut self,
        operation: RingTransferOperation<'_>,
    ) -> Result<Signature> {
        let (from, recipients) = (operation.from, operation.recipients);
        let (inputs, send_asset, amount) =
            (operation.inputs, operation.send_asset, operation.amount);
        let output_ring = None;
        let sent = self.send_ring_transfer(operation)?;

        let SentRingTransfer {
            data,
            fetch_view_tag,
            indexed,
            signature,
            tree_before,
        } = sent;

        assert_ring_transact(
            &self.rpc,
            &self.indexer,
            RingTransactAssertArgs {
                tree: &self.tree,
                data: &data,
                signature,
                fetch_view_tag,
                tree_before: &tree_before,
            },
        )?;

        // Rebuild the expected recipient / change UTXOs from the committed output
        // blindings (decoded independently of `Wallet::sync`), then mark consumed
        // inputs spent, so `assert_utxos` is a real cross-check of the synced wallet.
        let discovered = self.track_outputs(
            TrackedOutputs {
                from,
                recipients,
                inputs,
                send_asset,
                amount,
                output_ring,
            },
            &indexed,
        )?;
        self.indexed.push(indexed);

        // Discovery via `Wallet::sync`: the confidential builder tagged the recipient
        // output by the recipient's owner-pubkey view tag and the sender change by the
        // sender's owner-pubkey view tag, the two tags `sync` scans for the default-ring
        // path (see `sdk-libs/transaction/src/wallet/sync.rs`). Sync each actor and
        // confirm its wallet now holds the new outputs by hash — no hand-asserted view tag.
        for (to, recipient_hash) in recipients.iter().zip(&discovered.recipients) {
            self.sync(to)?;
            self.assert_wallet_holds(to, *recipient_hash, "recipient ring-transfer output")?;
        }
        self.sync(from)?;
        for change_hash in &discovered.change {
            self.assert_wallet_holds(from, *change_hash, "sender ring-transfer change")?;
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
            .any(|w| w.utxo_hash == output_hash);
        if !found {
            return Err(anyhow!(
                "{name}'s synced wallet did not discover the {what} (hash {})",
                hex32(&output_hash)
            ));
        }
        Ok(())
    }

    /// Take one spendable UTXO of `from` per listed asset (the (2, 3) shape),
    /// ring-bound or default, both legal ring transact inputs.
    fn take_ring_inputs(&mut self, from: &str, assets: [Address; 2]) -> Result<Vec<Utxo>> {
        let actor = self.actor_mut(from);
        let mut taken = Vec::with_capacity(assets.len());
        for asset in assets {
            let pos = actor
                .spendable
                .iter()
                .position(|u| u.asset.asset == asset)
                .ok_or_else(|| anyhow!("{from} needs a spendable ring UTXO of {asset}"))?;
            taken.push(actor.spendable.remove(pos));
        }
        Ok(taken)
    }

    /// Assemble the proved `TransactIxData`, send the `RingTransact` instruction, and
    /// wait for the indexed transaction.
    fn send_ring_transfer(
        &mut self,
        operation: RingTransferOperation<'_>,
    ) -> Result<SentRingTransfer> {
        let RingTransferOperation {
            from,
            recipients,
            inputs,
            send_asset,
            amount,
            withdrawal,
            compact_shape,
        } = operation;
        let from_keypair = self.actor(from).keypair.clone();
        let recipient_keypairs = recipients
            .iter()
            .map(|recipient| self.actor(recipient).keypair.clone())
            .collect::<Vec<_>>();
        let to_addresses = recipient_keypairs
            .iter()
            .map(|k| k.shielded_address())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let to_view_tag = recipient_keypairs
            .first()
            .map(|k| k.signing_pubkey().confidential_view_tag())
            .transpose()?;
        let sender_view_tag = from_keypair.signing_pubkey().confidential_view_tag()?;

        // The owner transaction signature authorizes its spends.
        let fee_payer = self
            .actor(from)
            .solana_signer
            .as_ref()
            .map(|keypair| keypair.insecure_clone())
            .unwrap_or_else(|| self.payer.insecure_clone());
        let payer_address = Address::new_from_array(fee_payer.pubkey().to_bytes());

        // The high-level builder produces a decryptable SppProofInputs (outputs,
        // ciphertexts, external_data) exactly as a confidential transact; the ring
        // rail differs only in the prover and the instruction, plus the public
        // ring_program_id and the rebound discriminator.
        let ring = Address::new_from_array(self.ring_program_id.to_bytes());
        let nullifier_pk = from_keypair.nullifier_key.pubkey()?;
        let hashes = inputs
            .iter()
            .map(|input| input.hash(&nullifier_pk, &[0; 32], &[0; 32], self.tree_id))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let states = crate::test_validator_asserts::wait_for_merkle_proofs(
            &self.indexer,
            self.tree_address,
            &hashes,
        );
        let notes = inputs
            .iter()
            .zip(states)
            .map(|(input, state)| {
                crate::utxo::wallet(
                    input.clone(),
                    &from_keypair.nullifier_key,
                    self.tree_id,
                    state.leaf_index,
                    None,
                    None,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let shape = match compact_shape {
            Some(shape) => shape,
            None => canonical_shape(notes.len(), 2 + to_addresses.len())?,
        };
        let mut transfer = match compact_shape {
            None => ConfidentialTransaction::new(notes, payer_address)?,
            Some(_) => ConfidentialTransaction::new_compact(notes, payer_address)?,
        }
        .with_output_tree_id(self.tree_id)?;
        match (to_addresses.is_empty(), withdrawal) {
            (false, None) => {
                for addr in &to_addresses {
                    if send_asset == SOL_MINT {
                        transfer.transfer_sol(addr, amount)?;
                    } else {
                        transfer.transfer(addr, send_asset, amount)?;
                    }
                }
            }
            (true, Some(withdrawal)) => match withdrawal {
                RingWithdrawal::Sol { recipient } => {
                    transfer.withdraw_sol(amount, recipient)?;
                }
                RingWithdrawal::Spl {
                    recipient_token, ..
                } => {
                    transfer.withdraw(send_asset, amount, recipient_token)?;
                }
            },
            (false, Some(_)) => {
                return Err(anyhow!("a ring transfer cannot both send and withdraw"));
            }
            (true, None) => {
                return Err(anyhow!("a ring transfer needs a recipient or a withdrawal"));
            }
        }
        transfer.pad_utxos(shape, &from_keypair.shielded_address()?)?;
        let mut proof_inputs = transfer.encrypt(&from_keypair)?;
        // Rebind the discriminator to RING_TRANSACT before anything commits to
        // external_data: it is folded into external_data_hash and private_tx_hash, so
        // the proof and the on-chain recompute must agree on it.
        proof_inputs.external_data.instruction_discriminator = RING_TRANSACT;

        let data = self.prove_and_assemble(&proof_inputs, &from_keypair, ring)?;

        let interface_transfer_accounts = withdrawal
            .map(|withdrawal| vec![withdrawal.interface_accounts()])
            .unwrap_or_default();
        let owner_signers = proof_inputs
            .owner_signer_pubkeys()?
            .iter()
            .map(|address| Pubkey::new_from_array(address.to_bytes()))
            .collect();

        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let transfer_ix = RingTransact {
            payer: fee_payer.pubkey(),
            input_trees: vec![self.tree],
            output_tree: self.tree,
            ring_program_id: self.ring_program_id,
            owner_signers,
            interface_transfer_accounts,
            data: data.clone(),
        }
        .instruction();
        let instructions = [transfer_ix.clone()];
        let budget = ComputeBudgetConfig::new(1_400_000);
        self.last_transaction_size = Some(transaction_size(
            &fee_payer.pubkey(),
            &instructions,
            budget,
        )?);
        let signature = send_transaction_with_budget(
            &mut self.rpc,
            &instructions,
            &fee_payer.pubkey(),
            &[&fee_payer],
            budget,
        )?;

        // A change-only transfer/withdrawal has no recipient slot, so locate the
        // indexed transaction by the sender's view tag instead.
        let fetch_view_tag = to_view_tag.unwrap_or(sender_view_tag);
        let indexed = wait_for_indexed_transaction(&self.indexer, fetch_view_tag, signature);

        Ok(SentRingTransfer {
            data,
            fetch_view_tag,
            indexed,
            signature,
            tree_before,
        })
    }

    /// Build the runtime-authorized ring witness and retain its public statement on the wire.
    fn prove_and_assemble(
        &self,
        proof_inputs: &SppProofInputs,
        signer: &zolana_keypair::ShieldedKeypair,
        ring: Address,
    ) -> Result<TransactIxData> {
        let input_utxos = self.ring_input_utxos(&proof_inputs.input_utxos)?;
        let tx_shape = proof_inputs.check_shape()?;
        let shape = Shape::new(tx_shape.n_inputs(), tx_shape.n_outputs());
        let prover = RingTransferProver {
            blinding_seed: proof_inputs.blinding_seed,
            output_tree_id: proof_inputs.output_tree_id,
            inputs: input_utxos,
            outputs: proof_inputs.output_utxos.clone(),
            external_data: proof_inputs.external_data.clone(),
            public_transfers: proof_inputs.public_transfers()?,
            signer_pk_hashes: proof_inputs.signer_pk_hashes(shape.signer_width())?,
            allow_dummy_inputs: true,
            ring_program_id: Some(ring),
            shape,
        };
        let mut result = prover.build()?;
        signer.complete_inputs(&mut result.inputs.inputs)?;
        let proof = ProverClient::local().prove_transfer_ring(&result.inputs)?;
        assemble_ix_data(
            proof_inputs,
            input_utxos_from_nullifiers(&result.nullifiers, &result.input_tree_indexes)?,
            result.private_tx_hash,
            result.tree_contexts.clone(),
            pack_transact_proof(&proof)?,
        )
    }

    /// Convert the builder's padded `SppProofInputUtxo` list into the prover's
    /// `TransferSpendInput` list, fetching a `SpendProof` for every real input
    /// against its ring-bound UTXO hash. A dummy carries no state proof (it mirrors
    /// the first real input's state root downstream) but still needs a real
    /// non-inclusion witness for its own nullifier: the circuit checks
    /// non-inclusion for every slot. All proofs come from one indexer snapshot
    /// per tree (see [`RingHarness::fetch_slot_proofs`]).
    fn ring_input_utxos(
        &self,
        input_utxos: &[SppProofInputUtxo],
    ) -> Result<Vec<TransferInputUtxo>> {
        // Both the ring-bound commitment and the nullifier were computed when the
        // spend was built, so the state proof is fetched against the same hash
        // the witness carries.
        let slots = input_utxos
            .iter()
            .map(|input_utxo| SpendSlot {
                utxo_hash: (!input_utxo.is_dummy()).then_some(input_utxo.hash()),
                nullifier: input_utxo.nullifier(),
            })
            .collect::<Vec<_>>();
        let proofs = self.fetch_slot_proofs(&slots)?;
        Ok(input_utxos
            .iter()
            .zip(proofs)
            .map(|(input_utxo, (proof, nullifier_proof))| TransferInputUtxo {
                utxo: input_utxo.clone(),
                proof,
                nullifier_proof,
            })
            .collect())
    }

    /// Track the expected recipient and per-asset sender-change UTXOs and mark the
    /// consumed inputs spent, rebuilt independently from the decoded output blindings
    /// so `assert_utxos` cross-checks the synced wallet. Mirrors the default-ring
    /// `transact` flow; a withdrawal has no recipient slot and reduces the SOL change
    /// by the public amount. Every output joins `tracked.output_ring`.
    fn track_outputs(
        &mut self,
        tracked: TrackedOutputs<'_>,
        indexed: &ShieldedTransaction,
    ) -> Result<DiscoveredOutputs> {
        let TrackedOutputs {
            from,
            recipients,
            inputs,
            send_asset,
            amount,
            output_ring,
        } = tracked;
        let from_keypair = self.actor(from).keypair.clone();
        let mut discovered = DiscoveredOutputs::default();

        let mut expected = Vec::new();
        for to in recipients {
            expected.push((
                *to,
                self.actor(to).keypair.signing_pubkey(),
                send_asset,
                amount,
                true,
            ));
        }
        // A withdrawal has no recipient and still moves `amount` out of the pool.
        let sent_total = u64::try_from(recipients.len().max(1))?
            .checked_mul(amount)
            .ok_or_else(|| anyhow!("sent amount overflows"))?;
        let mut assets = Vec::new();
        for input in inputs {
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
            let change = total
                .checked_sub(if asset == send_asset { sent_total } else { 0 })
                .ok_or_else(|| anyhow!("change underflow"))?;
            if change > 0 {
                expected.push((from, from_keypair.signing_pubkey(), asset, change, false));
            }
        }
        if expected.is_empty() && self.actor(from).solana_signer.is_some() {
            expected.push((from, from_keypair.signing_pubkey(), SOL_MINT, 0, false));
        }
        assert!(expected.len() <= indexed.output_slots.len());
        for (position, (actor, owner, asset, amount, recipient)) in expected.into_iter().enumerate()
        {
            let note = self.build_expected(
                actor,
                Utxo {
                    owner,
                    asset: self.assets.mint(&asset)?,
                    amount,
                    blinding: decode_output_blinding(
                        &from_keypair.viewing_key,
                        indexed,
                        position as u32,
                    )?,
                    ring_program_id: output_ring,
                    data: Data::default(),
                },
                indexed,
            )?;
            if recipient {
                discovered.recipients.push(note.utxo_hash);
            } else {
                discovered.change.push(note.utxo_hash);
            }
            self.actor_mut(actor).expected.push(note);
        }
        Ok(discovered)
    }

    /// Attempt a ring transfer whose proof bytes are zeroed; SPP's shared transact
    /// proof verifier must reject it. Builds the same instruction the happy path
    /// does (real inputs, padded dummies, decryptable outputs) but replaces the
    /// proof with `TransactProof::zeroed`, so only proof verification fails.
    /// Borrows (does not consume) the inputs: a rejected transfer spends nothing.
    pub fn ring_transfer_bad_proof(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
    ) -> Result<()> {
        if self.ring_config.is_none() {
            self.create_enabled_ring_config()?;
        }
        self.ensure_fresh_actor(from)?;
        self.ensure_fresh_actor(to)?;

        let inputs: Vec<Utxo> = {
            let actor = self.actor(from);
            let mut taken = Vec::with_capacity(2);
            for utxo in actor.spendable.iter().filter(|u| u.asset.asset == asset) {
                taken.push(utxo.clone());
                if taken.len() == 2 {
                    break;
                }
            }
            if taken.len() < 2 {
                return Err(anyhow!("{from} needs two spendable ring UTXOs of {asset}"));
            }
            taken
        };

        let from_keypair = self.actor(from).keypair.clone();
        let to_address = self.actor(to).keypair.shielded_address()?;
        let fee_payer = self
            .actor(from)
            .solana_signer
            .as_ref()
            .map(|keypair| keypair.insecure_clone())
            .unwrap_or_else(|| self.payer.insecure_clone());
        let payer_address = Address::new_from_array(fee_payer.pubkey().to_bytes());

        let nullifier_pk = from_keypair.nullifier_key.pubkey()?;
        let hashes = inputs
            .iter()
            .map(|input| input.hash(&nullifier_pk, &[0; 32], &[0; 32], self.tree_id))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let states = crate::test_validator_asserts::wait_for_merkle_proofs(
            &self.indexer,
            self.tree_address,
            &hashes,
        );
        let notes = inputs
            .iter()
            .zip(states)
            .map(|(input, state)| {
                crate::utxo::wallet(
                    input.clone(),
                    &from_keypair.nullifier_key,
                    self.tree_id,
                    state.leaf_index,
                    None,
                    None,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let shape = canonical_shape(notes.len(), 3)?;
        let mut transfer = ConfidentialTransaction::new(notes, payer_address)?
            .with_output_tree_id(self.tree_id)?;
        if asset == SOL_MINT {
            transfer.transfer_sol(&to_address, amount)?;
        } else {
            transfer.transfer(&to_address, asset, amount)?;
        }
        transfer.pad_utxos(shape, &from_keypair.shielded_address()?)?;
        let mut proof_inputs = transfer.encrypt(&from_keypair)?;
        proof_inputs.external_data.instruction_discriminator = RING_TRANSACT;

        // Assemble the instruction data with real nullifiers / root indices but a
        // zeroed proof, so verification is the only thing that fails.
        let ring = Address::new_from_array(self.ring_program_id.to_bytes());
        let tx_shape = proof_inputs.check_shape()?;
        let prover = RingTransferProver {
            blinding_seed: proof_inputs.blinding_seed,
            output_tree_id: proof_inputs.output_tree_id,
            inputs: self.ring_input_utxos(&proof_inputs.input_utxos)?,
            outputs: proof_inputs.output_utxos.clone(),
            external_data: proof_inputs.external_data.clone(),
            public_transfers: proof_inputs.public_transfers()?,
            signer_pk_hashes: proof_inputs.signer_pk_hashes(
                Shape::new(tx_shape.n_inputs(), tx_shape.n_outputs()).signer_width(),
            )?,
            allow_dummy_inputs: true,
            ring_program_id: Some(ring),
            shape: Shape::new(tx_shape.n_inputs(), tx_shape.n_outputs()),
        };
        let result = prover.build()?;
        let data = assemble_ix_data(
            &proof_inputs,
            input_utxos_from_nullifiers(&result.nullifiers, &result.input_tree_indexes)?,
            result.private_tx_hash,
            result.tree_contexts.clone(),
            TransactProof::zeroed(),
        )?;

        let owner_signers = proof_inputs
            .owner_signer_pubkeys()?
            .iter()
            .map(|address| Pubkey::new_from_array(address.to_bytes()))
            .collect();
        let transfer_ix = RingTransact {
            payer: fee_payer.pubkey(),
            input_trees: vec![self.tree],
            output_tree: self.tree,
            ring_program_id: self.ring_program_id,
            owner_signers,
            interface_transfer_accounts: Vec::new(),
            data,
        }
        .instruction();
        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        match send_transaction_with_budget(
            &mut self.rpc,
            &[transfer_ix],
            &fee_payer.pubkey(),
            &[&fee_payer],
            ComputeBudgetConfig::new(1_400_000),
        ) {
            Ok(_) => Err(anyhow!(
                "ring transfer with an invalid proof unexpectedly succeeded"
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

/// Assemble the `TransactIxData` from the signed transaction's external data and
/// the prover result, mirroring `client::prover::transact::witness::assemble`. Each
/// padded input carries its nullifier hash and root indices; authorization comes
/// from the leading owner-signer run in the accounts array, not from any
/// per-input field. `external_data` fields flow through unchanged (already
/// rebound to `RING_TRANSACT`).
#[allow(clippy::too_many_arguments)]
fn assemble_ix_data(
    proof_inputs: &SppProofInputs,
    inputs: Vec<InputUtxo>,
    private_tx_hash: [u8; 32],
    tree_contexts: Vec<TreeContext>,
    proof: TransactProof,
) -> Result<TransactIxData> {
    let shape = proof_inputs.check_shape()?;
    let n_inputs = shape.n_inputs();
    if inputs.len() > n_inputs {
        return Err(anyhow!(
            "witness input count {} exceeds shape {n_inputs}",
            inputs.len()
        ));
    }

    let external = &proof_inputs.external_data;
    let n_outputs = u8::try_from(shape.n_outputs())?;
    let n_slots = zolana_interface::N_PUBLIC_SLOTS as u8;
    let circuit = CircuitId::ConfidentialRingEd25519(n_inputs as u8, n_outputs, n_slots);
    Ok(TransactIxData {
        proof,
        expiry_unix_ts: external.expiry_unix_ts,
        private_tx_hash,
        circuit,
        inputs,
        tree_contexts,
        interface_transfers: external
            .interface_transfers
            .iter()
            .map(|transfer| transfer.interface_transfer())
            .collect(),
        data_hash: external.data_hash,
        ring_data_hash: external.ring_data_hash,
        tx_viewing_pk: external.tx_viewing_pk,
        salt: external.salt,
        outputs: external.outputs.clone(),
        messages: external.messages.clone(),
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
