//! Ring transfer and withdrawal operations.

use anyhow::{anyhow, Result};
use solana_account::Account;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    ConfidentialTransfer, ProofCompressed, ProverClient, RingTransferP256Prover,
    RingTransferProver, Shape, SpendProof, SppProofInputUtxo, SppProofInputs, TransferSpendInput,
};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{CircuitId, InputUtxo, TransactIxData, TransactProof},
        tag::RING_TRANSACT,
        RingTransact, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
        TransactSplWithdrawalAccounts,
    },
    verifying_keys::{Bsb22Commitment, RingP256ProofData},
};
use zolana_program_test::Rejection;
use zolana_transaction::{
    instructions::transact::SettlementTarget, Data, ShieldedTransaction, SyncWalletAuthority, Utxo,
    SOL_MINT,
};

use super::{decode_output_blinding, RingHarness};
use crate::{
    localnet::{
        send_transaction, send_transaction_fitting, RECIPIENT_POSITION_BASE, SOL_CHANGE_POSITION,
        SPL_CHANGE_POSITION, ZERO,
    },
    spl::create_token_account,
    test_validator_asserts::{
        assert_account_unchanged, assert_ring_transact, fetch_account,
        wait_for_indexed_transaction, wait_for_merkle_proof, wait_for_non_inclusion_proof,
        RingTransactAssertArgs,
    },
    transact::pack_transact_proof,
};

/// The output hashes a ring transfer produced, so the caller can confirm
/// `Wallet::sync` rediscovers each one.
#[derive(Default)]
struct DiscoveredOutputs {
    /// The recipient output hash (`None` for a change-only transfer / withdrawal).
    recipient: Option<[u8; 32]>,
    /// The sender's per-asset change output hashes.
    change: Vec<[u8; 32]>,
}

/// The prover rail a ring transfer is proved on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RingRail {
    /// Ownership authorized by the transaction signature (signer run).
    #[default]
    Eddsa,
    /// Ownership authorized inside the proof (RingP256 + BSB22 commitment).
    P256,
}

/// Cross-rail grafting and proof-data tampering for the negative cases. The
/// prover always runs on `rail`; the tamper only changes what goes on the wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ProofTamper {
    #[default]
    None,
    /// Corrupt the embedded BSB22 commitment (rejected before pairing, 7007).
    BadCommitment,
    /// A P256 proof submitted under the RingEddsa selector (pairing fails, 7008).
    P256ProofUnderEddsaSelector,
    /// An eddsa proof submitted under the RingP256 selector (no valid BSB22
    /// commitment can exist for it, so encoding fails first, 7007).
    EddsaProofUnderP256Selector,
    /// A wrong `default_owner_tag` in the proof data (pairing fails, 7008).
    BadDefaultOwnerTag,
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
    fn settlement_target(&self) -> SettlementTarget {
        match self {
            Self::Sol { recipient } => SettlementTarget::Sol {
                user_sol_account: Address::new_from_array(recipient.to_bytes()),
            },
            Self::Spl {
                mint,
                recipient_token,
            } => SettlementTarget::Spl {
                user_spl_token: Address::new_from_array(recipient_token.to_bytes()),
                spl_token_interface: Address::new_from_array(
                    zolana_interface::pda::spl_interface(mint).to_bytes(),
                ),
            },
        }
    }

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
    to: Option<&'a str>,
    inputs: &'a [Utxo],
    send_asset: Address,
    amount: u64,
    withdrawal: Option<RingWithdrawal>,
    rail: RingRail,
    tamper: ProofTamper,
}

impl RingHarness {
    /// Ring-transfer `amount` of `asset` from `from` to `to` over the eddsa rail
    /// (the owner authorizes the spend with its ed25519 transaction signature),
    /// consolidating two of `from`'s spendable UTXOs of `asset` into the
    /// (2, 3) shape.
    pub fn ring_transfer(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
    ) -> Result<Signature> {
        self.execute_ring_transfer(from, Some(to), [asset; 2], amount, None, RingRail::Eddsa)
    }

    /// Ring-transfer `amount` of `asset` from `from` to `to` over the P256 rail
    /// (ownership proved inside the RingP256 proof; the harness payer funds the
    /// transaction), consolidating two of `from`'s spendable UTXOs into the
    /// (2, 3) shape.
    pub fn ring_transfer_p256(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
    ) -> Result<Signature> {
        self.execute_ring_transfer(from, Some(to), [asset; 2], amount, None, RingRail::P256)
    }

    /// Ring-withdraw `amount` of `asset` from `from`'s ring UTXOs. The public
    /// amount leaves the pool while `from` keeps the change as a ring UTXO. Eddsa
    /// rail. Returns the settlement account the caller asserts against, a fresh
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
        let sig = self.execute_ring_transfer(
            from,
            None,
            [asset; 2],
            amount,
            Some(withdrawal),
            RingRail::Eddsa,
        )?;
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
        self.execute_ring_transfer(
            from,
            Some(to),
            [spl_mint, SOL_MINT],
            amount,
            None,
            RingRail::Eddsa,
        )
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
        rail: RingRail,
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
            to,
            inputs: &inputs,
            send_asset,
            amount,
            withdrawal,
            rail,
            tamper: ProofTamper::None,
        })
    }

    /// Send, assert, and track one prepared ring operation.
    fn execute_ring_operation(
        &mut self,
        operation: RingTransferOperation<'_>,
    ) -> Result<Signature> {
        let (from, to) = (operation.from, operation.to);
        let (inputs, send_asset, amount) =
            (operation.inputs, operation.send_asset, operation.amount);
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
        let discovered = self.track_outputs(from, to, inputs, send_asset, amount, &indexed)?;
        self.indexed.push(indexed);

        // Discovery via `Wallet::sync`: the confidential builder tagged the recipient
        // output by the recipient's owner-pubkey view tag and the sender change by the
        // sender's owner-pubkey view tag, the two tags `sync` scans for the default-ring
        // path (see `sdk-libs/transaction/src/wallet/sync.rs`). Sync each actor and
        // confirm its wallet now holds the new outputs by hash — no hand-asserted view tag.
        if let (Some(to), Some(recipient_hash)) = (to, discovered.recipient) {
            self.sync(to)?;
            self.assert_wallet_holds(to, recipient_hash, "recipient ring-transfer output")?;
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
            .any(|w| w.output_context.hash == output_hash && !w.spent);
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
                .position(|u| u.asset == asset)
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
            to,
            inputs,
            send_asset,
            amount,
            withdrawal,
            rail,
            tamper,
        } = operation;
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

        // An eddsa actor pays and signs its own spend; a P256 actor falls back
        // to the harness payer because ownership is proven inside the proof.
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
        let spends: Vec<SppProofInputUtxo> = inputs
            .iter()
            .map(|u| SppProofInputUtxo::new(u.clone(), &from_keypair))
            .collect();
        let mut transfer =
            ConfidentialTransfer::new(from_keypair.shielded_address()?, spends, payer_address);
        match (&to_address, withdrawal) {
            (Some(addr), None) => {
                transfer.send(addr, send_asset, amount)?;
            }
            (None, Some(withdrawal)) => {
                transfer.withdraw(send_asset, amount, withdrawal.settlement_target())?;
            }
            (Some(_), Some(_)) => {
                return Err(anyhow!("a ring transfer cannot both send and withdraw"));
            }
            (None, None) => {
                return Err(anyhow!("a ring transfer needs a recipient or a withdrawal"));
            }
        }
        let mut proof_inputs = match rail {
            RingRail::Eddsa => transfer.sign(&from_keypair, &self.assets)?,
            RingRail::P256 => transfer.sign_ring_p256(&from_keypair, &self.assets)?,
        };
        // Rebind the discriminator to RING_TRANSACT before anything commits to
        // external_data: it is folded into external_data_hash and private_tx_hash, so
        // the proof and the on-chain recompute must agree on it.
        proof_inputs.external_data.instruction_discriminator = RING_TRANSACT;

        let ring = Address::new_from_array(self.ring_program_id.to_bytes());
        let data = self.prove_and_assemble(&proof_inputs, &from_keypair, ring, rail, tamper)?;

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
            input_tree: self.tree,
            output_tree: self.tree,
            ring_program_id: self.ring_program_id,
            owner_signers,
            interface_transfer_accounts,
            data: data.clone(),
        }
        .instruction();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let instructions = [compute_budget, transfer_ix.clone()];
        let signature = send_transaction_fitting(&mut self.rpc, &instructions, &fee_payer, &[])?;

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

    /// Drive the ring prover rail and fold the result into a `TransactIxData`,
    /// mirroring `witness.rs::assemble`. The prover always runs on `rail`;
    /// `tamper` only changes what lands on the wire (grafted selector or
    /// corrupted proof data).
    fn prove_and_assemble(
        &self,
        proof_inputs: &SppProofInputs,
        signer: &zolana_keypair::ShieldedKeypair,
        ring: Address,
        rail: RingRail,
        tamper: ProofTamper,
    ) -> Result<TransactIxData> {
        let spend_inputs = self.ring_spend_inputs(&proof_inputs.input_utxos)?;
        let tx_shape = proof_inputs.check_shape()?;
        let shape = Shape::new(tx_shape.n_inputs(), tx_shape.n_outputs());
        let signer_pk_hashes = proof_inputs.signer_pk_hashes(tx_shape.n_inputs() + 1)?;

        match rail {
            RingRail::Eddsa => {
                let prover = RingTransferProver {
                    inputs: spend_inputs,
                    outputs: proof_inputs.output_utxos.clone(),
                    external_data: proof_inputs.external_data.clone(),
                    public_transfers: proof_inputs.public_transfers()?,
                    signer_pk_hashes,
                    allow_dummy_inputs: true,
                    ring_program_id: Some(ring),
                    shape: Some(shape),
                };
                let result = prover.build()?;
                let proof = ProverClient::local().prove_transfer_ring(&result.inputs)?;
                let proof = pack_transact_proof(&proof)?;
                if tamper == ProofTamper::EddsaProofUnderP256Selector {
                    // No valid BSB22 commitment can exist for an eddsa proof; a
                    // zeroed one is rejected at the encoding check.
                    assemble_ix_data(
                        proof_inputs,
                        &result.nullifiers,
                        result.private_tx_hash,
                        &result.input_root_indices,
                        RingRail::P256,
                        proof,
                        Some(Bsb22Commitment {
                            commitment: [0u8; 32],
                            commitment_pok: [0u8; 32],
                        }),
                        None,
                    )
                } else {
                    assemble_ix_data(
                        proof_inputs,
                        &result.nullifiers,
                        result.private_tx_hash,
                        &result.input_root_indices,
                        RingRail::Eddsa,
                        proof,
                        None,
                        None,
                    )
                }
            }
            RingRail::P256 => {
                let authorization =
                    SyncWalletAuthority::sign_p256(signer, &proof_inputs.message_hash()?)?;
                let prover = RingTransferP256Prover {
                    inputs: spend_inputs,
                    outputs: proof_inputs.output_utxos.clone(),
                    external_data: proof_inputs.external_data.clone(),
                    public_transfers: proof_inputs.public_transfers()?,
                    signer_pk_hashes,
                    allow_dummy_inputs: true,
                    authorization,
                    ring_program_id: Some(ring),
                    shape: Some(shape),
                };
                let result = prover.build()?;
                let proof = ProverClient::local().prove_transfer_p256_ring(&result.inputs)?;
                let (proof, commitment) = p256_transact_proof(&proof)?;
                let mut commitment = commitment;
                if tamper == ProofTamper::BadCommitment {
                    commitment.commitment = [u8::MAX; 32];
                }
                let wire_rail = if tamper == ProofTamper::P256ProofUnderEddsaSelector {
                    RingRail::Eddsa
                } else {
                    RingRail::P256
                };
                let default_owner_tag = if tamper == ProofTamper::BadDefaultOwnerTag {
                    result.default_owner_tag.map(|_| [u8::MAX; 32])
                } else {
                    result.default_owner_tag
                };
                assemble_ix_data(
                    proof_inputs,
                    &result.nullifiers,
                    result.private_tx_hash,
                    &result.input_root_indices,
                    wire_rail,
                    proof,
                    Some(commitment),
                    default_owner_tag,
                )
            }
        }
    }

    /// Convert the builder's padded `SppProofInputUtxo` list into the prover's
    /// `TransferSpendInput` list, fetching a `SpendProof` for every real input
    /// against its ring-bound UTXO hash. A dummy carries no state proof (it mirrors
    /// the first real input's state root downstream) but still needs a real
    /// non-inclusion witness for its own nullifier: the circuit checks
    /// non-inclusion for every slot.
    fn ring_spend_inputs(&self, spends: &[SppProofInputUtxo]) -> Result<Vec<TransferSpendInput>> {
        let mut out = Vec::with_capacity(spends.len());
        for spend in spends {
            let (proof, nullifier_proof) = if spend.is_dummy() {
                let nullifier = spend.nullifier()?;
                let nf = wait_for_non_inclusion_proof(&self.indexer, self.tree_address, nullifier);
                (None, Some(nf))
            } else {
                let nullifier_pk = spend.nullifier_key.pubkey()?;
                let utxo_hash = spend.utxo.hash(&nullifier_pk, &ZERO, &ZERO)?;
                let nullifier = spend
                    .nullifier_key
                    .nullifier(&utxo_hash, &spend.utxo.blinding)?;
                let state = wait_for_merkle_proof(&self.indexer, self.tree_address, utxo_hash);
                let nf = wait_for_non_inclusion_proof(&self.indexer, self.tree_address, nullifier);
                (
                    Some(SpendProof {
                        state,
                        nullifier: nf,
                    }),
                    None,
                )
            };
            out.push(TransferSpendInput {
                utxo: spend.utxo.clone(),
                nullifier_key: spend.nullifier_key.clone(),
                data_hash: None,
                ring_data_hash: None,
                proof,
                nullifier_proof,
            });
        }
        Ok(out)
    }

    /// Track the expected recipient and per-asset sender-change UTXOs and mark the
    /// consumed inputs spent, rebuilt independently from the decoded output blindings
    /// so `assert_utxos` cross-checks the synced wallet. Mirrors the default-ring
    /// `transact` flow; a withdrawal has no recipient slot and reduces the SOL change
    /// by the public amount.
    fn track_outputs(
        &mut self,
        from: &str,
        to: Option<&str>,
        inputs: &[Utxo],
        send_asset: Address,
        amount: u64,
        indexed: &ShieldedTransaction,
    ) -> Result<DiscoveredOutputs> {
        let from_keypair = self.actor(from).keypair.clone();
        let mut discovered = DiscoveredOutputs::default();

        if let Some(to) = to {
            let to_keypair = self.actor(to).keypair.clone();
            let recipient_utxo = self.build_expected(
                to,
                Utxo {
                    owner: to_keypair.signing_pubkey(),
                    asset: send_asset,
                    amount,
                    blinding: decode_output_blinding(
                        &from_keypair.viewing_key,
                        indexed,
                        RECIPIENT_POSITION_BASE as u32,
                    )?,
                    ring_program_id: None,
                    data: Data::default(),
                },
                indexed,
            )?;
            discovered.recipient = Some(recipient_utxo.output_context.hash);
            self.actor_mut(to).expected.push(recipient_utxo);
        }

        let nullifier_pk = from_keypair.nullifier_key.pubkey()?;
        for input in inputs {
            let consumed_hash = input.hash(&nullifier_pk, &ZERO, &ZERO)?;
            if let Some(utxo) = self
                .actor_mut(from)
                .expected
                .iter_mut()
                .find(|n| n.output_context.hash == consumed_hash)
            {
                utxo.spent = true;
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
                    Utxo {
                        owner: from_keypair.signing_pubkey(),
                        asset: change_asset,
                        amount: change,
                        blinding: decode_output_blinding(
                            &from_keypair.viewing_key,
                            indexed,
                            position as u32,
                        )?,
                        ring_program_id: None,
                        data: Data::default(),
                    },
                    indexed,
                )?;
                discovered.change.push(change_utxo.output_context.hash);
                self.actor_mut(from).expected.push(change_utxo);
            }
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
            for utxo in actor.spendable.iter().filter(|u| u.asset == asset) {
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

        let spends: Vec<SppProofInputUtxo> = inputs
            .iter()
            .map(|u| SppProofInputUtxo::new(u.clone(), &from_keypair))
            .collect();
        let mut transfer =
            ConfidentialTransfer::new(from_keypair.shielded_address()?, spends, payer_address);
        transfer.send(&to_address, asset, amount)?;
        let mut proof_inputs = transfer.sign(&from_keypair, &self.assets)?;
        proof_inputs.external_data.instruction_discriminator = RING_TRANSACT;

        // Assemble the instruction data with real nullifiers / root indices but a
        // zeroed proof, so verification is the only thing that fails.
        let ring = Address::new_from_array(self.ring_program_id.to_bytes());
        let tx_shape = proof_inputs.check_shape()?;
        let prover = RingTransferProver {
            inputs: self.ring_spend_inputs(&proof_inputs.input_utxos)?,
            outputs: proof_inputs.output_utxos.clone(),
            external_data: proof_inputs.external_data.clone(),
            public_transfers: proof_inputs.public_transfers()?,
            signer_pk_hashes: proof_inputs.signer_pk_hashes(tx_shape.n_inputs() + 1)?,
            allow_dummy_inputs: true,
            ring_program_id: Some(ring),
            shape: Some(Shape::new(tx_shape.n_inputs(), tx_shape.n_outputs())),
        };
        let result = prover.build()?;
        let data = assemble_ix_data(
            &proof_inputs,
            &result.nullifiers,
            result.private_tx_hash,
            &result.input_root_indices,
            RingRail::Eddsa,
            TransactProof::zeroed(),
            None,
            None,
        )?;

        let transfer_ix = RingTransact {
            payer: fee_payer.pubkey(),
            input_tree: self.tree,
            output_tree: self.tree,
            ring_program_id: self.ring_program_id,
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            data,
        }
        .instruction();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        match send_transaction(
            &mut self.rpc,
            &[compute_budget, transfer_ix],
            &fee_payer.pubkey(),
            &[&fee_payer],
        ) {
            Ok(_) => Err(anyhow!(
                "ring transfer with an invalid proof unexpectedly succeeded"
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

    /// Clone two of `from`'s spendable UTXOs of `asset` without consuming them
    /// (negative paths, where the spend never lands). `ring_only` selects the
    /// ring-owned set; `false` selects default-ring UTXOs (e.g. a default-ring
    /// P256 input, which exposes `default_owner_tag` on the wire).
    fn peek_spendable_inputs(
        &self,
        from: &str,
        asset: Address,
        ring_only: bool,
    ) -> Result<Vec<Utxo>> {
        let inputs: Vec<Utxo> = self
            .actor(from)
            .spendable
            .iter()
            .filter(|utxo| utxo.asset == asset && (utxo.ring_program_id.is_some() == ring_only))
            .take(2)
            .cloned()
            .collect();
        if inputs.len() != 2 {
            return Err(anyhow!(
                "{from} needs two spendable {} UTXOs of {asset}",
                if ring_only { "ring" } else { "default-ring" }
            ));
        }
        Ok(inputs)
    }

    /// Run a tampered ring-transfer attempt and assert the exact rejection plus
    /// an untouched tree. The inputs are peeked, so `from`'s spendable set is
    /// unchanged for a later happy-path attempt.
    #[allow(clippy::too_many_arguments)]
    fn expect_tampered_rejection(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
        rail: RingRail,
        tamper: ProofTamper,
        expected: ShieldedPoolError,
    ) -> Result<()> {
        if self.ring_config.is_none() {
            self.create_enabled_ring_config()?;
        }
        self.ensure_fresh_actor(from)?;
        self.ensure_fresh_actor(to)?;
        let inputs = self.peek_spendable_inputs(from, asset, true)?;
        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        match self.send_ring_transfer(RingTransferOperation {
            from,
            to: Some(to),
            inputs: &inputs,
            send_asset: asset,
            amount,
            withdrawal: None,
            rail,
            tamper,
        }) {
            Ok(_) => Err(anyhow!(
                "tampered ring transfer ({tamper:?}) unexpectedly succeeded"
            )),
            Err(error) => {
                let client_error = error
                    .downcast_ref::<zolana_client::ClientError>()
                    .unwrap_or_else(|| panic!("expected typed client error, got {error:?}"));
                Rejection::pool(expected).at(1).assert_client(client_error);
                assert_account_unchanged(&self.rpc, &self.tree, &tree_before)?;
                Ok(())
            }
        }
    }

    /// Request a valid P256 proof, corrupt only its embedded BSB22 commitment,
    /// and confirm SPP rejects the instruction at the encoding check, before
    /// pairing verification (7007).
    pub fn ring_transfer_p256_bad_commitment_rejected(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
    ) -> Result<()> {
        self.expect_tampered_rejection(
            from,
            to,
            asset,
            amount,
            RingRail::P256,
            ProofTamper::BadCommitment,
            ShieldedPoolError::InvalidTransactProofEncoding,
        )
    }

    /// Cross-rail grafting: a valid P256 proof submitted under the RingEddsa
    /// selector. The selector picks the eddsa verifying key, so pairing fails
    /// (7008).
    pub fn p256_proof_under_eddsa_selector_rejected(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
    ) -> Result<()> {
        self.expect_tampered_rejection(
            from,
            to,
            asset,
            amount,
            RingRail::P256,
            ProofTamper::P256ProofUnderEddsaSelector,
            ShieldedPoolError::TransactProofVerificationFailed,
        )
    }

    /// Cross-rail grafting: a valid eddsa proof submitted under the RingP256
    /// selector. No valid BSB22 commitment can exist for it — a zeroed one
    /// decodes as the point at infinity, so it slips past the encoding check
    /// and the graft fails at pairing verification instead (7008). Garbage
    /// commitments still fail at encoding (7007, covered by the bad-commitment
    /// tamper).
    pub fn eddsa_proof_under_p256_selector_rejected(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
    ) -> Result<()> {
        self.expect_tampered_rejection(
            from,
            to,
            asset,
            amount,
            RingRail::Eddsa,
            ProofTamper::EddsaProofUnderP256Selector,
            ShieldedPoolError::TransactProofVerificationFailed,
        )
    }

    /// Ring-transfer over the P256 rail spending DEFAULT-ring P256 inputs: the
    /// presence of a real default-ring P256 input exposes the owner's P256
    /// pubkey x-coordinate as `default_owner_tag` on the wire. Asserts the tag
    /// is present and equals `from`'s signing pubkey x-coordinate.
    pub fn ring_transfer_p256_default_input_exposes_owner_tag(
        &mut self,
        from: &str,
        to: &str,
        asset: Address,
        amount: u64,
    ) -> Result<Signature> {
        if self.ring_config.is_none() {
            self.create_enabled_ring_config()?;
        }
        self.ensure_fresh_actor(from)?;
        self.ensure_fresh_actor(to)?;
        let inputs = self.peek_spendable_inputs(from, asset, false)?;
        let sent = self.send_ring_transfer(RingTransferOperation {
            from,
            to: Some(to),
            inputs: &inputs,
            send_asset: asset,
            amount,
            withdrawal: None,
            rail: RingRail::P256,
            tamper: ProofTamper::None,
        })?;
        let CircuitId::RingP256(_, _, _, proof_data) = &sent.data.circuit else {
            return Err(anyhow!("expected a RingP256 circuit selector"));
        };
        let expected_tag = self.actor(from).keypair.signing_pubkey().as_p256()?.x();
        if proof_data.default_owner_tag != Some(expected_tag) {
            return Err(anyhow!(
                "default_owner_tag {:?} != signing pubkey x {}",
                proof_data.default_owner_tag,
                hex32(&expected_tag)
            ));
        }
        // Consume the spent inputs only after the transfer landed.
        let actor = self.actor_mut(from);
        for input in &inputs {
            if let Some(pos) = actor.spendable.iter().position(|u| u == input) {
                actor.spendable.remove(pos);
            }
        }
        Ok(sent.signature)
    }

    /// A real default-ring P256 input with a WRONG `default_owner_tag` in the
    /// proof data: the tag is bound into the public input, so pairing fails
    /// (7008).
    pub fn ring_transfer_p256_wrong_default_owner_tag_rejected(
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
        let inputs = self.peek_spendable_inputs(from, asset, false)?;
        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        match self.send_ring_transfer(RingTransferOperation {
            from,
            to: Some(to),
            inputs: &inputs,
            send_asset: asset,
            amount,
            withdrawal: None,
            rail: RingRail::P256,
            tamper: ProofTamper::BadDefaultOwnerTag,
        }) {
            Ok(_) => Err(anyhow!(
                "P256 ring transfer with a wrong default_owner_tag unexpectedly succeeded"
            )),
            Err(error) => {
                let client_error = error
                    .downcast_ref::<zolana_client::ClientError>()
                    .unwrap_or_else(|| panic!("expected typed client error, got {error:?}"));
                Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed)
                    .at(1)
                    .assert_client(client_error);
                assert_account_unchanged(&self.rpc, &self.tree, &tree_before)?;
                Ok(())
            }
        }
    }
}

/// Assemble the `TransactIxData` from the signed transaction's external data and
/// the prover result, mirroring `client::prover::transact::witness::assemble`. Each
/// padded input carries its nullifier hash and root indices; authorization comes
/// from the leading signer run in the accounts array (payer first), not from any
/// per-input field. `external_data` fields flow through unchanged (already
/// rebound to `RING_TRANSACT`).
#[allow(clippy::too_many_arguments)]
fn assemble_ix_data(
    proof_inputs: &SppProofInputs,
    nullifiers: &[[u8; 32]],
    private_tx_hash: [u8; 32],
    root_indices: &[(u16, u16)],
    rail: RingRail,
    proof: TransactProof,
    commitment: Option<Bsb22Commitment>,
    default_owner_tag: Option<[u8; 32]>,
) -> Result<TransactIxData> {
    let n_inputs = proof_inputs.check_shape()?.n_inputs();
    if nullifiers.len() != n_inputs || root_indices.len() != n_inputs {
        return Err(anyhow!(
            "witness input count {} / {} does not match shape {n_inputs}",
            nullifiers.len(),
            root_indices.len()
        ));
    }

    let mut inputs = Vec::with_capacity(n_inputs);
    for i in 0..n_inputs {
        let nullifier_hash = *nullifiers
            .get(i)
            .ok_or_else(|| anyhow!("missing nullifier {i}"))?;
        let &(utxo_tree_root_index, nullifier_tree_root_index) = root_indices
            .get(i)
            .ok_or_else(|| anyhow!("missing root index {i}"))?;
        inputs.push(InputUtxo {
            nullifier_hash,
            nullifier_tree_root_index,
            utxo_tree_root_index,
        });
    }

    let external = &proof_inputs.external_data;
    let n_outputs = external.outputs.len() as u8;
    let n_slots = zolana_interface::N_PUBLIC_SLOTS as u8;
    let circuit = match rail {
        RingRail::Eddsa => CircuitId::RingEddsa(n_inputs as u8, n_outputs, n_slots),
        RingRail::P256 => CircuitId::RingP256(
            n_inputs as u8,
            n_outputs,
            n_slots,
            RingP256ProofData {
                bsb22_commitment: commitment
                    .ok_or_else(|| anyhow!("P256 proof is missing its BSB22 commitment"))?,
                default_owner_tag,
            },
        ),
    };
    Ok(TransactIxData {
        proof,
        expiry_unix_ts: external.expiry_unix_ts,
        private_tx_hash,
        circuit,
        inputs,
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

/// Split a committed P256 proof into the unchanged transact proof triple and
/// the BSB22 payload carried by `CircuitId::RingP256`.
fn p256_transact_proof(proof: &zolana_client::Proof) -> Result<(TransactProof, Bsb22Commitment)> {
    Ok(ProofCompressed::try_from(*proof)?.into_ring_p256_transact_parts()?)
}
