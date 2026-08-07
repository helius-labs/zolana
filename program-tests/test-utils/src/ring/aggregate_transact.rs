//! Batched ring transfers settled against one recursive proof.

use std::time::Instant;

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    prover::{AggregateInputs, AggregateLeg},
    ConfidentialTransfer, ProofCompressed, ProverClient, RingTransferP256Prover,
    RingTransferProver, Shape, SppProofInputUtxo, SppProofInputs,
};
use zolana_interface::{
    instruction::{
        instruction_data::{
            aggregate_transact::{AggregateTransactIxData, EMPTY_LEG_COMMITMENT, EMPTY_LEG_PROOF},
            transact::{CircuitId, InputUtxo, TransactIxData},
        },
        AggregateTransact,
    },
    verifying_keys::{AggregateCircuitId, InnerCircuitKind, RingP256ProofData},
};
use zolana_transaction::SyncWalletAuthority;

use super::{ring_transact::RingRail, RingHarness};
use crate::localnet::send_transaction;

/// The prover carries the public input as a big integer. The batch needs its
/// 32-byte big-endian form.
fn fe32(value: &num_bigint::BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// What one batch cost to build and to send.
#[derive(Debug, Clone)]
pub struct AggregateTiming {
    pub leg_prove_ms: Vec<u128>,
    pub aggregate_prove_ms: u128,
    /// Serialized instruction data, the part that grows with the batch.
    pub instruction_data_len: usize,
    /// None when the transaction was over the size limit and never landed.
    pub signature: Option<Signature>,
}

impl AggregateTiming {
    pub fn legs_total_ms(&self) -> u128 {
        self.leg_prove_ms.iter().sum()
    }
}

struct BuiltLeg {
    data: TransactIxData,
    proof: zolana_client::Proof,
    public_input_hash: [u8; 32],
    prove_ms: u128,
}

impl RingHarness {
    /// Settle `count` transfers from `sender` against a single recursive proof.
    ///
    /// One sender per batch, because a leg's account run has no slot for an
    /// owner signature. On the eddsa rail that means the sender must also be
    /// the transaction payer. The P256 rail proves ownership in circuit, so any
    /// payer works.
    pub fn ring_aggregate_transfer(
        &mut self,
        sender: &str,
        count: usize,
        asset: Address,
        amount: u64,
        rail: RingRail,
    ) -> Result<AggregateTiming> {
        if self.ring_config.is_none() {
            self.create_enabled_ring_config()?;
        }

        let fee_payer = match rail {
            RingRail::Eddsa => self
                .actor(sender)
                .solana_signer
                .as_ref()
                .map(|keypair| keypair.insecure_clone())
                .ok_or_else(|| anyhow!("the eddsa rail needs {sender} to pay and sign"))?,
            RingRail::P256 => self.payer.insecure_clone(),
        };

        let mut legs = Vec::with_capacity(count);
        for index in 0..count {
            legs.push(self.build_leg(sender, index, asset, amount, rail, &fee_payer.pubkey())?);
        }

        let inner = match rail {
            RingRail::Eddsa => InnerCircuitKind::RingEddsa,
            RingRail::P256 => InnerCircuitKind::RingP256,
        };
        let aggregate_inputs = AggregateInputs {
            inner,
            num_inputs: 2,
            num_outputs: 3,
            legs: legs
                .iter()
                .map(|leg| AggregateLeg {
                    proof: leg.proof,
                    public_input_hash: leg.public_input_hash,
                })
                .collect(),
        };

        let started = Instant::now();
        let outer = ProverClient::local().prove_aggregate(&aggregate_inputs)?;
        let aggregate_prove_ms = started.elapsed().as_millis();

        let outer = ProofCompressed::try_from(outer)?;
        let (proof, bsb22_commitment) = outer.into_ring_p256_transact_parts()?;

        let circuit = AggregateCircuitId {
            kind: inner,
            num_inputs: 2,
            num_outputs: 3,
            num_public_asset_slots: zolana_interface::N_PUBLIC_SLOTS as u8,
            batch: u8::try_from(legs.len())?,
        };
        let data = AggregateTransactIxData {
            circuit,
            proof,
            bsb22_commitment,
            legs: legs.iter().map(|leg| leg.data.clone()).collect(),
            // The builder fills these from the accounts it emits.
            leg_account_counts: Vec::new(),
        };

        let instruction = AggregateTransact {
            payer: fee_payer.pubkey(),
            input_tree: self.tree,
            output_tree: self.tree,
            ring_program_ids: vec![self.ring_program_id; legs.len()],
            owner_signers: vec![Vec::new(); legs.len()],
            interface_transfer_accounts: vec![Vec::new(); legs.len()],
            data,
        }
        .instruction();

        let instruction_data_len = instruction.data.len();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        // A batch can exceed the transaction size limit before it exceeds any
        // compute limit, so the size is reported either way.
        let signature = send_transaction(
            &mut self.rpc,
            &[compute_budget, instruction],
            &fee_payer.pubkey(),
            &[&fee_payer],
        )
        .ok();

        Ok(AggregateTiming {
            leg_prove_ms: legs.iter().map(|leg| leg.prove_ms).collect(),
            aggregate_prove_ms,
            instruction_data_len,
            signature,
        })
    }

    /// Prove one leg and assemble its instruction data with the proof and the
    /// commitment cleared.
    fn build_leg(
        &mut self,
        sender: &str,
        index: usize,
        asset: Address,
        amount: u64,
        rail: RingRail,
        payer: &Pubkey,
    ) -> Result<BuiltLeg> {
        self.ensure_fresh_actor(sender)?;
        let recipient = format!("{sender}-aggregate-recipient-{index}");
        self.ensure_fresh_actor(&recipient)?;

        let inputs = self.take_ring_inputs(sender, asset)?;
        let from_keypair = self.actor(sender).keypair.clone();
        let to_address = self.actor(&recipient).keypair.shielded_address()?;
        let payer_address = Address::new_from_array(payer.to_bytes());

        let spends: Vec<SppProofInputUtxo> = inputs
            .iter()
            .map(|u| SppProofInputUtxo::new(u.clone(), &from_keypair))
            .collect();
        let mut transfer =
            ConfidentialTransfer::new(from_keypair.shielded_address()?, spends, payer_address);
        transfer.send(&to_address, asset, amount)?;

        let mut proof_inputs = match rail {
            RingRail::Eddsa => transfer.sign(&from_keypair, &self.assets)?,
            RingRail::P256 => transfer.sign_ring_p256(&from_keypair, &self.assets)?,
        };
        // The leg keeps the discriminator it would carry alone.
        proof_inputs.external_data.instruction_discriminator =
            zolana_interface::event::tag::RING_TRANSACT;

        let ring = Address::new_from_array(self.ring_program_id.to_bytes());
        self.prove_leg(&proof_inputs, &from_keypair, ring, rail)
    }

    fn prove_leg(
        &self,
        proof_inputs: &SppProofInputs,
        signer: &zolana_keypair::ShieldedKeypair,
        ring: Address,
        rail: RingRail,
    ) -> Result<BuiltLeg> {
        let spend_inputs = self.ring_spend_inputs(&proof_inputs.input_utxos)?;
        let tx_shape = proof_inputs.check_shape()?;
        let shape = Shape::new(tx_shape.n_inputs(), tx_shape.n_outputs());
        let signer_pk_hashes = proof_inputs.signer_pk_hashes(tx_shape.n_inputs() + 1)?;
        let n_inputs = u8::try_from(tx_shape.n_inputs())?;
        let n_outputs = u8::try_from(proof_inputs.external_data.outputs.len())?;
        let n_slots = zolana_interface::N_PUBLIC_SLOTS as u8;

        match rail {
            RingRail::Eddsa => {
                let result = RingTransferProver {
                    inputs: spend_inputs,
                    outputs: proof_inputs.output_utxos.clone(),
                    external_data: proof_inputs.external_data.clone(),
                    public_transfers: proof_inputs.public_transfers()?,
                    signer_pk_hashes,
                    allow_dummy_inputs: true,
                    ring_program_id: Some(ring),
                    shape: Some(shape),
                }
                .build()?;
                let started = Instant::now();
                let proof = ProverClient::local().prove_transfer_ring(&result.inputs)?;
                let prove_ms = started.elapsed().as_millis();
                Ok(BuiltLeg {
                    data: assemble_leg_data(
                        proof_inputs,
                        &result.nullifiers,
                        result.private_tx_hash,
                        &result.input_root_indices,
                        CircuitId::RingEddsa(n_inputs, n_outputs, n_slots),
                    )?,
                    proof,
                    public_input_hash: fe32(&result.inputs.public_input_hash),
                    prove_ms,
                })
            }
            RingRail::P256 => {
                let authorization =
                    SyncWalletAuthority::sign_p256(signer, &proof_inputs.message_hash()?)?;
                let result = RingTransferP256Prover {
                    inputs: spend_inputs,
                    outputs: proof_inputs.output_utxos.clone(),
                    external_data: proof_inputs.external_data.clone(),
                    public_transfers: proof_inputs.public_transfers()?,
                    signer_pk_hashes,
                    allow_dummy_inputs: true,
                    authorization,
                    ring_program_id: Some(ring),
                    shape: Some(shape),
                }
                .build()?;
                let started = Instant::now();
                let proof = ProverClient::local().prove_transfer_p256_ring(&result.inputs)?;
                let prove_ms = started.elapsed().as_millis();
                let circuit = CircuitId::RingP256(
                    n_inputs,
                    n_outputs,
                    n_slots,
                    RingP256ProofData {
                        bsb22_commitment: EMPTY_LEG_COMMITMENT,
                        default_owner_tag: result.default_owner_tag,
                    },
                );
                Ok(BuiltLeg {
                    data: assemble_leg_data(
                        proof_inputs,
                        &result.nullifiers,
                        result.private_tx_hash,
                        &result.input_root_indices,
                        circuit,
                    )?,
                    proof,
                    public_input_hash: fe32(&result.inputs.public_input_hash),
                    prove_ms,
                })
            }
        }
    }
}

/// A leg carries no proof and no commitment, so both are cleared here.
fn assemble_leg_data(
    proof_inputs: &SppProofInputs,
    nullifiers: &[[u8; 32]],
    private_tx_hash: [u8; 32],
    root_indices: &[(u16, u16)],
    circuit: CircuitId,
) -> Result<TransactIxData> {
    let n_inputs = proof_inputs.check_shape()?.n_inputs();
    if nullifiers.len() != n_inputs || root_indices.len() != n_inputs {
        return Err(anyhow!("witness input count does not match the shape"));
    }
    let inputs = (0..n_inputs)
        .map(|i| InputUtxo {
            nullifier_hash: nullifiers[i],
            utxo_tree_root_index: root_indices[i].0,
            nullifier_tree_root_index: root_indices[i].1,
        })
        .collect();

    let external = &proof_inputs.external_data;
    Ok(TransactIxData {
        expiry_unix_ts: external.expiry_unix_ts,
        private_tx_hash,
        circuit,
        tx_viewing_pk: external.tx_viewing_pk,
        salt: external.salt,
        proof: EMPTY_LEG_PROOF,
        inputs,
        interface_transfers: Vec::new(),
        data_hash: external.data_hash,
        ring_data_hash: external.ring_data_hash,
        outputs: external.outputs.clone(),
        messages: external.messages.clone(),
    })
}
