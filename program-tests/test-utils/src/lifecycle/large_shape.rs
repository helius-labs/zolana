//! Declared-shape consolidation: the large-input `transact` that only a
//! transaction v1 message can carry.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    assemble, ConfidentialTransfer, ProverClient, ProverInputs, Shape, SppProofInputUtxo,
};
use zolana_interface::instruction::Transact;
use zolana_transaction::Utxo;

use super::LifecycleHarness;
use crate::{
    localnet::{send_transaction_v1, v1_transaction_len},
    transact::pack_transact_proof,
};

/// Compute units a declared-shape consolidation requests. The default 200k
/// per-instruction budget covers roughly five inputs, so without this the
/// transaction fails on budget and the failure reads like a size problem.
pub const CONSOLIDATION_CU_LIMIT: u32 = 900_000;

/// What a declared-shape consolidation sent, so the acceptance assertions can
/// measure the transaction and check the state it produced.
pub struct ConsolidationRecord {
    pub signature: Signature,
    /// Serialized transaction v1 length including the signature array, measured
    /// from the instructions that were actually submitted.
    pub transaction_len: usize,
    /// Input nullifiers in instruction order. Each one owns a nullifier PDA and
    /// takes the next nullifier-queue index.
    pub nullifiers: Vec<[u8; 32]>,
    /// The view tag Photon files this transaction's outputs under.
    pub view_tag: [u8; 32],
}

impl LifecycleHarness {
    /// Spend `shape.n_inputs()` of `from`'s spendable `asset` UTXOs back to
    /// itself at the explicitly declared `shape`, submitted as a transaction
    /// **v1** message with no address lookup table.
    ///
    /// v1 is not a preference here. A large shape's instruction data alone
    /// exceeds the 1232-byte legacy packet, so no lookup table could rescue a
    /// legacy or v0 send: the addresses are not what overflows.
    ///
    /// Every input is owned by the single actor `from`, whose ed25519 key is the
    /// fee payer, so the signer run is one entry long and stays far inside
    /// `MAX_UNIQUE_SIGNERS`.
    pub fn consolidate_at_shape(
        &mut self,
        from: &str,
        asset: Address,
        shape: Shape,
    ) -> Result<ConsolidationRecord> {
        self.ensure_fresh_actor(from)?;
        let inputs = self.take_spendable(from, asset, shape.n_inputs())?;

        let keypair = self.actor(from).keypair.clone();
        let fee_payer = self
            .actor(from)
            .solana_signer
            .as_ref()
            .ok_or_else(|| anyhow!("{from} must be eddsa-owned to pay for its own spend"))?
            .insecure_clone();
        let payer_address = Address::new_from_array(fee_payer.pubkey().to_bytes());
        let view_tag = keypair.signing_pubkey().confidential_view_tag()?;

        let spends: Vec<SppProofInputUtxo> = inputs
            .iter()
            .map(|utxo| SppProofInputUtxo::new(utxo.clone(), &keypair))
            .collect();
        let proof_inputs =
            ConfidentialTransfer::new(keypair.shielded_address()?, spends, payer_address)
                .with_shape(shape)
                .sign(&keypair, &self.assets)?;

        let nullifiers: Vec<[u8; 32]> = proof_inputs
            .input_utxo_hashes()?
            .iter()
            .map(|context| context.nullifier)
            .collect();

        let (spend_proofs, dummy_proofs) = self.spend_proofs(&proof_inputs)?;
        let assembled = assemble(proof_inputs, &spend_proofs, &dummy_proofs)?;
        let ProverInputs::Eddsa(transfer_inputs) = &assembled.prover_inputs;
        let proof = ProverClient::local().prove_transfer(transfer_inputs)?;
        let ix_data = assembled.with_proof(pack_transact_proof(&proof)?);

        let ixs = [
            ComputeBudgetInstruction::set_compute_unit_limit(CONSOLIDATION_CU_LIMIT),
            Transact {
                payer: fee_payer.pubkey(),
                input_tree: self.tree,
                output_tree: self.tree,
                owner_signers: Vec::new(),
                interface_transfer_accounts: Vec::new(),
                data: ix_data,
            }
            .instruction(),
        ];
        let transaction_len = v1_transaction_len(&ixs, &fee_payer.pubkey(), 1)?;
        let signature = send_transaction_v1(&mut self.rpc, &ixs, &fee_payer, &[])?;

        Ok(ConsolidationRecord {
            signature,
            transaction_len,
            nullifiers,
            view_tag,
        })
    }

    /// Remove and return `count` of `name`'s spendable UTXOs of `asset`.
    fn take_spendable(&mut self, name: &str, asset: Address, count: usize) -> Result<Vec<Utxo>> {
        let actor = self.actor_mut(name);
        let mut taken = Vec::with_capacity(count);
        for _ in 0..count {
            let position = actor
                .spendable
                .iter()
                .position(|utxo| utxo.asset == asset)
                .ok_or_else(|| {
                    anyhow!(
                        "{name} needs {count} spendable UTXOs of {asset}, has {}",
                        taken.len()
                    )
                })?;
            taken.push(actor.spendable.remove(position));
        }
        Ok(taken)
    }
}
