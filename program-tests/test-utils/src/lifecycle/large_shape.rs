use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    assemble, ConfidentialTransfer, ProverClient, ProverInputs, Shape, SppProofInputUtxo,
};
use zolana_interface::instruction::Transact;
use zolana_transaction::{ShieldedTransaction, Utxo, WalletUtxo};

use super::{transfer::decode_output_blinding, LifecycleHarness};
use crate::{
    compute::TEST_TRANSACTION_CU_LIMIT,
    localnet::{send_transaction_v1, v1_transaction_len, SOL_CHANGE_POSITION, ZERO},
    test_validator_asserts::wait_for_indexed_transaction,
    transact::pack_transact_proof,
};

pub const CONSOLIDATION_CU_LIMIT: u32 = TEST_TRANSACTION_CU_LIMIT;

pub struct ConsolidationRecord {
    pub signature: Signature,
    pub transaction_len: usize,
    pub nullifiers: Vec<[u8; 32]>,
    pub view_tag: [u8; 32],
    pub input_total: u64,
    pub output: WalletUtxo,
    pub indexed: ShieldedTransaction,
}

impl LifecycleHarness {
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
        let payer_address = fee_payer.pubkey();
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

        let indexed = wait_for_indexed_transaction(&self.indexer, view_tag, signature);
        let input_total = inputs
            .iter()
            .try_fold(0u64, |total, utxo| total.checked_add(utxo.amount))
            .ok_or_else(|| anyhow!("consolidated amount overflows u64"))?;
        let output = self.build_expected(
            from,
            keypair.signing_pubkey(),
            asset,
            input_total,
            decode_output_blinding(&keypair.viewing_key, &indexed, SOL_CHANGE_POSITION as u32)?,
            &indexed,
        )?;

        let nullifier_pk = keypair.nullifier_key.pubkey()?;
        let tree_id = self.tree_id;
        let actor = self.actor_mut(from);
        for input in &inputs {
            let consumed_hash = input.hash(&nullifier_pk, &ZERO, &ZERO, tree_id)?;
            if let Some(utxo) = actor
                .expected
                .iter_mut()
                .find(|utxo| utxo.output_context.hash == consumed_hash)
            {
                utxo.spent = true;
            }
        }
        actor.expected.push(output.clone());
        actor.spendable.push(output.utxo.clone());
        self.indexed.push(indexed.clone());

        Ok(ConsolidationRecord {
            signature,
            transaction_len,
            nullifiers,
            view_tag,
            input_total,
            output,
            indexed,
        })
    }

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
