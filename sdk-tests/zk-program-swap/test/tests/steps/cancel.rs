use anyhow::{anyhow, Result};
use cucumber::{then, when};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signer::Signer;
use swap_sdk::{
    instructions::cancel::{Cancel, CancelSharedInputs, EscrowCancel},
    order::Escrow,
};
use zolana_client::{ProverClient, SpendProof, Transaction as TxBuilder};
use zolana_keypair::random_blinding;
use zolana_transaction::{utxo::Utxo, Data, SOL_MINT};

use crate::{localnet::send_transaction, SwapWorld};

impl SwapWorld {
    pub(crate) fn cancel_swap(&mut self, maker_name: &str) -> Result<()> {
        let order_index = self
            .open_orders
            .iter()
            .position(|o| o.maker_name == maker_name)
            .ok_or_else(|| anyhow!("no open order for {maker_name}"))?;
        let (terms, escrow_blinding, taker_viewing_pk) = {
            let order = self
                .open_orders
                .get(order_index)
                .ok_or_else(|| anyhow!("order gone"))?;
            (
                order.terms.clone(),
                order.escrow_blinding,
                order.taker_address.viewing_pubkey,
            )
        };

        let maker = self.actor(maker_name);
        let maker_keypair = maker.shielded_keypair.clone();
        let maker_solana = maker.solana_keypair.insecure_clone();
        let maker_recipient = maker_keypair
            .shielded_address()
            .map_err(|e| anyhow!("maker address: {e:?}"))?;

        let source_output_blinding = random_blinding();

        // The escrow input is PDA-owned and spent via the opening (terms +
        // blinding); the swap program signs for the escrow authority via
        // invoke_signed. Any opening holder can cancel after expiry.
        let escrow_input = Escrow {
            terms: terms.clone(),
            blinding: escrow_blinding,
            source_mint: SOL_MINT,
        }
        .spend()
        .map_err(|e| anyhow!("escrow spend: {e:?}"))?;

        let cancel_inputs = CancelSharedInputs {
            terms: terms.clone(),
            escrow_blinding,
            taker_viewing_pk,
            source_output_blinding,
            external_data_hash: [0u8; 32],
            maker_recipient,
        };
        let source_output = cancel_inputs.source_output(SOL_MINT);

        // The SPP transact carries a FUTURE relayer deadline (SPP rejects an
        // expired transact); the committed order expiry (in the past) rides the
        // cancel ix `order_expiry` and the swap proof, checked as `now > order_expiry`.
        const SPP_RELAYER_DEADLINE: u64 = u64::MAX;
        let payer_address = Address::new_from_array(maker_solana.pubkey().to_bytes());
        let tx = TxBuilder::new(maker_recipient, vec![escrow_input], payer_address)
            .with_expiry(SPP_RELAYER_DEADLINE);
        let signed = EscrowCancel { tx, source_output }
            .sign(&maker_keypair, &self.assets)
            .map_err(|e| anyhow!("escrow cancel sign: {e:?}"))?;

        let commitments = signed
            .input_utxo_hashes()
            .map_err(|e| anyhow!("input commitments: {e:?}"))?;
        let mut spend_proofs = Vec::new();
        for commitment in &commitments {
            let state = self.wait_for_merkle_proof(commitment.utxo_hash)?;
            let nullifier = self.wait_for_non_inclusion_proof(commitment.nullifier)?;
            spend_proofs.push(SpendProof { state, nullifier });
        }

        let external_data_hash = signed
            .external_data
            .hash()
            .map_err(|e| anyhow!("external data hash: {e:?}"))?;
        let cancel_inputs = CancelSharedInputs {
            external_data_hash,
            ..cancel_inputs
        };

        let ix = Cancel {
            inputs: cancel_inputs,
            signed,
            source_mint: SOL_MINT,
            payer: maker_solana.pubkey(),
            tree: self.tree,
        }
        .instruction(&spend_proofs, &ProverClient::local())?;
        let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        send_transaction(
            &mut self.rpc,
            &[compute, ix],
            &maker_solana.pubkey(),
            &[&maker_solana],
        )?;

        // Record the reclaimed source utxo so the maker can assert it, and retire the order.
        self.actor_mut(maker_name).spendable.push(Utxo {
            owner: maker_keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount: terms.source_amount,
            blinding: source_output_blinding,
            zone_program_id: None,
            data: Data::default(),
        });
        self.open_orders.remove(order_index);
        Ok(())
    }

    fn reclaimed_source_hash(
        &self,
        maker_name: &str,
        amount: u64,
        blinding: [u8; 31],
    ) -> Result<[u8; 32]> {
        let maker_keypair = self.actor(maker_name).shielded_keypair.clone();
        let utxo = Utxo {
            owner: maker_keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount,
            blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let nullifier_pk = maker_keypair
            .nullifier_key
            .pubkey()
            .map_err(|e| anyhow!("nullifier pk: {e:?}"))?;
        utxo.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
            .map_err(|e| anyhow!("source utxo hash: {e:?}"))
    }
}

#[when(expr = "{word} cancels the order after expiry")]
fn cancel_step(world: &mut SwapWorld, maker_name: String) {
    world.cancel_swap(&maker_name).expect("cancel succeeds");
}

#[then(expr = "{word} reclaims a spendable {int} lamport SOL UTXO")]
fn reclaims(world: &mut SwapWorld, maker_name: String, amount: i64) {
    let utxo = world
        .actor(&maker_name)
        .spendable
        .iter()
        .find(|u| u.asset == SOL_MINT && u.amount == amount as u64)
        .cloned()
        .expect("reclaimed utxo recorded");
    let hash = world
        .reclaimed_source_hash(&maker_name, utxo.amount, utxo.blinding)
        .expect("reclaimed source hash");
    world
        .wait_for_merkle_proof(hash)
        .expect("reclaimed source utxo indexed in the SPP tree");
}
