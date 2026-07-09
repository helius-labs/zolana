use anyhow::{anyhow, Result};
use cucumber::when;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use swap_sdk::{
    instructions::fill::{EscrowFill, Fill, FillSharedInputs},
    order::{Recipient, SOL_ASSET_ID},
    prover::SwapProverClient,
};
use zolana_client::{ProverClient, SpendProof, Transaction as TxBuilder};
use zolana_keypair::random_blinding;
use zolana_transaction::{instructions::types::SpendUtxo, utxo::Utxo, Data, SOL_MINT};

use crate::{localnet::send_v0_with_lookup_table, SwapWorld};

impl SwapWorld {
    pub(crate) fn fill_swap_derived(&mut self, maker_name: &str, taker_name: &str) -> Result<()> {
        self.ensure_actor(taker_name)?;
        let order_index = self
            .open_orders
            .iter()
            .position(|o| o.maker_name == maker_name)
            .ok_or_else(|| anyhow!("no open order for {maker_name}"))?;
        let escrow = {
            let order = self
                .open_orders
                .get(order_index)
                .ok_or_else(|| anyhow!("order gone"))?;
            order.escrow.clone()
        };
        let terms = escrow.terms.clone();
        if escrow.destination_asset_id != SOL_ASSET_ID {
            return Err(anyhow!("fill step supports the SOL destination rail only"));
        }

        let maker_keypair = self.actor(maker_name).shielded_keypair.clone();
        let maker_recipient = maker_keypair
            .shielded_address()
            .map_err(|e| anyhow!("maker addr: {e:?}"))?;
        let taker = self.actor(taker_name);
        let taker_keypair = taker.shielded_keypair.clone();
        let taker_solana = taker.solana_keypair.insecure_clone();
        let taker_recipient = taker_keypair
            .shielded_address()
            .map_err(|e| anyhow!("taker addr: {e:?}"))?;
        let taker_utxo = taker
            .spendable
            .iter()
            .find(|u| u.asset == SOL_MINT && u.amount == terms.destination_amount)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "{taker_name} has no spendable destination utxo of {}",
                    terms.destination_amount
                )
            })?;

        let source_output_blinding = random_blinding();

        let taker_in = Recipient {
            address: taker_recipient,
            amount: terms.destination_amount,
            blinding: taker_utxo.blinding,
            mint: SOL_MINT,
        }
        .output();
        let fill_shared_inputs = FillSharedInputs {
            escrow: escrow.clone(),
            taker_in,
            source_output_blinding,
            external_data_hash: [0u8; 32],
            maker_recipient,
            taker_recipient,
        };
        let destination_output_blinding = fill_shared_inputs
            .destination_output_blinding()
            .map_err(|e| anyhow!("destination blinding: {e:?}"))?;
        let source_output = fill_shared_inputs.source_output();
        let destination_output = fill_shared_inputs
            .destination_output()
            .map_err(|e| anyhow!("destination output: {e:?}"))?;

        let escrow_input = escrow
            .into_input_utxo()
            .map_err(|e| anyhow!("escrow spend: {e:?}"))?;
        let taker_spend = SpendUtxo::from_keypair(taker_utxo.clone(), &taker_keypair);

        let payer_address = Address::new_from_array(taker_solana.pubkey().to_bytes());
        let tx = TxBuilder::new(
            taker_recipient,
            vec![escrow_input, taker_spend],
            payer_address,
        )
        .with_expiry(terms.expiry);
        let signed = EscrowFill {
            tx,
            source_output,
            destination_output,
        }
        .sign(&taker_keypair, &self.assets)
        .map_err(|e| anyhow!("escrow fill sign: {e:?}"))?;

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
        let fill_shared_inputs = FillSharedInputs {
            external_data_hash,
            ..fill_shared_inputs
        };

        let (fill_proof, spp_proof) = fill_shared_inputs.prove(
            signed,
            &spend_proofs,
            &ProverClient::local(),
            &SwapProverClient::new_ffi(),
        )?;
        let ix = Fill {
            payer: taker_solana.pubkey(),
            tree: self.tree,
            fill_proof,
            spp_proof,
        }
        .instruction()?;

        let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let alt_addresses: Vec<Pubkey> = ix
            .accounts
            .iter()
            .filter(|meta| !meta.is_signer)
            .map(|meta| meta.pubkey)
            .chain(std::iter::once(ix.program_id))
            .collect();
        send_v0_with_lookup_table(
            &mut self.rpc,
            &[compute, ix],
            &taker_solana,
            &[&taker_solana],
            &alt_addresses,
        )?;

        let taker_mut = self.actor_mut(taker_name);
        taker_mut.spendable.retain(|u| {
            !(u.asset == taker_utxo.asset
                && u.amount == taker_utxo.amount
                && u.blinding == taker_utxo.blinding)
        });
        taker_mut.spendable.push(Utxo {
            owner: taker_keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount: escrow.source_amount,
            blinding: source_output_blinding,
            zone_program_id: None,
            data: Data::default(),
        });
        self.actor_mut(maker_name).spendable.push(Utxo {
            owner: maker_keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount: terms.destination_amount,
            blinding: destination_output_blinding,
            zone_program_id: None,
            data: Data::default(),
        });
        self.open_orders.remove(order_index);
        Ok(())
    }
}

#[when(expr = "taker {word} fills {word}'s order with derived fill")]
fn fill_derived_step(world: &mut SwapWorld, taker_name: String, maker_name: String) {
    world
        .fill_swap_derived(&maker_name, &taker_name)
        .expect("derived fill succeeds");
}
