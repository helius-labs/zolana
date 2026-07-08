use anyhow::{anyhow, Result};
use cucumber::{then, when};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use swap_prover::FillVerifiableEncryptionProofInputs;
use swap_sdk::{
    instructions::fill_verifiable_encryption::{
        EscrowFillVerifiableEncryption, FillVerifiableEncryption,
        FillVerifiableEncryptionSharedInputs,
    },
    order::{Escrow, SOL_ASSET_ID},
    MarkerData,
};
use zolana_client::{ProverClient, Rpc, SpendProof, Transaction as TxBuilder};
use zolana_keypair::random_blinding;
use zolana_transaction::{instructions::types::SpendUtxo, utxo::Utxo, Data, SOL_MINT};

use crate::{localnet::send_v0_with_lookup_table, SwapWorld};

impl SwapWorld {
    pub(crate) fn fill_swap(&mut self, maker_name: &str, taker_name: &str) -> Result<()> {
        self.ensure_actor(taker_name)?;
        let order_index = self
            .open_orders
            .iter()
            .position(|o| o.maker_name == maker_name)
            .ok_or_else(|| anyhow!("no open order for {maker_name}"))?;
        let (terms, escrow_blinding) = {
            let order = self
                .open_orders
                .get(order_index)
                .ok_or_else(|| anyhow!("order gone"))?;
            (order.terms.clone(), order.escrow_blinding)
        };
        if terms.destination_asset_id != SOL_ASSET_ID {
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

        // Discover the order from SPP: the taker scans the indexer for its
        // own view tag (the marker) and reads the marker payload, which names the
        // poster and points to the escrow leaf. The opening (terms + blinding) is held
        // from the price negotiation outside Solana, tracked here as the open order;
        // the marker only confirms the order is live in SPP and which leaf is the escrow.
        let taker_view_tag = taker_keypair
            .signing_pubkey()
            .confidential_view_tag()
            .map_err(|e| anyhow!("taker view tag: {e:?}"))?;
        let expected_escrow_hash = Escrow {
            terms: terms.clone(),
            blinding: escrow_blinding,
            source_mint: SOL_MINT,
        }
        .output(taker_recipient.viewing_pubkey)?
        .hash()
        .map_err(|e| anyhow!("escrow hash: {e:?}"))?;
        let marker = self.discover_marker(taker_view_tag)?;
        assert_eq!(
            marker.escrow_utxo_hash, expected_escrow_hash,
            "marker must point to this order's escrow leaf"
        );

        // Taker's destination utxo (destination_amount SOL) it spends to pay the maker.
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

        let taker_in_blinding = taker_utxo.blinding;
        let destination_output_blinding = random_blinding();
        let source_output_blinding = random_blinding();

        let fill_shared_inputs = FillVerifiableEncryptionSharedInputs {
            terms: terms.clone(),
            escrow_blinding,
            taker_in_blinding,
            destination_output_blinding,
            source_output_blinding,
            external_data_hash: [0u8; 32],
            maker_recipient,
            taker_recipient,
        };
        let fill_inputs = fill_shared_inputs
            .fill_proof_inputs(SOL_MINT, SOL_MINT)
            .map_err(|e| anyhow!("fill proof inputs: {e:?}"))?;

        // Derive the destination verifiable-encryption ciphertext before building the SPP
        // transact, so the tail slot carries exactly what the fill proof commits.
        let destination_ciphertext = fill_inputs
            .destination_ciphertext()
            .map_err(|e| anyhow!("destination ciphertext: {e:?}"))?;
        let source_output = fill_shared_inputs.source_output(SOL_MINT);
        let destination_output = fill_shared_inputs.destination_output(SOL_MINT);

        // Escrow input: PDA-owned, spent via the opening (terms + blinding); the swap
        // program signs for the escrow authority via invoke_signed. Taker input
        // is signed by the SPP payer (the taker's Solana key).
        let escrow_input = Escrow {
            terms: terms.clone(),
            blinding: escrow_blinding,
            source_mint: SOL_MINT,
        }
        .spend()
        .map_err(|e| anyhow!("escrow spend: {e:?}"))?;
        let taker_spend = SpendUtxo::from_keypair(taker_utxo.clone(), &taker_keypair);

        let payer_address = Address::new_from_array(taker_solana.pubkey().to_bytes());
        let tx = TxBuilder::new(
            taker_recipient,
            vec![escrow_input, taker_spend],
            payer_address,
        )
        .with_expiry(terms.expiry);
        let signed = EscrowFillVerifiableEncryption {
            tx,
            source_output,
            destination_output,
            destination_ciphertext,
            destination_view_tag: maker_recipient
                .signing_pubkey
                .confidential_view_tag()
                .map_err(|e| anyhow!("maker view tag: {e:?}"))?,
            destination_recipient_viewing_pk: maker_recipient.viewing_pubkey,
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
        let fill_shared_inputs = FillVerifiableEncryptionSharedInputs {
            external_data_hash,
            ..fill_shared_inputs
        };
        let fill_inputs = FillVerifiableEncryptionProofInputs {
            external_data_hash,
            ..fill_inputs
        };

        let (ix, fill_result) = FillVerifiableEncryption {
            inputs: fill_shared_inputs,
            signed,
            source_mint: SOL_MINT,
            destination_mint: SOL_MINT,
            payer: taker_solana.pubkey(),
            tree: self.tree,
        }
        .instruction(&spend_proofs, &ProverClient::local())?;

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

        // Retire the taker's spent destination utxo; record the maker's destination
        // utxo and the taker's source utxo.
        let taker_mut = self.actor_mut(taker_name);
        taker_mut.spendable.retain(|u| {
            !(u.asset == taker_utxo.asset
                && u.amount == taker_utxo.amount
                && u.blinding == taker_utxo.blinding)
        });
        taker_mut.spendable.push(Utxo {
            owner: taker_keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount: terms.source_amount,
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

        // Verify the maker recovers (destination_asset, destination_amount) from the
        // fill ciphertext.
        let (asset, amount) = fill_inputs
            .decrypt_destination(&fill_result.ciphertext)
            .map_err(|e| anyhow!("decrypt destination: {e:?}"))?;
        let expected_asset = swap_prover::asset_field(terms.destination_mint.as_array())
            .map_err(|e| anyhow!("destination asset field: {e:?}"))?;
        assert_eq!(
            (asset, amount),
            (expected_asset, terms.destination_amount),
            "maker must recover (destination_asset, destination_amount) from the verifiable encryption"
        );
        Ok(())
    }

    /// Discover the marker from chain: scan the indexer for the taker's view
    /// tag and read the plaintext marker payload. The caller asserts the marker's
    /// escrow hash and poster against the locally tracked order, so a missing or
    /// wrong marker fails the test rather than being papered over.
    fn discover_marker(&self, taker_view_tag: [u8; 32]) -> Result<MarkerData> {
        let response = self
            .indexer
            .get_shielded_transactions_by_tags(vec![taker_view_tag], None, None)
            .map_err(|e| anyhow!("indexer scan for marker tag: {e:?}"))?;
        for tx in response.transactions {
            for slot in &tx.output_slots {
                if slot.view_tag != taker_view_tag {
                    continue;
                }
                if let Ok(marker) = borsh::from_slice::<MarkerData>(&slot.payload) {
                    return Ok(marker);
                }
            }
        }
        Err(anyhow!(
            "taker could not discover the order marker from the indexer"
        ))
    }

    fn output_utxo_hash(
        &self,
        actor_name: &str,
        amount: u64,
        blinding: [u8; 31],
    ) -> Result<[u8; 32]> {
        let keypair = self.actor(actor_name).shielded_keypair.clone();
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount,
            blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let nullifier_pk = keypair
            .nullifier_key
            .pubkey()
            .map_err(|e| anyhow!("nf pk: {e:?}"))?;
        utxo.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
            .map_err(|e| anyhow!("utxo hash: {e:?}"))
    }
}

#[when(expr = "the taker {word} shields {int} lamports of SOL")]
fn taker_shields(world: &mut SwapWorld, name: String, amount: i64) {
    world
        .deposit_sol(&name, amount as u64)
        .expect("taker shield");
}

#[when(expr = "taker {word} fills {word}'s order")]
fn fill_step(world: &mut SwapWorld, taker_name: String, maker_name: String) {
    world
        .fill_swap(&maker_name, &taker_name)
        .expect("fill succeeds");
}

#[then(expr = "{word} holds a spendable {int} lamport SOL UTXO from fill")]
fn holds_fill_utxo(world: &mut SwapWorld, name: String, amount: i64) {
    let utxo = world
        .actor(&name)
        .spendable
        .iter()
        .find(|u| u.asset == SOL_MINT && u.amount == amount as u64)
        .cloned()
        .expect("fill utxo recorded");
    let hash = world
        .output_utxo_hash(&name, utxo.amount, utxo.blinding)
        .expect("utxo hash");
    world
        .wait_for_merkle_proof(hash)
        .expect("fill utxo indexed in the SPP tree");
}
