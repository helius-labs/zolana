use anyhow::{anyhow, Result};
use cucumber::{then, when};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use swap_sdk::{
    instructions::create_swap::{CreateSharedInputs, CreateSwap, EscrowCreate},
    order::{marker_output, BlindingField, Escrow, OrderTerms, SOL_ASSET_ID},
};
use zolana_client::{ProverClient, SpendProof, Transaction as TxBuilder};
use zolana_keypair::{random_blinding, ShieldedAddress};
use zolana_transaction::{instructions::types::SpendUtxo, utxo::Blinding, SOL_MINT};

use crate::{localnet::send_v0_with_lookup_table, SwapWorld};

/// A live order the harness tracks across create -> fill / cancel. The opening
/// (terms and `escrow_blinding`) is the full spend capability. `taker_address`
/// lets the fill side rebuild the taker recipient.
pub(crate) struct OpenOrder {
    pub(crate) maker_name: String,
    pub(crate) terms: OrderTerms,
    pub(crate) escrow_blinding: Blinding,
    pub(crate) source_mint: Address,
    pub(crate) taker_address: ShieldedAddress,
}

pub(crate) struct SwapParams {
    pub(crate) source_amount: u64,
    pub(crate) destination_asset: u64,
    pub(crate) destination_amount: u64,
    pub(crate) expiry: u64,
    pub(crate) fill_mode: u64,
}

impl SwapWorld {
    pub(crate) fn create_swap(
        &mut self,
        maker_name: &str,
        taker_name: &str,
        params: SwapParams,
    ) -> Result<()> {
        let SwapParams {
            source_amount,
            destination_asset,
            destination_amount,
            expiry,
            fill_mode,
        } = params;
        self.ensure_actor(maker_name)?;
        self.ensure_actor(taker_name)?;

        let maker = self.actor(maker_name);
        let maker_keypair = maker.shielded_keypair.clone();
        let maker_solana = maker.solana_keypair.insecure_clone();
        let input_utxo = maker
            .spendable
            .iter()
            .find(|u| u.asset == SOL_MINT && u.amount >= source_amount)
            .cloned()
            .ok_or_else(|| anyhow!("{maker_name} has no spendable SOL utxo >= {source_amount}"))?;

        // The taker owns the escrow (via its viewing pubkey) and the marker
        // (via its shielded address). Both come from its shielded keypair.
        let taker_shielded = self.actor(taker_name).shielded_keypair.clone();
        let taker_address = taker_shielded
            .shielded_address()
            .map_err(|e| anyhow!("taker address: {e:?}"))?;

        // The taker's ed25519 authorization identity (taker_pk_fe): the
        // owner_pk_field of its shielded signing key, so the fill's taker input
        // UTXO owner matches the order-committed taker.
        let taker_pk_fe = taker_shielded
            .signing_pubkey()
            .owner_pk_field()
            .map_err(|e| anyhow!("taker pk_fe: {e:?}"))?;

        let destination_mint = self.destination_mint(destination_asset)?;
        let maker_owner_hash = maker_keypair
            .owner_hash()
            .map_err(|e| anyhow!("owner hash: {e:?}"))?;
        let maker_viewing_pk = *maker_keypair.viewing_pubkey().as_bytes();
        let terms = OrderTerms {
            source_asset_id: SOL_ASSET_ID,
            source_amount,
            destination_asset_id: destination_asset,
            destination_mint,
            destination_amount,
            maker_owner_hash,
            maker_viewing_pk,
            expiry,
            taker_pk_fe,
            fill_mode,
        };

        let escrow_blinding = random_blinding();

        let escrow = Escrow {
            terms: terms.clone(),
            blinding: escrow_blinding,
            source_mint: SOL_MINT,
        }
        .output(taker_address.viewing_pubkey)?;
        let marker = marker_output(taker_address);

        let payer_address = Address::new_from_array(maker_solana.pubkey().to_bytes());
        let spend = SpendUtxo::from_keypair(input_utxo.clone(), &maker_keypair);
        let tx = TxBuilder::new(
            maker_keypair
                .shielded_address()
                .map_err(|e| anyhow!("addr: {e:?}"))?,
            vec![spend],
            payer_address,
        );
        let signed = EscrowCreate { tx, escrow, marker }
            .sign(&maker_keypair, &self.assets)
            .map_err(|e| anyhow!("escrow create sign: {e:?}"))?;

        // Resolve merkle / non-inclusion proofs for the single real input.
        let commitments = signed
            .input_commitments()
            .map_err(|e| anyhow!("input commitments: {e:?}"))?;
        let mut spend_proofs = Vec::new();
        for commitment in &commitments {
            let state = self.wait_for_merkle_proof(commitment.utxo_hash)?;
            let nullifier = self.wait_for_non_inclusion_proof(commitment.nullifier)?;
            spend_proofs.push(SpendProof { state, nullifier });
        }

        // Recover the create-inputs fields from the signed transaction so the swap
        // create proof commits the exact same private_tx_hash the SPP transact does.
        let spend = signed.inputs.first().ok_or_else(|| anyhow!("no input"))?;
        let nullifier_pubkey = spend
            .nullifier_key
            .pubkey()
            .map_err(|e| anyhow!("nullifier pubkey: {e:?}"))?;
        let source_input_hash = spend
            .utxo
            .hash(
                &nullifier_pubkey,
                &spend.data_hash.unwrap_or([0u8; 32]),
                &spend.zone_data_hash.unwrap_or([0u8; 32]),
            )
            .map_err(|e| anyhow!("source input hash: {e:?}"))?;
        let change_output = signed
            .outputs
            .first()
            .ok_or_else(|| anyhow!("no change output"))?;
        let change_amount = change_output.amount;
        let change_blinding = change_output.blinding.to_field();
        let external_data_hash = signed
            .external_data
            .hash()
            .map_err(|e| anyhow!("external data hash: {e:?}"))?;

        let create_inputs = CreateSharedInputs {
            terms: terms.clone(),
            escrow_blinding,
            taker_address,
            source_input_hash,
            change_amount,
            change_blinding,
            external_data_hash,
        };

        let ix = CreateSwap {
            inputs: create_inputs,
            signed,
            source_mint: SOL_MINT,
            payer: maker_solana.pubkey(),
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
            &maker_solana,
            &[&maker_solana],
            &alt_addresses,
        )?;

        // The maker's input utxo is now spent; drop it and record the open order.
        let maker_mut = self.actor_mut(maker_name);
        maker_mut.spendable.retain(|u| {
            !(u.asset == input_utxo.asset
                && u.amount == input_utxo.amount
                && u.blinding == input_utxo.blinding)
        });
        self.open_orders.push(OpenOrder {
            maker_name: maker_name.to_string(),
            terms,
            escrow_blinding,
            source_mint: SOL_MINT,
            taker_address,
        });
        Ok(())
    }

    fn escrow_utxo_hash(&self, order: &OpenOrder) -> Result<[u8; 32]> {
        let escrow = Escrow {
            terms: order.terms.clone(),
            blinding: order.escrow_blinding,
            source_mint: order.source_mint,
        }
        .output(order.taker_address.viewing_pubkey)?;
        escrow.hash().map_err(|e| anyhow!("escrow hash: {e:?}"))
    }

    /// Resolve the mint the order pays out on the destination side. SOL is the
    /// reserved id; any other destination asset id is registered in the harness
    /// `AssetRegistry` on first use with a deterministic mint so `resolve` and the
    /// committed `destination_mint` stay consistent across the order lifecycle.
    fn destination_mint(&mut self, asset_id: u64) -> Result<Address> {
        if asset_id == SOL_ASSET_ID {
            return Ok(SOL_MINT);
        }
        if let Ok(mint) = self.assets.resolve(asset_id) {
            return Ok(mint);
        }
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&asset_id.to_be_bytes());
        let mint = Address::new_from_array(bytes);
        self.assets
            .insert(asset_id, mint)
            .map_err(|e| anyhow!("register destination asset {asset_id}: {e:?}"))?;
        Ok(mint)
    }
}

#[when(
    expr = "the maker {word} creates a swap with taker {word}: {int} lamports SOL for {int} of asset {int} expiring at {int}"
)]
fn create_swap_step(
    world: &mut SwapWorld,
    maker_name: String,
    taker_name: String,
    source_amount: i64,
    destination_amount: i64,
    destination_asset: i64,
    expiry: i64,
) {
    world
        .create_swap(
            &maker_name,
            &taker_name,
            SwapParams {
                source_amount: source_amount as u64,
                destination_asset: destination_asset as u64,
                destination_amount: destination_amount as u64,
                expiry: expiry as u64,
                fill_mode: swap_prover::FILL_MODE_VERIFIABLE,
            },
        )
        .expect("create swap succeeds");
}

#[when(
    expr = "the maker {word} creates a derived swap with taker {word}: {int} lamports SOL for {int} of asset {int} expiring at {int}"
)]
fn create_derived_swap_step(
    world: &mut SwapWorld,
    maker_name: String,
    taker_name: String,
    source_amount: i64,
    destination_amount: i64,
    destination_asset: i64,
    expiry: i64,
) {
    world
        .create_swap(
            &maker_name,
            &taker_name,
            SwapParams {
                source_amount: source_amount as u64,
                destination_asset: destination_asset as u64,
                destination_amount: destination_amount as u64,
                expiry: expiry as u64,
                fill_mode: swap_prover::FILL_MODE_DERIVED,
            },
        )
        .expect("create derived swap succeeds");
}

#[then(expr = "the escrow for {word}'s order is indexed")]
fn escrow_indexed(world: &mut SwapWorld, maker_name: String) {
    let order = world
        .open_orders
        .iter()
        .find(|o| o.maker_name == maker_name)
        .expect("open order exists");
    let escrow_hash = world.escrow_utxo_hash(order).expect("escrow hash");
    world
        .wait_for_merkle_proof(escrow_hash)
        .expect("escrow UTXO indexed in the SPP tree");
}
