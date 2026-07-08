use anyhow::{anyhow, Result};
use cucumber::{then, when};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use swap_sdk::{
    instructions::create_swap::{CreateSharedInputs, CreateSwap, EscrowCreate},
    order::{marker_output_utxo, BlindingField, Escrow, OrderTerms, SOL_ASSET_ID},
};
use zolana_client::{ProverClient, SpendProof, Transaction as TxBuilder};
use zolana_keypair::{random_blinding, ShieldedAddress, ShieldedKeypair};
use zolana_transaction::{
    instructions::{
        transact::{OutputUtxo, SignedTransaction},
        types::SpendUtxo,
    },
    utxo::Blinding,
    Utxo, SOL_MINT,
};

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

struct MakerInput {
    keypair: ShieldedKeypair,
    solana: Keypair,
    utxo: Utxo,
}

struct OrderOutputs {
    escrow: OutputUtxo,
    marker: OutputUtxo,
}

impl SwapWorld {
    pub(crate) fn create_swap(
        &mut self,
        maker_name: &str,
        taker_name: &str,
        params: SwapParams,
    ) -> Result<()> {
        self.ensure_actor(maker_name)?;
        self.ensure_actor(taker_name)?;

        // 1. Select the maker input UTXO to spend.
        let input = self.select_input(maker_name, params.source_amount)?;

        // 2. Create the output UTXOs: escrow + marker (both taker-owned), and the
        //    maker change UTXO produced by signing the spend.
        let (terms, taker_address) = self.build_order_terms(&input.keypair, taker_name, &params)?;
        let escrow_blinding = random_blinding();
        let outputs = build_order_outputs(&terms, escrow_blinding, taker_address)?;
        let signed = self.sign_spend(&input, outputs)?;

        // 3. Build the proof inputs shared by the create proof and the SPP transact.
        let create_inputs =
            shared_inputs_from_signed(&terms, escrow_blinding, taker_address, &signed)?;

        // 4. Prove (outside the instruction), then assemble the create instruction.
        let spend_proofs = self.resolve_spend_proofs(&signed)?;
        let source_asset_id = create_inputs.terms.source_asset_id;
        let (proof, transact) =
            create_inputs.prove(signed, SOL_MINT, &spend_proofs, &ProverClient::local())?;
        let ix = CreateSwap {
            inputs: create_inputs,
            payer: input.solana.pubkey(),
            tree: self.tree,
            proof,
            transact,
            source_asset_id,
        }
        .instruction();

        // 5. Build and send the transaction (mechanical).
        self.send_create_ix(ix, &input.solana)?;

        self.record_open_order(
            maker_name,
            &input.utxo,
            terms,
            escrow_blinding,
            taker_address,
        );
        Ok(())
    }

    fn select_input(&self, maker_name: &str, source_amount: u64) -> Result<MakerInput> {
        let maker = self.actor(maker_name);
        let utxo = maker
            .spendable
            .iter()
            .find(|u| u.asset == SOL_MINT && u.amount >= source_amount)
            .cloned()
            .ok_or_else(|| anyhow!("{maker_name} has no spendable SOL utxo >= {source_amount}"))?;
        Ok(MakerInput {
            keypair: maker.shielded_keypair.clone(),
            solana: maker.solana_keypair.insecure_clone(),
            utxo,
        })
    }

    fn build_order_terms(
        &mut self,
        maker_keypair: &ShieldedKeypair,
        taker_name: &str,
        params: &SwapParams,
    ) -> Result<(OrderTerms, ShieldedAddress)> {
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

        let destination_mint = self.destination_mint(params.destination_asset)?;
        let maker_owner_hash = maker_keypair
            .owner_hash()
            .map_err(|e| anyhow!("owner hash: {e:?}"))?;
        let maker_viewing_pk = *maker_keypair.viewing_pubkey().as_bytes();

        let terms = OrderTerms {
            source_asset_id: SOL_ASSET_ID,
            source_amount: params.source_amount,
            destination_asset_id: params.destination_asset,
            destination_mint,
            destination_amount: params.destination_amount,
            maker_owner_hash,
            maker_viewing_pk,
            expiry: params.expiry,
            taker_pk_fe,
            fill_mode: params.fill_mode,
        };
        Ok((terms, taker_address))
    }

    fn sign_spend(&self, input: &MakerInput, outputs: OrderOutputs) -> Result<SignedTransaction> {
        let payer_address = Address::new_from_array(input.solana.pubkey().to_bytes());
        let spend = SpendUtxo::from_keypair(input.utxo.clone(), &input.keypair);
        let tx = TxBuilder::new(
            input
                .keypair
                .shielded_address()
                .map_err(|e| anyhow!("addr: {e:?}"))?,
            vec![spend],
            payer_address,
        );
        EscrowCreate {
            tx,
            escrow: outputs.escrow,
            marker: outputs.marker,
            payer: input.solana.pubkey(),
        }
        .sign(&input.keypair, &self.assets)
        .map_err(|e| anyhow!("escrow create sign: {e:?}"))
    }

    fn resolve_spend_proofs(&self, signed: &SignedTransaction) -> Result<Vec<SpendProof>> {
        let commitments = signed
            .input_utxo_hashes()
            .map_err(|e| anyhow!("input commitments: {e:?}"))?;
        let mut spend_proofs = Vec::new();
        for commitment in &commitments {
            let state = self.wait_for_merkle_proof(commitment.utxo_hash)?;
            let nullifier = self.wait_for_non_inclusion_proof(commitment.nullifier)?;
            spend_proofs.push(SpendProof { state, nullifier });
        }
        Ok(spend_proofs)
    }

    fn send_create_ix(&mut self, ix: Instruction, maker_solana: &Keypair) -> Result<()> {
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
            maker_solana,
            &[maker_solana],
            &alt_addresses,
        )?;
        Ok(())
    }

    fn record_open_order(
        &mut self,
        maker_name: &str,
        spent: &Utxo,
        terms: OrderTerms,
        escrow_blinding: Blinding,
        taker_address: ShieldedAddress,
    ) {
        let maker_mut = self.actor_mut(maker_name);
        maker_mut.spendable.retain(|u| {
            !(u.asset == spent.asset && u.amount == spent.amount && u.blinding == spent.blinding)
        });
        self.open_orders.push(OpenOrder {
            maker_name: maker_name.to_string(),
            terms,
            escrow_blinding,
            source_mint: SOL_MINT,
            taker_address,
        });
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

fn build_order_outputs(
    terms: &OrderTerms,
    escrow_blinding: Blinding,
    taker_address: ShieldedAddress,
) -> Result<OrderOutputs> {
    let escrow = Escrow {
        terms: terms.clone(),
        blinding: escrow_blinding,
        source_mint: SOL_MINT,
    }
    .output(taker_address.viewing_pubkey)?;
    let marker = marker_output_utxo(taker_address);
    Ok(OrderOutputs { escrow, marker })
}

// Recover the create-input fields from the signed transaction so the create proof
// commits the exact same private_tx_hash the SPP transact does.
fn shared_inputs_from_signed(
    terms: &OrderTerms,
    escrow_blinding: Blinding,
    taker_address: ShieldedAddress,
    signed: &SignedTransaction,
) -> Result<CreateSharedInputs> {
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
    let external_data_hash = signed
        .external_data
        .hash()
        .map_err(|e| anyhow!("external data hash: {e:?}"))?;

    Ok(CreateSharedInputs {
        terms: terms.clone(),
        escrow_blinding,
        taker_address,
        source_input_hash,
        change_amount: change_output.amount,
        change_blinding: change_output.blinding.to_field(),
        external_data_hash,
    })
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
