mod shared;

use std::time::Duration;

use anyhow::{anyhow, Result};
use shared::{
    send_v0_with_lookup_table, setup, spendable_utxo, TestEnv, DESTINATION_AMOUNT, SOURCE_AMOUNT,
};
use swap_sdk::{
    discover::discover_orders,
    instructions::{
        create_swap::{input_sum, CreateSwap, CreateSwapProofInputParams, OrderMarker},
        fill::{Fill, FillProofInputParams},
    },
    order::{OrderTerms, OrderUtxo, Recipient, SOL_ASSET_ID},
    prover::SwapProverClient,
};
use zolana_client::{ensure_registered, Rpc};
use zolana_interface::instruction::instruction_data::transact::TransactOutput;
use zolana_keypair::{hash::sha256_be, random_blinding, random_salt};
use zolana_transaction::{
    instructions::{
        transact::{
            first_nullifier, ConfidentialSlot, EncodeOutputSlot, ExternalData, OutputUtxo,
            PublicAmounts, Shape, SlotCx, SppProofInputs,
        },
        types::SppProofInputUtxo,
    },
    SOL_MINT,
};

const EXPIRY: u64 = 2_000_000_000;

// Confidential SOL<->SPL swap on the shielded pool -- create then derived fill --
// driven against a real localnet (validator + Photon indexer + prover) that
// `setup()` spins up, including registering an SPL asset with the pool.
//
// The maker escrows an SPL token and wants SOL; the taker pays SOL and receives the
// SPL -- i.e. the taker swaps SOL for the SPL token. Destination is SOL, so the
// derived fill rail applies; the SPL source rides the shielded UTXOs (the SPP
// transact is asset-generic for a purely-shielded spend, and the create/fill
// flows denominate change in the escrow asset).
//
// Flow:
//   1. Fund (in setup): maker shields 1.0 SPL, taker shields 0.25 SOL; each wallet
//      syncs from the indexer to discover and decrypt its own note.
//   2. Create: maker spends its 1.0 SPL UTXO -> escrow 0.4 SPL (taker-owned, held
//      under the escrow-authority PDA), marker (0-value taker-owned discovery
//      note), change 0.6 SPL (back to maker). ZK create proof, v0 tx via ALT.
//   3. Fill (derived): taker spends escrow (0.4 SPL) + its own 0.25 SOL UTXO ->
//      source_output 0.4 SPL (to taker), destination_output 0.25 SOL (to maker).
//      ZK fill proof, v0 tx.
//   4. Assert both fill outputs are indexed.
//
// Net: maker 1.0 SPL -> 0.6 SPL + 0.25 SOL; taker 0.25 SOL -> 0.4 SPL.
#[test]
fn create_and_fill_swap_inline() -> Result<()> {
    let TestEnv {
        rpc,
        indexer,
        tree,
        maker,
        mut taker,
        spl_mint,
    } = setup()?;
    let swap_prover_client = SwapProverClient::new_ffi();
    {
        ensure_registered(&rpc, &maker.keypair.to_solana_keypair()?, &maker.keypair)
            .map_err(|e| anyhow!("register maker: {e:?}"))?;

        // 1. Set order terms.
        let taker_address = taker.keypair.shielded_address()?;
        // The taker's ed25519 authorization identity: the fill's taker input UTXO
        // owner must match the order-committed taker.
        let taker_authorization_address = taker_address
            .solana_address()
            .map_err(|e| anyhow!("taker solana address: {e:?}"))?;

        let terms = OrderTerms {
            destination_mint: SOL_MINT,
            destination_amount: DESTINATION_AMOUNT,
            // The swap settlement goes to the maker's shielded address.
            destination: maker.keypair.shielded_address()?,
            taker: taker_authorization_address,
            expiry: EXPIRY,
            fill_mode: swap_prover::FILL_MODE_DERIVED,
        };

        let maker_address = maker.keypair.shielded_address()?;
        let escrow = OrderUtxo {
            terms,
            blinding: random_blinding(),
            source_mint: spl_mint,
            source_amount: SOURCE_AMOUNT,
            destination_asset_id: SOL_ASSET_ID,
        };
        let escrow_output_utxo = escrow.output_utxo(taker_address.viewing_pubkey)?;

        let maker_input_utxo = spendable_utxo(&maker, spl_mint, SOURCE_AMOUNT)?;

        // 2. Select input utxos.
        let create_spend = SppProofInputUtxo::new(maker_input_utxo, &maker.keypair);

        let create_nullifier_pubkey = create_spend
            .nullifier_key
            .pubkey()
            .map_err(|e| anyhow!("create nullifier pubkey: {e:?}"))?;
        let source_input_hash = create_spend
            .utxo
            .hash(
                &create_nullifier_pubkey,
                &create_spend.data_hash.unwrap_or([0u8; 32]),
                &create_spend.zone_data_hash.unwrap_or([0u8; 32]),
            )
            .map_err(|e| anyhow!("source input hash: {e:?}"))?;
        let inputs = vec![create_spend, SppProofInputUtxo::new_dummy()];

        // 3. create output utxos.
        let escrow_asset = escrow_output_utxo.asset;

        let leftover = input_sum(&inputs, &escrow_asset) - i128::from(escrow_output_utxo.amount);
        let change_amount = u64::try_from(leftover)
            .map_err(|_| anyhow!("insufficient escrow balance: {leftover}"))?;
        let change_blinding = random_blinding();
        let change = OutputUtxo {
            owner_address: Some(maker_address),
            asset: escrow_asset,
            amount: change_amount,
            blinding: change_blinding,
            ..Default::default()
        };

        let escrow_utxo_hash = escrow_output_utxo
            .hash()
            .map_err(|e| anyhow!("escrow output hash: {e:?}"))?;

        // 4. Encrypt output utxos.
        let change_slot = ConfidentialSlot::new(change, &maker.registry)?;
        let escrow_slot = ConfidentialSlot::new(escrow_output_utxo, &maker.registry)?;
        let marker_message = OrderMarker {
            escrow_utxo_hash,
            maker_pubkey: maker_address.solana_address()?,
            taker_address,
        }
        .message()?;

        let first_nullifier =
            first_nullifier(&inputs).map_err(|e| anyhow!("first nullifier: {e:?}"))?;
        let tx = maker
            .keypair
            .get_transaction_viewing_key(&first_nullifier)
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
        let salt = random_salt();
        let self_pubkey = maker.keypair.viewing_pubkey();

        let slots: [&dyn EncodeOutputSlot; 2] = [&change_slot, &escrow_slot];
        let mut outputs = Vec::with_capacity(slots.len());
        let mut transact_outputs = Vec::with_capacity(slots.len());
        let mut resolved_owner_tags = Vec::with_capacity(slots.len());
        let mut ordinal = 0u32;
        for slot in slots.iter() {
            let encoded = slot.encode_slot(&SlotCx {
                tx: &tx,
                self_pubkey,
                salt,
                slot_index: ordinal,
            })?;
            let output = slot.output().clone();
            let utxo_hash = output.hash()?;
            if encoded.data.is_some() {
                ordinal += 1;
            }
            transact_outputs.push(TransactOutput {
                utxo_hash,
                owner_tag: encoded.owner_tag,
                data: encoded.data,
            });
            resolved_owner_tags.push(encoded.resolved_owner_tag);
            outputs.push(output);
        }

        let external_data = ExternalData::new(
            *tx.pubkey().as_bytes(),
            salt,
            transact_outputs,
            resolved_owner_tags,
            vec![marker_message],
            u64::MAX,
        );
        let spp_proof_inputs = SppProofInputs {
            input_utxos: inputs,
            output_utxos: outputs,
            public_amounts: PublicAmounts::ZERO,
            external_data, // why does this contain external data instead of the external data hash?
            payer_pubkey_hash: sha256_be(maker_address.solana_address()?.as_array()),
            shape: Shape::IN2_OUT2,
            p256_signature: None,
        };

        let external_data_hash = spp_proof_inputs
            .external_data
            .hash()
            .map_err(|e| anyhow!("create external data hash: {e:?}"))?;
        // 7. create spp proof.
        let spp_proof = indexer
            .prove_transact(tree, spp_proof_inputs)
            .map_err(|e| anyhow!("create transact proof: {e:?}"))?;

        let create_swap_proof_inputs = CreateSwapProofInputParams {
            escrow,
            taker_address,
            source_input_hash,
            change_amount,
            change_blinding,
            external_data_hash,
        };

        let create_swap_proof = swap_prover_client
            .prove_create_swap(&create_swap_proof_inputs)
            .map_err(|e| anyhow!("create proof: {e:?}"))?;

        let create_swap_ix = CreateSwap {
            payer: maker_address.solana_address()?,
            tree,
            create_swap_proof: create_swap_proof.proof.into(),
            spp_proof,
        }
        .instruction()?;

        send_v0_with_lookup_table(&rpc, &maker.keypair.to_solana_keypair()?, create_swap_ix)?;
    }

    {
        let taker_address = taker.keypair.shielded_address()?;
        let order = discover_orders(&mut taker, &indexer, &rpc, Duration::from_secs(60))?
            .pop()
            .ok_or_else(|| anyhow!("no swap order discovered"))?;
        let escrow = order.escrow;
        let terms = escrow.terms.clone();

        let taker_input_utxo =
            spendable_utxo(&taker, terms.destination_mint, terms.destination_amount)?;
        let source_output_blinding = random_blinding();
        let taker_in = Recipient {
            address: taker_address,
            amount: terms.destination_amount,
            blinding: taker_input_utxo.blinding,
            mint: terms.destination_mint,
        }
        .output();
        let fill_inputs = FillProofInputParams {
            escrow: escrow.clone(),
            taker_in,
            source_output_blinding,
            external_data_hash: [0u8; 32],
            maker_recipient: terms.destination,
            taker_recipient: taker_address,
        };
        let source_output = fill_inputs.source_output();
        let destination_output = fill_inputs
            .destination_output()
            .map_err(|e| anyhow!("destination output: {e:?}"))?;
        let source_output_hash = source_output
            .hash()
            .map_err(|e| anyhow!("source output hash: {e:?}"))?;
        let destination_output_hash = destination_output
            .hash()
            .map_err(|e| anyhow!("destination output hash: {e:?}"))?;

        let escrow_input = escrow
            .into_input_utxo()
            .map_err(|e| anyhow!("escrow spend: {e:?}"))?;
        let taker_spend = SppProofInputUtxo::new(taker_input_utxo, &taker.keypair);

        let inputs = vec![escrow_input, taker_spend];

        let source_slot = ConfidentialSlot::new(source_output, &taker.registry)?;
        let destination_slot = ConfidentialSlot::new(destination_output, &taker.registry)?;

        let first_nullifier =
            first_nullifier(&inputs).map_err(|e| anyhow!("first nullifier: {e:?}"))?;
        let tx = taker
            .keypair
            .get_transaction_viewing_key(&first_nullifier)
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
        let salt = random_salt();
        let self_pubkey = taker.keypair.viewing_pubkey();

        let slots: [&dyn EncodeOutputSlot; 2] = [&source_slot, &destination_slot];
        let mut outputs = Vec::with_capacity(slots.len());
        let mut transact_outputs = Vec::with_capacity(slots.len());
        let mut resolved_owner_tags = Vec::with_capacity(slots.len());
        let mut ordinal = 0u32;
        for slot in slots.iter() {
            let encoded = slot.encode_slot(&SlotCx {
                tx: &tx,
                self_pubkey,
                salt,
                slot_index: ordinal,
            })?;
            let output = slot.output().clone();
            let utxo_hash = output.hash()?;
            if encoded.data.is_some() {
                ordinal += 1;
            }
            transact_outputs.push(TransactOutput {
                utxo_hash,
                owner_tag: encoded.owner_tag,
                data: encoded.data,
            });
            resolved_owner_tags.push(encoded.resolved_owner_tag);
            outputs.push(output);
        }

        let external_data = ExternalData::new(
            *tx.pubkey().as_bytes(),
            salt,
            transact_outputs,
            resolved_owner_tags,
            vec![],
            terms.expiry,
        );
        let fill_spp_proof_inputs = SppProofInputs {
            input_utxos: inputs,
            output_utxos: outputs,
            public_amounts: PublicAmounts::ZERO,
            external_data,
            payer_pubkey_hash: sha256_be(taker_address.solana_address()?.as_array()),
            shape: Shape::IN2_OUT2,
            p256_signature: None,
        };

        let fill_external_data_hash = fill_spp_proof_inputs
            .external_data
            .hash()
            .map_err(|e| anyhow!("fill external data hash: {e:?}"))?;

        let fill_inputs = FillProofInputParams {
            external_data_hash: fill_external_data_hash,
            ..fill_inputs
        };

        let spp_proof = indexer
            .prove_transact(tree, fill_spp_proof_inputs)
            .map_err(|e| anyhow!("fill transact proof: {e:?}"))?;

        let fill_proof = swap_prover_client
            .prove_fill(&fill_inputs)
            .map_err(|e| anyhow!("fill proof: {e:?}"))?;

        let fill_ix = Fill {
            payer: taker_address.solana_address()?,
            tree,
            fill_proof: fill_proof.proof.into(),
            spp_proof,
        }
        .instruction()?;

        send_v0_with_lookup_table(&rpc, &taker.keypair.to_solana_keypair()?, fill_ix)?;

        indexer
            .get_merkle_proofs(tree, vec![source_output_hash, destination_output_hash])
            .map_err(|e| anyhow!("fill outputs index: {e}"))?;
    }
    Ok(())
}
