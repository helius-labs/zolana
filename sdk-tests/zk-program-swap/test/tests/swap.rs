mod shared;

use std::time::Duration;

use anyhow::{anyhow, Result};
use shared::{
    send_v0_with_lookup_table, setup, spendable_utxo, TestEnv, DESTINATION_AMOUNT, SOURCE_AMOUNT,
};
use swap_sdk::{
    discover::discover_orders,
    instructions::{
        create_swap::{input_sum, CreateSwap, CreateSwapProofInputParams, MarkerEncrypt},
        fill::{Fill, FillProofInputParams},
    },
    order::{marker_output_utxo, OrderTerms, OrderUtxo, Recipient, SOL_ASSET_ID},
    prover::SwapProverClient,
};
use zolana_client::{ensure_registered, Rpc};
use zolana_keypair::{hash::sha256_be, random_blinding, random_salt};
use zolana_transaction::{
    instructions::{
        transact::{
            signed_to_field, ConfidentialSlot, EncodeOutputSlot, ExternalData, OutputUtxo,
            PublicAmounts, Shape, SignedTransaction as SppProofInputs, SlotCx,
        },
        types::SpendUtxo,
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
        let marker_output_utxo = marker_output_utxo(taker_address);

        let maker_input_utxo = spendable_utxo(&maker, spl_mint, SOURCE_AMOUNT)?;

        // 2. Select input utxos.
        let create_spend = SpendUtxo::from_keypair(maker_input_utxo, &maker.keypair);

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
        let first_nullifier = create_spend
            .nullifier_key
            .nullifier(&source_input_hash, &create_spend.utxo.blinding)
            .map_err(|e| anyhow!("first nullifier: {e:?}"))?;
        let inputs = vec![create_spend, SpendUtxo::new_dummy()]; // TODO: rename to input utxos

        // 3. create output utxos.
        let payer_pubkey_hash = sha256_be(maker_address.solana_address()?.as_array());

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

        let escrow_utxo_hash = escrow_output_utxo // Do we hash this twice?
            .hash()
            .map_err(|e| anyhow!("escrow output hash: {e:?}"))?;

        // 4. Encrypt output utxos.
        let change_slot = ConfidentialSlot::new(change, &maker.registry)?;
        let escrow_slot = ConfidentialSlot::new(escrow_output_utxo, &maker.registry)?;
        let marker_slot = MarkerEncrypt {
            marker: marker_output_utxo,
            escrow_utxo_hash,
            payer: maker_address.solana_address()?,
        }
        .encrypt()?;

        let tx_viewing_key = maker
            .keypair
            .get_transaction_viewing_key(&first_nullifier)?;

        let salt = random_salt();
        let self_pubkey = maker.keypair.viewing_pubkey();

        let slots: [&dyn EncodeOutputSlot; 3] = [&change_slot, &escrow_slot, &marker_slot];
        let mut outputs = Vec::with_capacity(slots.len());
        let mut output_utxo_hashes = Vec::with_capacity(slots.len());
        let mut output_ciphertexts = Vec::with_capacity(slots.len());
        for (slot_index, slot) in slots.iter().enumerate() {
            output_ciphertexts.push(slot.encode_slot(&SlotCx {
                tx: &tx_viewing_key,
                self_pubkey,
                salt,
                slot_index: slot_index as u32,
            })?);
            let output = slot.output().clone();
            output_utxo_hashes.push(output.hash()?);
            outputs.push(output);
        }
        // 5. create external data hash
        let external_data = ExternalData::new(
            *tx_viewing_key.pubkey().as_bytes(),
            salt,
            output_utxo_hashes,
            output_ciphertexts,
            u64::MAX,
        );
        let external_data_hash = external_data
            .hash()
            .map_err(|e| anyhow!("create external data hash: {e:?}"))?;

        // 6. Assemble Spp proof inputs.
        let signed_spp_proof_inputs = SppProofInputs {
            inputs,
            outputs,
            public_amounts: PublicAmounts {
                sol: signed_to_field(0),
                spl: signed_to_field(0),
                asset: [0u8; 32],
            },
            external_data,
            payer_pubkey_hash,
            shape: Shape::new(2, 3),
            p256_owner: None,
        };
        // 7. create spp proof.
        let spp_proof = indexer
            .prove_transact(tree, signed_spp_proof_inputs)
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
        let taker_spend = SpendUtxo::from_keypair(taker_input_utxo, &taker.keypair);

        let escrow_nullifier_pubkey = escrow_input
            .nullifier_key
            .pubkey()
            .map_err(|e| anyhow!("escrow nullifier pubkey: {e:?}"))?;
        let escrow_input_hash = escrow_input
            .utxo
            .hash(
                &escrow_nullifier_pubkey,
                &escrow_input.data_hash.unwrap_or([0u8; 32]),
                &escrow_input.zone_data_hash.unwrap_or([0u8; 32]),
            )
            .map_err(|e| anyhow!("escrow input hash: {e:?}"))?;
        let fill_first_nullifier = escrow_input
            .nullifier_key
            .nullifier(&escrow_input_hash, &escrow_input.utxo.blinding)
            .map_err(|e| anyhow!("fill first nullifier: {e:?}"))?;
        let inputs = vec![escrow_input, taker_spend];
        let payer_pubkey_hash = sha256_be(taker_address.solana_address()?.as_array());

        let source_slot = ConfidentialSlot::new(source_output, &taker.registry)?;
        let destination_slot = ConfidentialSlot::new(destination_output, &taker.registry)?;

        let tx_viewing_key = taker
            .keypair
            .get_transaction_viewing_key(&fill_first_nullifier)?;
        let salt = random_salt();
        let self_pubkey = taker.keypair.viewing_pubkey();

        let slots: [&dyn EncodeOutputSlot; 2] = [&source_slot, &destination_slot];
        let mut outputs = Vec::with_capacity(slots.len());
        let mut output_utxo_hashes = Vec::with_capacity(slots.len());
        let mut output_ciphertexts = Vec::with_capacity(slots.len());
        for (slot_index, slot) in slots.iter().enumerate() {
            output_ciphertexts.push(slot.encode_slot(&SlotCx {
                tx: &tx_viewing_key,
                self_pubkey,
                salt,
                slot_index: slot_index as u32,
            })?);
            let output = slot.output().clone();
            output_utxo_hashes.push(output.hash()?);
            outputs.push(output);
        }

        let external_data = ExternalData::new(
            *tx_viewing_key.pubkey().as_bytes(),
            salt,
            output_utxo_hashes,
            output_ciphertexts,
            terms.expiry,
        );
        let fill_external_data_hash = external_data
            .hash()
            .map_err(|e| anyhow!("fill external data hash: {e:?}"))?;

        let fill_signed = SppProofInputs {
            inputs,
            outputs,
            public_amounts: PublicAmounts {
                sol: signed_to_field(0),
                spl: signed_to_field(0),
                asset: [0u8; 32],
            },
            external_data,
            payer_pubkey_hash,
            shape: Shape::new(2, 2),
            p256_owner: None,
        };

        let fill_inputs = FillProofInputParams {
            external_data_hash: fill_external_data_hash,
            ..fill_inputs
        };

        let spp_proof = indexer
            .prove_transact(tree, fill_signed)
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
