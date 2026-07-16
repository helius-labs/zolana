mod shared;

use std::time::Duration;

use anyhow::{anyhow, Result};
use shared::{send_v0_with_lookup_table, setup, TestEnv, DESTINATION_AMOUNT, SOURCE_AMOUNT};
use swap_sdk::{
    index::index_taker,
    instructions::{
        make::{Make, MakeProofInputParams, OrderMarker, SppTxHashes},
        take::{Take, TakeProofInputParams},
    },
    prover::SwapProverClient,
    shared::input_sum,
    state::{OrderTerms, OrderUtxo},
};
use zolana_client::{ensure_registered, Rpc};
use zolana_keypair::random_blinding;
use zolana_transaction::{
    instructions::{
        transact::{
            encrypt_transaction_data, get_transaction_viewing_key, ExternalData, SppProofInputs,
            SppProofOutputUtxo,
        },
        types::SppProofInputUtxo,
    },
    Filter, SOL_ASSET_ID, SOL_MINT,
};

const EXPIRY: u64 = 2_000_000_000;

// Confidential SOL<->SPL swap on the shielded pool -- make then derived take --
// driven against a real localnet (validator + Photon indexer + prover) that
// `setup()` starts, including registering an SPL asset with the pool.
//
// The maker orders an SPL token and wants SOL; the taker pays SOL and receives the
// SPL. Destination is SOL, so the derived take rail applies; the SPL source stays
// in shielded UTXOs (the SPP transact is asset-generic for a purely-shielded
// spend, and the make/take flows denominate change in the order asset).
//
// Flow:
//   1. Fund (in setup): maker shields 1.0 SPL, taker shields 0.25 SOL; each wallet
//      syncs from the indexer to discover and decrypt its own note.
//   2. Make: maker spends its 1.0 SPL UTXO -> order UTXO 0.4 SPL (taker-owned, held
//      under the order-authority PDA), marker (0-value taker-owned discovery
//      note), change 0.6 SPL (back to maker). ZK make proof, v0 tx via ALT.
//   3. Take (derived): taker spends the order UTXO (0.4 SPL) + its own 0.25 SOL UTXO ->
//      source_output 0.4 SPL (to taker), destination_output 0.25 SOL (to maker).
//      ZK take proof, v0 tx.
//   4. Assert both take outputs are indexed.
//
// Net: maker 1.0 SPL -> 0.6 SPL + 0.25 SOL; taker 0.25 SOL -> 0.4 SPL.
#[test]
fn make_and_take_swap_inline() -> Result<()> {
    let TestEnv {
        rpc,
        indexer,
        tree,
        maker,
        mut taker,
        spl_mint,
    } = setup()?;
    let swap_prover_client = SwapProverClient::new();
    {
        ensure_registered(&rpc, &maker.keypair.to_solana_keypair()?, &maker.keypair)
            .map_err(|e| anyhow!("register maker: {e:?}"))?;

        // 1. Set order terms.
        let taker_address = taker.keypair.shielded_address()?;
        // The taker's ed25519 authorization identity: the take's taker input UTXO
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
            take_mode: swap_prover::TAKE_MODE_DERIVED,
        };

        let maker_address = maker.keypair.shielded_address()?;
        let order_utxo = OrderUtxo {
            terms,
            blinding: random_blinding(),
            source_mint: spl_mint,
            source_amount: SOURCE_AMOUNT,
            destination_asset_id: SOL_ASSET_ID,
        };
        let order_output_utxo = order_utxo.output_utxo(taker_address.viewing_pubkey)?;

        let maker_input_utxo = maker
            .balance(spl_mint, Some(Filter::MinAmount(SOURCE_AMOUNT)))?
            .utxos
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("no spendable utxo of {spl_mint} >= {SOURCE_AMOUNT}"))?;

        // 2. Select input utxos.
        let input_utxo = SppProofInputUtxo::new(maker_input_utxo, &maker.keypair);
        let input_utxos = vec![input_utxo, SppProofInputUtxo::new_dummy()];

        // 3. create output utxos.
        let order_utxo_asset = order_output_utxo.asset;

        let leftover =
            input_sum(&input_utxos, &order_utxo_asset) - i128::from(order_output_utxo.amount);
        let change_amount = u64::try_from(leftover)
            .map_err(|_| anyhow!("insufficient order balance: {leftover}"))?;
        let change = SppProofOutputUtxo::new(order_utxo_asset, change_amount, maker_address)?;

        let order_utxo_hash = order_output_utxo
            .hash()
            .map_err(|e| anyhow!("order output hash: {e:?}"))?;

        // 4. Encrypt output utxos.

        let transaction_viewing_key = get_transaction_viewing_key(&maker.keypair, &input_utxos)
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;

        let encoded_transaction_data = encrypt_transaction_data(
            &[change.clone(), order_output_utxo],
            &maker.registry,
            &transaction_viewing_key,
        )?;

        let marker_message = OrderMarker {
            order_utxo_hash,
            maker_pubkey: maker_address.solana_address()?,
            taker_address,
        }
        .message()?;
        let external_data = ExternalData::new(
            *transaction_viewing_key.pubkey().as_bytes(),
            encoded_transaction_data.salt,
            encoded_transaction_data.outputs,
            encoded_transaction_data.resolved_owner_tags,
            vec![marker_message],
        );
        let spp_proof_inputs = SppProofInputs::new(
            input_utxos,
            encoded_transaction_data.output_utxos,
            external_data,
            maker_address.solana_address()?,
        );

        let spp_tx_hashes = SppTxHashes::new(&spp_proof_inputs)?;
        // 5. create spp proof.
        let spp_proof = indexer
            .prove_transact(tree, spp_proof_inputs)
            .map_err(|e| anyhow!("make transact proof: {e:?}"))?;

        let make_proof_inputs = MakeProofInputParams {
            order_utxo,
            change,
            spp_tx_hashes,
        };

        let make_proof = swap_prover_client
            .prove_make(&make_proof_inputs.to_proof_inputs()?)
            .map_err(|e| anyhow!("make proof: {e:?}"))?;

        let make_ix = Make {
            payer: maker_address.solana_address()?,
            tree,
            make_proof: make_proof.into(),
            spp_proof,
        }
        .instruction()?;

        send_v0_with_lookup_table(&rpc, &maker.keypair.to_solana_keypair()?, make_ix)?;
    }

    {
        let taker_address = taker.keypair.shielded_address()?;
        let order = index_taker(
            &mut taker.wallet,
            &taker.keypair,
            &indexer,
            &rpc,
            Duration::from_secs(60),
        )?
        .pop()
        .ok_or_else(|| anyhow!("no swap order discovered"))?;
        let order_utxo = order.order_utxo;
        let terms = order_utxo.terms.clone();

        let taker_input_utxo = taker
            .balance(
                terms.destination_mint,
                Some(Filter::MinAmount(terms.destination_amount)),
            )?
            .utxos
            .first()
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "no spendable utxo of {} >= {}",
                    terms.destination_mint,
                    terms.destination_amount
                )
            })?;
        let taker_in = order_utxo.destination_output(taker_address, taker_input_utxo.blinding);
        let source_output = order_utxo.source_output(taker_address, random_blinding());
        let destination_output = order_utxo
            .derived_destination_output(terms.destination)
            .map_err(|e| anyhow!("destination output: {e:?}"))?;
        let source_output_hash = source_output
            .hash()
            .map_err(|e| anyhow!("source output hash: {e:?}"))?;
        let destination_output_hash = destination_output
            .hash()
            .map_err(|e| anyhow!("destination output hash: {e:?}"))?;

        let order_input_utxo = order_utxo
            .to_input_utxo()
            .map_err(|e| anyhow!("order spend: {e:?}"))?;
        let taker_spend = SppProofInputUtxo::new(taker_input_utxo, &taker.keypair);

        let inputs = vec![order_input_utxo, taker_spend];

        let transaction_viewing_key = get_transaction_viewing_key(&taker.keypair, &inputs)
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;

        let encoded = encrypt_transaction_data(
            &[source_output.clone(), destination_output.clone()],
            &taker.registry,
            &transaction_viewing_key,
        )?;

        let mut external_data = ExternalData::new(
            *transaction_viewing_key.pubkey().as_bytes(),
            encoded.salt,
            encoded.outputs,
            encoded.resolved_owner_tags,
            vec![],
        );
        external_data.expiry_unix_ts = terms.expiry;
        let take_spp_proof_inputs = SppProofInputs::new(
            inputs,
            encoded.output_utxos,
            external_data,
            taker_address.solana_address()?,
        );

        let take_proof_inputs = TakeProofInputParams {
            order_utxo,
            taker_in,
            source_output,
            destination_output,
            external_data_hash: take_spp_proof_inputs
                .external_data
                .hash()
                .map_err(|e| anyhow!("take external data hash: {e:?}"))?,
        };

        let spp_proof = indexer
            .prove_transact(tree, take_spp_proof_inputs)
            .map_err(|e| anyhow!("take transact proof: {e:?}"))?;

        let take_proof = swap_prover_client
            .prove_take(&take_proof_inputs.to_proof_inputs()?)
            .map_err(|e| anyhow!("take proof: {e:?}"))?;

        let take_ix = Take {
            payer: taker_address.solana_address()?,
            tree,
            take_proof: take_proof.into(),
            spp_proof,
        }
        .instruction()?;

        send_v0_with_lookup_table(&rpc, &taker.keypair.to_solana_keypair()?, take_ix)?;

        indexer
            .get_merkle_proofs(tree, vec![source_output_hash, destination_output_hash])
            .map_err(|e| anyhow!("take outputs index: {e}"))?;
    }
    Ok(())
}
