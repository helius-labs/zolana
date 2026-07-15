mod shared;

use std::time::Duration;

use anyhow::{anyhow, Result};
use shared::{send_v0_with_lookup_table, setup, TestEnv, DESTINATION_AMOUNT, SOURCE_AMOUNT};
use swap_sdk::{
    index::index_maker,
    instructions::{
        cancel::{Cancel, CancelProofInputParams},
        make::{Make, MakeProofInputParams, OrderMarker, SppTxHashes},
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

// The committed order expiry is already in the past, so the maker can cancel
// immediately: the swap program requires `now > order_expiry`. The SPP relayer
// deadline on the cancel transact must still be in the future, so it uses a
// separate constant.
const EXPIRY: u64 = 1_000_000;
const SPP_RELAYER_DEADLINE: u64 = 2_000_000_000;

// Confidential swap cancel on the shielded pool -- make then cancel -- driven
// against the same localnet (validator + Photon indexer + prover) as swap.rs.
//
// Flow:
//   1. Fund (in setup): maker shields 1.0 SPL, taker shields 0.25 SOL.
//   2. Make: identical to swap.rs, but the order expiry is already in the past.
//   3. Discover: the maker rediscovers the order opening from the indexer
//      (`index_maker`), decrypting the order UTXO slot from the sender side.
//   4. Cancel: the maker spends the order UTXO (0.4 SPL, order-authority-owned) ->
//      source output 0.4 SPL back to the maker. ZK cancel proof, v0 tx.
//   5. Assert the returned source output is indexed.
//
// Net: maker 1.0 SPL -> 0.6 SPL change + 0.4 SPL returned; the taker never acts.
#[test]
fn make_and_cancel_swap_inline() -> Result<()> {
    let TestEnv {
        rpc,
        indexer,
        tree,
        mut maker,
        taker,
        spl_mint,
    } = setup()?;
    let swap_prover_client = SwapProverClient::new();
    {
        ensure_registered(&rpc, &maker.keypair.to_solana_keypair()?, &maker.keypair)
            .map_err(|e| anyhow!("register maker: {e:?}"))?;

        let taker_address = taker.keypair.shielded_address()?;
        // The taker's ed25519 authorization identity: the order-committed taker.
        let taker_authorization_address = taker_address
            .solana_address()
            .map_err(|e| anyhow!("taker solana address: {e:?}"))?;
        // The order opening (terms + order UTXO blinding) the maker keeps locally.
        let terms = OrderTerms {
            destination_mint: SOL_MINT,
            destination_amount: DESTINATION_AMOUNT,
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
        let make_spend = SppProofInputUtxo::new(maker_input_utxo, &maker.keypair);
        let input_utxos = vec![make_spend, SppProofInputUtxo::new_dummy()];

        let order_utxo_asset = order_output_utxo.asset;
        let leftover =
            input_sum(&input_utxos, &order_utxo_asset) - i128::from(order_output_utxo.amount);
        let change_amount = u64::try_from(leftover)
            .map_err(|_| anyhow!("insufficient order balance: {leftover}"))?;
        let change = SppProofOutputUtxo::new(order_utxo_asset, change_amount, maker_address)?;

        let order_utxo_hash = order_output_utxo
            .hash()
            .map_err(|e| anyhow!("order output hash: {e:?}"))?;
        let marker_message = OrderMarker {
            order_utxo_hash,
            maker_pubkey: maker_address.solana_address()?,
            taker_address,
        }
        .message()?;

        let transaction_viewing_key = get_transaction_viewing_key(&maker.keypair, &input_utxos)
            .map_err(|e| anyhow!("make transaction viewing key: {e:?}"))?;

        let encoded = encrypt_transaction_data(
            &[change.clone(), order_output_utxo],
            &maker.registry,
            &transaction_viewing_key,
        )
        .map_err(|e| anyhow!("encode make slots: {e:?}"))?;

        let external_data = ExternalData::new(
            *transaction_viewing_key.pubkey().as_bytes(),
            encoded.salt,
            encoded.outputs,
            encoded.resolved_owner_tags,
            vec![marker_message],
        );
        let spp_proof_inputs = SppProofInputs::new(
            input_utxos,
            encoded.output_utxos,
            external_data,
            maker_address.solana_address()?,
        );

        let spp_proof = indexer
            .prove_transact(tree, spp_proof_inputs.clone())
            .map_err(|e| anyhow!("make transact proof: {e:?}"))?;

        let make_proof_inputs = MakeProofInputParams {
            order_utxo,
            change,
            spp_tx_hashes: SppTxHashes::new(&spp_proof_inputs)?,
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
        let maker_address = maker.keypair.shielded_address()?;

        let order = index_maker(
            &mut maker.wallet,
            &maker.keypair,
            &indexer,
            Duration::from_secs(60),
        )?
        .pop()
        .ok_or_else(|| anyhow!("no own swap order discovered"))?;
        let order_utxo = order.order_utxo;
        let taker_viewing_pubkey = order.taker_viewing_pubkey;

        let source_output = order_utxo.source_output(maker_address, random_blinding());
        let source_output_hash = source_output
            .hash()
            .map_err(|e| anyhow!("source output hash: {e:?}"))?;

        let order_input_utxo = order_utxo
            .to_input_utxo()
            .map_err(|e| anyhow!("order spend: {e:?}"))?;

        let input_utxos = vec![order_input_utxo];
        let transaction_viewing_key = get_transaction_viewing_key(&maker.keypair, &input_utxos)
            .map_err(|e| anyhow!("cancel transaction viewing key: {e:?}"))?;

        let encoded = encrypt_transaction_data(
            std::slice::from_ref(&source_output),
            &maker.registry,
            &transaction_viewing_key,
        )
        .map_err(|e| anyhow!("encode cancel slots: {e:?}"))?;

        let mut external_data = ExternalData::new(
            *transaction_viewing_key.pubkey().as_bytes(),
            encoded.salt,
            encoded.outputs,
            encoded.resolved_owner_tags,
            vec![],
        );
        external_data.expiry_unix_ts = SPP_RELAYER_DEADLINE;
        let cancel_spp_proof_inputs = SppProofInputs::new(
            input_utxos,
            encoded.output_utxos,
            external_data,
            maker_address.solana_address()?,
        );

        let cancel_proof_inputs = CancelProofInputParams {
            order_utxo: order_utxo.clone(),
            taker_viewing_pubkey,
            source_output,
            external_data_hash: cancel_spp_proof_inputs
                .external_data
                .hash()
                .map_err(|e| anyhow!("cancel external data hash: {e:?}"))?,
        };

        let spp_proof = indexer
            .prove_transact(tree, cancel_spp_proof_inputs)
            .map_err(|e| anyhow!("cancel transact proof: {e:?}"))?;

        let cancel_proof = swap_prover_client
            .prove_cancel(&cancel_proof_inputs.to_proof_inputs()?)
            .map_err(|e| anyhow!("cancel proof: {e:?}"))?;

        let cancel_ix = Cancel {
            maker: maker_address.solana_address()?,
            payer: maker_address.solana_address()?,
            tree,
            cancel_proof: cancel_proof.into(),
            order_expiry: order_utxo.terms.expiry,
            spp_proof,
        }
        .instruction()?;

        send_v0_with_lookup_table(&rpc, &maker.keypair.to_solana_keypair()?, cancel_ix)?;

        indexer
            .get_merkle_proofs(tree, vec![source_output_hash])
            .map_err(|e| anyhow!("cancel output index: {e}"))?;
    }
    Ok(())
}
