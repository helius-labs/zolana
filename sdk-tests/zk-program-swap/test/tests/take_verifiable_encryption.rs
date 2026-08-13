mod shared;

use std::time::Duration;

use anyhow::{anyhow, Result};
use shared::{send_v0_with_lookup_table, setup, TestEnv, DESTINATION_AMOUNT, SOURCE_AMOUNT};
use swap_sdk::{
    index::index_taker,
    instructions::{
        make::{Make, MakeProofInputParams, OrderMarker, SppTxHashes},
        take_verifiable_encryption::{
            TakeVerifiableEncryption, TakeVerifiableEncryptionProofInputParams,
        },
    },
    prover::SwapProverClient,
    shared::input_sum,
    state::{OrderTerms, OrderUtxo},
};
use zolana_client::Rpc;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
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
use zolana_wallet::{ensure_registered, sync_wallet};

const EXPIRY: u64 = 2_000_000_000;

// Confidential SOL<->SPL swap settled through the verifiable-encryption take
// rail (`take_verifiable_encryption`), driven against a real localnet
// (validator + Photon indexer + prover) that `setup()` starts. This is the
// runnable positive for the only instruction exercising the BSB22-committed
// swap verifier.
//
// The flow mirrors `swap.rs` up to the take: the maker escrows 0.4 SPL into an
// order UTXO whose terms select `TAKE_MODE_VERIFIABLE`. The taker then spends
// the order UTXO plus its own 0.25 SOL note; unlike the derived rail, the
// maker-bound destination output carries a fresh blinding and a verifiable
// ciphertext the circuit proves consistent with the output commitment.
//
// Resulting escrow state asserted at the end: both take outputs are appended
// to the tree (indexed with Merkle proofs), and the taker's synced wallet
// spends down its SOL note and now holds the escrowed 0.4 SPL.
#[test]
fn make_and_take_verifiable_encryption() -> Result<()> {
    let TestEnv {
        client,
        tree,
        maker,
        maker_input,
        mut taker,
        spl_mint,
    } = setup()?;
    let swap_prover_client = SwapProverClient::new();
    {
        ensure_registered(client.rpc(), &maker.keypair, &maker.keypair)
            .map_err(|e| anyhow!("register maker: {e:?}"))?;

        let taker_address = taker.keypair.shielded_address()?;
        let taker_authorization_address = taker_address
            .solana_address()
            .map_err(|e| anyhow!("taker solana address: {e:?}"))?;

        // The verifiable-encryption rail: the take must publish a ciphertext of
        // the destination output that the TVE circuit proves well-formed.
        let terms = OrderTerms {
            destination_mint: SOL_MINT,
            destination_amount: DESTINATION_AMOUNT,
            destination: maker.keypair.shielded_address()?,
            taker: taker_authorization_address,
            expiry: EXPIRY,
            take_mode: swap_prover::TAKE_MODE_VERIFIABLE,
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

        // The maker's SPL note is program-owned (signing = swap PDA, nullifier
        // = order key), so the maker wallet can never discover it; the fixture
        // retains it explicitly for exactly this spend (mirrors swap.rs).
        let input_utxos = vec![maker_input, SppProofInputUtxo::new_dummy()];

        let order_utxo_asset = order_output_utxo.asset;
        let leftover =
            input_sum(&input_utxos, &order_utxo_asset) - i128::from(order_output_utxo.amount);
        let change_amount = u64::try_from(leftover)
            .map_err(|_| anyhow!("insufficient order balance: {leftover}"))?;
        let change = SppProofOutputUtxo::new(order_utxo_asset, change_amount, maker_address)?;

        let order_utxo_hash = order_output_utxo
            .hash()
            .map_err(|e| anyhow!("order output hash: {e:?}"))?;

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
        let spp_proof = client
            .indexer()
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

        let make_signature = send_v0_with_lookup_table(client.rpc(), &maker.keypair, make_ix)?;
        client
            .confirm_private_transaction_sync(make_signature)
            .map_err(|e| anyhow!("confirm make indexed: {e:?}"))?;
    }

    let (source_output_hash, destination_output_hash) = {
        let taker_address = taker.keypair.shielded_address()?;
        let order = index_taker(
            &mut taker.wallet,
            &taker.keypair,
            client.indexer(),
            client.rpc(),
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
        // The TVE destination output carries a fresh blinding; the circuit
        // proves the published ciphertext encrypts exactly this output.
        let destination_output =
            order_utxo.destination_output(terms.destination, random_blinding());
        let destination_ciphertext = order_utxo
            .destination_ciphertext(&destination_output)
            .map_err(|e| anyhow!("destination ciphertext: {e:?}"))?;
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

        // Only the source slot is encrypted conventionally; the destination
        // slot is appended by hand with the verifiable ciphertext as its data
        // and the maker's view tag inline.
        let mut encoded = encrypt_transaction_data(
            std::slice::from_ref(&source_output),
            &taker.registry,
            &transaction_viewing_key,
        )?;
        let destination_view_tag = terms
            .destination
            .signing_pubkey
            .confidential_view_tag()
            .map_err(|e| anyhow!("maker view tag: {e:?}"))?;
        encoded.outputs.push(TransactOutput {
            utxo_hash: destination_output_hash,
            owner_tag: OwnerTag::Inline(destination_view_tag),
            data: Some(destination_ciphertext),
        });
        encoded.resolved_owner_tags.push(destination_view_tag);
        encoded.output_utxos.push(destination_output.clone());

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

        let take_proof_inputs = TakeVerifiableEncryptionProofInputParams {
            order_utxo,
            taker_in,
            source_output,
            destination_output,
            external_data_hash: take_spp_proof_inputs
                .external_data
                .hash()
                .map_err(|e| anyhow!("take external data hash: {e:?}"))?,
        };

        let spp_proof = client
            .indexer()
            .prove_transact(tree, take_spp_proof_inputs)
            .map_err(|e| anyhow!("take transact proof: {e:?}"))?;

        let take_proof = swap_prover_client
            .prove_take_verifiable_encryption(&take_proof_inputs.to_proof_inputs()?)
            .map_err(|e| anyhow!("take_verifiable_encryption proof: {e:?}"))?;

        let take_ix = TakeVerifiableEncryption {
            payer: taker_address.solana_address()?,
            tree,
            take_proof: take_proof
                .try_into()
                .map_err(|e| anyhow!("tve proof must carry a BSB22 commitment: {e:?}"))?,
            spp_proof,
        }
        .instruction()?;

        let take_signature = send_v0_with_lookup_table(client.rpc(), &taker.keypair, take_ix)?;
        client
            .confirm_private_transaction_sync(take_signature)
            .map_err(|e| anyhow!("confirm take indexed: {e:?}"))?;

        (source_output_hash, destination_output_hash)
    };

    // Resulting escrow state: both take outputs landed in the tree, and the
    // taker's wallet (re-synced from the indexer) now spends the escrowed
    // source amount while its destination-side SOL note is gone.
    client
        .indexer()
        .get_merkle_proofs(
            tree,
            vec![source_output_hash, destination_output_hash],
            None,
        )
        .map_err(|e| anyhow!("take outputs index: {e}"))?;

    sync_wallet(&mut taker.wallet, &taker.keypair, client.indexer())
        .map_err(|e| anyhow!("sync taker after take: {e:?}"))?;
    let taker_spl = taker.balance(spl_mint, None)?;
    assert!(
        taker_spl
            .utxos
            .iter()
            .any(|utxo| utxo.amount == SOURCE_AMOUNT),
        "taker must hold the escrowed source note of {SOURCE_AMOUNT} after the take"
    );
    let taker_sol = taker.balance(SOL_MINT, Some(Filter::MinAmount(DESTINATION_AMOUNT)))?;
    assert!(
        taker_sol.utxos.is_empty(),
        "the taker's destination-side SOL note must be spent by the take"
    );
    Ok(())
}
