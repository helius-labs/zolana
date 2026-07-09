mod shared;

use std::time::Duration;

use anyhow::{anyhow, Result};
use shared::{
    send_v0_with_lookup_table, setup, spendable_utxo, TestEnv, DESTINATION_AMOUNT, SOURCE_AMOUNT,
};
use swap_sdk::{
    discover::discover_own_orders,
    instructions::{
        cancel::{Cancel, CancelSharedInputs, EscrowCancel},
        create_swap::{CreateSwap, CreateSwapProofInputs, EscrowCreate},
    },
    order::{marker_output_utxo, Escrow, OrderTerms, SOL_ASSET_ID},
    prover::SwapProverClient,
};
use zolana_client::{ensure_registered, Rpc, Transaction as TxBuilder};
use zolana_keypair::random_blinding;
use zolana_transaction::{instructions::types::SpendUtxo, SOL_MINT};

// The committed order expiry is already in the past, so the maker can cancel
// immediately: the swap program requires `now > order_expiry`. The SPP relayer
// deadline on the cancel transact must still be in the future, so it rides a
// separate constant.
const EXPIRY: u64 = 1_000_000;
const SPP_RELAYER_DEADLINE: u64 = 2_000_000_000;

// Confidential swap cancel on the shielded pool -- create then cancel -- driven
// against the same localnet (validator + Photon indexer + prover) as swap.rs.
//
// Flow:
//   1. Fund (in setup): maker shields 1.0 SPL, taker shields 0.25 SOL.
//   2. Create: identical to swap.rs, but the order expiry is already in the past.
//   3. Discover: the maker rediscovers the order opening from the indexer
//      (`discover_own_orders`), decrypting the escrow slot from the sender side.
//   4. Cancel: the maker spends the escrow (0.4 SPL, escrow-authority-owned) ->
//      source output 0.4 SPL back to the maker. ZK cancel proof, v0 tx.
//   5. Assert the returned source output is indexed.
//
// Net: maker 1.0 SPL -> 0.6 SPL change + 0.4 SPL returned; the taker never acts.
#[test]
fn create_and_cancel_swap_inline() -> Result<()> {
    let TestEnv {
        rpc,
        indexer,
        tree,
        mut maker,
        taker,
        spl_mint,
    } = setup()?;
    let swap_prover_client = SwapProverClient::new_ffi();
    {
        ensure_registered(&rpc, &maker.keypair.to_solana_keypair()?, &maker.keypair)
            .map_err(|e| anyhow!("register maker: {e:?}"))?;

        let taker_address = taker.keypair.shielded_address()?;
        // The taker's ed25519 authorization identity: the order-committed taker.
        let taker_authorization_address = taker_address
            .solana_address()
            .map_err(|e| anyhow!("taker solana address: {e:?}"))?;
        // The order opening (terms + escrow blinding) the maker holds off-chain.
        let terms = OrderTerms {
            destination_mint: SOL_MINT,
            destination_amount: DESTINATION_AMOUNT,
            destination: maker.keypair.shielded_address()?,
            taker: taker_authorization_address,
            expiry: EXPIRY,
            fill_mode: swap_prover::FILL_MODE_DERIVED,
        };

        let maker_address = maker.keypair.shielded_address()?;
        let escrow = Escrow {
            terms,
            blinding: random_blinding(),
            source_mint: spl_mint,
            source_amount: SOURCE_AMOUNT,
            destination_asset_id: SOL_ASSET_ID,
        };
        let escrow_output_utxo = escrow.output_utxo(taker_address.viewing_pubkey)?;
        let marker_output_utxo = marker_output_utxo(taker_address);

        let maker_input_utxo = spendable_utxo(&maker, spl_mint, SOURCE_AMOUNT)?;
        let create_spend = SpendUtxo::from_keypair(maker_input_utxo, &maker.keypair);
        let create_tx = TxBuilder::new(
            maker_address,
            vec![create_spend],
            maker_address.solana_address()?,
        );

        let signed_private_transaction = EscrowCreate {
            tx: create_tx,
            escrow: escrow_output_utxo,
            marker: marker_output_utxo,
            payer: maker_address.solana_address()?,
        }
        .sign(&maker.keypair, &maker.registry)
        .map_err(|e| anyhow!("escrow create sign: {e:?}"))?;

        let spp_proof = indexer
            .prove_transact(tree, signed_private_transaction.clone())
            .map_err(|e| anyhow!("create transact proof: {e:?}"))?;

        // Custom proof
        let first_input_utxo = signed_private_transaction
            .inputs
            .first()
            .ok_or_else(|| anyhow!("no create input"))?;
        let create_nullifier_pubkey = first_input_utxo
            .nullifier_key
            .pubkey()
            .map_err(|e| anyhow!("create nullifier pubkey: {e:?}"))?;
        let source_input_hash = first_input_utxo
            .utxo
            .hash(
                &create_nullifier_pubkey,
                &first_input_utxo.data_hash.unwrap_or([0u8; 32]),
                &first_input_utxo.zone_data_hash.unwrap_or([0u8; 32]),
            )
            .map_err(|e| anyhow!("source input hash: {e:?}"))?;
        let change_output_utxo = signed_private_transaction
            .outputs
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("no create change output"))?;
        let external_data_hash = signed_private_transaction
            .external_data
            .hash()
            .map_err(|e| anyhow!("create external data hash: {e:?}"))?;

        let create_swap_proof_inputs = CreateSwapProofInputs {
            escrow,
            taker_address,
            source_input_hash,
            change_output_utxo,
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
        let maker_address = maker.keypair.shielded_address()?;

        // The maker rediscovers her own order from the chain instead of retaining
        // the opening in memory: the create transaction's sender bundle plus the
        // re-derived per-transaction viewing key decrypt the taker-addressed
        // escrow slot from the sender side.
        let order = discover_own_orders(&mut maker, &indexer, Duration::from_secs(60))?
            .pop()
            .ok_or_else(|| anyhow!("no own swap order discovered"))?;
        let escrow = order.escrow;
        let taker_viewing_pk = order.taker_viewing_pk;

        let source_output_blinding = random_blinding();
        let cancel_inputs = CancelSharedInputs {
            escrow: escrow.clone(),
            taker_viewing_pk,
            source_output_blinding,
            external_data_hash: [0u8; 32],
            maker_recipient: maker_address,
        };
        let source_output = cancel_inputs.source_output();
        let source_output_hash = source_output
            .hash()
            .map_err(|e| anyhow!("source output hash: {e:?}"))?;

        let escrow_input = escrow
            .into_input_utxo()
            .map_err(|e| anyhow!("escrow spend: {e:?}"))?;

        let cancel_tx = TxBuilder::new(
            maker_address,
            vec![escrow_input],
            maker_address.solana_address()?,
        )
        .with_expiry(SPP_RELAYER_DEADLINE);

        let cancel_signed = EscrowCancel {
            tx: cancel_tx,
            source_output,
        }
        .sign(&maker.keypair, &maker.registry)
        .map_err(|e| anyhow!("escrow cancel sign: {e:?}"))?;

        let cancel_external_data_hash = cancel_signed
            .external_data
            .hash()
            .map_err(|e| anyhow!("cancel external data hash: {e:?}"))?;

        let cancel_inputs = CancelSharedInputs {
            external_data_hash: cancel_external_data_hash,
            ..cancel_inputs
        };

        let spp_proof = indexer
            .prove_transact(tree, cancel_signed)
            .map_err(|e| anyhow!("cancel transact proof: {e:?}"))?;

        let cancel_proof = swap_prover_client
            .prove_cancel(&cancel_inputs)
            .map_err(|e| anyhow!("cancel proof: {e:?}"))?;

        let cancel_ix = Cancel {
            maker: maker_address.solana_address()?,
            payer: maker_address.solana_address()?,
            tree,
            cancel_proof: cancel_proof.proof.into(),
            order_expiry: escrow.terms.expiry,
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
