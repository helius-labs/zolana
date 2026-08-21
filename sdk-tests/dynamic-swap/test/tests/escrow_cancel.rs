mod shared;

use anyhow::{anyhow, bail, Result};
use dynamic_swap_program::state::{Escrow, Pair};
use dynamic_swap_sdk::{
    escrow_pda,
    instructions::{
        cancel::{Cancel, CancelProofInputParams},
        create_escrow::{CreateEscrow, EscrowOpenProofInputParams},
        settle::{derive_output_blinding, Settle, CANCEL_REFUND_BLINDING_DOMAIN},
    },
    prover::DynamicSwapProverClient,
    state::{escrow_authority_address, EscrowUtxo},
    Groth16ProofBytes,
};
use shared::{
    assert_liquidity, deposit_pool_liquidity, get_slot_with_retry, setup_with_pair, wait_for_slot,
    MIN_ORDER_AMOUNT, PRICE_TOLERANCE,
};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_keypair::random_blinding;
use zolana_transaction::{
    instructions::transact::{
        encrypt_transaction_data, get_transaction_viewing_key, spp_proof_inputs::asset_field,
        ExternalData, SppProofInputs, SppProofOutputUtxo,
    },
    instructions::types::SppProofInputUtxo,
    Filter, Wallet,
};
use zolana_wallet::sync_wallet;

const PRICE: u64 = 5;
const ORDER_AMOUNT: u64 = 100_000_000;
const MAX_ORDER_SIZE: u64 = 600_000_000;
const POOL_DEPOSIT: u64 = 1_000_000_000;
/// Small enough that the test crosses expiry in under two minutes of real slot
/// progression, wide enough that building the cancel proof (~15-40s of key
/// loading + in-process proving) finishes before it -- the NotYetExpired probe
/// sends the real, already-built cancel payload pre-expiry.
const EXPIRY_SLOTS: u64 = 200;

/// The failure surface is delimited (`Custom({code})`) or hex (`0x{code:x}`)
/// depending on which RPC layer reports it; accept both.
fn assert_custom_error(context: &str, err: &anyhow::Error, code: u32) {
    let message = format!("{err:?}");
    let delimited = format!("Custom({code})");
    let hex = format!("{code:#x}");
    assert!(
        message.contains(&delimited) || message.contains(&hex),
        "{context}: expected custom error {code}, got: {message}"
    );
}

// Cancel flow, plus both time-gate negatives (the gates are program-side and
// precede proof verification, so one escrow serves all three):
//   1. create_escrow at a small expiry window (taker-only, IN1_OUT2).
//   2. Build the real cancel payload, send it PRE-expiry -> NotYetExpired.
//   3. Wait past `created_at + expiry_slots`.
//   4. Probe settle POST-expiry (garbage proof; the gate rejects before
//      verification) -> Expired.
//   5. Send the same cancel payload again -> the full order amount returns to
//      the recipient in the source asset, the escrow account closes, rent goes
//      to the owner, and the refund note is wallet-discoverable by the taker.
#[test]
fn cancel_after_expiry() -> Result<()> {
    let (env, pair) = setup_with_pair(PRICE, EXPIRY_SLOTS, MAX_ORDER_SIZE)?;
    let authority_solana = &env.authority.keypair;
    let user_solana = &env.user.keypair;
    let prover = DynamicSwapProverClient::new();

    // The escrow's reservation must be covered by committed liquidity.
    deposit_pool_liquidity(&env, pair, POOL_DEPOSIT)?;

    let recipient_owner_hash = env
        .user
        .owner_hash()
        .map_err(|e| anyhow!("user owner hash: {e:?}"))?;

    // 1. create_escrow (taker-only). The taker keeps the order UTXO data it
    // chose (blinding, amount) -- a cancel needs no discovery.
    let maker_encryption_pubkey = {
        let pair_account = env
            .client
            .rpc()
            .get_account(pair)
            .map_err(|e| anyhow!("get pair account: {e:?}"))?
            .ok_or_else(|| anyhow!("pair account not found"))?;
        bytemuck::from_bytes::<Pair>(&pair_account.data).maker_encryption_pubkey
    };
    let escrow_authority = escrow_authority_address(&pair, &maker_encryption_pubkey)
        .map_err(|e| anyhow!("escrow authority address: {e:?}"))?;

    let escrow_utxo = EscrowUtxo {
        recipient_owner_hash,
        asset: env.spl_mint,
        order_amount: ORDER_AMOUNT,
        min_price: PRICE,
        blinding: random_blinding(),
    };
    let (escrow, escrow_state) = {
        let mut user_wallet = Wallet::new(env.user.address()?, env.assets.clone())
            .map_err(|e| anyhow!("user wallet: {e:?}"))?;
        sync_wallet(&mut user_wallet, &env.user.keypair, env.client.indexer())
            .map_err(|e| anyhow!("sync user wallet: {e:?}"))?;
        let funding_utxo = user_wallet
            .balance(env.spl_mint, Some(Filter::MinAmount(ORDER_AMOUNT)))
            .map_err(|e| anyhow!("user balance: {e:?}"))?
            .utxos
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("no spendable utxo of {} >= {ORDER_AMOUNT}", env.spl_mint))?;

        let source_in = SppProofInputUtxo::new(funding_utxo.clone(), &env.user.keypair);
        let order_out = escrow_utxo
            .output_utxo(&escrow_authority)
            .map_err(|e| anyhow!("order_out: {e:?}"))?;
        let order_utxo_hash = order_out
            .hash()
            .map_err(|e| anyhow!("order_utxo hash: {e:?}"))?;
        let change_amount = funding_utxo
            .amount
            .checked_sub(ORDER_AMOUNT)
            .ok_or_else(|| anyhow!("order_amount exceeds the taker's funding UTXO"))?;
        let taker_change =
            SppProofOutputUtxo::new(env.spl_mint, change_amount, env.user.address()?)
                .map_err(|e| anyhow!("taker_change: {e:?}"))?;

        let input_utxos = vec![source_in.clone()];
        let viewing_key = get_transaction_viewing_key(&env.user.keypair, &input_utxos)
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
        let encoded = encrypt_transaction_data(
            &[order_out.clone(), taker_change.clone()],
            &env.assets,
            &viewing_key,
        )
        .map_err(|e| anyhow!("encode outputs: {e:?}"))?;
        let external_data = ExternalData::new(
            *viewing_key.pubkey().as_bytes(),
            encoded.salt,
            encoded.outputs,
            encoded.resolved_owner_tags,
            vec![],
        );
        let external_data_hash = external_data
            .hash()
            .map_err(|e| anyhow!("external data hash: {e:?}"))?;
        // The escrow authority owns the data-bearing order output but spends no
        // input, so it must be declared as the extra owner signer (the program's
        // CPI flips its account); the circuit requires a data-carrying output's
        // owner in the authorized signer set.
        let spp_proof_inputs = SppProofInputs::new(
            input_utxos,
            encoded.output_utxos,
            external_data,
            user_solana.pubkey(),
        )
        .with_owner_signer(
            escrow_authority
                .solana_address()
                .map_err(|e| anyhow!("escrow authority solana address: {e:?}"))?,
        );
        let transact = env
            .client
            .indexer()
            .prove_transact(env.tree, spp_proof_inputs)
            .map_err(|e| anyhow!("prove_transact: {e:?}"))?;

        let proof_inputs = EscrowOpenProofInputParams {
            source_in,
            order_out,
            taker_change,
            escrow_authority_owner_hash: escrow_authority
                .owner_hash()
                .map_err(|e| anyhow!("escrow authority owner hash: {e:?}"))?,
            source_asset: asset_field(&env.spl_mint).map_err(|e| anyhow!("source asset: {e:?}"))?,
            public_price_floor: PRICE - PRICE_TOLERANCE,
            price_tolerance: PRICE_TOLERANCE,
            min_order_amount: MIN_ORDER_AMOUNT,
            max_order_size: MAX_ORDER_SIZE,
            order_amount: ORDER_AMOUNT,
            min_price: PRICE,
            external_data_hash,
        }
        .to_proof_inputs()
        .map_err(|e| anyhow!("escrow_open proof inputs: {e:?}"))?;
        let order_proof = prover
            .prove_escrow_open(&proof_inputs)
            .map_err(|e| anyhow!("prove escrow_open: {e:?}"))?;

        let escrow = escrow_pda(&order_utxo_hash);
        let ix = CreateEscrow {
            taker: user_solana.pubkey(),
            pair,
            escrow,
            tree: env.tree,
            proof: Groth16ProofBytes {
                proof_a: order_proof.proof_a,
                proof_b: order_proof.proof_b,
                proof_c: order_proof.proof_c,
            },
            public_price_floor: PRICE - PRICE_TOLERANCE,
            transact,
        }
        .instruction()
        .map_err(|e| anyhow!("create_escrow instruction: {e:?}"))?;
        // create_escrow fits as a legacy transaction (see BENCHMARK.md).
        let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        env.client
            .rpc()
            .create_and_send_transaction(&[compute, ix], user_solana.pubkey(), &[&user_solana])
            .map_err(|e| anyhow!("send create_escrow: {e:?}"))?;

        let escrow_account = env
            .client
            .rpc()
            .get_account(escrow)
            .map_err(|e| anyhow!("get escrow account: {e:?}"))?
            .ok_or_else(|| anyhow!("escrow account not found"))?;
        let escrow_state: Escrow = *bytemuck::from_bytes::<Escrow>(&escrow_account.data);
        let escrow_bump = solana_pubkey::Pubkey::find_program_address(
            &[Escrow::SEED_PREFIX, &order_utxo_hash],
            &dynamic_swap_program::ID,
        )
        .1;
        let expected = Escrow {
            discriminator: dynamic_swap_program::state::discriminator::ESCROW,
            bump: escrow_bump,
            _pad: [0u8; 6],
            pair,
            order_utxo_hash,
            owner: user_solana.pubkey(),
            created_at: escrow_state.created_at,
            execution_price: PRICE,
        };
        assert_eq!(escrow_state, expected);
        // The reservation moved MAX_ORDER_SIZE out of the public bound.
        assert_liquidity(
            &env,
            pair,
            POOL_DEPOSIT - MAX_ORDER_SIZE,
            1,
            "after create_escrow",
        )?;
        (escrow, escrow_state)
    };

    // 2. Build the real cancel payload while the escrow is still live. The SPP
    // transact carries no expiry of its own for confidential transfers and the
    // program-side gates precede proof verification, so this exact payload is
    // probed pre-expiry (NotYetExpired) and replayed post-expiry (success).
    let (cancel_ix, refund_out_hash, probe_transact) = {
        let order_in = escrow_utxo
            .to_input_utxo(&escrow_authority)
            .map_err(|e| anyhow!("order_in: {e:?}"))?;
        let mut refund_out =
            SppProofOutputUtxo::new(env.spl_mint, ORDER_AMOUNT, env.user.address()?)
                .map_err(|e| anyhow!("refund_out: {e:?}"))?;
        refund_out.blinding =
            derive_output_blinding(&escrow_utxo.blinding, CANCEL_REFUND_BLINDING_DOMAIN)
                .map_err(|e| anyhow!("refund_out blinding: {e:?}"))?;
        let refund_out_hash = refund_out
            .hash()
            .map_err(|e| anyhow!("refund_out hash: {e:?}"))?;

        let input_utxos = vec![order_in.clone()];
        let viewing_key = get_transaction_viewing_key(&env.user.keypair, &input_utxos)
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
        let encoded = encrypt_transaction_data(&[refund_out.clone()], &env.assets, &viewing_key)
            .map_err(|e| anyhow!("encode outputs: {e:?}"))?;
        let external_data = ExternalData::new(
            *viewing_key.pubkey().as_bytes(),
            encoded.salt,
            encoded.outputs,
            encoded.resolved_owner_tags,
            vec![],
        );
        let external_data_hash = external_data
            .hash()
            .map_err(|e| anyhow!("external data hash: {e:?}"))?;
        let spp_proof_inputs = SppProofInputs::new(
            input_utxos,
            encoded.output_utxos,
            external_data,
            user_solana.pubkey(),
        );
        let transact = env
            .client
            .indexer()
            .prove_transact(env.tree, spp_proof_inputs)
            .map_err(|e| anyhow!("prove_transact: {e:?}"))?;

        let proof_inputs = CancelProofInputParams {
            order_in,
            refund_out,
            order_amount: ORDER_AMOUNT,
            recipient_owner_hash,
            min_price: PRICE,
            order_utxo_hash: escrow_state.order_utxo_hash,
            external_data_hash,
        }
        .to_proof_inputs()
        .map_err(|e| anyhow!("cancel proof inputs: {e:?}"))?;
        let cancel_proof = prover
            .prove_escrow_cancel(&proof_inputs)
            .map_err(|e| anyhow!("prove escrow_cancel: {e:?}"))?;

        let cancel_ix = Cancel {
            caller: user_solana.pubkey(),
            pair,
            escrow,
            rent_recipient: user_solana.pubkey(),
            tree: env.tree,
            proof: Groth16ProofBytes {
                proof_a: cancel_proof.proof_a,
                proof_b: cancel_proof.proof_b,
                proof_c: cancel_proof.proof_c,
            },
            transact: transact.clone(),
        }
        .instruction()
        .map_err(|e| anyhow!("cancel instruction: {e:?}"))?;
        (cancel_ix, refund_out_hash, transact)
    };
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);

    // The pre-expiry probe must actually be pre-expiry: proving latency is
    // bounded by EXPIRY_SLOTS by construction, but assert it rather than let a
    // slow machine turn the NotYetExpired probe into a flake.
    let now = get_slot_with_retry(env.client.rpc().client())?;
    let expires_at = escrow_state
        .created_at
        .checked_add(EXPIRY_SLOTS)
        .ok_or_else(|| anyhow!("expiry overflows"))?;
    if now > expires_at {
        bail!("cancel proof took longer than the expiry window; raise EXPIRY_SLOTS");
    }

    // Cancel before expiry is rejected by the program-side gate.
    let err = env
        .client
        .rpc()
        .create_and_send_transaction(
            &[compute.clone(), cancel_ix.clone()],
            user_solana.pubkey(),
            &[&user_solana],
        )
        .expect_err("cancel before expiry must fail");
    assert_custom_error("cancel before expiry", &anyhow!("{err:?}"), 9001);

    // 3. Cross the expiry boundary.
    wait_for_slot(env.client.rpc().client(), expires_at)?;

    // 4. Settle after expiry is rejected by the program-side gate, which runs
    // before proof verification -- a garbage proof and any well-formed transact
    // payload reach it.
    let settle_ix = Settle {
        authority: authority_solana.pubkey(),
        pair,
        escrow,
        rent_recipient: user_solana.pubkey(),
        tree: env.tree,
        proof: Groth16ProofBytes {
            proof_a: [0u8; 32],
            proof_b: [0u8; 64],
            proof_c: [0u8; 32],
        },
        transact: probe_transact,
    }
    .instruction()
    .map_err(|e| anyhow!("settle instruction: {e:?}"))?;
    let err = env
        .client
        .rpc()
        .create_and_send_transaction(
            &[compute.clone(), settle_ix],
            authority_solana.pubkey(),
            &[&authority_solana],
        )
        .expect_err("settle after expiry must fail");
    assert_custom_error("settle after expiry", &anyhow!("{err:?}"), 9000);

    // 5. The same cancel payload now succeeds: gates are program-side, so the
    // pre-expiry proof stays valid.
    env.client
        .rpc()
        .create_and_send_transaction(&[compute, cancel_ix], user_solana.pubkey(), &[&user_solana])
        .map_err(|e| anyhow!("send cancel: {e:?}"))?;

    // The refund landed as a real UTXO in the pool tree.
    let response = env
        .client
        .indexer()
        .get_merkle_proofs(env.tree, vec![refund_out_hash], None)
        .map_err(|e| anyhow!("get merkle proofs: {e:?}"))?;
    if response.proofs.len() != 1 {
        bail!(
            "expected the refund leaf to be indexed, indexer returned {} proofs",
            response.proofs.len()
        );
    }
    // And the taker's wallet rediscovers the refunded amount.
    let mut user_wallet = Wallet::new(env.user.address()?, env.assets.clone())
        .map_err(|e| anyhow!("user wallet: {e:?}"))?;
    sync_wallet(&mut user_wallet, &env.user.keypair, env.client.indexer())
        .map_err(|e| anyhow!("sync user wallet: {e:?}"))?;
    user_wallet
        .balance(env.spl_mint, Some(Filter::MinAmount(ORDER_AMOUNT)))
        .map_err(|e| anyhow!("user balance after cancel: {e:?}"))?
        .utxos
        .into_iter()
        .find(|utxo| utxo.amount == ORDER_AMOUNT)
        .ok_or_else(|| anyhow!("refund note not discovered after cancel"))?;

    // Cancellation closes the escrow account and releases the reservation in
    // full: the exact MAX_ORDER_SIZE taken at create_escrow returns to the
    // bound.
    assert!(
        env.client
            .rpc()
            .get_account(escrow)
            .map_err(|e| anyhow!("get escrow account after cancel: {e:?}"))?
            .is_none(),
        "escrow account must be closed after cancel"
    );
    assert_liquidity(&env, pair, POOL_DEPOSIT, 0, "after cancel")?;

    Ok(())
}
