mod shared;

use anyhow::{anyhow, bail, Result};
use dynamic_swap_program::state::{Escrow, Pair};
use dynamic_swap_sdk::{
    escrow_pda,
    instructions::{
        cancel::{Cancel, CancelProofInputParams},
        create_escrow::{CreateEscrow, EscrowOpenProofInputParams},
        settle::{cancel_blinding_seed, Settle},
    },
    prover::DynamicSwapProverClient,
    shared::transaction_blindings,
    state::{escrow_authority_address, escrow_nullifier_key, EscrowUtxo},
    Groth16ProofBytes,
};
use shared::{
    assert_liquidity, deposit_pool_liquidity, get_slot_with_retry, send, setup_with_pair,
    wait_for_slot, wait_until, MIN_ORDER_AMOUNT, PRICE_TOLERANCE,
};
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_keypair::random_blinding;
use zolana_test_utils::utxo::{
    encrypt_transaction_data, get_transaction_viewing_key, prepare_output_blindings,
};
use zolana_transaction::{
    instructions::transact::{asset_field, ExternalData, SppProofInputs, SppProofOutputUtxo},
    utxo::SppProofInputUtxo,
};
use zolana_wallet::{sync_wallet, Filter, Wallet};

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
    let (env, pair) = setup_with_pair(6, PRICE, EXPIRY_SLOTS, MAX_ORDER_SIZE)?;
    let tree_id = env.localnet.tree_id;
    let authority_solana = &env.authority.keypair;
    let user_solana = &env.user.keypair;
    let prover = DynamicSwapProverClient::new();

    // The escrow's reservation must be covered by committed liquidity.
    deposit_pool_liquidity(&env, pair, POOL_DEPOSIT)?;

    let recipient_owner_hash = env
        .user
        .owner_hash()
        .map_err(|e| anyhow!("user owner hash: {e:?}"))?;

    // 1. create_escrow (taker-only). The taker keeps the order UTXO data (the
    // SPP-derived blinding, amount) -- a cancel needs no discovery.
    let maker_encryption_pubkey = {
        let pair_account = env
            .localnet
            .client
            .rpc()
            .get_account(pair)
            .map_err(|e| anyhow!("get pair account: {e:?}"))?
            .ok_or_else(|| anyhow!("pair account not found"))?;
        bytemuck::from_bytes::<Pair>(&pair_account.data).maker_encryption_pubkey
    };
    let escrow_authority = escrow_authority_address(&pair, &maker_encryption_pubkey)
        .map_err(|e| anyhow!("escrow authority address: {e:?}"))?;

    let mut escrow_utxo = EscrowUtxo {
        recipient_owner_hash,
        asset: env.source_mint(),
        order_amount: ORDER_AMOUNT,
        min_price: PRICE,
        blinding: random_blinding(),
    };
    let (escrow, escrow_state) = {
        let mut user_wallet = Wallet::new(env.user.address()?, env.assets.clone())
            .map_err(|e| anyhow!("user wallet: {e:?}"))?;
        let funding_utxo = wait_until("funding note", || {
            sync_wallet(
                &mut user_wallet,
                &env.user.keypair,
                env.localnet.client.indexer(),
            )
            .map_err(|e| anyhow!("sync user wallet: {e:?}"))?;
            Ok(user_wallet
                .balance(env.spl_mint, Some(Filter::MinAmount(ORDER_AMOUNT)))
                .map_err(|e| anyhow!("user balance: {e:?}"))?
                .utxos
                .first()
                .cloned())
        })?;

        let source_in = SppProofInputUtxo::from(funding_utxo.clone());
        let change_amount = funding_utxo
            .utxo
            .amount
            .checked_sub(ORDER_AMOUNT)
            .ok_or_else(|| anyhow!("order_amount exceeds the taker's funding UTXO"))?;
        let input_utxos = vec![source_in.clone()];
        // SPP derives both output blindings from the transaction's seed; the
        // taker keeps the order's for the cancel below.
        let mut transaction_outputs = vec![
            escrow_utxo
                .output_utxo(&escrow_authority)
                .map_err(|e| anyhow!("order_out: {e:?}"))?,
            SppProofOutputUtxo::new(env.source_mint(), change_amount, env.user.address()?)
                .map_err(|e| anyhow!("taker_change: {e:?}"))?,
        ];
        let blinding_seed = prepare_output_blindings(&input_utxos, &mut transaction_outputs)?;
        let [order_out, taker_change]: [_; 2] = transaction_outputs
            .try_into()
            .map_err(|_| anyhow!("create_escrow transaction must have two outputs"))?;
        escrow_utxo.blinding = order_out.blinding;
        let order_utxo_hash = order_out
            .hash(tree_id)
            .map_err(|e| anyhow!("order_utxo hash: {e:?}"))?;

        let viewing_key = get_transaction_viewing_key(&env.user.keypair, &input_utxos)
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
        let encoded = encrypt_transaction_data(
            &[order_out.clone(), taker_change.clone()],
            &viewing_key,
            tree_id,
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
        // The escrow authority owns the data-bearing order output without
        // spending an input, so it is an owner signer (the program's CPI flips
        // its account).
        let spp_proof_inputs = SppProofInputs {
            input_utxos,
            output_utxos: encoded.output_utxos,
            external_data,
            payer: user_solana.pubkey(),
            blinding_seed,
            output_tree_id: tree_id,
        };
        let private_tx_blinding = spp_proof_inputs
            .private_tx_blinding()
            .map_err(|e| anyhow!("private tx blinding: {e:?}"))?;
        let transact = env
            .localnet
            .client
            .indexer()
            .prove_transact(spp_proof_inputs, &env.user.keypair)
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
            private_tx_blinding,
            output_tree_id: tree_id,
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
            tree: env.localnet.tree,
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
        send(env.localnet.client.rpc(), user_solana, &[], ix)
            .map_err(|e| anyhow!("send create_escrow: {e:?}"))?;

        let escrow_account = env
            .localnet
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
            .to_input_utxo(
                &escrow_authority,
                tree_id,
                env.leaf_index(escrow_state.order_utxo_hash),
            )
            .map_err(|e| anyhow!("order_in: {e:?}"))?;
        // The refund blinding derives from the order opening and the order's
        // nullifier (input 0), so the taker recomputes the refund note.
        let blinding_seed = cancel_blinding_seed(&order_in.utxo.blinding)?;
        let (private_tx_blinding, blindings) =
            transaction_blindings(&order_in.nullifier(), &blinding_seed, 1)?;
        let mut refund_out =
            SppProofOutputUtxo::new(env.source_mint(), ORDER_AMOUNT, env.user.address()?)
                .map_err(|e| anyhow!("refund_out: {e:?}"))?;
        refund_out.blinding = blindings
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("cancel derives a refund blinding"))?;
        let refund_out_hash = refund_out
            .hash(tree_id)
            .map_err(|e| anyhow!("refund_out hash: {e:?}"))?;

        let input_utxos = vec![order_in.clone()];
        let viewing_key = get_transaction_viewing_key(&env.user.keypair, &input_utxos)
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
        let encoded =
            encrypt_transaction_data(std::slice::from_ref(&refund_out), &viewing_key, tree_id)
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
        let spp_proof_inputs = SppProofInputs {
            input_utxos,
            output_utxos: encoded.output_utxos,
            external_data,
            payer: user_solana.pubkey(),
            blinding_seed,
            output_tree_id: tree_id,
        };
        let transact = env
            .localnet
            .client
            .indexer()
            .prove_transact(spp_proof_inputs, &escrow_nullifier_key())
            .map_err(|e| anyhow!("prove_transact: {e:?}"))?;

        let proof_inputs = CancelProofInputParams {
            order_in,
            refund_out,
            order_amount: ORDER_AMOUNT,
            recipient_owner_hash,
            min_price: PRICE,
            order_utxo_hash: escrow_state.order_utxo_hash,
            external_data_hash,
            private_tx_blinding,
            output_tree_id: tree_id,
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
            tree: env.localnet.tree,
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

    // The pre-expiry probe must actually be pre-expiry: proving latency is
    // bounded by EXPIRY_SLOTS by construction, but assert it rather than let a
    // slow machine turn the NotYetExpired probe into a flake.
    let now = get_slot_with_retry(env.localnet.client.rpc().client())?;
    let expires_at = escrow_state
        .created_at
        .checked_add(EXPIRY_SLOTS)
        .ok_or_else(|| anyhow!("expiry overflows"))?;
    if now > expires_at {
        bail!("cancel proof took longer than the expiry window; raise EXPIRY_SLOTS");
    }

    // Cancel before expiry is rejected by the program-side gate.
    let err = send(
        env.localnet.client.rpc(),
        user_solana,
        &[],
        cancel_ix.clone(),
    )
    .expect_err("cancel before expiry must fail");
    assert_custom_error("cancel before expiry", &anyhow!("{err:?}"), 9001);

    // 3. Cross the expiry boundary.
    wait_for_slot(env.localnet.client.rpc().client(), expires_at)?;

    // 4. Settle after expiry is rejected by the program-side gate, which runs
    // before proof verification -- a garbage proof and any well-formed transact
    // payload reach it.
    let settle_ix = Settle {
        authority: authority_solana.pubkey(),
        pair,
        escrow,
        rent_recipient: user_solana.pubkey(),
        tree: env.localnet.tree,
        proof: Groth16ProofBytes {
            proof_a: [0u8; 32],
            proof_b: [0u8; 64],
            proof_c: [0u8; 32],
        },
        transact: probe_transact,
    }
    .instruction()
    .map_err(|e| anyhow!("settle instruction: {e:?}"))?;
    let err = send(env.localnet.client.rpc(), authority_solana, &[], settle_ix)
        .expect_err("settle after expiry must fail");
    assert_custom_error("settle after expiry", &anyhow!("{err:?}"), 9000);

    // 5. The same cancel payload now succeeds: gates are program-side, so the
    // pre-expiry proof stays valid.
    send(env.localnet.client.rpc(), user_solana, &[], cancel_ix)
        .map_err(|e| anyhow!("send cancel: {e:?}"))?;

    // The refund landed as a real UTXO in the pool tree.
    env.leaf_index(refund_out_hash);
    // And the taker's wallet rediscovers the refunded amount.
    let mut user_wallet = Wallet::new(env.user.address()?, env.assets.clone())
        .map_err(|e| anyhow!("user wallet: {e:?}"))?;
    wait_until("refund note", || {
        sync_wallet(
            &mut user_wallet,
            &env.user.keypair,
            env.localnet.client.indexer(),
        )
        .map_err(|e| anyhow!("sync user wallet: {e:?}"))?;
        Ok(user_wallet
            .balance(env.spl_mint, Some(Filter::MinAmount(ORDER_AMOUNT)))
            .map_err(|e| anyhow!("user balance after cancel: {e:?}"))?
            .utxos
            .into_iter()
            .find(|utxo| utxo.utxo.amount == ORDER_AMOUNT))
    })?;

    // Cancellation closes the escrow account and releases the reservation in
    // full: the exact MAX_ORDER_SIZE taken at create_escrow returns to the
    // bound.
    assert!(
        env.localnet
            .client
            .rpc()
            .get_account(escrow)
            .map_err(|e| anyhow!("get escrow account after cancel: {e:?}"))?
            .is_none(),
        "escrow account must be closed after cancel"
    );
    assert_liquidity(&env, pair, POOL_DEPOSIT, 0, "after cancel")?;

    Ok(())
}
