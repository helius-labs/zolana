mod shared;

use anyhow::{anyhow, bail, Result};
use dynamic_swap_program::state::Escrow;
use dynamic_swap_sdk::{
    escrow_pda,
    instructions::{
        cancel::{Cancel, CancelProofInputParams},
        create_escrow::{CreateEscrow, EscrowOpenProofInputParams},
        settle::{cancel_blinding_seed, Settle},
        skip_expired::SkipExpired,
    },
    prover::DynamicSwapProverClient,
    shared::{pad_spp_outputs, transaction_blindings},
    state::{escrow_authority_address, escrow_nullifier_key, EscrowUtxo},
    Groth16ProofBytes,
};
use shared::{
    assert_liquidity, deposit_pool_liquidity, get_slot_with_retry, read_pair, send,
    setup_with_pair, wait_for_slot, wait_until, TestEnv, MIN_ORDER_AMOUNT, PRICE_TOLERANCE,
};
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_keypair::{random_blinding, ShieldedAddress};
use zolana_test_utils::utxo::{
    encrypt_transaction_data, get_transaction_viewing_key, prepare_output_blindings,
};
use zolana_test_utils::wallet::{sync_wallet, Filter, Wallet};
use zolana_transaction::{
    instructions::transact::{asset_field, ExternalData, SppProofInputs, SppProofOutputUtxo},
    utxo::SppProofInputUtxo,
};

const PRICE: u64 = 5;
const ORDER_AMOUNT: u64 = 100_000_000;
const MAX_ORDER_SIZE: u64 = 600_000_000;
/// Covers both orders' reservations.
const POOL_DEPOSIT: u64 = 2 * MAX_ORDER_SIZE;
/// Small enough that the test crosses expiry quickly, wide enough that the
/// second order and both cancel proofs (in-process proving) are built before
/// the first order expires -- the pre-expiry probes need a live queue head.
const EXPIRY_SLOTS: u64 = 500;

const EXPIRED: u32 = 9000;
const NOT_YET_EXPIRED: u32 = 9001;
const NOT_QUEUE_HEAD: u32 = 9032;
const ESCROW_CANCELLED: u32 = 9033;

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

fn garbage_proof() -> Groth16ProofBytes {
    Groth16ProofBytes {
        proof_a: [0u8; 32],
        proof_b: [0u8; 64],
        proof_c: [0u8; 32],
    }
}

struct QueueCx<'a> {
    env: &'a TestEnv,
    pair: Pubkey,
    escrow_authority: ShieldedAddress,
    recipient_owner_hash: [u8; 32],
    prover: DynamicSwapProverClient,
}

/// An order the taker created. The taker keeps the order UTXO data (the
/// SPP-derived blinding, amount), so a cancel needs no discovery.
struct Order {
    escrow: Pubkey,
    state: Escrow,
    utxo: EscrowUtxo,
    /// The taker note this order spent, so the next order funds from another.
    funding_hash: [u8; 32],
}

impl Order {
    fn expires_at(&self) -> Result<u64> {
        self.state
            .created_at
            .checked_add(EXPIRY_SLOTS)
            .ok_or_else(|| anyhow!("expiry overflows"))
    }
}

/// A cancel built while the order is live. The SPP transact carries no expiry
/// of its own and the program-side gates precede proof verification, so the
/// same payload is probed pre-expiry and replayed post-expiry.
struct CancelPayload {
    ix: Instruction,
    refund_out_hash: [u8; 32],
    transact: TransactIxData,
}

/// create_escrow (taker-only) at queue position `order_id`, funded by any
/// taker note other than `spent`.
fn create_order(cx: &QueueCx, order_id: u64, spent: Option<[u8; 32]>) -> Result<Order> {
    let env = cx.env;
    let tree_id = env.localnet.tree_id;
    let user_solana = &env.user.keypair;
    let mut utxo = EscrowUtxo {
        recipient_owner_hash: cx.recipient_owner_hash,
        asset: env.source_mint(),
        order_amount: ORDER_AMOUNT,
        min_price: PRICE,
        blinding: random_blinding(),
    };

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
            .into_iter()
            .find(|note| Some(note.utxo_hash) != spent))
    })?;

    let source_in = SppProofInputUtxo::from(funding_utxo.clone());
    let funding_hash = source_in.utxo_hash;
    let change_amount = funding_utxo
        .utxo
        .amount
        .checked_sub(ORDER_AMOUNT)
        .ok_or_else(|| anyhow!("order_amount exceeds the taker's funding UTXO"))?;
    let input_utxos = vec![source_in.clone()];
    // SPP derives both output blindings from the transaction's seed; the taker
    // keeps the order's for the cancel.
    let mut transaction_outputs = vec![
        utxo.output_utxo(&cx.escrow_authority)
            .map_err(|e| anyhow!("order_out: {e:?}"))?,
        SppProofOutputUtxo::new(env.source_mint(), change_amount, env.user.address()?)
            .map_err(|e| anyhow!("taker_change: {e:?}"))?,
    ];
    let blinding_seed = prepare_output_blindings(&input_utxos, &mut transaction_outputs)?;
    let [order_out, taker_change]: [_; 2] = transaction_outputs
        .try_into()
        .map_err(|_| anyhow!("create_escrow transaction must have two outputs"))?;
    utxo.blinding = order_out.blinding;
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
    // The escrow authority owns the data-bearing order output without spending
    // an input, so it is an owner signer (the program's CPI flips its account).
    let spp_proof_inputs = pad_spp_outputs(SppProofInputs {
        input_utxos,
        output_utxos: encoded.output_utxos,
        external_data,
        payer: user_solana.pubkey(),
        blinding_seed,
        output_tree_id: tree_id,
        cache_accounts: Default::default(),
    })?;
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
        escrow_authority_owner_hash: cx
            .escrow_authority
            .owner_hash()
            .map_err(|e| anyhow!("escrow authority owner hash: {e:?}"))?,
        source_asset: asset_field(&env.spl_mint).map_err(|e| anyhow!("source asset: {e:?}"))?,
        public_price_floor: PRICE - PRICE_TOLERANCE,
        price_tolerance: PRICE_TOLERANCE,
        min_order_amount: MIN_ORDER_AMOUNT,
        max_order_size: MAX_ORDER_SIZE,
        order_amount: ORDER_AMOUNT,
        min_price: PRICE,
        private_tx_blinding,
        output_tree_id: tree_id,
    }
    .to_proof_inputs()
    .map_err(|e| anyhow!("escrow_open proof inputs: {e:?}"))?;
    let order_proof = cx
        .prover
        .prove_escrow_open(&proof_inputs)
        .map_err(|e| anyhow!("prove escrow_open: {e:?}"))?;

    let escrow = escrow_pda(&cx.pair, order_id);
    let ix = CreateEscrow {
        taker: user_solana.pubkey(),
        pair: cx.pair,
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

    let state = read_escrow(env, escrow)?.ok_or_else(|| anyhow!("escrow account not found"))?;
    let escrow_bump = Pubkey::find_program_address(
        &[
            Escrow::SEED_PREFIX,
            cx.pair.as_ref(),
            &order_id.to_le_bytes(),
        ],
        &dynamic_swap_program::ID,
    )
    .1;
    let expected = Escrow {
        discriminator: dynamic_swap_program::state::discriminator::ESCROW,
        bump: escrow_bump,
        cancelled: 0,
        _pad: [0u8; 5],
        pair: cx.pair,
        order_utxo_hash,
        owner: user_solana.pubkey(),
        created_at: state.created_at,
        execution_price: PRICE,
        order_id,
    };
    assert_eq!(state, expected);
    Ok(Order {
        escrow,
        state,
        utxo,
        funding_hash,
    })
}

/// Build the real cancel payload for `order` (refund to the taker).
fn build_cancel(cx: &QueueCx, order: &Order) -> Result<CancelPayload> {
    let env = cx.env;
    let tree_id = env.localnet.tree_id;
    let user_solana = &env.user.keypair;
    let order_in = order
        .utxo
        .to_input_utxo(
            &cx.escrow_authority,
            tree_id,
            env.leaf_index(order.state.order_utxo_hash),
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
    let spp_proof_inputs = pad_spp_outputs(SppProofInputs {
        input_utxos,
        output_utxos: encoded.output_utxos,
        external_data,
        payer: user_solana.pubkey(),
        blinding_seed,
        output_tree_id: tree_id,
        cache_accounts: Default::default(),
    })?;
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
        recipient_owner_hash: cx.recipient_owner_hash,
        min_price: PRICE,
        order_utxo_hash: order.state.order_utxo_hash,
        private_tx_blinding,
        output_tree_id: tree_id,
    }
    .to_proof_inputs()
    .map_err(|e| anyhow!("cancel proof inputs: {e:?}"))?;
    let cancel_proof = cx
        .prover
        .prove_escrow_cancel(&proof_inputs)
        .map_err(|e| anyhow!("prove escrow_cancel: {e:?}"))?;

    let ix = cancel_ix(
        cx,
        order,
        Groth16ProofBytes {
            proof_a: cancel_proof.proof_a,
            proof_b: cancel_proof.proof_b,
            proof_c: cancel_proof.proof_c,
        },
        transact.clone(),
    )?;
    Ok(CancelPayload {
        ix,
        refund_out_hash,
        transact,
    })
}

fn cancel_ix(
    cx: &QueueCx,
    order: &Order,
    proof: Groth16ProofBytes,
    transact: TransactIxData,
) -> Result<Instruction> {
    let user_solana = &cx.env.user.keypair;
    Cancel {
        caller: user_solana.pubkey(),
        pair: cx.pair,
        escrow: order.escrow,
        rent_recipient: user_solana.pubkey(),
        tree: cx.env.localnet.tree,
        proof,
        transact,
    }
    .instruction()
    .map_err(|e| anyhow!("cancel instruction: {e:?}"))
}

/// A settle attempt by the maker. The FIFO, cancellation, and window gates run
/// before proof verification, so a garbage proof and any well-formed transact
/// payload reach them.
fn settle_probe(cx: &QueueCx, order: &Order, transact: TransactIxData) -> Result<Instruction> {
    Settle {
        authority: cx.env.authority.keypair.pubkey(),
        pair: cx.pair,
        escrow: order.escrow,
        rent_recipient: cx.env.user.keypair.pubkey(),
        tree: cx.env.localnet.tree,
        proof: garbage_proof(),
        transact,
    }
    .instruction()
    .map_err(|e| anyhow!("settle instruction: {e:?}"))
}

fn skip_ix(cx: &QueueCx, order: &Order) -> Instruction {
    SkipExpired {
        pair: cx.pair,
        escrow: order.escrow,
        rent_recipient: cx.env.user.keypair.pubkey(),
    }
    .instruction()
}

fn read_escrow(env: &TestEnv, escrow: Pubkey) -> Result<Option<Escrow>> {
    Ok(env
        .localnet
        .client
        .rpc()
        .get_account(escrow)
        .map_err(|e| anyhow!("get escrow account: {e:?}"))?
        .map(|account| *bytemuck::from_bytes::<Escrow>(&account.data)))
}

fn assert_queue(env: &TestEnv, pair: Pubkey, next: u64, head: u64, context: &str) -> Result<()> {
    let state = read_pair(env, pair)?;
    assert_eq!(
        (state.next_order_id, state.head_order_id),
        (next, head),
        "{context}: (next_order_id, head_order_id)"
    );
    Ok(())
}

// FIFO queue, cancel, and skip flow over two orders A (id 0) and B (id 1). The
// gates are program-side and precede proof verification, so the probes reuse
// real or garbage payloads:
//   1. create A then B at a small expiry window (taker-only, IN1_OUT2).
//   2. Build both real cancel payloads while the orders are live.
//   3. Pre-expiry: settle B -> NotQueueHead (A is the head), skip A ->
//      NotYetExpired, cancel A -> NotYetExpired.
//   4. Wait past B's expiry (B expires after A).
//   5. Settle A post-expiry -> Expired.
//   6. Cancel B ahead of the head: B is refunded and its reservation released,
//      but its account stays as a cancellation marker. A second cancel ->
//      EscrowCancelled.
//   7. Skip B -> NotQueueHead. Skip A (open, expired) -> the head moves to B
//      and A stays open for its refund. Skip B (marker) -> the marker closes
//      and the head moves past it.
//   8. Cancel A behind the head -> A is refunded and closes. Both refunds are
//      wallet-discoverable by the taker and the pool returns to its deposit.
#[test]
fn queue_cancel_and_skip_after_expiry() -> Result<()> {
    let (env, pair) = setup_with_pair(6, PRICE, EXPIRY_SLOTS, MAX_ORDER_SIZE)?;
    let authority_solana = &env.authority.keypair;
    let user_solana = &env.user.keypair;

    // Both escrows' reservations must be covered by committed liquidity.
    deposit_pool_liquidity(&env, pair, POOL_DEPOSIT)?;

    let maker_encryption_pubkey = read_pair(&env, pair)?.maker_encryption_pubkey;
    let cx = QueueCx {
        env: &env,
        pair,
        escrow_authority: escrow_authority_address(&pair, &maker_encryption_pubkey)
            .map_err(|e| anyhow!("escrow authority address: {e:?}"))?,
        recipient_owner_hash: env
            .user
            .owner_hash()
            .map_err(|e| anyhow!("user owner hash: {e:?}"))?,
        prover: DynamicSwapProverClient::new(),
    };

    // 1. Two orders join the queue in creation order.
    assert_queue(&env, pair, 0, 0, "before create_escrow")?;
    let order_a = create_order(&cx, 0, None)?;
    let order_b = create_order(&cx, 1, Some(order_a.funding_hash))?;
    assert_queue(&env, pair, 2, 0, "after create_escrow")?;
    assert_liquidity(
        &env,
        pair,
        POOL_DEPOSIT - 2 * MAX_ORDER_SIZE,
        2,
        "after create_escrow",
    )?;

    // 2. Both refunds, built while the orders are live.
    let cancel_a = build_cancel(&cx, &order_a)?;
    let cancel_b = build_cancel(&cx, &order_b)?;

    // 3. The pre-expiry probes must actually run before A expires: proving
    // latency is bounded by EXPIRY_SLOTS by construction, but assert it rather
    // than let a slow machine turn a probe into a flake.
    let now = get_slot_with_retry(env.localnet.client.rpc().client())?;
    if now > order_a.expires_at()? {
        bail!("building the orders took longer than the expiry window; raise EXPIRY_SLOTS");
    }
    let err = send(
        env.localnet.client.rpc(),
        authority_solana,
        &[],
        settle_probe(&cx, &order_b, cancel_b.transact.clone())?,
    )
    .expect_err("settling behind the queue head must fail");
    assert_custom_error("settle B before A", &anyhow!("{err:?}"), NOT_QUEUE_HEAD);
    let err = send(
        env.localnet.client.rpc(),
        user_solana,
        &[],
        skip_ix(&cx, &order_a),
    )
    .expect_err("skipping a live head must fail");
    assert_custom_error("skip A before expiry", &anyhow!("{err:?}"), NOT_YET_EXPIRED);
    let err = send(
        env.localnet.client.rpc(),
        user_solana,
        &[],
        cancel_a.ix.clone(),
    )
    .expect_err("cancel before expiry must fail");
    assert_custom_error(
        "cancel A before expiry",
        &anyhow!("{err:?}"),
        NOT_YET_EXPIRED,
    );

    // 4. Cross both expiry boundaries.
    wait_for_slot(env.localnet.client.rpc().client(), order_b.expires_at()?)?;

    // 5. The head can no longer settle.
    let err = send(
        env.localnet.client.rpc(),
        authority_solana,
        &[],
        settle_probe(&cx, &order_a, cancel_a.transact.clone())?,
    )
    .expect_err("settle after expiry must fail");
    assert_custom_error("settle A after expiry", &anyhow!("{err:?}"), EXPIRED);

    // 6. Cancel B ahead of the head: refunded, reservation released, account
    // kept as a cancellation marker until the head passes it.
    send(env.localnet.client.rpc(), user_solana, &[], cancel_b.ix)
        .map_err(|e| anyhow!("send cancel B: {e:?}"))?;
    env.leaf_index(cancel_b.refund_out_hash);
    let marker = read_escrow(&env, order_b.escrow)?
        .ok_or_else(|| anyhow!("a cancel ahead of the head must keep its account"))?;
    assert_eq!(
        marker,
        Escrow {
            cancelled: 1,
            ..order_b.state
        }
    );
    assert_liquidity(
        &env,
        pair,
        POOL_DEPOSIT - MAX_ORDER_SIZE,
        1,
        "after cancel B",
    )?;
    let err = send(
        env.localnet.client.rpc(),
        user_solana,
        &[],
        cancel_ix(&cx, &order_b, garbage_proof(), cancel_b.transact)?,
    )
    .expect_err("cancelling a marker must fail");
    assert_custom_error("cancel B twice", &anyhow!("{err:?}"), ESCROW_CANCELLED);

    // 7. The queue advances one position at a time, from the head.
    let err = send(
        env.localnet.client.rpc(),
        user_solana,
        &[],
        skip_ix(&cx, &order_b),
    )
    .expect_err("skipping behind the queue head must fail");
    assert_custom_error("skip B before A", &anyhow!("{err:?}"), NOT_QUEUE_HEAD);

    send(
        env.localnet.client.rpc(),
        user_solana,
        &[],
        skip_ix(&cx, &order_a),
    )
    .map_err(|e| anyhow!("send skip A: {e:?}"))?;
    assert_queue(&env, pair, 2, 1, "after skip A")?;
    assert_eq!(
        read_escrow(&env, order_a.escrow)?,
        Some(order_a.state),
        "a skipped open order stays open for its refund"
    );

    send(
        env.localnet.client.rpc(),
        user_solana,
        &[],
        skip_ix(&cx, &order_b),
    )
    .map_err(|e| anyhow!("send skip B: {e:?}"))?;
    assert_queue(&env, pair, 2, 2, "after skip B")?;
    assert!(
        read_escrow(&env, order_b.escrow)?.is_none(),
        "skipping a cancellation marker must close it"
    );

    // 8. Cancel A behind the head: refunded and closed.
    send(env.localnet.client.rpc(), user_solana, &[], cancel_a.ix)
        .map_err(|e| anyhow!("send cancel A: {e:?}"))?;
    env.leaf_index(cancel_a.refund_out_hash);
    assert!(
        read_escrow(&env, order_a.escrow)?.is_none(),
        "a cancel behind the head must close the escrow"
    );
    assert_liquidity(&env, pair, POOL_DEPOSIT, 0, "after cancel A")?;

    // The taker's wallet rediscovers both refunds.
    let mut user_wallet = Wallet::new(env.user.address()?, env.assets.clone())
        .map_err(|e| anyhow!("user wallet: {e:?}"))?;
    wait_until("refund notes", || {
        sync_wallet(
            &mut user_wallet,
            &env.user.keypair,
            env.localnet.client.indexer(),
        )
        .map_err(|e| anyhow!("sync user wallet: {e:?}"))?;
        let refunds = user_wallet
            .balance(env.spl_mint, Some(Filter::MinAmount(ORDER_AMOUNT)))
            .map_err(|e| anyhow!("user balance after cancel: {e:?}"))?
            .utxos
            .into_iter()
            .filter(|note| note.utxo.amount == ORDER_AMOUNT)
            .count();
        Ok((refunds == 2).then_some(()))
    })?;

    Ok(())
}
