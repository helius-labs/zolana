mod shared;

use anyhow::{anyhow, bail, Result};
use dynamic_swap_program::state::{Escrow, Pair};
use dynamic_swap_sdk::{
    discovery::{discover_escrow_note, DiscoveredEscrow},
    escrow_pda,
    instructions::{
        create_escrow::{CreateEscrow, EscrowOpenProofInputParams},
        rebalance_liquidity::{RebalanceLiquidity, RebalanceProofInputParams},
        settle::{settle_blinding_seed, Settle, SettleProofInputParams},
        withdraw_liquidity::{WithdrawLiquidity, WithdrawProofInputParams, WithdrawSplAccounts},
    },
    prover::DynamicSwapProverClient,
    shared::transaction_blindings,
    state::{
        escrow_authority_address, escrow_nullifier_key, EscrowUtxo, IndexedPoolNote, PoolUtxo,
    },
    Groth16ProofBytes,
};
use shared::{
    assert_liquidity, deposit_pool_liquidity, discover_pool_notes_with_retry,
    escrow_authority_identity, pool_authority_identity, send, setup_with_pair, token_balance,
    wait_until, MAKER_DEST_BALANCE, MIN_ORDER_AMOUNT, PRICE_TOLERANCE,
};
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_keypair::random_blinding;
use zolana_test_utils::utxo::{
    encrypt_transaction_data, get_transaction_viewing_key, prepare_output_blindings,
};
use zolana_transaction::{
    instructions::transact::{
        asset_field, ExternalData, SettlementTransfer, SppProofInputs, SppProofOutputUtxo,
    },
    utxo::SppProofInputUtxo,
};
use zolana_wallet::{resolve_registered_address, sync_wallet, Filter, Wallet};

const PRICE: u64 = 5;
const ORDER_AMOUNT: u64 = 100_000_000;
const OWED: u64 = ORDER_AMOUNT * PRICE;
/// Covers OWED with slack, so a settle leaves recoverable surplus in the pool
/// change note (MAX_ORDER_SIZE - OWED).
const MAX_ORDER_SIZE: u64 = 600_000_000;
/// Committed before the escrow so the reservation is covered.
const POOL_DEPOSIT: u64 = 1_000_000_000;
/// Wide enough that the settle proof (~14s of in-process proving) always lands
/// inside the window; the cancel flow uses its own small window.
const EXPIRY_SLOTS: u64 = 100_000;

// Full happy path over the committed-liquidity design:
//   1. setup_with_pair: register the SPL(source)->SPL(destination) pair at
//      PRICE with MAX_ORDER_SIZE and the maker encryption pubkey.
//   2. deposit_liquidity: the maker shields POOL_DEPOSIT of the destination
//      asset into a public pool note; available_liquidity = POOL_DEPOSIT.
//   3. create_escrow: the taker spends its funding UTXO (IN1_OUT2), priced at
//      creation; the reservation moves MAX_ORDER_SIZE out of the bound.
//   4. settle: the maker recovers the order and pool notes purely from Solana
//      and the indexer, and spends order + pool -> recipient paid OWED of the
//      destination asset, pool change re-locked with booked clamped down by
//      MAX_ORDER_SIZE, maker receipt (the full escrowed SPL). Maker-only.
//   5. rebalance_liquidity: the maker publishes the settle surplus
//      (MAX_ORDER_SIZE - OWED) back into available_liquidity.
//   6. withdraw_liquidity: the maker unshields the whole remaining pool back
//      to its token account; the pool and the bound return to zero.
#[test]
fn create_pair_escrow_and_settle() -> Result<()> {
    // 1. setup_with_pair: register the SPL(source)->SPL(destination) pair.
    let (env, pair) = setup_with_pair(5, PRICE, EXPIRY_SLOTS, MAX_ORDER_SIZE)?;
    let authority_solana = &env.authority.keypair;
    let user_solana = &env.user.keypair;
    let tree_id = env.localnet.tree_id;
    let prover = DynamicSwapProverClient::new();

    // 2. Commit liquidity. The deposit is fully public, so the bound rises by
    // exactly the deposited amount.
    let pool_note = deposit_pool_liquidity(&env, pair, POOL_DEPOSIT)?;
    assert_liquidity(&env, pair, POOL_DEPOSIT, 0, "after deposit")?;

    let recipient_owner_hash = env
        .user
        .owner_hash()
        .map_err(|e| anyhow!("user owner hash: {e:?}"))?;
    // create_escrow: the escrow account key and its state are all that cross into
    // settle -- everything else settle needs is fetched fresh there.
    let (escrow, escrow_state, expected_payout_hash) = {
        // 3. create_escrow. Discover the taker's funding UTXO the way a real
        // wallet would: sync from Photon and pick a spendable note of the source
        // asset large enough to cover the order; the circuit's change output
        // returns the remainder, so no pre-split is needed.
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

        // The taker builds the order owner from public data alone: the pair
        // account's maker encryption pubkey plus the hardcoded zero-secret
        // nullifier pubkey.
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

        let order_amount = ORDER_AMOUNT;

        let source_in = SppProofInputUtxo::from(funding_utxo.clone());

        let escrow_utxo = EscrowUtxo {
            recipient_owner_hash,
            asset: env.source_mint(),
            order_amount,
            min_price: PRICE,
            blinding: random_blinding(),
        };
        let change_amount = funding_utxo
            .utxo
            .amount
            .checked_sub(order_amount)
            .ok_or_else(|| anyhow!("order_amount exceeds the taker's funding UTXO"))?;

        // Output order (order, taker_change) matches the program's own output
        // index and the circuit. SPP derives both blindings from the
        // transaction's seed; the order ciphertext hands its blinding to the
        // maker.
        let input_utxos = vec![source_in.clone()];
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
        let order_utxo_hash = order_out
            .hash(tree_id)
            .map_err(|e| anyhow!("order_utxo hash: {e:?}"))?;

        // The taker precomputes its payout note. The order is owned under the
        // public zero-secret nullifier key, so its nullifier (settle's first
        // published nullifier) and every settle blinding derive from the
        // taker's own order opening.
        let expected_payout_hash = {
            let order_nullifier = escrow_nullifier_key()
                .nullifier(&order_utxo_hash, &order_out.blinding)
                .map_err(|e| anyhow!("order nullifier: {e:?}"))?;
            let seed = settle_blinding_seed(&order_out.blinding)?;
            let (_, blindings) = transaction_blindings(&order_nullifier, &seed, 1)?;
            let mut payout =
                SppProofOutputUtxo::new(env.destination_mint(), OWED, env.user.address()?)
                    .map_err(|e| anyhow!("payout: {e:?}"))?;
            payout.blinding = blindings
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("settle derives a recipient blinding"))?;
            payout
                .hash(tree_id)
                .map_err(|e| anyhow!("payout hash: {e:?}"))?
        };

        // Both ciphertexts are kept: the order slot is the maker handoff, the
        // change slot is the taker's own note.
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

        let escrow_authority_owner_hash = escrow_authority
            .owner_hash()
            .map_err(|e| anyhow!("escrow authority owner hash: {e:?}"))?;
        let source_asset =
            asset_field(&env.spl_mint).map_err(|e| anyhow!("source asset: {e:?}"))?;
        let proof_inputs = EscrowOpenProofInputParams {
            source_in,
            order_out,
            taker_change,
            escrow_authority_owner_hash,
            source_asset,
            public_price_floor: PRICE - PRICE_TOLERANCE,
            price_tolerance: PRICE_TOLERANCE,
            min_order_amount: MIN_ORDER_AMOUNT,
            max_order_size: MAX_ORDER_SIZE,
            order_amount,
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

        // The taker signs alone and pays fees + escrow rent.
        send(env.localnet.client.rpc(), user_solana, &[], ix)
            .map_err(|e| anyhow!("send create_escrow: {e:?}"))?;

        // The reservation moved MAX_ORDER_SIZE out of the public bound.
        assert_liquidity(
            &env,
            pair,
            POOL_DEPOSIT - MAX_ORDER_SIZE,
            1,
            "after create_escrow",
        )?;

        // The taker's change landed as a wallet-discoverable note (its
        // ciphertext carries the taker's own view tag, distinct from the order
        // slot's escrow-authority tag).
        wait_until("taker change note", || {
            sync_wallet(
                &mut user_wallet,
                &env.user.keypair,
                env.localnet.client.indexer(),
            )
            .map_err(|e| anyhow!("resync user wallet: {e:?}"))?;
            Ok(user_wallet
                .balance(env.spl_mint, None)
                .map_err(|e| anyhow!("user balance after escrow: {e:?}"))?
                .utxos
                .into_iter()
                .find(|utxo| utxo.utxo.amount == change_amount))
        })?;

        // create_escrow prices the order at creation and stores the order leaf
        // as the PDA seed; `created_at` is program-stamped from the Clock, so it
        // is the one field read back rather than predicted.
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

        (escrow, escrow_state, expected_payout_hash)
    };

    // 4. settle: the payout is funded from the committed pool. The recipient is
    // paid `order_amount * execution_price` of the destination asset; the pool
    // change re-locks with its booked value clamped down by the reservation;
    // the maker receipt (the full escrowed SPL) goes to the pair's stored
    // receipt owner-hash.
    let (recipient_out_hash, pool_change) = {
        // Recover everything settle needs purely from Solana, the registry, and
        // the indexer, isolated in its own scope so the settlement math below can
        // only use recovered values, not create-time state or test-env
        // conveniences.
        let (escrow_owner, pool_owner, recipient, discovered, discovered_pool, source_asset) = {
            let recipient =
                resolve_registered_address(env.localnet.client.rpc(), user_solana.pubkey())
                    .map_err(|e| anyhow!("resolve recipient: {e:?}"))?
                    .address;
            let escrow_owner = escrow_authority_identity(&env.authority.keypair, &pair)?;
            let pool_owner = pool_authority_identity(&env.authority.keypair, &pair)?;
            // The scan is keyed by the committed order leaf from the escrow
            // account being settled, so the result is pinned to this escrow.
            let discovered = wait_until("escrow order note", || {
                Ok(discover_escrow_note(
                    env.localnet.client.indexer(),
                    &escrow_owner,
                    &escrow_state.order_utxo_hash,
                )
                .ok())
            })?;
            // The registry-resolved recipient must be the one the order's data
            // hash commits -- the settle proof re-opens exactly that owner-hash.
            if recipient
                .owner_hash()
                .map_err(|e| anyhow!("recipient owner hash: {e:?}"))?
                != discovered.recipient_owner_hash
            {
                bail!("registered recipient does not match the order's committed recipient");
            }
            // The maker's pool scan finds the public deposit note without any
            // client-side tracking.
            let discovered_pool = discover_pool_notes_with_retry(&env, &pool_owner, 1)?
                .into_iter()
                .find(|note| note.booked == POOL_DEPOSIT)
                .ok_or_else(|| anyhow!("pool deposit note not discovered"))?;
            // The pair stores the source asset as an id + a hashed field element,
            // not the mint; resolve the mint from that id via the asset registry.
            let source_asset = {
                let pair_account = env
                    .localnet
                    .client
                    .rpc()
                    .get_account(pair)
                    .map_err(|e| anyhow!("get pair account: {e:?}"))?
                    .ok_or_else(|| anyhow!("pair account not found"))?;
                let source_asset_id =
                    bytemuck::from_bytes::<Pair>(&pair_account.data).source_asset_id;
                env.assets
                    .resolve(source_asset_id)
                    .map_err(|e| anyhow!("resolve source asset: {e:?}"))?
            };
            (
                escrow_owner,
                pool_owner,
                recipient,
                discovered,
                discovered_pool,
                source_asset,
            )
        };
        let execution_price = escrow_state.execution_price;
        let order_utxo_hash = escrow_state.order_utxo_hash;
        let DiscoveredEscrow {
            order_amount,
            order_blinding,
            recipient_owner_hash,
            min_price,
        } = discovered;

        let owed = order_amount
            .checked_mul(execution_price)
            .ok_or_else(|| anyhow!("order_amount * execution_price overflows"))?;

        // The discovered pool note must match the one the deposit created.
        let pool_in_note = IndexedPoolNote {
            note: PoolUtxo {
                asset: env.destination_mint(),
                amount: discovered_pool.amount,
                booked: discovered_pool.booked,
                blinding: discovered_pool.blinding,
            },
            leaf_index: env.leaf_index(discovered_pool.utxo_hash),
        };
        assert_eq!(pool_in_note, pool_note, "discovered pool note mismatch");

        let pool_address = pool_owner
            .shielded_address()
            .map_err(|e| anyhow!("pool authority address: {e:?}"))?;
        let pool_authority_owner_hash = pool_address
            .owner_hash()
            .map_err(|e| anyhow!("pool authority owner hash: {e:?}"))?;

        let escrow_utxo = EscrowUtxo {
            recipient_owner_hash,
            asset: source_asset,
            order_amount,
            min_price,
            blinding: order_blinding,
        };
        let order_in = escrow_utxo
            .to_input_utxo(
                &escrow_owner
                    .shielded_address()
                    .map_err(|e| anyhow!("escrow authority address: {e:?}"))?,
                tree_id,
                env.leaf_index(order_utxo_hash),
            )
            .map_err(|e| anyhow!("order_in: {e:?}"))?;
        // The reconstructed input must hash back to the leaf create_escrow
        // committed on Solana: this pins the decrypted order UTXO data against
        // the commitment before we spend it.
        if order_in.hash() != escrow_state.order_utxo_hash {
            bail!("reconstructed order utxo does not match the committed escrow leaf");
        }
        let pool_in = pool_in_note
            .to_input_utxo(&pool_address, tree_id)
            .map_err(|e| anyhow!("pool_in: {e:?}"))?;

        // Every settle output blinding derives from the order opening and the
        // order's nullifier (input 0), so the taker recomputes its payout note
        // without a ciphertext.
        let input_utxos = vec![order_in.clone(), pool_in.clone()];
        let blinding_seed = settle_blinding_seed(&order_in.utxo.blinding)?;
        let (private_tx_blinding, blindings) =
            transaction_blindings(&order_in.nullifier(), &blinding_seed, 3)?;
        let [recipient_blinding, change_blinding, receipt_blinding]: [_; 3] = blindings
            .try_into()
            .map_err(|_| anyhow!("settle derives three output blindings"))?;

        // The pool change: booked drops by the full reservation (clamped at
        // zero) while only owed actually leaves -- the gap stays in the note as
        // surplus, published later by the rebalance below.
        let pool_change_note = PoolUtxo {
            asset: env.destination_mint(),
            amount: pool_in_note
                .note
                .amount
                .checked_sub(owed)
                .ok_or_else(|| anyhow!("owed exceeds the pool note amount"))?,
            booked: pool_in_note.note.booked.saturating_sub(MAX_ORDER_SIZE),
            blinding: change_blinding,
        };

        let mut recipient_out = SppProofOutputUtxo::new(env.destination_mint(), owed, recipient)
            .map_err(|e| anyhow!("recipient_out: {e:?}"))?;
        recipient_out.blinding = recipient_blinding;
        let pool_change_out = pool_change_note
            .output_utxo(&pool_address)
            .map_err(|e| anyhow!("pool_change: {e:?}"))?;
        let mut maker_receipt =
            SppProofOutputUtxo::new(source_asset, order_amount, env.authority.address()?)
                .map_err(|e| anyhow!("maker_receipt: {e:?}"))?;
        maker_receipt.blinding = receipt_blinding;

        let recipient_out_hash = recipient_out
            .hash(tree_id)
            .map_err(|e| anyhow!("recipient_out hash: {e:?}"))?;
        let pool_change_hash = pool_change_out
            .hash(tree_id)
            .map_err(|e| anyhow!("pool_change hash: {e:?}"))?;
        let maker_receipt_hash = maker_receipt
            .hash(tree_id)
            .map_err(|e| anyhow!("maker_receipt hash: {e:?}"))?;

        // All three ciphertexts are kept: the recipient's for the taker's
        // wallet, the pool change's for the maker's pool scan, the receipt's
        // for the maker's wallet.
        let viewing_key = get_transaction_viewing_key(&env.authority.keypair, &input_utxos)
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
        let encoded = encrypt_transaction_data(
            &[
                recipient_out.clone(),
                pool_change_out.clone(),
                maker_receipt.clone(),
            ],
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
        // Both authorities own inputs, so both are owner signers by
        // construction (escrow_authority first-input order, pool_authority
        // second) -- matching the Settle builder's account tail.
        let spp_proof_inputs = SppProofInputs {
            input_utxos,
            output_utxos: encoded.output_utxos,
            external_data,
            payer: authority_solana.pubkey(),
            blinding_seed,
            output_tree_id: tree_id,
        };
        let transact = env
            .localnet
            .client
            .indexer()
            .prove_transact(spp_proof_inputs, escrow_owner.as_ref())
            .map_err(|e| anyhow!("prove_transact: {e:?}"))?;

        let destination_asset =
            asset_field(&env.dest_mint).map_err(|e| anyhow!("destination asset: {e:?}"))?;
        let receipt_owner_hash = env.authority.owner_hash()?;
        let proof_inputs = SettleProofInputParams {
            order_in,
            pool_in,
            pool_booked_in: pool_in_note.note.booked,
            recipient_out,
            pool_change: pool_change_out,
            maker_receipt,
            execution_price,
            order_amount,
            recipient_owner_hash,
            min_price,
            order_utxo_hash,
            destination_asset,
            pool_authority_owner_hash,
            max_order_size: MAX_ORDER_SIZE,
            receipt_owner_hash,
            external_data_hash,
            private_tx_blinding,
            output_tree_id: tree_id,
        }
        .to_proof_inputs()
        .map_err(|e| anyhow!("settle proof inputs: {e:?}"))?;
        let order_proof = prover
            .prove_pool_settle(&proof_inputs)
            .map_err(|e| anyhow!("prove pool_settle: {e:?}"))?;

        let settle_ix = Settle {
            authority: authority_solana.pubkey(),
            pair,
            escrow,
            rent_recipient: user_solana.pubkey(),
            tree: env.localnet.tree,
            proof: Groth16ProofBytes {
                proof_a: order_proof.proof_a,
                proof_b: order_proof.proof_b,
                proof_c: order_proof.proof_c,
            },
            transact,
        }
        .instruction()
        .map_err(|e| anyhow!("settle instruction: {e:?}"))?;
        // Maker-only: the pair authority signs; the program's CPI signs for
        // both the order and pool inputs.
        send(env.localnet.client.rpc(), authority_solana, &[], settle_ix)
            .map_err(|e| anyhow!("send settle: {e:?}"))?;

        // Settle payout: recipient paid `order_amount * execution_price` of the
        // destination asset; the pool change re-locked; the maker receipt is
        // the full escrowed SPL. A wrong asset or amount would hash differently
        // and never be indexed.
        let leaves = vec![recipient_out_hash, pool_change_hash, maker_receipt_hash];
        let proofs = zolana_test_utils::test_validator_asserts::wait_for_merkle_proofs(
            env.localnet.client.indexer(),
            env.localnet.tree,
            &leaves,
        );
        let pool_change_leaf = proofs
            .iter()
            .find(|proof| proof.leaf == pool_change_hash)
            .ok_or_else(|| anyhow!("pool change leaf not indexed"))?
            .leaf_index;
        (
            recipient_out_hash,
            IndexedPoolNote {
                note: pool_change_note,
                leaf_index: pool_change_leaf,
            },
        )
    };

    assert_eq!(
        recipient_out_hash, expected_payout_hash,
        "the settle payout must be the note the taker precomputed at creation"
    );

    // Settlement closes the escrow account and releases the reservation; the
    // bound stays untouched (the unspent reservation lives in the change note
    // as surplus).
    assert!(
        env.localnet
            .client
            .rpc()
            .get_account(escrow)
            .map_err(|e| anyhow!("get escrow account after settle: {e:?}"))?
            .is_none(),
        "escrow account must be closed after settlement"
    );
    assert_liquidity(&env, pair, POOL_DEPOSIT - MAX_ORDER_SIZE, 0, "after settle")?;

    // 5. rebalance_liquidity: publish the settle surplus. The change note holds
    // amount = POOL_DEPOSIT - OWED with booked = POOL_DEPOSIT - MAX_ORDER_SIZE,
    // so the full surplus (MAX_ORDER_SIZE - OWED) is creditable.
    let credit = MAX_ORDER_SIZE - OWED;
    let rebalanced_note = {
        let pool_owner = pool_authority_identity(&env.authority.keypair, &pair)?;
        let pool_address = pool_owner
            .shielded_address()
            .map_err(|e| anyhow!("pool authority address: {e:?}"))?;
        let destination_asset =
            asset_field(&env.dest_mint).map_err(|e| anyhow!("destination asset: {e:?}"))?;

        let prepared = RebalanceProofInputParams {
            inputs: vec![pool_change.clone()],
            outputs: vec![PoolUtxo {
                booked: pool_change.note.booked + credit,
                ..pool_change.note.clone()
            }],
            pool_authority: pool_address,
            credit,
            destination_asset,
            tree_id,
        }
        .prepare()
        .map_err(|e| anyhow!("rebalance prepare: {e:?}"))?;

        let spp_proof_inputs = prepared
            .spp_proof_inputs(&env.authority.keypair, authority_solana.pubkey())
            .map_err(|e| anyhow!("rebalance spp inputs: {e:?}"))?;
        let external_data_hash = spp_proof_inputs
            .external_data
            .hash()
            .map_err(|e| anyhow!("external data hash: {e:?}"))?;
        let bundle = prepared
            .to_proof_inputs(external_data_hash)
            .map_err(|e| anyhow!("rebalance proof inputs: {e:?}"))?;
        let rebalance_proof = prover
            .prove_pool_rebalance(&bundle.proof_inputs)
            .map_err(|e| anyhow!("prove pool_rebalance: {e:?}"))?;

        let transact = env
            .localnet
            .client
            .indexer()
            .prove_transact(spp_proof_inputs, pool_owner.as_ref())
            .map_err(|e| anyhow!("prove_transact: {e:?}"))?;

        let rebalance_ix = RebalanceLiquidity {
            authority: authority_solana.pubkey(),
            pair,
            tree: env.localnet.tree,
            credit,
            proof: Groth16ProofBytes {
                proof_a: rebalance_proof.proof_a,
                proof_b: rebalance_proof.proof_b,
                proof_c: rebalance_proof.proof_c,
            },
            transact,
        }
        .instruction()
        .map_err(|e| anyhow!("rebalance instruction: {e:?}"))?;
        send(
            env.localnet.client.rpc(),
            authority_solana,
            &[],
            rebalance_ix,
        )
        .map_err(|e| anyhow!("send rebalance: {e:?}"))?;

        let note = prepared
            .outputs
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("rebalance keeps its output note"))?;
        let leaf = note
            .output_utxo(&pool_address)
            .and_then(|output| output.hash(tree_id).map_err(|e| anyhow!("{e:?}")))
            .map_err(|e| anyhow!("rebalanced note hash: {e:?}"))?;
        IndexedPoolNote {
            note,
            leaf_index: env.leaf_index(leaf),
        }
    };
    assert_liquidity(&env, pair, POOL_DEPOSIT - OWED, 0, "after rebalance")?;

    // 6. withdraw_liquidity: unshield the entire remaining pool back to the
    // maker's token account. The pool note is fully booked after the
    // rebalance, so the whole amount is withdrawable.
    {
        let pool_owner = pool_authority_identity(&env.authority.keypair, &pair)?;
        let pool_address = pool_owner
            .shielded_address()
            .map_err(|e| anyhow!("pool authority address: {e:?}"))?;
        let destination_asset =
            asset_field(&env.dest_mint).map_err(|e| anyhow!("destination asset: {e:?}"))?;
        let amount = rebalanced_note.note.amount;

        let spp_input = rebalanced_note
            .to_input_utxo(&pool_address, tree_id)
            .map_err(|e| anyhow!("pool_in: {e:?}"))?;
        // SPP derives the change blinding from the transaction's seed.
        let blinding_seed = random_blinding();
        let (private_tx_blinding, blindings) =
            transaction_blindings(&spp_input.nullifier(), &blinding_seed, 1)?;
        let pool_out = PoolUtxo {
            asset: env.destination_mint(),
            amount: 0,
            booked: 0,
            blinding: blindings
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("withdraw derives a change blinding"))?,
        };
        let spp_output = pool_out
            .output_utxo(&pool_address)
            .map_err(|e| anyhow!("pool_out: {e:?}"))?;
        let viewing_key =
            get_transaction_viewing_key(&env.authority.keypair, std::slice::from_ref(&spp_input))
                .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
        let encoded =
            encrypt_transaction_data(std::slice::from_ref(&spp_output), &viewing_key, tree_id)
                .map_err(|e| anyhow!("encode outputs: {e:?}"))?;
        let external_data = ExternalData::new(
            *viewing_key.pubkey().as_bytes(),
            encoded.salt,
            encoded.outputs,
            encoded.resolved_owner_tags,
            vec![],
        )
        .with_interface_transfer(SettlementTransfer::Spl {
            mint: env.dest_mint,
            is_deposit: false,
            amount,
            user_spl_token: env.authority_dest_token,
        })
        .map_err(|e| anyhow!("interface transfer: {e:?}"))?;
        let external_data_hash = external_data
            .hash()
            .map_err(|e| anyhow!("external data hash: {e:?}"))?;

        let withdraw_proof_inputs = WithdrawProofInputParams {
            pool_in: rebalanced_note.note.clone(),
            pool_out: pool_out.clone(),
            pool_authority: pool_address,
            amount,
            destination_asset,
            external_data_hash,
            private_tx_blinding,
            tree_id,
        }
        .to_proof_inputs()
        .map_err(|e| anyhow!("withdraw proof inputs: {e:?}"))?;
        let withdraw_proof = prover
            .prove_pool_withdraw(&withdraw_proof_inputs)
            .map_err(|e| anyhow!("prove pool_withdraw: {e:?}"))?;

        let spp_proof_inputs = SppProofInputs {
            input_utxos: vec![spp_input],
            output_utxos: encoded.output_utxos,
            external_data,
            payer: authority_solana.pubkey(),
            blinding_seed,
            output_tree_id: tree_id,
        };
        let transact = env
            .localnet
            .client
            .indexer()
            .prove_transact(spp_proof_inputs, pool_owner.as_ref())
            .map_err(|e| anyhow!("prove_transact: {e:?}"))?;

        let balance_before = token_balance(&env, env.authority_dest_token)?;
        let withdraw_ix = WithdrawLiquidity {
            authority: authority_solana.pubkey(),
            pair,
            tree: env.localnet.tree,
            amount,
            spl: WithdrawSplAccounts {
                mint: env.dest_mint,
                user_token: env.authority_dest_token,
                token_program: zolana_interface::pda::spl_token_program_id(),
            },
            proof: Groth16ProofBytes {
                proof_a: withdraw_proof.proof_a,
                proof_b: withdraw_proof.proof_b,
                proof_c: withdraw_proof.proof_c,
            },
            transact,
        }
        .instruction()
        .map_err(|e| anyhow!("withdraw instruction: {e:?}"))?;
        send(
            env.localnet.client.rpc(),
            authority_solana,
            &[],
            withdraw_ix,
        )
        .map_err(|e| anyhow!("send withdraw: {e:?}"))?;

        let balance_after = token_balance(&env, env.authority_dest_token)?;
        assert_eq!(
            balance_after,
            balance_before + amount,
            "withdrawal must land in the maker's token account"
        );
        // Deposited POOL_DEPOSIT, paid OWED to the recipient, recovered the
        // rest: the maker's net destination-asset spend is exactly OWED.
        assert_eq!(balance_after, MAKER_DEST_BALANCE - OWED);
    }
    assert_liquidity(&env, pair, 0, 0, "after withdraw")?;

    Ok(())
}
