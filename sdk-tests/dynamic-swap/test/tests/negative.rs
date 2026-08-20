mod shared;

use anyhow::{anyhow, Result};
use dynamic_swap_sdk::{
    escrow_pda,
    instructions::{
        create_escrow::{CreateEscrow, EscrowOpenProofInputParams},
        create_pair::CreatePair,
        deposit_liquidity::DepositLiquidity,
        update_price::UpdatePrice,
        withdraw_liquidity::{WithdrawLiquidity, WithdrawSplAccounts},
    },
    pair_pda,
    state::PoolUtxo,
    Groth16ProofBytes,
};
use shared::{escrow_authority_identity, setup, TestEnv, DESTINATION_ASSET_ID, SOURCE_ASSET_ID};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_interface::{
    instruction::instruction_data::transact::{InterfaceTransfer, TransactIxData, TransactProof},
    verifying_keys::CircuitId,
};
use zolana_keypair::random_blinding;
use zolana_transaction::{
    instructions::{transact::spp_proof_inputs::asset_field, types::SppProofInputUtxo},
    Utxo,
};

const PRICE: u64 = 5;
const EXPIRY_SLOTS: u64 = 100_000;
const MAX_ORDER_SIZE: u64 = 600_000_000;

const UNAUTHORIZED: u32 = 9012;
const INVALID_PRICE: u32 = 9016;
const MAX_PRICE_EXCEEDED: u32 = 9019;
const INVALID_ENCRYPTION_PUBKEY: u32 = 9020;
const INVALID_EXPIRY: u32 = 9021;
const INSUFFICIENT_LIQUIDITY: u32 = 9022;
const INVALID_MAX_ORDER_SIZE: u32 = 9023;
const ASSET_MISMATCH: u32 = 9024;
const INVALID_DEPOSIT_ENTRY: u32 = 9025;
const INTERFACE_TRANSFER_MISMATCH: u32 = 9026;
const INVALID_WITHDRAWAL_AMOUNT: u32 = 9027;

// A custom program error surfaces in the RPC error two ways: the structured
// `InstructionError::Custom(<decimal>)` and the program-log line `custom program
// error: 0x<hex>`. Match both of those *delimited* forms only -- a bare decimal
// would spuriously match compute-unit counts or lamport amounts elsewhere in the
// error text.
fn assert_custom_error(context: &str, err: &anyhow::Error, code: u32) {
    let text = format!("{err:?}");
    let structured = format!("Custom({code})");
    let hex = format!("0x{code:x}");
    assert!(
        text.contains(&structured) || text.contains(&hex),
        "{context}: expected custom error {code} ({structured} / {hex}) in: {text}"
    );
}

// Derives the pair PDA and sends `create_pair`. The pool starts empty.
// Returns the pair PDA (or the RPC error, which the rejection cases assert on).
fn create_pair(
    env: &TestEnv,
    authority_solana: &dyn Signer,
    price: u64,
    expiry_slots: u64,
    max_order_size: u64,
    maker_encryption_pubkey: [u8; 33],
) -> Result<Pubkey> {
    let pair = pair_pda(
        &authority_solana.pubkey(),
        SOURCE_ASSET_ID,
        DESTINATION_ASSET_ID,
    );
    let source_asset = asset_field(&env.spl_mint).map_err(|e| anyhow!("source asset: {e:?}"))?;
    let destination_asset =
        asset_field(&env.dest_mint).map_err(|e| anyhow!("destination asset: {e:?}"))?;
    let create_pair_ix = CreatePair {
        payer: authority_solana.pubkey(),
        pair,
        price,
        source_asset_id: SOURCE_ASSET_ID,
        destination_asset_id: DESTINATION_ASSET_ID,
        expiry_slots,
        max_order_size,
        source_asset,
        destination_asset,
        maker_receipt_owner_hash: env.authority.owner_hash()?,
        maker_encryption_pubkey,
    }
    .instruction()
    .map_err(|e| anyhow!("create_pair instruction: {e:?}"))?;
    env.client
        .rpc()
        .create_and_send_transaction(
            &[create_pair_ix],
            authority_solana.pubkey(),
            &[authority_solana],
        )
        .map_err(|e| anyhow!("send create_pair: {e:?}"))?;
    Ok(pair)
}

/// A wincode-deserializable transact payload for gates that reject before proof
/// verification touches it.
fn dummy_transact() -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit: CircuitId::ConfidentialEddsa(1, 2, 0),
        tx_viewing_pk: [2u8; 33],
        salt: [0u8; 16],
        proof: TransactProof::zeroed(),
        inputs: vec![],
        interface_transfers: vec![],
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![],
        messages: vec![],
    }
}

fn withdraw_spl_accounts(env: &TestEnv) -> WithdrawSplAccounts {
    WithdrawSplAccounts {
        mint: env.dest_mint,
        user_token: env.authority_dest_token,
        token_program: zolana_interface::pda::spl_token_program_id(),
    }
}

fn dummy_withdraw_transact(env: &TestEnv, amount: u64) -> TransactIxData {
    let mut transact = dummy_transact();
    transact.interface_transfers = vec![InterfaceTransfer::SplWithdrawal {
        amount,
        spl_interface_bump: zolana_interface::pda::spl_interface_with_bump(&env.dest_mint).1,
    }];
    transact
}

// Proof-free access-control and validation rejections, all under one validator
// (kept in a single `#[test]` because each `setup()` boots its own localnet on
// fixed ports, so multiple tests in one binary would race for them):
//   - create_pair with price 0                    -> InvalidPrice
//   - create_pair with expiry_slots 0             -> InvalidExpiry
//   - create_pair with a non-SEC1 encryption key  -> InvalidEncryptionPubkey
//   - update_price to 0                           -> InvalidPrice
//   - update_price by a non-authority             -> Unauthorized
//   - create_escrow with max_price < pair.price   -> MaxPriceExceeded
#[test]
fn zero_price_and_authority_checks() -> Result<()> {
    let env = setup()?;
    let authority_solana = &env.authority.keypair;
    let user_solana = &env.user.keypair;

    let pair = pair_pda(
        &authority_solana.pubkey(),
        SOURCE_ASSET_ID,
        DESTINATION_ASSET_ID,
    );
    let maker_encryption_pubkey = *escrow_authority_identity(&env.authority.keypair, &pair)?
        .viewing_pubkey()
        .as_bytes();

    // create_pair rejects a zero price (create_escrow could not write a nonzero
    // execution_price, so escrows on the pair could never settle).
    let err = create_pair(
        &env,
        &authority_solana,
        0,
        EXPIRY_SLOTS,
        MAX_ORDER_SIZE,
        maker_encryption_pubkey,
    )
    .err()
    .ok_or_else(|| anyhow!("create_pair with price 0 must fail"))?;
    assert_custom_error("create_pair zero price", &err, INVALID_PRICE);

    // create_pair rejects a zero settle window (every escrow would be
    // immediately cancellable and unsettleable).
    let err = create_pair(
        &env,
        &authority_solana,
        PRICE,
        0,
        MAX_ORDER_SIZE,
        maker_encryption_pubkey,
    )
    .err()
    .ok_or_else(|| anyhow!("create_pair with expiry 0 must fail"))?;
    assert_custom_error("create_pair zero expiry", &err, INVALID_EXPIRY);

    // create_pair rejects a zero max_order_size (every escrow would be
    // unprovable and every reservation empty).
    let err = create_pair(
        &env,
        &authority_solana,
        PRICE,
        EXPIRY_SLOTS,
        0,
        maker_encryption_pubkey,
    )
    .err()
    .ok_or_else(|| anyhow!("create_pair with max_order_size 0 must fail"))?;
    assert_custom_error(
        "create_pair zero max_order_size",
        &err,
        INVALID_MAX_ORDER_SIZE,
    );

    // create_pair rejects an encryption pubkey that is not a SEC1-compressed
    // P256 point (order UTXO handoffs would be undecryptable).
    let mut bad_encryption_pubkey = maker_encryption_pubkey;
    bad_encryption_pubkey[0] = 0x04;
    let err = create_pair(
        &env,
        &authority_solana,
        PRICE,
        EXPIRY_SLOTS,
        MAX_ORDER_SIZE,
        bad_encryption_pubkey,
    )
    .err()
    .ok_or_else(|| anyhow!("create_pair with a bad encryption pubkey must fail"))?;
    assert_custom_error(
        "create_pair bad encryption pubkey",
        &err,
        INVALID_ENCRYPTION_PUBKEY,
    );

    // A valid pair for the remaining checks.
    let pair = create_pair(
        &env,
        &authority_solana,
        PRICE,
        EXPIRY_SLOTS,
        MAX_ORDER_SIZE,
        maker_encryption_pubkey,
    )?;

    // update_price rejects a zero price for the same reason as create_pair.
    let zero_ix = UpdatePrice {
        authority: authority_solana.pubkey(),
        pair,
        price: 0,
    }
    .instruction()
    .map_err(|e| anyhow!("update_price instruction: {e:?}"))?;
    let err = env
        .client
        .rpc()
        .create_and_send_transaction(&[zero_ix], authority_solana.pubkey(), &[&authority_solana])
        .err()
        .ok_or_else(|| anyhow!("update_price to 0 must fail"))?;
    assert_custom_error("update_price zero", &anyhow!("{err:?}"), INVALID_PRICE);

    // A non-authority signer cannot move the price: `authority_solana` pays the
    // fee, the intruder signs as the claimed authority but is not the pair's
    // stored authority.
    let intruder = Keypair::new();
    let intruder_ix = UpdatePrice {
        authority: intruder.pubkey(),
        pair,
        price: PRICE + 1,
    }
    .instruction()
    .map_err(|e| anyhow!("update_price instruction: {e:?}"))?;
    let err = env
        .client
        .rpc()
        .create_and_send_transaction(
            &[intruder_ix],
            authority_solana.pubkey(),
            &[&authority_solana, &intruder],
        )
        .err()
        .ok_or_else(|| anyhow!("non-authority update_price must fail"))?;
    assert_custom_error(
        "non-authority update_price",
        &anyhow!("{err:?}"),
        UNAUTHORIZED,
    );

    // create_escrow rejects a max_price below the pair's current price. The gate
    // runs before proof verification, so a garbage proof and an empty transact
    // payload reach it.
    let escrow_ix = CreateEscrow {
        taker: user_solana.pubkey(),
        pair,
        escrow: escrow_pda(&[0u8; 32]),
        tree: Pubkey::new_unique(),
        proof: Groth16ProofBytes {
            proof_a: [0u8; 32],
            proof_b: [0u8; 64],
            proof_c: [0u8; 32],
        },
        max_price: PRICE - 1,
        transact: dummy_transact(),
    }
    .instruction()
    .map_err(|e| anyhow!("create_escrow instruction: {e:?}"))?;
    let err = env
        .client
        .rpc()
        .create_and_send_transaction(&[escrow_ix], user_solana.pubkey(), &[&user_solana])
        .err()
        .ok_or_else(|| anyhow!("create_escrow above max_price must fail"))?;
    assert_custom_error(
        "create_escrow above max_price",
        &anyhow!("{err:?}"),
        MAX_PRICE_EXCEEDED,
    );

    // create_escrow at an acceptable price but with an empty pool: the
    // worst-case reservation cannot be covered. The gate runs before proof
    // verification.
    let escrow_ix = CreateEscrow {
        taker: user_solana.pubkey(),
        pair,
        escrow: escrow_pda(&[0u8; 32]),
        tree: Pubkey::new_unique(),
        proof: Groth16ProofBytes {
            proof_a: [0u8; 32],
            proof_b: [0u8; 64],
            proof_c: [0u8; 32],
        },
        max_price: PRICE,
        transact: dummy_transact(),
    }
    .instruction()
    .map_err(|e| anyhow!("create_escrow instruction: {e:?}"))?;
    let err = env
        .client
        .rpc()
        .create_and_send_transaction(&[escrow_ix], user_solana.pubkey(), &[&user_solana])
        .err()
        .ok_or_else(|| anyhow!("create_escrow with an empty pool must fail"))?;
    assert_custom_error(
        "create_escrow with an empty pool",
        &anyhow!("{err:?}"),
        INSUFFICIENT_LIQUIDITY,
    );

    // withdraw_liquidity by a non-authority is rejected before anything else.
    let intruder = Keypair::new();
    let withdraw_ix = WithdrawLiquidity {
        authority: intruder.pubkey(),
        pair,
        tree: Pubkey::new_unique(),
        amount: 1,
        spl: withdraw_spl_accounts(&env),
        proof: Groth16ProofBytes {
            proof_a: [0u8; 32],
            proof_b: [0u8; 64],
            proof_c: [0u8; 32],
        },
        transact: dummy_withdraw_transact(&env, 1),
    }
    .instruction()
    .map_err(|e| anyhow!("withdraw instruction: {e:?}"))?;
    let err = env
        .client
        .rpc()
        .create_and_send_transaction(
            &[withdraw_ix],
            authority_solana.pubkey(),
            &[&authority_solana, &intruder],
        )
        .err()
        .ok_or_else(|| anyhow!("non-authority withdraw must fail"))?;
    assert_custom_error("non-authority withdraw", &anyhow!("{err:?}"), UNAUTHORIZED);

    // A zero withdrawal is rejected before transfer-shape and proof checks.
    let withdraw_data = dynamic_swap_sdk::WithdrawLiquidityIxData {
        amount: 0,
        proof: Groth16ProofBytes {
            proof_a: [0u8; 32],
            proof_b: [0u8; 64],
            proof_c: [0u8; 32],
        },
        transact: dummy_transact(),
    };
    let mut withdraw_bytes = vec![dynamic_swap_sdk::tag::WITHDRAW_LIQUIDITY];
    withdraw_bytes.extend_from_slice(
        &wincode::serialize(&withdraw_data).map_err(|e| anyhow!("serialize withdraw: {e:?}"))?,
    );
    let withdraw_ix = solana_instruction::Instruction {
        program_id: dynamic_swap_program::ID,
        accounts: vec![
            solana_instruction::AccountMeta::new(authority_solana.pubkey(), true),
            solana_instruction::AccountMeta::new(pair, false),
        ],
        data: withdraw_bytes,
    };
    let err = env
        .client
        .rpc()
        .create_and_send_transaction(
            &[withdraw_ix],
            authority_solana.pubkey(),
            &[&authority_solana],
        )
        .err()
        .ok_or_else(|| anyhow!("zero withdraw must fail"))?;
    assert_custom_error(
        "zero withdraw",
        &anyhow!("{err:?}"),
        INVALID_WITHDRAWAL_AMOUNT,
    );

    // withdraw_liquidity beyond the bound: the empty pool covers nothing.
    let withdraw_ix = WithdrawLiquidity {
        authority: authority_solana.pubkey(),
        pair,
        tree: Pubkey::new_unique(),
        amount: 1,
        spl: withdraw_spl_accounts(&env),
        proof: Groth16ProofBytes {
            proof_a: [0u8; 32],
            proof_b: [0u8; 64],
            proof_c: [0u8; 32],
        },
        transact: dummy_withdraw_transact(&env, 1),
    }
    .instruction()
    .map_err(|e| anyhow!("withdraw instruction: {e:?}"))?;
    let err = env
        .client
        .rpc()
        .create_and_send_transaction(
            &[withdraw_ix],
            authority_solana.pubkey(),
            &[&authority_solana],
        )
        .err()
        .ok_or_else(|| anyhow!("over-bound withdraw must fail"))?;
    assert_custom_error(
        "over-bound withdraw",
        &anyhow!("{err:?}"),
        INSUFFICIENT_LIQUIDITY,
    );

    // rebalance_liquidity moves no public value: any interface transfer in the
    // forwarded transact is a mismatch. The builder cannot produce this
    // malformed payload, so hand-roll the instruction; the gate fires before
    // the account tail is touched.
    let mut bad_transact = dummy_transact();
    bad_transact.interface_transfers = vec![InterfaceTransfer::SplWithdrawal {
        amount: 1,
        spl_interface_bump: 0,
    }];
    let rebalance_data = dynamic_swap_sdk::RebalanceLiquidityIxData {
        proof: Groth16ProofBytes {
            proof_a: [0u8; 32],
            proof_b: [0u8; 64],
            proof_c: [0u8; 32],
        },
        credit: 0,
        transact: bad_transact,
    };
    let mut rebalance_bytes = vec![dynamic_swap_sdk::tag::REBALANCE_LIQUIDITY];
    rebalance_bytes.extend_from_slice(
        &wincode::serialize(&rebalance_data).map_err(|e| anyhow!("serialize rebalance: {e:?}"))?,
    );
    let rebalance_ix = solana_instruction::Instruction {
        program_id: dynamic_swap_program::ID,
        accounts: vec![
            solana_instruction::AccountMeta::new(authority_solana.pubkey(), true),
            solana_instruction::AccountMeta::new(pair, false),
        ],
        data: rebalance_bytes,
    };
    let err = env
        .client
        .rpc()
        .create_and_send_transaction(
            &[rebalance_ix],
            authority_solana.pubkey(),
            &[&authority_solana],
        )
        .err()
        .ok_or_else(|| anyhow!("rebalance with an interface transfer must fail"))?;
    assert_custom_error(
        "rebalance with an interface transfer",
        &anyhow!("{err:?}"),
        INTERFACE_TRANSFER_MISMATCH,
    );

    // deposit_liquidity with a mint that is not the pair's destination asset.
    let deposit_ix = DepositLiquidity {
        depositor: authority_solana.pubkey(),
        pair,
        tree: Pubkey::new_unique(),
        mint: env.spl_mint,
        user_token: Pubkey::new_unique(),
        token_program: zolana_interface::pda::spl_token_program_id(),
        amount: 1,
        blinding: random_blinding(),
    }
    .instruction()
    .map_err(|e| anyhow!("deposit instruction: {e:?}"))?;
    let err = env
        .client
        .rpc()
        .create_and_send_transaction(
            &[deposit_ix],
            authority_solana.pubkey(),
            &[&authority_solana],
        )
        .err()
        .ok_or_else(|| anyhow!("deposit with the wrong mint must fail"))?;
    assert_custom_error(
        "deposit with the wrong mint",
        &anyhow!("{err:?}"),
        ASSET_MISMATCH,
    );

    // deposit_liquidity with a zero amount does not form a valid pool note.
    let deposit_ix = DepositLiquidity {
        depositor: authority_solana.pubkey(),
        pair,
        tree: Pubkey::new_unique(),
        mint: env.dest_mint,
        user_token: Pubkey::new_unique(),
        token_program: zolana_interface::pda::spl_token_program_id(),
        amount: 0,
        blinding: random_blinding(),
    }
    .instruction()
    .map_err(|e| anyhow!("deposit instruction: {e:?}"))?;
    let err = env
        .client
        .rpc()
        .create_and_send_transaction(
            &[deposit_ix],
            authority_solana.pubkey(),
            &[&authority_solana],
        )
        .err()
        .ok_or_else(|| anyhow!("zero-amount deposit must fail"))?;
    assert_custom_error(
        "zero-amount deposit",
        &anyhow!("{err:?}"),
        INVALID_DEPOSIT_ENTRY,
    );

    // Client-side rejections: the proof builders refuse inputs the circuits
    // would reject, so a bad payload never reaches proving.
    client_side_rejections(&env, pair, maker_encryption_pubkey)?;

    Ok(())
}

// The proof-input builders mirror the circuits' constraints and bail before
// proving: an over-cap order, a booked overdraw, and an over-credited
// rebalance are all client errors, not on-chain ones.
fn client_side_rejections(
    env: &TestEnv,
    pair: Pubkey,
    maker_encryption_pubkey: [u8; 33],
) -> Result<()> {
    let pool_authority =
        dynamic_swap_sdk::state::pool_authority_address(&pair, &maker_encryption_pubkey)
            .map_err(|e| anyhow!("pool authority address: {e:?}"))?;
    let destination_asset =
        asset_field(&env.dest_mint).map_err(|e| anyhow!("destination asset: {e:?}"))?;

    // escrow_open: owed = order_amount * execution_price must fit
    // max_order_size.
    let over_cap_amount = MAX_ORDER_SIZE / PRICE + 1;
    let source_in = SppProofInputUtxo::new(
        Utxo {
            owner: env.user.address()?.signing_pubkey,
            asset: env.spl_mint,
            amount: over_cap_amount,
            blinding: random_blinding(),
            ring_program_id: None,
            data: Default::default(),
        },
        &env.user.keypair,
    );
    let order_out = zolana_transaction::instructions::transact::SppProofOutputUtxo::new(
        env.spl_mint,
        over_cap_amount,
        env.user.address()?,
    )
    .map_err(|e| anyhow!("order_out: {e:?}"))?;
    let taker_change = zolana_transaction::instructions::transact::SppProofOutputUtxo::new(
        env.spl_mint,
        0,
        env.user.address()?,
    )
    .map_err(|e| anyhow!("taker_change: {e:?}"))?;
    assert!(
        EscrowOpenProofInputParams {
            source_in,
            order_out,
            taker_change,
            escrow_authority_owner_hash: [1u8; 32],
            source_asset: asset_field(&env.spl_mint).map_err(|e| anyhow!("{e:?}"))?,
            execution_price: PRICE,
            max_order_size: MAX_ORDER_SIZE,
            order_amount: over_cap_amount,
            external_data_hash: [0u8; 32],
        }
        .to_proof_inputs()
        .is_err(),
        "escrow_open must reject owed > max_order_size client-side"
    );

    // pool_withdraw: the withdrawn amount must not exceed the note's booked
    // value.
    assert!(
        dynamic_swap_sdk::instructions::withdraw_liquidity::WithdrawProofInputParams {
            pool_in: PoolUtxo {
                asset: env.dest_mint,
                amount: 100,
                booked: 10,
                blinding: random_blinding(),
            },
            pool_out: PoolUtxo {
                asset: env.dest_mint,
                amount: 50,
                booked: 0,
                blinding: random_blinding(),
            },
            pool_authority,
            amount: 50,
            destination_asset,
            external_data_hash: [0u8; 32],
        }
        .to_proof_inputs()
        .is_err(),
        "pool_withdraw must reject an overdraw of booked client-side"
    );

    // pool_rebalance: the credit is capped by the spent notes' surplus.
    assert!(
        dynamic_swap_sdk::instructions::rebalance_liquidity::RebalanceProofInputParams {
            inputs: vec![PoolUtxo {
                asset: env.dest_mint,
                amount: 100,
                booked: 90,
                blinding: random_blinding(),
            }],
            outputs: vec![PoolUtxo {
                asset: env.dest_mint,
                amount: 100,
                booked: 120,
                blinding: random_blinding(),
            }],
            pool_authority,
            credit: 30,
            destination_asset,
        }
        .prepare()
        .is_err(),
        "pool_rebalance must reject booked_out > amount_out client-side"
    );

    Ok(())
}
