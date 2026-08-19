mod shared;

use anyhow::{anyhow, Result};
use dynamic_swap_sdk::{
    instructions::{
        rebalance_liquidity::{RebalanceLiquidity, RebalanceProofInputParams},
        withdraw_liquidity::{WithdrawLiquidity, WithdrawProofInputParams, WithdrawSplAccounts},
    },
    prover::DynamicSwapProverClient,
    state::PoolUtxo,
    Groth16ProofBytes,
};
use shared::{
    assert_liquidity, deposit_pool_liquidity, discover_pool_notes_with_retry,
    pool_authority_identity, send_v0_with_lookup_table, setup_with_pair, token_balance,
    MAKER_DEST_BALANCE,
};
use solana_signer::Signer;
use zolana_keypair::{random_blinding, ShieldedAddress};
use zolana_transaction::instructions::transact::{
    encrypt_transaction_data, get_transaction_viewing_key, spp_proof_inputs::asset_field,
    ExternalData, SettlementTransfer, SppProofInputs,
};

const PRICE: u64 = 5;
const EXPIRY_SLOTS: u64 = 100_000;
const MAX_ORDER_SIZE: u64 = 600_000_000;

const POOL_DEPOSIT: u64 = 2_000_000_000;
const SPLIT_A: u64 = 1_200_000_000;
const SPLIT_B: u64 = POOL_DEPOSIT - SPLIT_A;
const WITHDRAW_AMOUNT: u64 = 500_000_000;

struct PoolCx<'a> {
    env: &'a shared::TestEnv,
    pair: solana_pubkey::Pubkey,
    pool_address: ShieldedAddress,
    destination_asset: [u8; 32],
    prover: DynamicSwapProverClient,
}

/// Send one rebalance (any real in/out layout, credit 0 here) and return the
/// created notes.
fn rebalance(
    cx: &PoolCx,
    inputs: Vec<PoolUtxo>,
    outputs: Vec<PoolUtxo>,
    credit: u64,
) -> Result<()> {
    let authority_solana = &cx.env.authority.keypair;
    let prepared = RebalanceProofInputParams {
        inputs,
        outputs,
        pool_authority: cx.pool_address,
        credit,
        destination_asset: cx.destination_asset,
    }
    .prepare()
    .map_err(|e| anyhow!("rebalance prepare: {e:?}"))?;

    // The canonical padded assembly handles the dummy slots' owner tags and
    // ciphertexts; its external data hash feeds the swap proof.
    let spp_proof_inputs = prepared
        .spp_proof_inputs(
            &cx.env.authority.keypair,
            &cx.env.assets,
            authority_solana.pubkey(),
        )
        .map_err(|e| anyhow!("rebalance spp inputs: {e:?}"))?;
    let external_data_hash = spp_proof_inputs
        .external_data
        .hash()
        .map_err(|e| anyhow!("external data hash: {e:?}"))?;
    let bundle = prepared
        .to_proof_inputs(external_data_hash)
        .map_err(|e| anyhow!("rebalance proof inputs: {e:?}"))?;
    let proof = cx
        .prover
        .prove_pool_rebalance(&bundle.proof_inputs)
        .map_err(|e| anyhow!("prove pool_rebalance: {e:?}"))?;

    let transact = cx
        .env
        .client
        .indexer()
        .prove_transact(cx.env.tree, spp_proof_inputs)
        .map_err(|e| anyhow!("prove_transact: {e:?}"))?;

    let ix = RebalanceLiquidity {
        authority: authority_solana.pubkey(),
        pair: cx.pair,
        tree: cx.env.tree,
        credit,
        proof: Groth16ProofBytes {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
        },
        transact,
    }
    .instruction()
    .map_err(|e| anyhow!("rebalance instruction: {e:?}"))?;
    send_v0_with_lookup_table(cx.env.client.rpc(), &authority_solana, &[], ix)
        .map_err(|e| anyhow!("send rebalance: {e:?}"))?;
    Ok(())
}

/// Send one withdrawal (`amount = 0` re-blinds) from `pool_in` into `pool_out`.
fn withdraw(cx: &PoolCx, pool_in: PoolUtxo, pool_out: PoolUtxo, amount: u64) -> Result<()> {
    let authority_solana = &cx.env.authority.keypair;
    let spp_input = pool_in
        .to_input_utxo(&cx.pool_address)
        .map_err(|e| anyhow!("pool_in: {e:?}"))?;
    let spp_output = pool_out
        .output_utxo(&cx.pool_address)
        .map_err(|e| anyhow!("pool_out: {e:?}"))?;

    let viewing_key =
        get_transaction_viewing_key(&cx.env.authority.keypair, std::slice::from_ref(&spp_input))
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
    let encoded = encrypt_transaction_data(
        std::slice::from_ref(&spp_output),
        &cx.env.assets,
        &viewing_key,
    )
    .map_err(|e| anyhow!("encode outputs: {e:?}"))?;
    let mut external_data = ExternalData::new(
        *viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    if amount > 0 {
        external_data = external_data
            .with_interface_transfer(SettlementTransfer::Spl {
                mint: cx.env.dest_mint,
                is_deposit: false,
                amount,
                user_spl_token: solana_address::Address::new_from_array(
                    cx.env.authority_dest_token.to_bytes(),
                ),
                spl_token_interface: solana_address::Address::new_from_array(
                    zolana_interface::pda::spl_interface(&cx.env.dest_mint).to_bytes(),
                ),
            })
            .map_err(|e| anyhow!("interface transfer: {e:?}"))?;
    }
    let external_data_hash = external_data
        .hash()
        .map_err(|e| anyhow!("external data hash: {e:?}"))?;

    let bundle = WithdrawProofInputParams {
        pool_in,
        pool_out,
        pool_authority: cx.pool_address,
        amount,
        destination_asset: cx.destination_asset,
        external_data_hash,
    }
    .to_proof_inputs()
    .map_err(|e| anyhow!("withdraw proof inputs: {e:?}"))?;
    let proof = cx
        .prover
        .prove_pool_withdraw(&bundle.proof_inputs)
        .map_err(|e| anyhow!("prove pool_withdraw: {e:?}"))?;

    let spp_proof_inputs = SppProofInputs::new(
        vec![bundle.spp_input],
        encoded.output_utxos,
        external_data,
        authority_solana.pubkey(),
    );
    let transact = cx
        .env
        .client
        .indexer()
        .prove_transact(cx.env.tree, spp_proof_inputs)
        .map_err(|e| anyhow!("prove_transact: {e:?}"))?;

    let ix = WithdrawLiquidity {
        authority: authority_solana.pubkey(),
        pair: cx.pair,
        tree: cx.env.tree,
        amount,
        spl: (amount > 0).then(|| WithdrawSplAccounts {
            mint: solana_pubkey::Pubkey::new_from_array(cx.env.dest_mint.to_bytes()),
            user_token: cx.env.authority_dest_token,
            token_program: zolana_interface::pda::spl_token_program_id(),
        }),
        proof: Groth16ProofBytes {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
        },
        transact,
    }
    .instruction()
    .map_err(|e| anyhow!("withdraw instruction: {e:?}"))?;
    send_v0_with_lookup_table(cx.env.client.rpc(), &authority_solana, &[], ix)
        .map_err(|e| anyhow!("send withdraw: {e:?}"))?;
    Ok(())
}

// Pool lifecycle without any escrow: deposit -> split (1->2, credit 0) ->
// merge (2->1, credit 0) -> partial withdrawal -> re-blind (amount 0) ->
// drain. Asserts the public accounting after every step and that the maker's
// token balance round-trips: every unit deposited comes back.
#[test]
fn pool_deposit_rebalance_withdraw() -> Result<()> {
    let (env, pair) = setup_with_pair(PRICE, EXPIRY_SLOTS, MAX_ORDER_SIZE)?;
    let pool_owner = pool_authority_identity(&env.authority.keypair, &pair)?;
    let pool_address = pool_owner
        .shielded_address()
        .map_err(|e| anyhow!("pool authority address: {e:?}"))?;
    let cx = PoolCx {
        env: &env,
        pair,
        pool_address,
        destination_asset: asset_field(&env.dest_mint)
            .map_err(|e| anyhow!("destination asset: {e:?}"))?,
        prover: DynamicSwapProverClient::new(),
    };

    // Deposit: the fully public note raises the bound by its exact amount.
    let deposit_note = deposit_pool_liquidity(&env, pair, POOL_DEPOSIT)?;
    assert_liquidity(&env, pair, POOL_DEPOSIT, 0, "after deposit")?;
    let discovered = discover_pool_notes_with_retry(&env, &pool_owner, 1)?;
    assert_eq!(discovered.len(), 1, "deposit note must be discoverable");

    // Split 1 -> 2 (credit 0): pre-sizing for parallel settles; no public
    // effect beyond the new notes.
    let note_a = PoolUtxo {
        asset: env.dest_mint,
        amount: SPLIT_A,
        booked: SPLIT_A,
        blinding: random_blinding(),
    };
    let note_b = PoolUtxo {
        asset: env.dest_mint,
        amount: SPLIT_B,
        booked: SPLIT_B,
        blinding: random_blinding(),
    };
    rebalance(
        &cx,
        vec![deposit_note],
        vec![note_a.clone(), note_b.clone()],
        0,
    )?;
    assert_liquidity(&env, pair, POOL_DEPOSIT, 0, "after split")?;

    // Merge 2 -> 1 (credit 0), and the merged note is now confidential (the
    // maker's own fresh blinding, encrypted slot).
    let merged = PoolUtxo {
        asset: env.dest_mint,
        amount: POOL_DEPOSIT,
        booked: POOL_DEPOSIT,
        blinding: random_blinding(),
    };
    rebalance(&cx, vec![note_a, note_b], vec![merged.clone()], 0)?;
    assert_liquidity(&env, pair, POOL_DEPOSIT, 0, "after merge")?;

    // Partial withdrawal: bound and booked both drop by the public amount, and
    // the tokens land back in the maker's account.
    let balance_before = token_balance(&env, env.authority_dest_token)?;
    let after_withdraw = PoolUtxo {
        asset: env.dest_mint,
        amount: POOL_DEPOSIT - WITHDRAW_AMOUNT,
        booked: POOL_DEPOSIT - WITHDRAW_AMOUNT,
        blinding: random_blinding(),
    };
    withdraw(&cx, merged, after_withdraw.clone(), WITHDRAW_AMOUNT)?;
    assert_liquidity(
        &env,
        pair,
        POOL_DEPOSIT - WITHDRAW_AMOUNT,
        0,
        "after withdraw",
    )?;
    assert_eq!(
        token_balance(&env, env.authority_dest_token)?,
        balance_before + WITHDRAW_AMOUNT,
        "withdrawal must land in the maker's token account"
    );

    // Re-blind (amount 0): rotates the note with no SPL leg and no public
    // effect.
    let reblinded = PoolUtxo {
        asset: env.dest_mint,
        amount: after_withdraw.amount,
        booked: after_withdraw.booked,
        blinding: random_blinding(),
    };
    withdraw(&cx, after_withdraw, reblinded.clone(), 0)?;
    assert_liquidity(
        &env,
        pair,
        POOL_DEPOSIT - WITHDRAW_AMOUNT,
        0,
        "after re-blind",
    )?;

    // Drain the rest: the pool and the bound return to zero, and the maker's
    // token balance round-trips to its starting value.
    let empty = PoolUtxo {
        asset: env.dest_mint,
        amount: 0,
        booked: 0,
        blinding: random_blinding(),
    };
    withdraw(&cx, reblinded.clone(), empty, reblinded.amount)?;
    assert_liquidity(&env, pair, 0, 0, "after drain")?;
    assert_eq!(
        token_balance(&env, env.authority_dest_token)?,
        MAKER_DEST_BALANCE,
        "every deposited unit must round-trip back to the maker"
    );

    Ok(())
}
