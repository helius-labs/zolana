mod shared;

use anyhow::{anyhow, Result};
use dynamic_swap_sdk::{
    instructions::{
        rebalance_liquidity::{RebalanceLiquidity, RebalanceProofInputParams},
        withdraw_liquidity::{WithdrawLiquidity, WithdrawProofInputParams, WithdrawSplAccounts},
    },
    prover::DynamicSwapProverClient,
    shared::transaction_blindings,
    state::{IndexedPoolNote, PoolUtxo},
    Groth16ProofBytes,
};
use shared::{
    assert_liquidity, deposit_pool_liquidity, discover_pool_notes_with_retry,
    pool_authority_identity, send, setup_with_pair, token_balance, MAKER_DEST_BALANCE,
};
use solana_signer::Signer;
use zolana_keypair::{random_blinding, ShieldedAddress, ShieldedPda};
use zolana_test_utils::utxo::{encrypt_transaction_data, get_transaction_viewing_key};
use zolana_transaction::instructions::transact::{
    asset_field, ExternalData, SettlementTransfer, SppProofInputs,
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
    pool_owner: ShieldedPda,
    pool_address: ShieldedAddress,
    destination_asset: [u8; 32],
    prover: DynamicSwapProverClient,
}

impl PoolCx<'_> {
    /// A pool note of `amount` fully booked; its blinding is replaced by SPP's
    /// derivation for the slot it lands in.
    fn note(&self, amount: u64) -> PoolUtxo {
        PoolUtxo {
            asset: self.env.destination_mint(),
            amount,
            booked: amount,
            blinding: random_blinding(),
        }
    }

    fn indexed(&self, note: PoolUtxo) -> Result<IndexedPoolNote> {
        let leaf = note
            .output_utxo(&self.pool_address)?
            .hash(self.env.localnet.tree_id)
            .map_err(|e| anyhow!("pool note hash: {e:?}"))?;
        Ok(IndexedPoolNote {
            note,
            leaf_index: self.env.leaf_index(leaf),
        })
    }
}

/// Send one rebalance (any real in/out layout) and return the committed output
/// notes.
fn rebalance(
    cx: &PoolCx,
    inputs: Vec<IndexedPoolNote>,
    outputs: Vec<PoolUtxo>,
    credit: u64,
) -> Result<Vec<IndexedPoolNote>> {
    let authority_solana = &cx.env.authority.keypair;
    let prepared = RebalanceProofInputParams {
        inputs,
        outputs,
        pool_authority: cx.pool_address,
        credit,
        destination_asset: cx.destination_asset,
        tree_id: cx.env.localnet.tree_id,
    }
    .prepare()
    .map_err(|e| anyhow!("rebalance prepare: {e:?}"))?;

    // The external data hash of the padded transact feeds the swap proof.
    let spp_proof_inputs = prepared
        .spp_proof_inputs(&cx.env.authority.keypair, authority_solana.pubkey())
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
        .localnet
        .client
        .indexer()
        .prove_transact(spp_proof_inputs, cx.pool_owner.as_ref())
        .map_err(|e| anyhow!("prove_transact: {e:?}"))?;

    let ix = RebalanceLiquidity {
        authority: authority_solana.pubkey(),
        pair: cx.pair,
        tree: cx.env.localnet.tree,
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
    send(cx.env.localnet.client.rpc(), authority_solana, &[], ix)
        .map_err(|e| anyhow!("send rebalance: {e:?}"))?;
    prepared
        .outputs
        .into_iter()
        .map(|note| cx.indexed(note))
        .collect()
}

/// Withdraw `amount` from `pool_in` and return the committed change note.
fn withdraw(cx: &PoolCx, pool_in: IndexedPoolNote, amount: u64) -> Result<IndexedPoolNote> {
    let authority_solana = &cx.env.authority.keypair;
    let tree_id = cx.env.localnet.tree_id;
    let spp_input = pool_in
        .to_input_utxo(&cx.pool_address, tree_id)
        .map_err(|e| anyhow!("pool_in: {e:?}"))?;
    // SPP derives the change blinding from the transaction's seed.
    let blinding_seed = random_blinding();
    let (private_tx_blinding, blindings) =
        transaction_blindings(&spp_input.nullifier(), &blinding_seed, 1)?;
    let remaining = pool_in
        .note
        .amount
        .checked_sub(amount)
        .ok_or_else(|| anyhow!("withdrawal exceeds the pool note"))?;
    let pool_out = PoolUtxo {
        blinding: blindings
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("withdraw derives a change blinding"))?,
        booked: pool_in
            .note
            .booked
            .checked_sub(amount)
            .ok_or_else(|| anyhow!("withdrawal exceeds the booked value"))?,
        ..cx.note(remaining)
    };
    let spp_output = pool_out
        .output_utxo(&cx.pool_address)
        .map_err(|e| anyhow!("pool_out: {e:?}"))?;

    let viewing_key =
        get_transaction_viewing_key(&cx.env.authority.keypair, std::slice::from_ref(&spp_input))
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
        mint: cx.env.dest_mint,
        is_deposit: false,
        amount,
        user_spl_token: cx.env.authority_dest_token,
    })
    .map_err(|e| anyhow!("interface transfer: {e:?}"))?;
    let external_data_hash = external_data
        .hash()
        .map_err(|e| anyhow!("external data hash: {e:?}"))?;

    let proof_inputs = WithdrawProofInputParams {
        pool_in: pool_in.note.clone(),
        pool_out: pool_out.clone(),
        pool_authority: cx.pool_address,
        amount,
        destination_asset: cx.destination_asset,
        external_data_hash,
        private_tx_blinding,
        tree_id,
    }
    .to_proof_inputs()
    .map_err(|e| anyhow!("withdraw proof inputs: {e:?}"))?;
    let proof = cx
        .prover
        .prove_pool_withdraw(&proof_inputs)
        .map_err(|e| anyhow!("prove pool_withdraw: {e:?}"))?;

    let spp_proof_inputs = SppProofInputs {
        input_utxos: vec![spp_input],
        output_utxos: encoded.output_utxos,
        external_data,
        payer: authority_solana.pubkey(),
        blinding_seed,
        output_tree_id: tree_id,
    };
    let transact = cx
        .env
        .localnet
        .client
        .indexer()
        .prove_transact(spp_proof_inputs, cx.pool_owner.as_ref())
        .map_err(|e| anyhow!("prove_transact: {e:?}"))?;

    let ix = WithdrawLiquidity {
        authority: authority_solana.pubkey(),
        pair: cx.pair,
        tree: cx.env.localnet.tree,
        amount,
        spl: WithdrawSplAccounts {
            mint: cx.env.dest_mint,
            user_token: cx.env.authority_dest_token,
            token_program: zolana_interface::pda::spl_token_program_id(),
        },
        proof: Groth16ProofBytes {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
        },
        transact,
    }
    .instruction()
    .map_err(|e| anyhow!("withdraw instruction: {e:?}"))?;
    send(cx.env.localnet.client.rpc(), authority_solana, &[], ix)
        .map_err(|e| anyhow!("send withdraw: {e:?}"))?;
    cx.indexed(pool_out)
}

// Pool lifecycle without any escrow: deposit -> split (1->2, credit 0) ->
// merge (2->1, credit 0) -> partial withdrawal -> full withdrawal. Asserts the public
// accounting after every step and that the maker's token balance round-trips:
// every unit deposited comes back.
#[test]
fn pool_deposit_rebalance_withdraw() -> Result<()> {
    let (env, pair) = setup_with_pair(11, PRICE, EXPIRY_SLOTS, MAX_ORDER_SIZE)?;
    let pool_owner = pool_authority_identity(&env.authority.keypair, &pair)?;
    let pool_address = pool_owner
        .shielded_address()
        .map_err(|e| anyhow!("pool authority address: {e:?}"))?;
    let cx = PoolCx {
        env: &env,
        pair,
        pool_owner,
        pool_address,
        destination_asset: asset_field(&env.dest_mint)
            .map_err(|e| anyhow!("destination asset: {e:?}"))?,
        prover: DynamicSwapProverClient::new(),
    };

    // Deposit: the fully public note raises the bound by its exact amount.
    let deposit_note = deposit_pool_liquidity(&env, pair, POOL_DEPOSIT)?;
    assert_liquidity(&env, pair, POOL_DEPOSIT, 0, "after deposit")?;
    let discovered = discover_pool_notes_with_retry(&env, &cx.pool_owner, 1)?;
    assert_eq!(discovered.len(), 1, "deposit note must be discoverable");

    // Split 1 -> 2 (credit 0): pre-sizing for parallel settles; no public
    // effect beyond the new notes.
    let split = rebalance(
        &cx,
        vec![deposit_note],
        vec![cx.note(SPLIT_A), cx.note(SPLIT_B)],
        0,
    )?;
    assert_liquidity(&env, pair, POOL_DEPOSIT, 0, "after split")?;

    // Merge 2 -> 1 (credit 0), and the merged note is now confidential (a
    // derived blinding, no public payload).
    let merged = rebalance(&cx, split, vec![cx.note(POOL_DEPOSIT)], 0)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("merge keeps its output note"))?;
    assert_liquidity(&env, pair, POOL_DEPOSIT, 0, "after merge")?;

    // Partial withdrawal: bound and booked both drop by the public amount, and
    // the tokens land back in the maker's account.
    let balance_before = token_balance(&env, env.authority_dest_token)?;
    let after_withdraw = withdraw(&cx, merged, WITHDRAW_AMOUNT)?;
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

    // Withdraw the remainder: the pool and the bound return to zero, and the maker's
    // token balance round-trips to its starting value.
    withdraw(&cx, after_withdraw, POOL_DEPOSIT - WITHDRAW_AMOUNT)?;
    assert_liquidity(&env, pair, 0, 0, "after complete withdrawal")?;
    assert_eq!(
        token_balance(&env, env.authority_dest_token)?,
        MAKER_DEST_BALANCE,
        "every deposited unit must round-trip back to the maker"
    );

    Ok(())
}
