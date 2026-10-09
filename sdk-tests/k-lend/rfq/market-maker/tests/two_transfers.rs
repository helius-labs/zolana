use anyhow::{anyhow, Result};
use zolana_client::{sign_transaction, Rpc};
use zolana_interface::pda;
use zolana_test_utils::wallet::Wallet;
use zolana_transaction::WalletUtxo;

use k_lend_market_maker::{swap_message, transfers, Holdings};
use k_lend_rfq_sdk::transfer::Transfer;

use k_lend_rfq_test_utils::{
    chain::{blocking, compute_units},
    setup::{setup, TestEnv, USER_SHIELD_COLLATERAL},
    wallet::TestWallet,
};

const MAKER_SHIELD_COLLATERAL: u64 = 50_000_000;
const USER_PAYS: u64 = 7_000_000;
const MAKER_PAYS: u64 = 3_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_transacts_against_one_tree_settle_in_one_transaction() -> Result<()> {
    let TestEnv {
        localnet,
        mut user,
        market_maker,
        collateral_mint,
        pair,
        ..
    } = setup(15).await?;
    let rpc = localnet.client.rpc();
    market_maker
        .seed_inventory(&pair, 0, MAKER_SHIELD_COLLATERAL)
        .await?;

    let first_utxo = |wallet: &Wallet| -> Result<WalletUtxo> {
        wallet
            .balance(collateral_mint, None)?
            .utxos
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("no collateral utxo"))
    };
    let user_wallet: &TestWallet = user.wallet();
    let user_transfer = blocking(|| {
        Transfer {
            inputs: vec![first_utxo(user_wallet)?],
            width: 1,
            amount: USER_PAYS,
            recipient: market_maker.identity(),
            payer: market_maker.address(),
            tree: localnet.tree,
            tree_id: localnet.tree_id,
        }
        .prove(&localnet.client, &user_wallet.keypair)
    })?;
    let user_identity = user.identity();
    let maker_address = market_maker.address();
    let maker_inputs = vec![market_maker
        .spendable(&collateral_mint)
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("no maker collateral utxo"))?];
    let maker_keypair = market_maker.keypair();
    let maker_transfer = blocking(|| {
        Transfer {
            inputs: maker_inputs,
            width: 1,
            amount: MAKER_PAYS,
            recipient: user_identity,
            payer: maker_address,
            tree: localnet.tree,
            tree_id: localnet.tree_id,
        }
        .prove(&localnet.client, maker_keypair)
    })?;
    let nullifiers = [
        *user_transfer
            .nullifiers
            .first()
            .ok_or_else(|| anyhow!("user transfer spends nothing"))?,
        *maker_transfer
            .nullifiers
            .first()
            .ok_or_else(|| anyhow!("maker transfer spends nothing"))?,
    ];
    let (blockhash, _) = blocking(|| rpc.get_latest_blockhash())?;
    let message = swap_message(
        &maker_address,
        [user_transfer.instruction, maker_transfer.instruction],
        blockhash,
    )?;
    let roots: Vec<_> = transfers(&message)?
        .iter()
        .map(|transfer| transfer.tree_contexts.clone())
        .collect();
    assert_eq!(roots.first(), roots.get(1));

    let signature = blocking(|| {
        rpc.process_transaction(sign_transaction(
            message,
            &[maker_keypair, &user.wallet().keypair],
        )?)
    })?;
    blocking(|| localnet.client.confirm_private_transaction_sync(signature))
        .map_err(|e| anyhow!("index two-transfer transaction {signature}: {e:?}"))?;
    println!(
        "two 1x2 transacts in one transaction: {} CU",
        blocking(|| compute_units(rpc, &signature))?
    );

    let nullifier_pdas: Vec<_> = nullifiers
        .iter()
        .map(|nullifier| pda::nullifier_pda(&localnet.tree, nullifier).0)
        .collect();
    assert_ne!(nullifier_pdas.first(), nullifier_pdas.get(1));
    for nullifier_pda in &nullifier_pdas {
        assert!(blocking(|| rpc.get_account(*nullifier_pda))?.is_some());
    }

    user.sync(&localnet).await?;
    market_maker.sync().await?;
    assert_eq!(
        user.holdings(&pair)?,
        Holdings {
            collateral: USER_SHIELD_COLLATERAL - USER_PAYS + MAKER_PAYS,
            shares: 0,
        }
    );
    assert_eq!(
        market_maker.holdings(&pair),
        Holdings {
            collateral: MAKER_SHIELD_COLLATERAL + USER_PAYS - MAKER_PAYS,
            shares: 0,
        }
    );
    market_maker.shutdown().await;
    Ok(())
}
