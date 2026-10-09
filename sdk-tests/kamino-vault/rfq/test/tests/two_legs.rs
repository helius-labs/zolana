use anyhow::{anyhow, Result};
use zolana_client::{sign_transaction, Rpc};
use zolana_interface::pda;
use zolana_test_utils::wallet::Wallet;
use zolana_transaction::WalletUtxo;

use kamino_vault_rfq_sdk::{
    swap::{legs, swap_message, Holdings},
    user::Payment,
};

use crate::shared::{blocking, compute_units, setup, TestEnv, TestWallet, USER_SHIELD_USDC};

const MAKER_SHIELD_USDC: u64 = 50_000_000;
const USER_PAYS: u64 = 7_000_000;
const MAKER_PAYS: u64 = 3_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_transacts_against_one_tree_settle_in_one_transaction() -> Result<()> {
    let TestEnv {
        localnet,
        mut user,
        market_maker,
        usdc_mint,
        vault,
        ..
    } = setup(15).await?;
    let rpc = localnet.client.rpc();
    market_maker
        .shield(&localnet, usdc_mint, MAKER_SHIELD_USDC)
        .await?;

    let first_utxo = |wallet: &Wallet| -> Result<WalletUtxo> {
        wallet
            .balance(usdc_mint, None)?
            .utxos
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("no usdc utxo"))
    };
    let user_wallet: &TestWallet = user.wallet();
    let user_leg = blocking(|| {
        Payment {
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
    let (maker_leg, maker_keypair) = market_maker
        .with_wallet(|wallet, keypair| -> Result<_> {
            let leg = Payment {
                inputs: vec![first_utxo(wallet)?],
                width: 1,
                amount: MAKER_PAYS,
                recipient: user_identity,
                payer: maker_address,
                tree: localnet.tree,
                tree_id: localnet.tree_id,
            }
            .prove(&localnet.client, keypair)?;
            Ok((leg, keypair.clone()))
        })
        .await?;
    let nullifiers = [
        *user_leg
            .nullifiers
            .first()
            .ok_or_else(|| anyhow!("user leg spends nothing"))?,
        *maker_leg
            .nullifiers
            .first()
            .ok_or_else(|| anyhow!("maker leg spends nothing"))?,
    ];
    let (blockhash, _) = blocking(|| rpc.get_latest_blockhash())?;
    let message = swap_message(
        &maker_address,
        [user_leg.instruction, maker_leg.instruction],
        blockhash,
    )?;
    let roots: Vec<_> = legs(&message)?
        .iter()
        .map(|leg| leg.tree_contexts.clone())
        .collect();
    assert_eq!(roots.first(), roots.get(1));

    let signature = blocking(|| {
        rpc.process_transaction(sign_transaction(
            message,
            &[&maker_keypair, &user.wallet().keypair],
        )?)
    })?;
    blocking(|| localnet.client.confirm_private_transaction_sync(signature))
        .map_err(|e| anyhow!("index two-leg transaction {signature}: {e:?}"))?;
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
        user.holdings(&vault)?,
        Holdings {
            usdc: USER_SHIELD_USDC - USER_PAYS + MAKER_PAYS,
            shares: 0,
        }
    );
    assert_eq!(
        market_maker.holdings(&vault),
        Holdings {
            usdc: MAKER_SHIELD_USDC + USER_PAYS - MAKER_PAYS,
            shares: 0,
        }
    );
    Ok(())
}
