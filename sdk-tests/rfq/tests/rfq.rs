mod shared;

use anyhow::{anyhow, Result};
use shared::{send_cosigned_v0_with_lookup_table, setup, TestEnv, BUY_USDC, SELL_SOL};
use solana_signer::Signer;
use zolana_client::{IndexerRpcConfig, Rpc};
use zolana_interface::instruction::Transact;
use zolana_transaction::{
    instructions::{
        transact::{
            encrypt_transaction_data, get_transaction_viewing_key, ExternalData, SppProofInputs,
            SppProofOutputUtxo,
        },
        types::SppProofInputUtxo,
    },
    Address, AssetBalance, Data, Filter, Utxo, SOL_ASSET_ID, SOL_MINT,
};
use zolana_wallet::sync_wallet;

// `Transact` places the shielded-pool and System Program accounts after the
// payer/tree prefix, so the additional taker signer lands at account index 5,
// before the settlement accounts.

#[test]
fn cosigned_rfq_settlement() -> Result<()> {
    let TestEnv {
        client,
        tree,
        mut maker,
        mut taker,
        usdc_mint,
    } = setup()?;

    let maker_address = maker.keypair.shielded_address()?;
    let taker_address = taker.keypair.shielded_address()?;
    let maker_solana = maker.keypair.to_solana_keypair()?;
    let taker_solana = taker.keypair.to_solana_keypair()?;

    let maker_sol_utxo = maker
        .balance(SOL_MINT, Some(Filter::MinAmount(SELL_SOL)))?
        .utxos
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("no maker sol utxo >= {SELL_SOL}"))?;
    let taker_usdc_utxo = taker
        .balance(usdc_mint, Some(Filter::MinAmount(BUY_USDC)))?
        .utxos
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("no taker usdc utxo >= {BUY_USDC}"))?;

    let maker_spend = SppProofInputUtxo::new(maker_sol_utxo, &maker.keypair);
    let taker_spend = SppProofInputUtxo::new(taker_usdc_utxo, &taker.keypair);
    let inputs = vec![maker_spend, taker_spend];

    let sol_to_taker = SppProofOutputUtxo::new(SOL_MINT, SELL_SOL, taker_address)?;
    let usdc_to_maker = SppProofOutputUtxo::new(usdc_mint, BUY_USDC, maker_address)?;
    let outputs = vec![sol_to_taker, usdc_to_maker];

    let transaction_viewing_key = get_transaction_viewing_key(&maker.keypair, &inputs)
        .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
    let encoded = encrypt_transaction_data(&outputs, &maker.registry, &transaction_viewing_key)?;

    let external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    let proof_inputs = SppProofInputs::new(
        inputs,
        encoded.output_utxos,
        external_data,
        maker_address.solana_address()?,
    );

    let data = client
        .prove_transact(
            Address::new_from_array(tree.to_bytes()),
            proof_inputs,
            Some(IndexerRpcConfig::wait()),
        )
        .map_err(|e| anyhow!("prove transact: {e:?}"))?;
    let ix = Transact {
        payer: maker_solana.pubkey(),
        input_tree: tree,
        output_tree: tree,
        owner_signers: vec![taker_solana.pubkey()],
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction();

    let signature =
        send_cosigned_v0_with_lookup_table(client.rpc(), &maker_solana, &taker_solana, ix)?;
    client
        .confirm_private_transaction_sync(signature)
        .map_err(|e| anyhow!("confirm settlement indexed: {e:?}"))?;

    let sol_output = outputs
        .first()
        .ok_or_else(|| anyhow!("missing sol output"))?;
    let usdc_output = outputs
        .get(1)
        .ok_or_else(|| anyhow!("missing usdc output"))?;
    let sol_to_taker_hash = sol_output
        .hash()
        .map_err(|e| anyhow!("sol output hash: {e:?}"))?;
    let usdc_to_maker_hash = usdc_output
        .hash()
        .map_err(|e| anyhow!("usdc output hash: {e:?}"))?;
    client
        .indexer()
        .get_merkle_proofs(tree, vec![sol_to_taker_hash, usdc_to_maker_hash], None)
        .map_err(|e| anyhow!("settlement outputs index: {e}"))?;

    sync_wallet(&mut maker.wallet, &maker.keypair, client.indexer())
        .map_err(|e| anyhow!("resync maker: {e:?}"))?;
    sync_wallet(&mut taker.wallet, &taker.keypair, client.indexer())
        .map_err(|e| anyhow!("resync taker: {e:?}"))?;

    let usdc_asset_id = maker.registry.asset_id(&usdc_mint)?;
    assert_eq!(
        taker.balance(SOL_MINT, None)?,
        AssetBalance {
            asset_id: SOL_ASSET_ID,
            mint: SOL_MINT,
            amount: SELL_SOL,
            utxos: vec![Utxo {
                owner: taker_address.signing_pubkey,
                asset: SOL_MINT,
                amount: SELL_SOL,
                blinding: sol_output.blinding,
                ring_program_id: None,
                data: Data::default(),
            }],
        },
        "taker received the settled SOL utxo"
    );
    assert_eq!(
        maker.balance(usdc_mint, None)?,
        AssetBalance {
            asset_id: usdc_asset_id,
            mint: usdc_mint,
            amount: BUY_USDC,
            utxos: vec![Utxo {
                owner: maker_address.signing_pubkey,
                asset: usdc_mint,
                amount: BUY_USDC,
                blinding: usdc_output.blinding,
                ring_program_id: None,
                data: Data::default(),
            }],
        },
        "maker received the settled USDC utxo"
    );
    assert_eq!(
        maker.balance(SOL_MINT, None)?.amount,
        0,
        "maker spent its entire SOL position"
    );
    assert_eq!(
        taker.balance(usdc_mint, None)?.amount,
        0,
        "taker spent its entire USDC position"
    );

    Ok(())
}
