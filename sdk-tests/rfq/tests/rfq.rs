use zolana_test_utils::utxo::{
    encrypt_transaction_data, get_transaction_viewing_key, prepare_output_blindings,
};
use zolana_transaction::utxo::SppProofInputUtxo;
mod shared;

use anyhow::{anyhow, Result};
use shared::{send_cosigned, setup, TestEnv, BUY_USDC, SELL_SOL};
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_interface::instruction::Transact;
use zolana_transaction::{
    instructions::transact::{ExternalData, SppProofInputs, SppProofOutputUtxo},
    Data, Utxo, SOL_ASSET_ID, SOL_MINT,
};
use zolana_wallet::{sync_wallet, Filter};

// `Transact` places the shielded-pool and System Program accounts after the
// payer/tree prefix, so the additional taker signer lands at account index 5,
// before the settlement accounts.

#[test]
fn cosigned_rfq_settlement() -> Result<()> {
    let TestEnv {
        localnet,
        mut maker,
        mut taker,
        usdc_mint,
    } = setup(9)?;

    let maker_address = maker.keypair.shielded_address()?;
    let taker_address = taker.keypair.shielded_address()?;
    let maker_solana = &maker.keypair;
    let taker_solana = &taker.keypair;

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

    let maker_input_utxo = SppProofInputUtxo::from(maker_sol_utxo);
    let taker_input_utxo = SppProofInputUtxo::from(taker_usdc_utxo);
    let inputs = vec![maker_input_utxo, taker_input_utxo];

    let sol_to_taker =
        SppProofOutputUtxo::new(zolana_transaction::Mint::SOL, SELL_SOL, taker_address)?;
    let usdc_to_maker =
        SppProofOutputUtxo::new(maker.registry.mint(&usdc_mint)?, BUY_USDC, maker_address)?;
    let mut outputs = vec![sol_to_taker, usdc_to_maker];
    let blinding_seed = prepare_output_blindings(&inputs, &mut outputs)?;

    let transaction_viewing_key = get_transaction_viewing_key(&maker.keypair, &inputs)
        .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
    let encoded = encrypt_transaction_data(&outputs, &transaction_viewing_key, localnet.tree_id)?;

    let external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    let proof_inputs = SppProofInputs {
        input_utxos: inputs,
        output_utxos: encoded.output_utxos,
        external_data,
        payer: maker_address.solana_address()?,
        blinding_seed,
        output_tree_id: localnet.tree_id,
    };

    let data = localnet
        .client
        .prove_transact(
            proof_inputs,
            None,
            &zolana_test_utils::utxo::ProofKeys(&[
                &maker.keypair.nullifier_key,
                &taker.keypair.nullifier_key,
            ]),
        )
        .map_err(|e| anyhow!("prove transact: {e:?}"))?;
    let ix = Transact {
        payer: maker_solana.pubkey(),
        input_trees: vec![localnet.tree],
        output_tree: localnet.tree,
        owner_signers: vec![taker_solana.pubkey()],
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction();

    let signature = send_cosigned(localnet.client.rpc(), &maker_solana, &taker_solana, ix)?;
    localnet
        .client
        .confirm_private_transaction_sync(signature)
        .map_err(|e| anyhow!("confirm settlement indexed: {e:?}"))?;

    let sol_output = outputs
        .first()
        .ok_or_else(|| anyhow!("missing sol output"))?;
    let usdc_output = outputs
        .get(1)
        .ok_or_else(|| anyhow!("missing usdc output"))?;
    let sol_to_taker_hash = sol_output
        .hash(localnet.tree_id)
        .map_err(|e| anyhow!("sol output hash: {e:?}"))?;
    let usdc_to_maker_hash = usdc_output
        .hash(localnet.tree_id)
        .map_err(|e| anyhow!("usdc output hash: {e:?}"))?;
    localnet
        .client
        .indexer()
        .get_merkle_proofs(
            localnet.tree,
            vec![sol_to_taker_hash, usdc_to_maker_hash],
            None,
        )
        .map_err(|e| anyhow!("settlement outputs index: {e}"))?;

    sync_wallet(&mut maker.wallet, &maker.keypair, localnet.client.indexer())
        .map_err(|e| anyhow!("resync maker: {e:?}"))?;
    sync_wallet(&mut taker.wallet, &taker.keypair, localnet.client.indexer())
        .map_err(|e| anyhow!("resync taker: {e:?}"))?;

    let usdc_asset_id = maker.registry.asset_id(&usdc_mint)?;
    assert_eq!(
        {
            let balance = taker.balance(SOL_MINT, None)?;
            (
                balance.asset_id,
                balance.mint,
                balance.amount,
                balance
                    .utxos
                    .into_iter()
                    .map(|note| note.utxo)
                    .collect::<Vec<_>>(),
            )
        },
        (
            SOL_ASSET_ID,
            SOL_MINT,
            SELL_SOL,
            vec![Utxo {
                owner: taker_address.signing_pubkey,
                asset: zolana_transaction::Mint::SOL,
                amount: SELL_SOL,
                blinding: sol_output.blinding,
                ring_program_id: None,
                data: Data::default(),
            }],
        ),
        "taker received the settled SOL utxo"
    );
    assert_eq!(
        {
            let balance = maker.balance(usdc_mint, None)?;
            (
                balance.asset_id,
                balance.mint,
                balance.amount,
                balance
                    .utxos
                    .into_iter()
                    .map(|note| note.utxo)
                    .collect::<Vec<_>>(),
            )
        },
        (
            usdc_asset_id,
            usdc_mint,
            BUY_USDC,
            vec![Utxo {
                owner: maker_address.signing_pubkey,
                asset: maker.registry.mint(&usdc_mint)?,
                amount: BUY_USDC,
                blinding: usdc_output.blinding,
                ring_program_id: None,
                data: Data::default(),
            }],
        ),
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
