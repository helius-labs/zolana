mod shared;

use anyhow::{anyhow, Result};
use shared::{
    send_v0_with_lookup_table, setup, TestEnv, LOCK_AMOUNT, SHIELD_AMOUNT, SPP_RELAYER_DEADLINE,
    UNLOCK_TIMESTAMP,
};
use timelock_escrow_sdk::{
    instructions::{
        escrow::{Escrow, EscrowProofInputParams, SppTxHashes},
        withdraw::{Withdraw, WithdrawProofInputParams},
    },
    prover::EscrowProverClient,
    shared::input_sum,
    state::{EscrowTerms, EscrowUtxo},
};
use zolana_client::Rpc;
use zolana_keypair::random_blinding;
use zolana_transaction::{
    instructions::{
        transact::{
            encrypt_transaction_data, get_transaction_viewing_key, ExternalData, SppProofInputs,
            SppProofOutputUtxo,
        },
        types::SppProofInputUtxo,
    },
    AssetBalance, Data, Filter, Utxo, SOL_ASSET_ID, SOL_MINT,
};
use zolana_wallet::sync_wallet;

// Timelock escrow lock-then-withdraw on the shielded pool, driven against a
// real localnet (validator + Photon indexer + prover) that `setup()` starts.
//
// Flow:
//   1. Fund (in setup): creator shields 0.5 SOL; syncs from the indexer to
//      discover and decrypt its own note.
//   2. Escrow: creator spends its 0.5 SOL UTXO -> escrow UTXO 0.3 SOL (owned
//      by the escrow-authority PDA, committed unlock timestamp already in
//      the past) + change 0.2 SOL (back to the creator). ZK escrow proof, v0
//      tx via ALT.
//   3. Withdraw: creator (still holding the escrow UTXO hash locally --
//      no discovery needed) spends the escrow UTXO -> source output 0.3 SOL
//      back to itself. ZK withdraw proof, v0 tx.
//   4. Assert the creator's synced confidential balance after each step, and
//      that the withdraw output is indexed.
//
// Net: creator 0.5 SOL -> 0.2 SOL change + 0.3 SOL returned via withdraw.
#[test]
fn escrow_then_withdraw() -> Result<()> {
    let TestEnv {
        client,
        tree,
        mut creator,
    } = setup()?;

    let terms = EscrowTerms {
        creator: creator.keypair.shielded_address()?,
        unlock_timestamp: UNLOCK_TIMESTAMP,
    };
    let escrow_utxo = EscrowUtxo {
        terms,
        blinding: random_blinding(),
        asset: SOL_MINT,
        amount: LOCK_AMOUNT,
    };

    // escrow: lock `escrow_utxo` -- spend the creator's own shielded balance,
    // append the escrow UTXO (owned by the escrow-authority PDA) plus a
    // change output back to the creator.
    let creator_address = creator.keypair.shielded_address()?;
    let escrow_output_utxo = escrow_utxo.output_utxo()?;

    let creator_input_utxo = creator
        .balance(
            escrow_utxo.asset,
            Some(Filter::MinAmount(escrow_utxo.amount)),
        )?
        .utxos
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("no spendable utxo >= {}", escrow_utxo.amount))?;
    let input_utxo = SppProofInputUtxo::new(creator_input_utxo, &creator.keypair);
    let input_utxos = vec![input_utxo, SppProofInputUtxo::new_dummy()];

    let escrow_utxo_asset = escrow_output_utxo.asset;
    let leftover =
        input_sum(&input_utxos, &escrow_utxo_asset) - i128::from(escrow_output_utxo.amount);
    let change_amount = u64::try_from(leftover)
        .map_err(|_| anyhow!("insufficient shielded balance: {leftover}"))?;
    let change = SppProofOutputUtxo::new(escrow_utxo_asset, change_amount, creator_address)?;
    let change_blinding = change.blinding;

    let transaction_viewing_key = get_transaction_viewing_key(&creator.keypair, &input_utxos)
        .map_err(|e| anyhow!("escrow transaction viewing key: {e:?}"))?;
    let encoded = encrypt_transaction_data(
        &[change.clone(), escrow_output_utxo],
        &creator.registry,
        &transaction_viewing_key,
    )
    .map_err(|e| anyhow!("encode escrow slots: {e:?}"))?;

    let external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    let spp_proof_inputs = SppProofInputs::new(
        input_utxos,
        encoded.output_utxos,
        external_data,
        creator_address.solana_address()?,
    );

    let spp_tx_hashes = SppTxHashes::new(&spp_proof_inputs)?;
    let spp_proof = client
        .indexer()
        .prove_transact(tree, spp_proof_inputs)
        .map_err(|e| anyhow!("escrow transact proof: {e:?}"))?;

    let escrow_proof_inputs = EscrowProofInputParams {
        escrow_utxo: escrow_utxo.clone(),
        change,
        spp_tx_hashes,
    };
    let escrow_proof = EscrowProverClient::new()
        .prove_escrow(&escrow_proof_inputs.to_proof_inputs()?)
        .map_err(|e| anyhow!("escrow proof: {e:?}"))?;

    let escrow_ix = Escrow {
        payer: creator_address.solana_address()?,
        tree,
        escrow_proof: escrow_proof.into(),
        spp_proof,
    }
    .instruction()?;

    let signature = send_v0_with_lookup_table(
        client.rpc(),
        &creator.keypair.to_solana_keypair()?,
        escrow_ix,
    )?;
    client
        .confirm_private_transaction_sync(signature)
        .map_err(|e| anyhow!("confirm escrow indexed: {e:?}"))?;

    // Assert the creator's confidential balance dropped to the change amount:
    // the original 0.5 SOL note is spent, replaced by the 0.2 SOL change note.
    // The escrow UTXO is owned by the escrow-authority PDA and tagged for
    // discovery using the PDA's own signing pubkey, so it never surfaces in
    // the creator's own wallet sync.
    sync_wallet(&mut creator.wallet, &creator.keypair, client.indexer())
        .map_err(|e| anyhow!("sync creator after escrow: {e:?}"))?;
    let balance_after_escrow = creator
        .balance(SOL_MINT, None)
        .map_err(|e| anyhow!("creator balance after escrow: {e:?}"))?;
    let expected_change_utxo = Utxo {
        owner: creator_address.signing_pubkey,
        asset: SOL_MINT,
        amount: change_amount,
        blinding: change_blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    assert_eq!(
        balance_after_escrow,
        AssetBalance {
            asset_id: SOL_ASSET_ID,
            mint: SOL_MINT,
            amount: SHIELD_AMOUNT - LOCK_AMOUNT,
            utxos: vec![expected_change_utxo.clone()],
        }
    );

    // withdraw: after `unlock_timestamp`, spend the escrow UTXO back to the
    // creator.
    let source_output = escrow_utxo.source_output(creator_address, random_blinding());
    let source_output_blinding = source_output.blinding;
    let source_output_hash = source_output
        .hash()
        .map_err(|e| anyhow!("source output hash: {e:?}"))?;

    let escrow_input_utxo = escrow_utxo
        .to_input_utxo()
        .map_err(|e| anyhow!("escrow spend: {e:?}"))?;
    let input_utxos = vec![escrow_input_utxo];

    let transaction_viewing_key = get_transaction_viewing_key(&creator.keypair, &input_utxos)
        .map_err(|e| anyhow!("withdraw transaction viewing key: {e:?}"))?;
    let encoded = encrypt_transaction_data(
        std::slice::from_ref(&source_output),
        &creator.registry,
        &transaction_viewing_key,
    )
    .map_err(|e| anyhow!("encode withdraw slots: {e:?}"))?;

    let mut external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    external_data.expiry_unix_ts = SPP_RELAYER_DEADLINE;
    let withdraw_spp_proof_inputs = SppProofInputs::new(
        input_utxos,
        encoded.output_utxos,
        external_data,
        creator_address.solana_address()?,
    );

    let withdraw_proof_inputs = WithdrawProofInputParams {
        escrow_utxo: escrow_utxo.clone(),
        source_output,
        external_data_hash: withdraw_spp_proof_inputs
            .external_data
            .hash()
            .map_err(|e| anyhow!("withdraw external data hash: {e:?}"))?,
    };

    let spp_proof = client
        .indexer()
        .prove_transact(tree, withdraw_spp_proof_inputs)
        .map_err(|e| anyhow!("withdraw transact proof: {e:?}"))?;
    let withdraw_proof = EscrowProverClient::new()
        .prove_withdraw(&withdraw_proof_inputs.to_proof_inputs()?)
        .map_err(|e| anyhow!("withdraw proof: {e:?}"))?;

    let withdraw_ix = Withdraw {
        creator: creator_address.solana_address()?,
        payer: creator_address.solana_address()?,
        tree,
        withdraw_proof: withdraw_proof.into(),
        unlock_timestamp: UNLOCK_TIMESTAMP,
        spp_proof,
    }
    .instruction()?;

    let signature = send_v0_with_lookup_table(
        client.rpc(),
        &creator.keypair.to_solana_keypair()?,
        withdraw_ix,
    )?;
    client
        .confirm_private_transaction_sync(signature)
        .map_err(|e| anyhow!("confirm withdraw indexed: {e:?}"))?;

    // Assert the withdrawn output landed in the creator's confidential
    // balance: the change note plus the returned escrow amount sum back to
    // the original shielded deposit. Withdraw only spends the PDA-owned
    // escrow UTXO, so both notes stay as distinct entries: the change note
    // from the first sync, the source output from the second.
    sync_wallet(&mut creator.wallet, &creator.keypair, client.indexer())
        .map_err(|e| anyhow!("sync creator after withdraw: {e:?}"))?;
    let balance_after_withdraw = creator
        .balance(SOL_MINT, None)
        .map_err(|e| anyhow!("creator balance after withdraw: {e:?}"))?;
    let expected_source_output_utxo = Utxo {
        owner: creator_address.signing_pubkey,
        asset: SOL_MINT,
        amount: LOCK_AMOUNT,
        blinding: source_output_blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    assert_eq!(
        balance_after_withdraw,
        AssetBalance {
            asset_id: SOL_ASSET_ID,
            mint: SOL_MINT,
            amount: SHIELD_AMOUNT,
            utxos: vec![expected_change_utxo, expected_source_output_utxo],
        }
    );

    client
        .indexer()
        .get_merkle_proofs(tree, vec![source_output_hash], None)
        .map_err(|e| anyhow!("withdraw output index: {e}"))?;
    Ok(())
}
