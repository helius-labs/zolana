mod shared;

use anyhow::{anyhow, Result};
use shared::{
    send, setup, TestEnv, LOCK_AMOUNT, SHIELD_AMOUNT, SPP_RELAYER_DEADLINE, UNLOCK_TIMESTAMP,
};
use timelock_escrow_program::instructions::withdraw::slot;
use timelock_escrow_sdk::{
    instructions::{
        escrow::{Escrow, EscrowProofInputParams},
        withdraw::{Withdraw, WithdrawProofInputParams},
    },
    prover::EscrowProverClient,
    zk_program::ProgramOwner,
};
use zolana_client::Rpc;
use zolana_test_utils::test_validator_asserts::wait_for_merkle_proof;
use zolana_transaction::{Data, Mint, Utxo, SOL_ASSET_ID, SOL_MINT};
use zolana_wallet::sync_wallet;

#[test]
fn escrow_then_withdraw() -> Result<()> {
    let TestEnv {
        localnet,
        mut creator,
        funding,
        funding_leaf_index,
    } = setup(4)?;
    let creator_address = creator.keypair.shielded_address()?;

    let escrow = EscrowProofInputParams {
        creator: creator_address,
        funding,
        funding_leaf_index,
        amount: LOCK_AMOUNT,
        unlock_timestamp: UNLOCK_TIMESTAMP,
        output_tree_id: localnet.tree_id,
    }
    .build(&creator.keypair)?;
    let spp_proof = localnet
        .client
        .indexer()
        .prove_transact(escrow.spp_proof_inputs(), &ProgramOwner::nullifier_key())
        .map_err(|e| anyhow!("escrow transact proof: {e:?}"))?;
    let escrow_proof = EscrowProverClient::new().prove_escrow(&escrow.to_proof_inputs()?)?;
    let escrow_utxo = escrow.escrow_utxo().clone();
    let change_blinding = escrow.change()?.blinding;
    let escrow_ix = Escrow {
        transaction: escrow,
        spp_proof,
        escrow_proof: escrow_proof.into(),
    }
    .instruction()?;

    let signature = send(localnet.client.rpc(), &creator.keypair, escrow_ix)?;
    localnet
        .client
        .confirm_private_transaction_sync(signature)
        .map_err(|e| anyhow!("confirm escrow indexed: {e:?}"))?;

    sync_wallet(
        &mut creator.wallet,
        &creator.keypair,
        localnet.client.indexer(),
    )
    .map_err(|e| anyhow!("sync creator after escrow: {e:?}"))?;
    let balance_after_escrow = creator
        .balance(SOL_MINT, None)
        .map_err(|e| anyhow!("creator balance after escrow: {e:?}"))?;
    let expected_change_utxo = Utxo {
        owner: creator_address.signing_pubkey,
        asset: Mint::SOL,
        amount: SHIELD_AMOUNT - LOCK_AMOUNT,
        blinding: change_blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    assert_eq!(
        (
            balance_after_escrow.asset_id,
            balance_after_escrow.mint,
            balance_after_escrow.amount,
            balance_after_escrow
                .utxos
                .into_iter()
                .map(|note| note.utxo)
                .collect::<Vec<_>>()
        ),
        (
            SOL_ASSET_ID,
            SOL_MINT,
            SHIELD_AMOUNT - LOCK_AMOUNT,
            vec![expected_change_utxo.clone()],
        )
    );

    let escrow_state = wait_for_merkle_proof(
        localnet.client.indexer(),
        localnet.tree,
        escrow_utxo.hash()?,
    );
    let withdraw = WithdrawProofInputParams {
        escrow_utxo,
        escrow_leaf_index: escrow_state.leaf_index,
        payer: creator_address.solana_address()?,
        expiry_unix_ts: SPP_RELAYER_DEADLINE,
        output_tree_id: localnet.tree_id,
    }
    .build(&creator.keypair)?;
    let spp_proof = localnet
        .client
        .indexer()
        .prove_transact(withdraw.spp_proof_inputs(), &ProgramOwner::nullifier_key())
        .map_err(|e| anyhow!("withdraw transact proof: {e:?}"))?;
    let withdraw_proof = EscrowProverClient::new().prove_withdraw(&withdraw.to_proof_inputs()?)?;
    let source_output_blinding = withdraw.source_output()?.blinding;
    let source_output_hash = *withdraw.transaction().output_hash(slot::SOURCE_OUTPUT)?;
    let withdraw_ix = Withdraw {
        transaction: withdraw,
        spp_proof,
        withdraw_proof: withdraw_proof.into(),
    }
    .instruction()?;

    let signature = send(localnet.client.rpc(), &creator.keypair, withdraw_ix)?;
    localnet
        .client
        .confirm_private_transaction_sync(signature)
        .map_err(|e| anyhow!("confirm withdraw indexed: {e:?}"))?;

    sync_wallet(
        &mut creator.wallet,
        &creator.keypair,
        localnet.client.indexer(),
    )
    .map_err(|e| anyhow!("sync creator after withdraw: {e:?}"))?;
    let balance_after_withdraw = creator
        .balance(SOL_MINT, None)
        .map_err(|e| anyhow!("creator balance after withdraw: {e:?}"))?;
    let expected_source_output_utxo = Utxo {
        owner: creator_address.signing_pubkey,
        asset: Mint::SOL,
        amount: LOCK_AMOUNT,
        blinding: source_output_blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    assert_eq!(
        (
            balance_after_withdraw.asset_id,
            balance_after_withdraw.mint,
            balance_after_withdraw.amount,
            balance_after_withdraw
                .utxos
                .into_iter()
                .map(|note| note.utxo)
                .collect::<Vec<_>>()
        ),
        (
            SOL_ASSET_ID,
            SOL_MINT,
            SHIELD_AMOUNT,
            vec![expected_change_utxo, expected_source_output_utxo],
        )
    );

    localnet
        .client
        .indexer()
        .get_merkle_proofs(localnet.tree, vec![source_output_hash], None)
        .map_err(|e| anyhow!("withdraw output index: {e}"))?;
    Ok(())
}
