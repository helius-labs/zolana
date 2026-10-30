mod localnet;

use anyhow::{Result, anyhow};
use localnet::{
    DEPOSITS, LOCK_AMOUNT, TestEnv, UNLOCK_TIMESTAMP, creator_transactions, send, setup,
};
use solana_signer::Signer;
use timelock_escrow_program::{
    circuits::{
        EscrowClient, EscrowPrivateInputsClient, EscrowPublicInputsClient, EscrowTerms,
        WithdrawClient, WithdrawPrivateInputsClient, WithdrawPublicInputsClient, escrow_authority,
    },
    client::{EscrowInstruction, WithdrawInstruction},
    instructions::escrow::slot,
};
use spr_keypair::random_blinding;
use spr_program::{
    DataUtxo, InputRecords, ProgramOwner, TransactionOptions, proof::compressed_proof,
};
use spr_program_test::workspace_path;
use spr_transaction::{AssetRegistry, SOL_MINT, WalletUtxo, decrypt_spendable};

#[test]
fn escrow_then_withdraw() -> Result<()> {
    let TestEnv {
        localnet,
        creator,
        deposit_slot,
    } = setup(4)?;
    let address = creator.shielded_address()?;
    let payer = creator.pubkey();
    let authority = escrow_authority(&payer);
    let assets = AssetRegistry::default();
    let context = || TransactionOptions {
        blinding_seed: Some(random_blinding()),
        output_tree_id: Some(localnet.tree_id),
    };
    let shielded = DEPOSITS.iter().sum::<u64>();

    let transactions = creator_transactions(&localnet, &creator, deposit_slot)?;
    let balances = decrypt_spendable(&creator, &transactions, &assets)?.balances;
    let balance = balances
        .get_balance(SOL_MINT)
        .ok_or_else(|| anyhow!("the creator holds no SOL"))?;
    assert_eq!(balance.amount, shielded);
    assert_eq!(balance.utxos.len(), DEPOSITS.len());

    let creator_owner = *InputRecords::new().address(&address)?.owner();
    let transaction = EscrowClient {
        private: EscrowPrivateInputsClient {
            tx_context: context(),
            token_utxos_asset_a: balance.utxos.clone(),
            unlock: UNLOCK_TIMESTAMP,
            amount: LOCK_AMOUNT,
        },
        public: EscrowPublicInputsClient {
            escrow_owner: authority.address(address.viewing_pubkey)?,
            creator_identity: creator_owner.key().identity()?.to_decimal(),
        },
    }
    .prepare(&address, payer)?;
    let result =
        xark::prover::circuit_at(workspace_path("target/zk/timelock-escrow-program/escrow"))
            .prove(transaction.proof_inputs)?;
    let proof = compressed_proof(&result.proof).map_err(anyhow::Error::msg)?;
    let spp_proof_inputs = transaction.finalized.encrypt_with_keys(&creator)?;
    let escrow_output = spp_proof_inputs
        .output_utxos
        .get(slot::ESCROW)
        .cloned()
        .ok_or_else(|| anyhow!("the escrow transaction has no escrow output"))?;
    let transact = localnet
        .client
        .prove_transact(spp_proof_inputs, None, &creator)?;
    let escrow_slot = send(
        &localnet,
        &creator,
        EscrowInstruction {
            creator: payer,
            tree: localnet.tree,
            proof,
            viewing_pubkey: *address.viewing_pubkey.as_bytes(),
            transact,
        }
        .instruction()?,
    )?;

    let transactions = creator_transactions(&localnet, &creator, escrow_slot)?;
    let balances = decrypt_spendable(&creator, &transactions, &assets)?.balances;
    assert_eq!(
        balances.get_balance(SOL_MINT).map(|balance| balance.amount),
        Some(shielded - LOCK_AMOUNT)
    );
    let DataUtxo {
        utxo: escrow_utxo,
        data: terms,
        address: _,
    } = authority
        .decrypt_data_utxos::<EscrowTerms>(&creator.viewing_key, &transactions, &assets)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("the creator has no open escrow"))?;
    assert_eq!(
        escrow_utxo,
        WalletUtxo {
            slot: escrow_utxo.slot,
            tx_signature: escrow_utxo.tx_signature,
            slot_index: escrow_utxo.slot_index,
            ..authority.input(&escrow_output, localnet.tree_id, escrow_utxo.leaf_index)?
        }
    );
    assert_eq!(
        terms,
        EscrowTerms {
            creator: creator_owner,
            unlock: UNLOCK_TIMESTAMP,
        }
    );

    let unlock_timestamp = terms.unlock;
    let transaction = WithdrawClient {
        private: WithdrawPrivateInputsClient {
            tx_context: context(),
            escrow: escrow_utxo,
            terms: terms.into(),
        },
        public: WithdrawPublicInputsClient {
            unlock: unlock_timestamp,
            creator_identity: creator_owner.key().identity()?.to_decimal(),
        },
    }
    .prepare(&address, payer)?;
    let result =
        xark::prover::circuit_at(workspace_path("target/zk/timelock-escrow-program/withdraw"))
            .prove(transaction.proof_inputs)?;
    let proof = compressed_proof(&result.proof).map_err(anyhow::Error::msg)?;
    let spp_proof_inputs = transaction.finalized.encrypt_with_keys(&creator)?;
    let transact =
        localnet
            .client
            .prove_transact(spp_proof_inputs, None, &ProgramOwner::nullifier_key())?;
    let withdraw_slot = send(
        &localnet,
        &creator,
        WithdrawInstruction {
            creator: payer,
            tree: localnet.tree,
            proof,
            unlock_timestamp,
            transact,
        }
        .instruction()?,
    )?;

    let transactions = creator_transactions(&localnet, &creator, withdraw_slot)?;
    let balances = decrypt_spendable(&creator, &transactions, &assets)?.balances;
    assert_eq!(
        balances.get_balance(SOL_MINT).map(|balance| balance.amount),
        Some(shielded)
    );
    assert!(
        authority
            .decrypt_data_utxos::<EscrowTerms>(&creator.viewing_key, &transactions, &assets)?
            .is_empty()
    );
    Ok(())
}
