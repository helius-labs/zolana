mod localnet;

use anyhow::{anyhow, Result};
use localnet::{
    creator_transactions, send, setup, TestEnv, DEPOSITS, LOCK_AMOUNT, UNLOCK_TIMESTAMP,
};
use solana_signer::Signer;
use timelock_escrow_program::{
    circuits::{
        escrow_authority, Escrow, EscrowPrivateInputs, EscrowPublicInputs, EscrowTerms, Withdraw,
        WithdrawPrivateInputs, WithdrawPublicInputs,
    },
    client::{EscrowInstruction, WithdrawInstruction},
    instructions::escrow::slot,
};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_program::{DataUtxo, Groth16Prover, Owner, ProgramOwner, TxContext, ZkProgram};
use zolana_transaction::{decrypt_spendable, AssetRegistry, WalletUtxo, SOL_MINT};

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
    let creator_identity = solana_owner_identity(payer.as_array())?;
    let assets = AssetRegistry::default();
    let tx_context = || TxContext::new().with_output_tree_id(Some(localnet.tree_id));
    let shielded = DEPOSITS.iter().sum::<u64>();

    let transactions = creator_transactions(&localnet, &creator, deposit_slot)?;
    let balances = decrypt_spendable(&creator, &transactions, &assets)?.balances;
    let balance = balances
        .get_balance(SOL_MINT)
        .ok_or_else(|| anyhow!("the creator holds no SOL"))?;
    assert_eq!(balance.amount, shielded);
    assert_eq!(balance.utxos.len(), DEPOSITS.len());

    let escrow = Escrow {
        private: EscrowPrivateInputs {
            tx_context: tx_context(),
            token_utxos_asset_a: balance.utxos.clone(),
            unlock: UNLOCK_TIMESTAMP,
            amount: LOCK_AMOUNT,
        },
        public: EscrowPublicInputs {
            escrow_owner: authority.address(address.viewing_pubkey)?,
            creator_identity,
        },
    };
    let transaction = escrow.create_program_transaction(&address, payer)?;
    let proof = Groth16Prover::<Escrow>::new_with_test_setup()?
        .prove_inputs(&transaction.proof_inputs)?
        .compressed()?;
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
            creator: Owner::try_from(&address)?,
            unlock: UNLOCK_TIMESTAMP,
        }
    );

    let unlock_timestamp = terms.unlock;
    let withdraw = Withdraw {
        private: WithdrawPrivateInputs {
            tx_context: tx_context(),
            escrow: escrow_utxo,
            terms,
        },
        public: WithdrawPublicInputs {
            unlock: unlock_timestamp,
            creator_identity,
        },
    };
    let transaction = withdraw.create_program_transaction(&address, payer)?;
    let proof = Groth16Prover::<Withdraw>::new_with_test_setup()?
        .prove_inputs(&transaction.proof_inputs)?
        .compressed()?;
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
    assert!(authority
        .decrypt_data_utxos::<EscrowTerms>(&creator.viewing_key, &transactions, &assets)?
        .is_empty());
    Ok(())
}
