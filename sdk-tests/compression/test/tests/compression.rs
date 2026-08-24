mod shared;

use anyhow::{anyhow, bail, Result};
use compression_example_sdk::{
    account_pda,
    discovery::discover_account,
    instructions::{
        create::{address_input, Create, CreateProofInputParams},
        update::{Update, UpdateProofInputParams, UpdateTransfer},
    },
    state::AccountState,
};
use shared::{send, setup, tree_root};
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::{ProofCompressed, ProverClient};
use zolana_test_utils::test_validator_asserts::{
    wait_for_indexed_utxo, wait_for_non_inclusion_proof,
};
use zolana_transaction::{Utxo, WalletUtxo};

fn assert_account(
    wallet_utxo: &WalletUtxo,
    expected_output: &Utxo,
    expected_hash: [u8; 32],
    expected_authority: Address,
    expected_value: u64,
    expected_tree: Address,
) -> Result<()> {
    let state = AccountState::decode(
        wallet_utxo
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| anyhow!("state data missing"))?,
    )?;
    if wallet_utxo.utxo != *expected_output
        || wallet_utxo.output_context.hash != expected_hash
        || wallet_utxo.output_context.tree != expected_tree
        || state.authority != expected_authority.to_bytes()
        || state.value != expected_value
        || state.address == [0u8; 32]
        || wallet_utxo.spent
    {
        bail!("discovered account does not match expected state");
    }
    Ok(())
}

#[test]
fn create_and_update_plaintext_compressed_account() -> Result<()> {
    let env = setup()?;
    let pda = account_pda(&env.authority.pubkey());

    let (_, _, address) = address_input(&pda)?;
    let non_inclusion = wait_for_non_inclusion_proof(&env.indexer, env.tree, address);
    let (utxo_root_index, utxo_root) = tree_root(&env.rpc, env.tree)?;
    let create = CreateProofInputParams {
        authority: env.authority.pubkey(),
        new_value: 1,
        output_seed: [11u8; 32],
        non_inclusion,
        utxo_root,
        utxo_root_index,
    }
    .to_transfer_inputs()?;
    let proof = ProverClient::local().prove_transfer(&create.transfer_inputs)?;
    let create_ix = Create {
        payer: env.authority.pubkey(),
        tree: env.tree,
        new_value: 1,
        output_seed: [11u8; 32],
        spp_proof: create.with_proof(ProofCompressed::try_from(proof)?),
    }
    .instruction()?;

    let create_signature = send(&env, create_ix.clone(), None)?;
    wait_for_indexed_utxo(&env.indexer, pda.to_bytes(), create_signature);
    let current = discover_account(&env.indexer, pda)?;
    assert_account(
        &current,
        &create.output,
        create.output_hash,
        env.authority.pubkey(),
        1,
        env.tree,
    )?;
    let created_state = AccountState::decode(
        current
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| anyhow!("created state data missing"))?,
    )?;
    if created_state.address != create.input_nullifier {
        bail!("compressed address is not the address-input nullifier");
    }

    if send(&env, create_ix, Some(1)).is_ok() {
        bail!("duplicate create unexpectedly succeeded");
    }

    let UpdateTransfer {
        spp_proof_inputs,
        old_value,
        old_blinding,
        output: update_output,
        output_hash: update_output_hash,
        input_nullifier: update_input_nullifier,
    } = UpdateProofInputParams {
        authority: env.authority.pubkey(),
        current: current.clone(),
        new_value: 2,
        output_seed: [12u8; 32],
    }
    .to_proof_inputs()?;
    if update_input_nullifier != current.nullifier {
        bail!("update does not spend the discovered UTXO nullifier");
    }
    let update_ix = Update {
        payer: env.authority.pubkey(),
        tree: env.tree,
        old_value,
        old_blinding,
        new_value: 2,
        output_seed: [12u8; 32],
        spp_proof: env.indexer.prove_transact(env.tree, spp_proof_inputs)?,
    }
    .instruction()?;

    let update_signature = send(&env, update_ix.clone(), None)?;
    wait_for_indexed_utxo(&env.indexer, pda.to_bytes(), update_signature);
    let updated = discover_account(&env.indexer, pda)?;
    assert_account(
        &updated,
        &update_output,
        update_output_hash,
        env.authority.pubkey(),
        2,
        env.tree,
    )?;
    let old_state = AccountState::decode(
        current
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| anyhow!("old state data missing"))?,
    )?;
    let new_state = AccountState::decode(
        updated
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| anyhow!("new state data missing"))?,
    )?;
    if old_state.address != new_state.address || current.utxo.owner != updated.utxo.owner {
        bail!("update changed the compressed address or PDA owner");
    }
    if send(&env, update_ix, Some(1)).is_ok() {
        bail!("stale update unexpectedly succeeded");
    }
    Ok(())
}
