use zolana_test_utils::utxo::prepare_output_blindings;
mod shared;

use anyhow::{anyhow, bail, Result};
use compression_example_program::error::CompressionError;
use compression_example_sdk::{
    account_pda,
    discovery::discover_account,
    instructions::{
        create::{address_input, Create, CreateProofInputParams},
        read::{Read, ReadProofInputParams},
        update::{Update, UpdateCompressedAccount, UpdateProofInputParams},
    },
    shared::DEFAULT_TREE_ID,
    state::{decode_state, pda_shielded_address},
};
use shared::{send, send_from, setup, tree_root, Environment};
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{NonInclusionProof, ProofCompressed, ProverClient, Rpc};
use zolana_interface::{
    event::OutputDataEncoding,
    instruction::{
        instruction_data::transact::{OwnerTag, TransactOutput},
        AssetDeposit, Deposit, DepositAsset, Transact,
    },
};
use zolana_keypair::ShieldedKeypair;
use zolana_test_utils::test_validator_asserts::{
    wait_for_indexed_utxo, wait_for_merkle_proof, wait_for_non_inclusion_proof,
};
use zolana_transaction::WalletUtxo;
use zolana_transaction::{
    instructions::transact::{ExternalData, SppProofInputs, SppProofOutputUtxo},
    utxo::SppProofInputUtxo,
    Data, Utxo, SOL_MINT,
};

const POISON_AMOUNT: u64 = 1_000_000;

fn assert_account(
    wallet_utxo: &WalletUtxo,
    expected_output: &Utxo,
    expected_hash: [u8; 32],
    expected_authority: Address,
    expected_value: u64,
    expected_tree: Address,
    indexer: &zolana_client::ZolanaIndexer,
) -> Result<()> {
    assert!(
        indexer
            .get_shielded_transactions_by_nullifiers(
                vec![wallet_utxo.nullifier],
                None,
                Some(1),
                None
            )?
            .transactions
            .is_empty(),
        "account note is unspent"
    );
    let state = decode_state(
        wallet_utxo
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| anyhow!("state data missing"))?,
    )?;
    if wallet_utxo.utxo != *expected_output
        || wallet_utxo.utxo_hash != expected_hash
        || zolana_interface::pda::tree(wallet_utxo.tree_id) != expected_tree
        || state.authority != expected_authority.to_bytes()
        || state.value != expected_value
        || state.address == [0u8; 32]
    {
        bail!("discovered account does not match expected state");
    }
    Ok(())
}

// A custom program error surfaces as `Custom(<decimal>)` or as the program-log
// line `custom program error: 0x<hex>`; match only those delimited forms.
fn assert_custom_error(context: &str, result: Result<Signature>, error: CompressionError) {
    let code = error as u32;
    let text = match result {
        Ok(signature) => panic!("{context}: unexpectedly succeeded ({signature})"),
        Err(err) => format!("{err:?}"),
    };
    assert!(
        text.contains(&format!("Custom({code})")) || text.contains(&format!("0x{code:x}")),
        "{context}: expected {error:?} ({code}) in: {text}"
    );
}

/// Prove `current` unspent with a fresh inclusion proof and the supplied
/// nullifier non-inclusion proof, and build the read.
fn prove_read(
    env: &Environment,
    current: &WalletUtxo,
    non_inclusion: NonInclusionProof,
) -> Result<Read> {
    let read = ReadProofInputParams {
        current: current.clone(),
        merkle_proof: wait_for_merkle_proof(&env.indexer, env.tree, current.utxo_hash),
        non_inclusion,
    }
    .to_proof_inputs()?;
    Ok(Read {
        authority: env.authority.pubkey(),
        tree: env.tree,
        value: read.value,
        version: read.version,
        blinding: read.blinding,
        nullifier: read.nullifier,
        nullifier_tree_root_index: read.nullifier_tree_root_index,
        utxo_tree_root_index: read.utxo_tree_root_index,
        proof: read.proof_inputs.prove()?,
    })
}

fn malformed_plaintext_payload() -> Vec<u8> {
    let mut payload = vec![OutputDataEncoding::PLAINTEXT_TAG];
    payload.extend_from_slice(&3u32.to_le_bytes());
    payload.extend_from_slice(&[0xff; 3]);
    payload
}

fn land_malformed_tagged_output(env: &mut Environment, pda: Address) -> Result<Signature> {
    let attacker = ShieldedKeypair::new_ed25519()?;
    env.rpc.airdrop(&attacker.pubkey(), 10_000_000_000)?;
    let attacker_address = attacker.shielded_address()?;
    let deposit_ix = Deposit {
        tree: env.tree,
        depositor: attacker.pubkey(),
        deposits: vec![AssetDeposit {
            asset: DepositAsset::Sol,
            view_tag: attacker_address.confidential_view_tag()?,
            owner: attacker_address.owner_hash()?,
            amount: POISON_AMOUNT,
            utxo_data: None,
            memo: None,
        }],
    }
    .instruction()?;
    let deposit_signature = send_from(env, deposit_ix, &attacker, None)?;
    // A proofless deposit publishes its UTXO in the clear, so read it back from
    // the indexer.
    let deposited = wait_for_indexed_utxo(
        &env.indexer,
        attacker_address.confidential_view_tag()?,
        deposit_signature,
    )
    .output_slot
    .proofless_output()
    .ok_or_else(|| anyhow!("indexed deposit output is not a proofless UTXO"))?;

    let input_utxo: SppProofInputUtxo = zolana_test_utils::utxo::indexed(
        Utxo {
            owner: attacker.signing_pubkey(),
            asset: zolana_transaction::Mint::SOL,
            amount: deposited.amount,
            blinding: deposited.blinding,
            ring_program_id: None,
            data: Data::default(),
        },
        &attacker.nullifier_key,
        &env.indexer,
        DEFAULT_TREE_ID,
    )?
    .into();
    assert_eq!(
        (input_utxo.utxo.asset.asset, input_utxo.utxo.amount),
        (SOL_MINT, POISON_AMOUNT)
    );
    wait_for_merkle_proof(&env.indexer, env.tree, input_utxo.hash());

    let input_utxos = vec![input_utxo];
    let mut poison_outputs = vec![SppProofOutputUtxo {
        asset: zolana_transaction::Mint::SOL,
        amount: POISON_AMOUNT,
        owner_address: Some(pda_shielded_address(&pda)?),
        owner_tag: Some(pda.to_bytes()),
        data: Data::default(),
        ..SppProofOutputUtxo::default()
    }];
    // The circuit recomputes every output blinding, so even a hand-built
    // attacker transfer has to take the derived value.
    let blinding_seed = prepare_output_blindings(&input_utxos, &mut poison_outputs)?;
    let poison_output = poison_outputs
        .pop()
        .ok_or_else(|| anyhow!("poison output"))?;
    let output_hash = poison_output.hash(DEFAULT_TREE_ID)?;
    let external = ExternalData::new(
        [0u8; 33],
        [0u8; 16],
        vec![TransactOutput {
            utxo_hash: output_hash,
            owner_tag: OwnerTag::Inline(pda.to_bytes()),
            data: Some(malformed_plaintext_payload()),
        }],
        vec![pda.to_bytes()],
        Vec::new(),
    );
    let transact = env.indexer.prove_transact(
        SppProofInputs {
            input_utxos,
            output_utxos: vec![poison_output],
            external_data: external,
            payer: attacker.pubkey(),
            blinding_seed,
            output_tree_id: DEFAULT_TREE_ID,
        },
        &attacker,
    )?;
    let poison_ix = Transact {
        payer: attacker.pubkey(),
        input_trees: vec![env.tree],
        output_tree: env.tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact,
    }
    .instruction();
    let poison_signature = send_from(env, poison_ix, &attacker, None)?;
    wait_for_indexed_utxo(&env.indexer, pda.to_bytes(), poison_signature);
    Ok(poison_signature)
}

#[test]
fn default_tree_is_tree_pda_zero() {
    assert_eq!(
        compression_example_program::instructions::shared::DEFAULT_TREE,
        zolana_interface::pda::tree(0)
    );
}

#[test]
fn create_and_update_plaintext_compressed_account() -> Result<()> {
    let mut env = setup()?;
    let pda = account_pda(&env.authority.pubkey());

    let (_, address) = address_input(&pda, DEFAULT_TREE_ID)?;
    let non_inclusion = wait_for_non_inclusion_proof(&env.indexer, env.tree, address);
    let (utxo_root_index, utxo_root) = tree_root(&env.rpc, env.tree)?;
    let create = CreateProofInputParams {
        authority: env.authority.pubkey(),
        new_value: 1,
        non_inclusion,
        utxo_root,
        utxo_root_index,
    }
    .to_proof_inputs()?;
    let proof = ProverClient::local().prove_transfer(&create.transfer_inputs)?;
    let create_ix = Create {
        payer: env.authority.pubkey(),
        tree: env.tree,
        new_value: 1,
        nullifier_tree_root_index: create.nullifier_tree_root_index,
        utxo_tree_root_index: create.utxo_tree_root_index,
        proof: ProofCompressed::try_from(proof)?.to_transact_proof(),
    }
    .instruction()?;

    let create_signature = send(&env, create_ix.clone(), None)?;
    wait_for_indexed_utxo(&env.indexer, pda.to_bytes(), create_signature);
    let current = discover_account(&env.indexer, pda)?;
    assert_account(
        &current.utxo,
        &create.output,
        create.output_hash,
        env.authority.pubkey(),
        1,
        env.tree,
        &env.indexer,
    )?;
    if current.version != 0 {
        bail!("created account version is not 0");
    }
    let created_state = decode_state(
        current
            .utxo
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| anyhow!("created state data missing"))?,
    )?;
    if created_state.address != create.input_nullifier {
        bail!("compressed address is not the address-input nullifier");
    }

    land_malformed_tagged_output(&mut env, pda)?;
    let after_poison = discover_account(&env.indexer, pda)?;
    assert_account(
        &after_poison.utxo,
        &create.output,
        create.output_hash,
        env.authority.pubkey(),
        1,
        env.tree,
        &env.indexer,
    )?;
    if after_poison.version != 0 {
        bail!("poisoned scan did not keep the created account");
    }

    if send(&env, create_ix, Some(1)).is_ok() {
        bail!("duplicate create unexpectedly succeeded");
    }

    let current_non_inclusion =
        wait_for_non_inclusion_proof(&env.indexer, env.tree, current.utxo.nullifier);
    let read_current = prove_read(&env, &current.utxo, current_non_inclusion.clone())?;
    assert_custom_error(
        "read of a forged value",
        send(
            &env,
            Read {
                value: read_current.value + 1,
                ..read_current
            }
            .instruction()?,
            None,
        ),
        CompressionError::ProofVerificationFailed,
    );
    let read_current_ix = read_current.instruction()?;
    send(&env, read_current_ix.clone(), None)?;

    let UpdateCompressedAccount {
        spp_proof_inputs,
        old_value,
        version,
        output: update_output,
        output_hash: update_output_hash,
        input_nullifier: update_input_nullifier,
    } = UpdateProofInputParams {
        authority: env.authority.pubkey(),
        current: current.utxo.clone(),
        new_value: 2,
    }
    .to_proof_inputs()?;
    if update_input_nullifier != current.utxo.nullifier {
        bail!("update does not input_utxo the discovered UTXO nullifier");
    }
    let update_ix = Update {
        payer: env.authority.pubkey(),
        input_tree: env.tree,
        output_tree: env.tree,
        old_value,
        version,
        old_blinding: current.utxo.utxo.blinding,
        new_value: 2,
        spp_proof: env.indexer.prove_transact(
            spp_proof_inputs,
            &compression_example_sdk::shared::zero_nullifier_key(),
        )?,
    }
    .instruction()?;

    let update_signature = send(&env, update_ix.clone(), None)?;
    wait_for_indexed_utxo(&env.indexer, pda.to_bytes(), update_signature);
    let updated = discover_account(&env.indexer, pda)?;
    assert_account(
        &updated.utxo,
        &update_output,
        update_output_hash,
        env.authority.pubkey(),
        2,
        env.tree,
        &env.indexer,
    )?;
    if updated.version != 1 {
        bail!("updated account version is not 1");
    }
    let old_state = decode_state(
        current
            .utxo
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| anyhow!("old state data missing"))?,
    )?;
    let new_state = decode_state(
        updated
            .utxo
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| anyhow!("new state data missing"))?,
    )?;
    if old_state.address != new_state.address || current.utxo.utxo.owner != updated.utxo.utxo.owner
    {
        bail!("update changed the compressed address or PDA owner");
    }
    if send(&env, update_ix, Some(1)).is_ok() {
        bail!("stale update unexpectedly succeeded");
    }

    // Both roots the old read was proven against are still in the root
    // histories, so only the spent version's nullifier PDA rejects it.
    assert_custom_error(
        "read of the old version after an update",
        send(&env, read_current_ix, Some(1)),
        CompressionError::StateSpent,
    );
    // No forester runs here, so the spent nullifier is still only queued: a
    // fresh proof of the old version against the current state root and the
    // unchanged nullifier root verifies, and the nullifier PDA rejects it.
    assert_custom_error(
        "read of a spent version whose nullifier is queued",
        send(
            &env,
            prove_read(&env, &current.utxo, current_non_inclusion)?.instruction()?,
            None,
        ),
        CompressionError::StateSpent,
    );
    let read_updated = prove_read(
        &env,
        &updated.utxo,
        wait_for_non_inclusion_proof(&env.indexer, env.tree, updated.utxo.nullifier),
    )?;
    send(&env, read_updated.instruction()?, None)?;
    Ok(())
}
