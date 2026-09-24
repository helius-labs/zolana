use zolana_test_utils::utxo::prepare_output_blindings;
mod shared;

use anyhow::{anyhow, bail, Result};
use compression_example_program::error::CompressionError;
use compression_example_sdk::{
    account_pda,
    discovery::{discover_account, DiscoveredAccount},
    instructions::{
        create::{address_input, Create, CreateProofInputParams},
        read::{Read, ReadProofInputParams},
        update::{Update, UpdateCompressedAccount, UpdateProofInputParams},
    },
    shared::DEFAULT_TREE_ID,
    state::{decode_state, pda_shielded_address, AccountState},
};
use shared::{send, send_from, setup, tree_root, Environment};
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ComputeBudgetConfig, NonInclusionProof, ProofCompressed, ProverClient, Rpc};
use zolana_interface::{
    event::OutputDataEncoding,
    instruction::instruction_data::transact::{
        OwnerTag, TransactOutput, TransactProof, TreeContext,
    },
    pda::nullifier_pda,
    state::tree::{default_tree_fees, nullifier_tree_params},
};
use zolana_keypair::ShieldedKeypair;
use zolana_program::{
    compression::CompressedAccountMeta,
    instruction::{AssetDeposit, Deposit, DepositAsset, Transact},
};
use zolana_program_test::{create_tree_instructions, fixture, next_tree_id};
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
    client: &impl Rpc,
) -> Result<()> {
    assert!(
        client
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
    tree: Address,
    current: &WalletUtxo,
    non_inclusion: NonInclusionProof,
) -> Result<Read> {
    let read = ReadProofInputParams {
        current: current.clone(),
        merkle_proof: wait_for_merkle_proof(&env.localnet.client, tree, current.utxo_hash),
        non_inclusion,
    }
    .to_proof_inputs()?;
    Ok(Read {
        authority: env.authority.pubkey(),
        tree,
        value: read.value,
        version: read.version,
        meta: read.meta,
        nullifier: read.nullifier,
        proof: read.proof_inputs.prove()?,
    })
}

/// Proves an update's SPP transaction. Returns the meta of the UTXO it spends,
/// with the root indexes the proof is made against, and the proof.
fn prove_update(
    env: &Environment,
    spp_proof_inputs: SppProofInputs,
    meta: CompressedAccountMeta,
) -> Result<(CompressedAccountMeta, TransactProof)> {
    let transact = env.localnet.client.prove_transact(
        spp_proof_inputs,
        None,
        &compression_example_sdk::shared::zero_nullifier_key(),
    )?;
    let [tree_context] = transact.tree_contexts.as_slice() else {
        bail!("SPP transact must declare exactly one input tree");
    };
    let meta = CompressedAccountMeta {
        tree_context: *tree_context,
        ..meta
    };
    Ok((meta, transact.proof))
}

fn malformed_plaintext_payload() -> Vec<u8> {
    let mut payload = vec![OutputDataEncoding::PLAINTEXT_TAG];
    payload.extend_from_slice(&3u32.to_le_bytes());
    payload.extend_from_slice(&[0xff; 3]);
    payload
}

fn land_malformed_tagged_output(env: &Environment, pda: Address) -> Result<Signature> {
    let attacker = ShieldedKeypair::from_keypair(&fixture::actor(1))?;
    let attacker_address = attacker.shielded_address()?;
    let deposit_ix = Deposit {
        tree: env.localnet.tree,
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
        &env.localnet.client,
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
        &env.localnet.client,
        DEFAULT_TREE_ID,
    )?
    .into();
    assert_eq!(
        (input_utxo.utxo.asset.asset, input_utxo.utxo.amount),
        (SOL_MINT, POISON_AMOUNT)
    );
    wait_for_merkle_proof(&env.localnet.client, env.localnet.tree, input_utxo.hash());

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
    let transact = env.localnet.client.prove_transact(
        SppProofInputs {
            input_utxos,
            output_utxos: vec![poison_output],
            external_data: external,
            payer: attacker.pubkey(),
            blinding_seed,
            output_tree_id: DEFAULT_TREE_ID,
            cache_accounts: Default::default(),
        },
        None,
        &attacker,
    )?;
    let poison_ix = Transact {
        payer: attacker.pubkey(),
        input_trees: vec![env.localnet.tree],
        output_tree: env.localnet.tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact,
    }
    .instruction();
    let poison_signature = send_from(env, poison_ix, &attacker, None)?;
    wait_for_indexed_utxo(&env.localnet.client, pda.to_bytes(), poison_signature);
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
    let env = setup(10)?;
    let pda = account_pda(&env.authority.pubkey());

    let (_, address) = address_input(&pda, DEFAULT_TREE_ID)?;
    let non_inclusion =
        wait_for_non_inclusion_proof(&env.localnet.client, env.localnet.tree, address);
    let (utxo_root_index, utxo_root) = tree_root(&env.localnet.client, env.localnet.tree)?;
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
        tree: env.localnet.tree,
        new_value: 1,
        address_tree_context: create.address_tree_context,
        proof: ProofCompressed::try_from(proof)?.to_transact_proof(),
    }
    .instruction()?;

    let create_signature = send(&env, create_ix.clone(), None)?;
    wait_for_indexed_utxo(&env.localnet.client, pda.to_bytes(), create_signature);
    let current = discover_account(&env.localnet.client, pda)?;
    assert_account(
        &current.utxo,
        &create.output,
        create.output_hash,
        env.authority.pubkey(),
        1,
        env.localnet.tree,
        &env.localnet.client,
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

    land_malformed_tagged_output(&env, pda)?;
    let after_poison = discover_account(&env.localnet.client, pda)?;
    assert_account(
        &after_poison.utxo,
        &create.output,
        create.output_hash,
        env.authority.pubkey(),
        1,
        env.localnet.tree,
        &env.localnet.client,
    )?;
    if after_poison.version != 0 {
        bail!("poisoned scan did not keep the created account");
    }

    if send(&env, create_ix, Some(1)).is_ok() {
        bail!("duplicate create unexpectedly succeeded");
    }

    let current_non_inclusion = wait_for_non_inclusion_proof(
        &env.localnet.client,
        env.localnet.tree,
        current.utxo.nullifier,
    );
    let read_current = prove_read(
        &env,
        env.localnet.tree,
        &current.utxo,
        current_non_inclusion.clone(),
    )?;
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
    // Roots come only from a tree account the pool owns; any other account
    // could carry roots of the caller's choosing.
    assert_custom_error(
        "read against an account the pool does not own",
        send(
            &env,
            Read {
                tree: env.authority.pubkey(),
                ..read_current
            }
            .instruction()?,
            None,
        ),
        CompressionError::InvalidTreeAccount,
    );
    assert_custom_error(
        "read against a state root index outside the history",
        send(
            &env,
            Read {
                meta: CompressedAccountMeta {
                    tree_context: TreeContext {
                        utxo_tree_root_index: u16::MAX,
                        ..read_current.meta.tree_context
                    },
                    ..read_current.meta
                },
                ..read_current
            }
            .instruction()?,
            None,
        ),
        CompressionError::InvalidRootIndex,
    );
    assert_custom_error(
        "read against a nullifier root index outside the history",
        send(
            &env,
            Read {
                meta: CompressedAccountMeta {
                    tree_context: TreeContext {
                        nullifier_tree_root_index: u16::MAX,
                        ..read_current.meta.tree_context
                    },
                    ..read_current.meta
                },
                ..read_current
            }
            .instruction()?,
            None,
        ),
        CompressionError::InvalidRootIndex,
    );
    let read_current_ix = read_current.instruction()?;
    send(&env, read_current_ix.clone(), None)?;

    let UpdateCompressedAccount {
        spp_proof_inputs,
        meta,
        old_value,
        version,
        output: update_output,
        output_hash: update_output_hash,
        input_nullifier,
    } = UpdateProofInputParams {
        authority: env.authority.pubkey(),
        current: current.utxo.clone(),
        new_value: 2,
        output_tree_id: DEFAULT_TREE_ID,
    }
    .to_proof_inputs()?;
    if input_nullifier != current.utxo.nullifier {
        bail!("update does not spend the discovered UTXO nullifier");
    }
    let (meta, proof) = prove_update(&env, spp_proof_inputs, meta)?;
    let update_ix = Update {
        payer: env.authority.pubkey(),
        input_tree: env.localnet.tree,
        output_tree: env.localnet.tree,
        meta,
        input_nullifier,
        old_value,
        version,
        new_value: 2,
        proof,
    }
    .instruction()?;

    let update_signature = send(&env, update_ix.clone(), None)?;
    wait_for_indexed_utxo(&env.localnet.client, pda.to_bytes(), update_signature);
    let updated = discover_account(&env.localnet.client, pda)?;
    assert_account(
        &updated.utxo,
        &update_output,
        update_output_hash,
        env.authority.pubkey(),
        2,
        env.localnet.tree,
        &env.localnet.client,
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

    // The old read with an empty account in place of the spent version's
    // nullifier PDA. Its proof still verifies, so only the PDA derivation
    // check stops it from passing the spent version off as unspent.
    let mut read_with_foreign_pda = read_current_ix.clone();
    read_with_foreign_pda
        .accounts
        .get_mut(2)
        .ok_or_else(|| anyhow!("read instruction has no nullifier PDA account"))?
        .pubkey = nullifier_pda(&env.localnet.tree, &updated.utxo.nullifier).0;
    assert_custom_error(
        "read of the old version with a foreign nullifier PDA",
        send(&env, read_with_foreign_pda, None),
        CompressionError::InvalidNullifierPda,
    );
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
            prove_read(
                &env,
                env.localnet.tree,
                &current.utxo,
                current_non_inclusion,
            )?
            .instruction()?,
            None,
        ),
        CompressionError::StateSpent,
    );
    let read_updated = prove_read(
        &env,
        env.localnet.tree,
        &updated.utxo,
        wait_for_non_inclusion_proof(
            &env.localnet.client,
            env.localnet.tree,
            updated.utxo.nullifier,
        ),
    )?;
    send(&env, read_updated.instruction()?, None)?;
    Ok(())
}

struct PoolTree {
    address: Address,
    id: u16,
}

/// A second pool tree, created by the fixture's protocol authority.
fn create_pool_tree(env: &Environment) -> Result<PoolTree> {
    let authority = fixture::protocol_authority();
    let id = next_tree_id(&env.localnet.client)?;
    let params = nullifier_tree_params();
    let fees = default_tree_fees(params.input_queue_zkp_batch_size)
        .ok_or_else(|| anyhow!("default tree fees do not fit the zkp batch size"))?;
    let creation = create_tree_instructions(
        &env.localnet.client,
        &env.authority.pubkey(),
        &authority.pubkey(),
        params,
        fees,
    )?;
    env.localnet.client.create_and_send_transaction(
        &creation.instructions,
        env.authority.pubkey(),
        &[&env.authority, &authority],
        ComputeBudgetConfig::for_instruction_count(creation.instructions.len()),
    )?;
    Ok(PoolTree {
        address: creation.tree,
        id,
    })
}

fn create_account(env: &Environment, value: u64) -> Result<DiscoveredAccount> {
    let pda = account_pda(&env.authority.pubkey());
    let (_, address) = address_input(&pda, DEFAULT_TREE_ID)?;
    let non_inclusion =
        wait_for_non_inclusion_proof(&env.localnet.client, env.localnet.tree, address);
    let (utxo_root_index, utxo_root) = tree_root(&env.localnet.client, env.localnet.tree)?;
    let create = CreateProofInputParams {
        authority: env.authority.pubkey(),
        new_value: value,
        non_inclusion,
        utxo_root,
        utxo_root_index,
    }
    .to_proof_inputs()?;
    let proof = ProverClient::local().prove_transfer(&create.transfer_inputs)?;
    let signature = send(
        env,
        Create {
            payer: env.authority.pubkey(),
            tree: env.localnet.tree,
            new_value: value,
            address_tree_context: create.address_tree_context,
            proof: ProofCompressed::try_from(proof)?.to_transact_proof(),
        }
        .instruction()?,
        None,
    )?;
    wait_for_indexed_utxo(&env.localnet.client, pda.to_bytes(), signature);
    discover_account(&env.localnet.client, pda)
}

fn update_account(
    env: &Environment,
    current: &DiscoveredAccount,
    new_value: u64,
    output_tree: &PoolTree,
) -> Result<DiscoveredAccount> {
    let pda = account_pda(&env.authority.pubkey());
    let UpdateCompressedAccount {
        spp_proof_inputs,
        meta,
        old_value,
        version,
        input_nullifier,
        ..
    } = UpdateProofInputParams {
        authority: env.authority.pubkey(),
        current: current.utxo.clone(),
        new_value,
        output_tree_id: output_tree.id,
    }
    .to_proof_inputs()?;
    let (meta, proof) = prove_update(env, spp_proof_inputs, meta)?;
    let signature = send(
        env,
        Update {
            payer: env.authority.pubkey(),
            input_tree: zolana_interface::pda::tree(current.utxo.tree_id),
            output_tree: output_tree.address,
            meta,
            input_nullifier,
            old_value,
            version,
            new_value,
            proof,
        }
        .instruction()?,
        None,
    )?;
    wait_for_indexed_utxo(&env.localnet.client, pda.to_bytes(), signature);
    discover_account(&env.localnet.client, pda)
}

fn state_of(account: &DiscoveredAccount) -> Result<AccountState> {
    decode_state(
        account
            .utxo
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| anyhow!("state data missing"))?,
    )
}

/// An account's UTXO moves out of the tree it was created in and is updated
/// and read in the tree it moved to. Update and read take the address from
/// the state, so a moved account keeps working; deriving it from the UTXO's
/// current tree would strand the account on its first update after the move.
#[test]
fn compressed_account_moves_between_trees() -> Result<()> {
    let env = setup(11)?;
    let other_tree = create_pool_tree(&env)?;
    let created = create_account(&env, 1)?;
    let moved = update_account(&env, &created, 2, &other_tree)?;
    let updated_in_place = update_account(&env, &moved, 3, &other_tree)?;
    let read = prove_read(
        &env,
        other_tree.address,
        &updated_in_place.utxo,
        wait_for_non_inclusion_proof(
            &env.localnet.client,
            other_tree.address,
            updated_in_place.utxo.nullifier,
        ),
    )?;
    send(&env, read.instruction()?, None)?;

    let created_state = state_of(&created)?;
    let final_state = state_of(&updated_in_place)?;
    assert_eq!(
        (
            moved.utxo.tree_id,
            updated_in_place.utxo.tree_id,
            final_state.address,
            final_state.value,
            final_state.version,
        ),
        (other_tree.id, other_tree.id, created_state.address, 3, 2)
    );
    Ok(())
}
