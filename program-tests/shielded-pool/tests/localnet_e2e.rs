//! Local-validator full-cycle SOL test.
//!
//! Flow: proofless shield into a private UTXO, transfer part of that value to a
//! second private owner, then unshield the transferred UTXO back to public SOL.

#[path = "common/transact.rs"]
mod transact_common;

use anyhow::anyhow;
use num_bigint::BigUint;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_client::{Rpc, SolanaRpc, TransferOutput, STATE_TREE_HEIGHT};
use zolana_event::{indexed_events_from_instruction_groups, instruction_may_emit_events};
use zolana_hasher::{sha256::Sha256BE, Hasher, Poseidon};
use zolana_interface::{
    instruction::{
        tag, CreateProtocolConfig, Deposit, Transact, TransactSolWithdrawal, TransactWithdrawal,
    },
    pda,
    state::tree_account_size,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::{
    create_tree_instructions, index_events, parsed_instruction_from_compiled, rpc_state_root,
    single_deposit_view, IndexedEvent, IndexedTransaction, TestIndexer, ZolanaProgramTest,
};
use zolana_transaction::{instructions::transact::private_tx_hash, Data, Utxo, SOL_MINT};
use zolana_tree::TreeAccount;

use crate::transact_common::{
    build_transfer_prover_inputs, dummy_input, dummy_transfer_output, eddsa_input_utxo,
    external_data_hash, fe, ix_output_ciphertext, new_transact_ix_data, nullifier_tree,
    output_owner_pk_hashes, prove_and_verify_transfer, public_input_hash, public_sol_field,
    real_output, set_output_owner_tags, spend_input, start_prover, transfer_output, SpendInputArgs,
    TransferProverInputsArgs,
};

const RPC_URL_ENV: &str = "ZOLANA_LOCALNET_URL";
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const AMOUNT: u64 = 1_000_000_000;
const TRANSFER_AMOUNT: u64 = 400_000_000;
const CHANGE_AMOUNT: u64 = AMOUNT - TRANSFER_AMOUNT;

type TestResult<T = ()> = anyhow::Result<T>;

#[test]
fn shield_transfer_unshield_sol_on_localnet_prints_signatures() -> TestResult {
    start_prover()?;

    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());

    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mut rpc = SolanaRpc::new(rpc_url.clone());
    let mut indexer = TestIndexer::new();
    rpc.assert_executable(&program_id)?;

    let payer = Keypair::new();
    let authority = Keypair::new();
    print_signature(
        "airdrop payer",
        &rpc.airdrop(&payer.pubkey(), 20_000_000_000)?,
    );
    print_signature(
        "airdrop authority",
        &rpc.airdrop(&authority.pubkey(), 1_000_000_000)?,
    );
    let recipient_owner = Keypair::new();
    print_signature(
        "airdrop recipient owner",
        &rpc.airdrop(&recipient_owner.pubkey(), 1_000_000)?,
    );

    let authority_bytes = authority.pubkey().to_bytes();
    let create_config = CreateProtocolConfig {
        authority: authority.pubkey(),
        protocol_authority: authority_bytes.into(),
        tree_creation_authority: authority_bytes.into(),
        tree_creation_is_permissionless: false,
        forester_authority: authority_bytes.into(),
        zone_creation_authority: authority_bytes.into(),
        zone_creation_is_permissionless: false,
        merge_authority: authority_bytes.into(),
    }
    .instruction();
    let create_config_tx = send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &[create_config],
        &authority.pubkey(),
        &[&authority],
    )?;
    print_signature("create_protocol_config", &create_config_tx.signature);

    let tree = Keypair::new();
    let create_tree = create_tree_instructions(
        &rpc,
        &payer.pubkey(),
        &authority.pubkey(),
        &tree.pubkey(),
        tree_account_size() as u64,
    )?;
    let create_tree_tx = send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &create_tree,
        &payer.pubkey(),
        &[&payer, &tree, &authority],
    )?;
    print_signature("create_tree", &create_tree_tx.signature);
    let tree_pubkey = tree.pubkey();
    let zero = [0u8; 32];

    let payer_bytes = payer.pubkey().to_bytes();
    let payer_blinding: [u8; 31] = [7u8; 31];
    let payer_nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let payer_nullifier_pk = payer_nullifier_key.pubkey()?;
    let payer_utxo = Utxo {
        owner: PublicKey::from_ed25519(&payer_bytes),
        asset: SOL_MINT,
        amount: AMOUNT,
        blinding: payer_blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let payer_owner_pk_hash = payer_utxo.owner.hash()?;
    let payer_owner_field = owner_hash(&payer_utxo.owner, &payer_nullifier_pk)?;

    let shield_data = ZolanaProgramTest::sol_shield_data(AMOUNT, payer_owner_field, payer_blinding);
    let shield_ix = Deposit {
        tree: tree_pubkey,
        depositor: payer.pubkey(),
        spl: None,
        view_tag: shield_data.view_tag,
        owner: shield_data.owner,
        blinding: shield_data.blinding,
        public_amount: shield_data.public_amount,
        program_data_hash: shield_data.program_data_hash,
        program_data: shield_data.program_data,
        cpi_signer: shield_data.cpi_signer,
    }
    .instruction();
    let shield_tx = send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &[shield_ix],
        &payer.pubkey(),
        &[&payer],
    )?;
    print_signature("deposit", &shield_tx.signature);

    let shield_view = single_deposit_view(&shield_tx.events)?;
    let payer_utxo_hash = payer_utxo.hash(&payer_nullifier_pk, &zero, &zero)?;
    assert_eq!(payer_utxo_hash, shield_view.utxo_hash);

    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree.append(&payer_utxo_hash)?;
    let (shield_utxo_root, nullifier_root) = on_chain_roots(&rpc, &tree_pubkey, 1)?;
    assert_eq!(state_tree.root(), shield_utxo_root, "shield root gate");
    assert_eq!(rpc_state_root(&rpc, &tree_pubkey)?, indexer.root());

    let nf_tree = nullifier_tree()?;
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");

    let payer_nullifier = payer_nullifier_key.nullifier(&payer_utxo_hash, &payer_blinding)?;
    let payer_non_inclusion =
        nf_tree.get_non_inclusion_proof(&BigUint::from_bytes_be(&payer_nullifier))?;
    let payer_state_path: Vec<[u8; 32]> = state_tree.get_proof_of_leaf(0, true)?.to_vec();
    let payer_spend_input = spend_input(SpendInputArgs {
        utxo: &payer_utxo,
        owner_field: &payer_owner_field,
        state_path: &payer_state_path,
        state_path_index: 0,
        non_inclusion: &payer_non_inclusion,
        roots: (shield_utxo_root, nullifier_root),
        nullifier: &payer_nullifier,
        owner_pk_hash: &payer_owner_pk_hash,
        nullifier_key: &payer_nullifier_key,
    })?;

    let recipient_bytes = recipient_owner.pubkey().to_bytes();
    let recipient_nullifier_key = NullifierKey::from_secret([11u8; 31]);
    let recipient_nullifier_pk = recipient_nullifier_key.pubkey()?;
    let recipient_public_key = PublicKey::from_ed25519(&recipient_bytes);
    let recipient_owner_field = owner_hash(&recipient_public_key, &recipient_nullifier_pk)?;

    let change_output = real_output(
        payer_utxo.owner,
        payer_nullifier_pk,
        SOL_MINT,
        CHANGE_AMOUNT,
        [13u8; 31],
    );
    let recipient_output = real_output(
        recipient_public_key,
        recipient_nullifier_pk,
        SOL_MINT,
        TRANSFER_AMOUNT,
        [17u8; 31],
    );
    let change_hash = change_output.hash()?;
    let recipient_hash = recipient_output.hash()?;
    let transfer_dummy_nullifier = fe(20);
    let transfer_roots = (shield_utxo_root, nullifier_root);
    let (transfer_dummy_output, transfer_dummy_hash) = dummy_transfer_output(&[19u8; 31])
        .map_err(|err| anyhow!("transfer dummy output: {err}"))?;

    // One ciphertext per output (1:1 owner mapping); each real output's view_tag is
    // its owner's `confidential_view_tag` so the program's `hash_field(view_tag)`
    // matches that owner's `owner_pk_field`.
    let change_view_tag = payer_utxo.owner.confidential_view_tag()?;
    let recipient_view_tag = recipient_public_key.confidential_view_tag()?;
    let mut transfer_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(payer_nullifier, 1),
            eddsa_input_utxo(transfer_dummy_nullifier, 1),
        ],
        None,
        vec![change_hash, recipient_hash, transfer_dummy_hash],
        vec![
            ix_output_ciphertext(change_view_tag),
            ix_output_ciphertext(recipient_view_tag),
            ix_output_ciphertext([3u8; 32]),
        ],
        None,
    );
    let transfer_owner_pk_hashes = output_owner_pk_hashes(&transfer_ix_data.output_ciphertexts, 3)
        .map_err(|err| anyhow!("transfer output owner pk hashes: {err}"))?;
    let mut transfer_outputs = vec![
        transfer_output(&change_output)?,
        transfer_output(&recipient_output)?,
        transfer_dummy_output,
    ];
    set_output_owner_tags(
        &mut transfer_outputs,
        &transfer_owner_pk_hashes,
        &[payer_nullifier_pk, recipient_nullifier_pk, zero],
    );
    let transfer_external_hash = external_data_hash(&transfer_ix_data, &zero)?;
    let transfer_private_tx = private_tx_hash(
        &[payer_utxo_hash, zero],
        &[change_hash, recipient_hash, zero],
        &transfer_external_hash,
    )?;
    let payer_pubkey_hash = Sha256BE::hash(&payer_bytes)?;
    let transfer_public_input_hash = public_input_hash(
        &[payer_nullifier, transfer_dummy_nullifier],
        &[change_hash, recipient_hash, transfer_dummy_hash],
        &[shield_utxo_root, shield_utxo_root],
        &[nullifier_root, nullifier_root],
        &transfer_private_tx,
        &transfer_external_hash,
        &zero,
        &payer_pubkey_hash,
        &[payer_owner_pk_hash, payer_owner_pk_hash],
        &transfer_owner_pk_hashes,
        &zero,
    );
    let transfer_prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![
            payer_spend_input,
            dummy_input(
                &transfer_dummy_nullifier,
                transfer_roots,
                &payer_owner_pk_hash,
            ),
        ],
        outputs: transfer_outputs,
        external_data_hash: transfer_external_hash,
        private_tx_hash: transfer_private_tx,
        public_sol_amount: zero,
        payer_pubkey_hash,
        public_input_hash: transfer_public_input_hash,
    });
    transfer_ix_data.proof = prove_and_verify_transfer(
        &transfer_prover_inputs,
        transfer_public_input_hash,
        "transfer",
    )?;
    transfer_ix_data.private_tx_hash = transfer_private_tx;

    let transfer_ix = Transact {
        payer: payer.pubkey(),
        tree: tree_pubkey,
        cpi_signer: None,
        withdrawal: None,
        data: transfer_ix_data,
    }
    .instruction();
    let transfer_tx = send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &[transfer_ix],
        &payer.pubkey(),
        &[&payer],
    )?;
    print_signature("shielded_transfer", &transfer_tx.signature);

    state_tree.append(&change_hash)?;
    state_tree.append(&recipient_hash)?;
    state_tree.append(&transfer_dummy_hash)?;
    let (transfer_utxo_root, transfer_nullifier_root) = on_chain_roots(&rpc, &tree_pubkey, 4)?;
    assert_eq!(state_tree.root(), transfer_utxo_root, "transfer root gate");
    assert_eq!(transfer_nullifier_root, nullifier_root);

    let recipient_utxo = Utxo {
        owner: recipient_public_key,
        asset: SOL_MINT,
        amount: TRANSFER_AMOUNT,
        blinding: recipient_output.blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    assert_eq!(
        recipient_hash,
        recipient_utxo.hash(&recipient_nullifier_pk, &zero, &zero)?
    );
    let recipient_owner_pk_hash = recipient_utxo.owner.hash()?;
    let recipient_nullifier =
        recipient_nullifier_key.nullifier(&recipient_hash, &recipient_utxo.blinding)?;
    let recipient_non_inclusion =
        nf_tree.get_non_inclusion_proof(&BigUint::from_bytes_be(&recipient_nullifier))?;
    let recipient_state_path: Vec<[u8; 32]> = state_tree.get_proof_of_leaf(2, true)?.to_vec();
    let recipient_spend_input = spend_input(SpendInputArgs {
        utxo: &recipient_utxo,
        owner_field: &recipient_owner_field,
        state_path: &recipient_state_path,
        state_path_index: 2,
        non_inclusion: &recipient_non_inclusion,
        roots: (transfer_utxo_root, transfer_nullifier_root),
        nullifier: &recipient_nullifier,
        owner_pk_hash: &recipient_owner_pk_hash,
        nullifier_key: &recipient_nullifier_key,
    })?;

    let public_recipient = Keypair::new().pubkey();
    print_signature(
        "airdrop public recipient",
        &rpc.airdrop(&public_recipient, 1_000_000)?,
    );
    let public_recipient_before = account_lamports(&rpc, &public_recipient)?;
    let vault = pda::sol_interface();
    let vault_before = account_lamports(&rpc, &vault)?;
    let withdraw_dummy_nullifier = fe(21);
    let withdraw_dummy_outputs: Vec<(TransferOutput, [u8; 32])> = [[1u8; 31], [2u8; 31], [3u8; 31]]
        .iter()
        .map(|blinding| {
            dummy_transfer_output(blinding).map_err(|err| anyhow!("withdraw dummy output: {err}"))
        })
        .collect::<TestResult<_>>()?;
    let withdraw_output_hashes: Vec<[u8; 32]> = withdraw_dummy_outputs
        .iter()
        .map(|(_, hash)| *hash)
        .collect();
    let mut withdraw_outputs: Vec<TransferOutput> = withdraw_dummy_outputs
        .into_iter()
        .map(|(out, _)| out)
        .collect();

    let mut withdraw_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(recipient_nullifier, 4),
            eddsa_input_utxo(withdraw_dummy_nullifier, 4),
        ],
        Some(-(TRANSFER_AMOUNT as i64)),
        withdraw_output_hashes.clone(),
        vec![
            ix_output_ciphertext([1u8; 32]),
            ix_output_ciphertext([2u8; 32]),
        ],
        None,
    );
    let withdraw_owner_pk_hashes = output_owner_pk_hashes(
        &withdraw_ix_data.output_ciphertexts,
        withdraw_output_hashes.len(),
    )
    .map_err(|err| anyhow!("withdraw output owner pk hashes: {err}"))?;
    set_output_owner_tags(
        &mut withdraw_outputs,
        &withdraw_owner_pk_hashes,
        &[zero, zero, zero],
    );
    let withdraw_external_hash =
        external_data_hash(&withdraw_ix_data, &public_recipient.to_bytes())?;
    let withdraw_private_tx = private_tx_hash(
        &[recipient_hash, zero],
        &[zero, zero, zero],
        &withdraw_external_hash,
    )?;
    let public_sol_field = public_sol_field(withdraw_ix_data.public_sol_amount);
    let recipient_pubkey_hash = Sha256BE::hash(&recipient_bytes)?;
    let withdraw_public_input_hash = public_input_hash(
        &[recipient_nullifier, withdraw_dummy_nullifier],
        &withdraw_output_hashes,
        &[transfer_utxo_root, transfer_utxo_root],
        &[transfer_nullifier_root, transfer_nullifier_root],
        &withdraw_private_tx,
        &withdraw_external_hash,
        &public_sol_field,
        &recipient_pubkey_hash,
        &[recipient_owner_pk_hash, recipient_owner_pk_hash],
        &withdraw_owner_pk_hashes,
        &zero,
    );
    let withdraw_prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![
            recipient_spend_input,
            dummy_input(
                &withdraw_dummy_nullifier,
                (transfer_utxo_root, transfer_nullifier_root),
                &recipient_owner_pk_hash,
            ),
        ],
        outputs: withdraw_outputs,
        external_data_hash: withdraw_external_hash,
        private_tx_hash: withdraw_private_tx,
        public_sol_amount: public_sol_field,
        payer_pubkey_hash: recipient_pubkey_hash,
        public_input_hash: withdraw_public_input_hash,
    });
    withdraw_ix_data.proof = prove_and_verify_transfer(
        &withdraw_prover_inputs,
        withdraw_public_input_hash,
        "withdraw",
    )?;
    withdraw_ix_data.private_tx_hash = withdraw_private_tx;

    let withdraw_ix = Transact {
        payer: recipient_owner.pubkey(),
        tree: tree_pubkey,
        cpi_signer: None,
        withdrawal: Some(TransactWithdrawal::Sol(TransactSolWithdrawal {
            recipient: public_recipient,
        })),
        data: withdraw_ix_data,
    }
    .instruction();
    let withdraw_tx = send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &[withdraw_ix],
        &payer.pubkey(),
        &[&payer, &recipient_owner],
    )?;
    print_signature("unshield", &withdraw_tx.signature);

    let public_recipient_after = account_lamports(&rpc, &public_recipient)?;
    let vault_after = account_lamports(&rpc, &vault)?;
    assert_eq!(
        public_recipient_after,
        public_recipient_before + TRANSFER_AMOUNT,
        "public recipient credited"
    );
    assert_eq!(
        vault_after,
        vault_before - TRANSFER_AMOUNT,
        "vault debited by transferred amount"
    );

    println!("localnet shield-transfer-unshield SOL test passed via {rpc_url}");
    Ok(())
}

fn on_chain_roots(
    rpc: &SolanaRpc,
    tree: &Pubkey,
    utxo_index: u16,
) -> TestResult<([u8; 32], [u8; 32])> {
    let address = Address::new_from_array(tree.to_bytes());
    let mut data = rpc
        .get_account(address)?
        .ok_or_else(|| anyhow!("tree account not found: {tree}"))?
        .data;
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes())
        .map_err(|err| anyhow!("load tree account: {err:?}"))?;
    Ok((
        account
            .get_utxo_tree_root(utxo_index)
            .map_err(|err| anyhow!("get utxo root {utxo_index}: {err:?}"))?,
        account
            .get_nullifier_tree_root(0)
            .map_err(|err| anyhow!("get nullifier root: {err:?}"))?,
    ))
}

fn account_lamports(rpc: &SolanaRpc, pubkey: &Pubkey) -> TestResult<u64> {
    let address = Address::new_from_array(pubkey.to_bytes());
    Ok(rpc
        .get_account(address)?
        .map(|account| account.lamports)
        .unwrap_or(0))
}

fn send_indexed(
    rpc: &mut SolanaRpc,
    indexer: &mut TestIndexer,
    program_id: Pubkey,
    ixs: &[solana_instruction::Instruction],
    payer: &Pubkey,
    signers: &[&Keypair],
) -> TestResult<zolana_program_test::IndexedTransaction> {
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = Message::new(ixs, Some(payer));
    let produces_events = produces_shielded_events(program_id, &message);
    let transaction = Transaction::new(signers, message, blockhash);
    let signature = rpc.send_transaction(&transaction)?;
    let events = if produces_events {
        fetch_indexed_events(rpc, indexer, program_id, &signature)?
    } else {
        Vec::new()
    };
    Ok(IndexedTransaction { signature, events })
}

fn fetch_indexed_events(
    rpc: &SolanaRpc,
    indexer: &mut TestIndexer,
    program_id: Pubkey,
    signature: &Signature,
) -> TestResult<Vec<IndexedEvent>> {
    let confirmed = rpc.fetch_confirmed_instruction_groups(signature)?;
    let events = indexed_events_from_instruction_groups(program_id, &confirmed.groups);
    index_events(indexer, &events)?;
    Ok(events)
}

fn produces_shielded_events(program_id: Pubkey, message: &Message) -> bool {
    message.instructions.iter().any(|instruction| {
        parsed_instruction_from_compiled(&message.account_keys, instruction, Some(1))
            .is_ok_and(|instruction| instruction_may_emit_events(program_id, &instruction))
    })
}

fn print_signature(label: &str, signature: &solana_signature::Signature) {
    println!("{label}: {signature}");
}

#[test]
fn shielded_event_detection_checks_program_context() {
    use solana_instruction::{AccountMeta, Instruction};

    let shielded_pool = Pubkey::new_unique();
    let other_program = Pubkey::new_unique();

    let unrelated = Message::new(
        &[Instruction {
            program_id: other_program,
            accounts: Vec::new(),
            data: vec![tag::DEPOSIT],
        }],
        None,
    );
    assert!(!produces_shielded_events(shielded_pool, &unrelated));

    let direct = Message::new(
        &[Instruction {
            program_id: shielded_pool,
            accounts: Vec::new(),
            data: vec![tag::DEPOSIT],
        }],
        None,
    );
    assert!(produces_shielded_events(shielded_pool, &direct));

    let zone_wrapper = Message::new(
        &[Instruction {
            program_id: other_program,
            accounts: vec![AccountMeta::new_readonly(shielded_pool, false)],
            data: vec![tag::ZONE_DEPOSIT],
        }],
        None,
    );
    assert!(produces_shielded_events(shielded_pool, &zone_wrapper));
}
