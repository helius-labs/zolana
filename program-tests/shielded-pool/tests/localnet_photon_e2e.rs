//! Local-validator SOL cycle backed by a real Photon Zolana indexer.
//!
//! Run with `just test-localnet-e2e-photon`.

#[path = "common/nullifier_test_forester.rs"]
mod nullifier_test_forester;
#[path = "common/transact.rs"]
#[allow(dead_code)]
mod transact_common;

use std::{
    collections::VecDeque,
    fs,
    path::Path,
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::anyhow;
use nullifier_test_forester::{ForesterAuthority, NullifierTestForester};
use serial_test::serial;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_client::{
    prover::field::{be, right_align_slice},
    EncryptedUtxoMatch, MerkleProof as IndexedMerkleProof,
    NonInclusionProof as IndexedNonInclusionProof, ProverClient, ProverInputs, Rpc,
    ShieldedTransaction, SolanaRpc, SpendProof, SpendUtxo, Transaction as ClientTransaction,
    TransferInput, TransferOutput, UtxoInputs, ZolanaIndexer,
};
use zolana_event::OutputData;
use zolana_hasher::{sha256::Sha256BE, Hasher};
use zolana_interface::{
    instruction::{
        CreateProtocolConfig, CreateTree, Deposit, Transact, TransactSolWithdrawal,
        TransactWithdrawal,
    },
    pda,
    state::{
        address_tree_params, tree_account_size, ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
        ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{
    hash::owner_hash, pubkey::PublicKey, shielded::ShieldedKeypair, NullifierKey, ViewingKey,
};
use zolana_program_test::{
    create_tree_instructions, rpc_state_root, system_create_account_ix, ZolanaProgramTest,
};
use zolana_test_utils::smart_account::{self, execute_sync_ix, StandardSigners};
use zolana_transaction::{
    instructions::transact::{no_address_hashes, private_tx_hash},
    serialization::{confidential::ConfidentialSenderBundle, DecodeCx, UtxoSerialization},
    utxo::derive_blinding,
    AssetRegistry, Data, Utxo, Wallet, WalletUtxo, DEFAULT_TAG_WINDOW, SOL_MINT,
};
use zolana_tree::TreeAccount;

use crate::transact_common::{
    build_transfer_prover_inputs, dummy_input, dummy_transfer_output, eddsa_input_utxo,
    external_data_hash, fe, ix_output_ciphertext, new_transact_ix_data, output_owner_pk_hashes,
    pack_proof, prove_and_verify_transfer, public_input_hash, public_sol_field, real_output,
    set_output_owner_tags, start_prover, transfer_output, TransferProverInputsArgs,
};

const RPC_URL_ENV: &str = "ZOLANA_LOCALNET_URL";
const INDEXER_URL_ENV: &str = "ZOLANA_INDEXER_URL";
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:8784";
const PHOTON_SNAPSHOT_FIXTURE_DIR_ENV: &str = "ZOLANA_PHOTON_SNAPSHOT_FIXTURE_DIR";
const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
const AMOUNT: u64 = 1_000_000_000;
const TRANSFER_AMOUNT: u64 = 400_000_000;
const CHANGE_AMOUNT: u64 = AMOUNT - TRANSFER_AMOUNT;
const LOCALNET_NULLIFIER_ZKP_BATCH_SIZE: u64 = 10;
const LOCALNET_NULLIFIER_BATCH_UPDATE_COUNT: u64 = 20;
const LOCALNET_NULLIFIERS_PER_QUEUE_TX: u64 = 2;

type TestResult<T = ()> = anyhow::Result<T>;

#[derive(Clone)]
struct PhotonSnapshotFixtureTx {
    signature: Signature,
    slot: u64,
    kind: &'static str,
    order: u64,
}

#[derive(serde::Serialize)]
struct PhotonSnapshotFixtureManifest {
    version: u8,
    tree: String,
    seed_deposit_count: u64,
    queue_tx_count: u64,
    batch_update_count: u64,
    nullifier_zkp_batch_size: u64,
    nullifiers: Vec<String>,
    transactions: Vec<PhotonSnapshotFixtureManifestTx>,
}

#[derive(serde::Serialize)]
struct PhotonSnapshotFixtureManifestTx {
    signature: String,
    slot: u64,
    kind: &'static str,
    order: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpendRail {
    P256,
    Eddsa,
}

impl SpendRail {
    fn label(self) -> &'static str {
        match self {
            SpendRail::P256 => "p256",
            SpendRail::Eddsa => "eddsa",
        }
    }
}

#[test]
#[serial]
fn shield_transfer_unshield_sol_with_photon_indexer() -> TestResult {
    restart_localnet();
    start_prover()?;

    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());
    let indexer_url =
        std::env::var(INDEXER_URL_ENV).unwrap_or_else(|_| DEFAULT_INDEXER_URL.to_owned());

    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mut rpc = SolanaRpc::new(rpc_url.clone());
    let indexer = ZolanaIndexer::new(indexer_url.clone()).with_http_trace();
    rpc.assert_executable(&program_id)?;
    let unknown_transactions =
        indexer.get_shielded_transactions_by_tags(vec![[253u8; 32]], None, Some(10))?;
    assert!(
        unknown_transactions.transactions.is_empty(),
        "unknown tag should not return transactions"
    );

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
    }
    .instruction();
    let create_config_sig = send_transaction(
        &mut rpc,
        &[create_config],
        &authority.pubkey(),
        &[&authority],
    )?;
    print_signature("create_protocol_config", &create_config_sig);

    let tree = Keypair::new();
    let create_tree = create_tree_instructions(
        &rpc,
        &payer.pubkey(),
        &authority.pubkey(),
        &tree.pubkey(),
        tree_account_size() as u64,
    )?;
    let create_tree_sig = send_transaction(
        &mut rpc,
        &create_tree,
        &payer.pubkey(),
        &[&payer, &tree, &authority],
    )?;
    print_signature("create_tree", &create_tree_sig);
    let tree_pubkey = tree.pubkey();
    let tree_address = Address::new_from_array(tree_pubkey.to_bytes());
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
        program: shield_data.program,
    }
    .instruction();
    let shield_sig = send_transaction(&mut rpc, &[shield_ix], &payer.pubkey(), &[&payer])?;
    print_signature("deposit", &shield_sig);
    capture_fixture(&rpc, "proofless_shield", &shield_sig);

    let payer_utxo_hash = payer_utxo.hash(&payer_nullifier_pk, &zero, &zero)?;
    let indexed_deposit = wait_for_indexed_utxo(&indexer, shield_data.view_tag, shield_sig)?;
    assert_eq!(indexed_deposit.output_slot.view_tag, shield_data.view_tag);
    assert_eq!(indexed_deposit.tx_signature, shield_sig);
    assert_eq!(
        indexed_deposit.output_slot.output_context.hash,
        payer_utxo_hash
    );
    assert_eq!(
        indexed_deposit.output_slot.output_context.tree,
        tree_address
    );
    assert!(indexed_deposit.tx_viewing_pk.is_none());
    let unknown_utxos = indexer.get_encrypted_utxos_by_tags(vec![[254u8; 32]], None, Some(10))?;
    assert!(
        unknown_utxos.matches.is_empty(),
        "unknown tag should not return encrypted UTXOs"
    );

    let payer_nullifier = payer_nullifier_key.nullifier(&payer_utxo_hash, &payer_blinding)?;
    let payer_state_proof = wait_for_merkle_proof(&indexer, tree_address, payer_utxo_hash)?;
    assert_eq!(
        indexed_deposit.output_slot.output_context.leaf_index,
        payer_state_proof.leaf_index
    );
    let payer_nullifier_proof =
        wait_for_non_inclusion_proof(&indexer, tree_address, payer_nullifier)?;
    let extra_nullifier_a = fe(90);
    let extra_nullifier_b = fe(91);
    let batched_non_inclusion = wait_for("batched indexed non-inclusion proofs", || {
        let response = indexer
            .get_non_inclusion_proofs(tree_address, vec![extra_nullifier_a, extra_nullifier_b])?;
        if response.proofs.len() == 2 {
            Ok(Some(response.proofs))
        } else {
            Ok(None)
        }
    })?;
    assert_eq!(batched_non_inclusion[0].leaf, extra_nullifier_a);
    assert_eq!(batched_non_inclusion[1].leaf, extra_nullifier_b);
    let (shield_utxo_root, nullifier_root) = on_chain_roots(&rpc, &tree_pubkey, 1)?;
    assert_eq!(payer_state_proof.root, shield_utxo_root, "shield root gate");
    assert_eq!(
        payer_nullifier_proof.root, nullifier_root,
        "nullifier root gate"
    );
    assert_eq!(rpc_state_root(&rpc, &tree_pubkey)?, payer_state_proof.root);
    let payer_spend_input = indexed_spend_input(IndexedSpendInputArgs {
        utxo: &payer_utxo,
        owner_field: &payer_owner_field,
        state_proof: &payer_state_proof,
        nullifier_proof: &payer_nullifier_proof,
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
    let transfer_roots = (payer_state_proof.root, payer_nullifier_proof.root);
    let (transfer_dummy_output, transfer_dummy_hash) = dummy_transfer_output(&[19u8; 31])
        .map_err(|err| anyhow!("transfer dummy output: {err}"))?;

    // One ciphertext per output (1:1 owner mapping); each real output's view_tag is
    // its owner's `confidential_view_tag` so the program's `hash_field(view_tag)`
    // matches that owner's `owner_pk_field`.
    let change_view_tag = payer_utxo.owner.confidential_view_tag()?;
    let recipient_view_tag = recipient_public_key.confidential_view_tag()?;
    let mut transfer_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(payer_nullifier, payer_state_proof.root_index),
            eddsa_input_utxo(transfer_dummy_nullifier, payer_state_proof.root_index),
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
        &no_address_hashes(2),
        &transfer_external_hash,
    )?;
    let payer_pubkey_hash = Sha256BE::hash(&payer_bytes)?;
    let transfer_public_input_hash = public_input_hash(
        &[payer_nullifier, transfer_dummy_nullifier],
        &[change_hash, recipient_hash, transfer_dummy_hash],
        &[transfer_roots.0, transfer_roots.0],
        &[transfer_roots.1, transfer_roots.1],
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
        withdrawal: None,
        data: transfer_ix_data,
    }
    .instruction();
    let transfer_sig = send_transaction(&mut rpc, &[transfer_ix], &payer.pubkey(), &[&payer])?;
    print_signature("shielded_transfer", &transfer_sig);
    capture_fixture(&rpc, "shielded_transfer", &transfer_sig);

    let indexed_transfer =
        wait_for_indexed_transaction(&indexer, recipient_view_tag, transfer_sig)?;
    assert_eq!(indexed_transfer.nullifiers.len(), 2);
    assert_eq!(indexed_transfer.output_slots.len(), 3);
    assert!(!indexed_transfer.proofless);
    assert_eq!(
        indexed_transfer.output_slots[0].output_context.hash,
        change_hash
    );
    assert_eq!(
        indexed_transfer.output_slots[1].output_context.hash,
        recipient_hash
    );

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
    let recipient_state_proof = wait_for_merkle_proof(&indexer, tree_address, recipient_hash)?;
    let recipient_nullifier_proof =
        wait_for_non_inclusion_proof(&indexer, tree_address, recipient_nullifier)?;
    let batched_state_proofs = wait_for("batched indexed merkle proofs", || {
        let response =
            indexer.get_merkle_proofs(tree_address, vec![payer_utxo_hash, recipient_hash])?;
        if response.proofs.len() == 2 {
            Ok(Some(response.proofs))
        } else {
            Ok(None)
        }
    })?;
    assert_eq!(batched_state_proofs[0].leaf, payer_utxo_hash);
    assert_eq!(batched_state_proofs[1].leaf, recipient_hash);
    let (transfer_utxo_root, transfer_nullifier_root) =
        on_chain_roots(&rpc, &tree_pubkey, recipient_state_proof.root_index)?;
    assert_eq!(
        recipient_state_proof.root, transfer_utxo_root,
        "transfer root gate"
    );
    assert_eq!(recipient_nullifier_proof.root, transfer_nullifier_root);
    let recipient_spend_input = indexed_spend_input(IndexedSpendInputArgs {
        utxo: &recipient_utxo,
        owner_field: &recipient_owner_field,
        state_proof: &recipient_state_proof,
        nullifier_proof: &recipient_nullifier_proof,
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
    let withdraw_roots = (recipient_state_proof.root, recipient_nullifier_proof.root);
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
            eddsa_input_utxo(recipient_nullifier, recipient_state_proof.root_index),
            eddsa_input_utxo(withdraw_dummy_nullifier, recipient_state_proof.root_index),
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
        &no_address_hashes(2),
        &withdraw_external_hash,
    )?;
    let public_sol_field = public_sol_field(withdraw_ix_data.public_sol_amount);
    let recipient_pubkey_hash = Sha256BE::hash(&recipient_bytes)?;
    let withdraw_public_input_hash = public_input_hash(
        &[recipient_nullifier, withdraw_dummy_nullifier],
        &withdraw_output_hashes,
        &[withdraw_roots.0, withdraw_roots.0],
        &[withdraw_roots.1, withdraw_roots.1],
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
                withdraw_roots,
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
        withdrawal: Some(TransactWithdrawal::Sol(TransactSolWithdrawal {
            recipient: public_recipient,
        })),
        data: withdraw_ix_data,
    }
    .instruction();
    let withdraw_sig = send_transaction(
        &mut rpc,
        &[withdraw_ix],
        &payer.pubkey(),
        &[&payer, &recipient_owner],
    )?;
    print_signature("unshield", &withdraw_sig);
    capture_fixture(&rpc, "unshield", &withdraw_sig);
    let indexed_withdraw = wait_for_indexed_transaction(&indexer, [0u8; 32], withdraw_sig)?;
    assert_eq!(indexed_withdraw.nullifiers.len(), 2);
    let first_page = wait_for("paginated indexed transactions", || {
        let response =
            indexer.get_shielded_transactions_by_tags(vec![[2u8; 32], [0u8; 32]], None, Some(1))?;
        if response.transactions.len() == 1 && response.next_cursor.is_some() {
            Ok(Some(response))
        } else {
            Ok(None)
        }
    })?;
    let second_page = indexer.get_shielded_transactions_by_tags(
        vec![[2u8; 32], [0u8; 32]],
        first_page.next_cursor,
        Some(1),
    )?;
    assert!(
        !second_page.transactions.is_empty(),
        "paginated transaction query should return a second page"
    );

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

    println!(
        "localnet Photon-backed shield-transfer-unshield SOL test passed via rpc={rpc_url} indexer={indexer_url}"
    );
    Ok(())
}

#[test]
#[serial]
fn nullifier_test_forester_batches_queued_nullifiers_with_photon_indexer() -> TestResult {
    restart_localnet();
    start_prover()?;

    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());
    let indexer_url =
        std::env::var(INDEXER_URL_ENV).unwrap_or_else(|_| DEFAULT_INDEXER_URL.to_owned());

    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mut rpc = SolanaRpc::new(rpc_url.clone());
    let indexer = ZolanaIndexer::new(indexer_url.clone()).with_http_trace();
    rpc.assert_executable(&program_id)?;

    let payer = Keypair::new();
    let authority = Keypair::new();
    let forester_key = Keypair::new();
    let merge_key = Keypair::new();
    let tree_key = Keypair::new();
    let zone_key = Keypair::new();
    print_signature(
        "airdrop forester-test payer",
        &rpc.airdrop(&payer.pubkey(), 20_000_000_000)?,
    );
    print_signature(
        "airdrop forester-test authority",
        &rpc.airdrop(&authority.pubkey(), 1_000_000_000)?,
    );
    print_signature(
        "airdrop forester-test forester",
        &rpc.airdrop(&forester_key.pubkey(), 1_000_000_000)?,
    );

    let accounts = smart_account::standard_accounts();
    for ix in accounts.create_ixs(
        &payer.pubkey(),
        StandardSigners {
            protocol: authority.pubkey(),
            forester: forester_key.pubkey(),
            merge: merge_key.pubkey(),
            tree: tree_key.pubkey(),
            zone: zone_key.pubkey(),
        },
    ) {
        send_transaction(&mut rpc, &[ix], &payer.pubkey(), &[&payer])?;
    }
    print_signature(
        "airdrop forester-test protocol-vault",
        &rpc.airdrop(&accounts.protocol_vault, 5_000_000_000)?,
    );

    let create_config = CreateProtocolConfig {
        authority: accounts.protocol_vault,
        protocol_authority: accounts.protocol_vault.to_bytes().into(),
        tree_creation_authority: accounts.tree_vault.to_bytes().into(),
        tree_creation_is_permissionless: false,
        forester_authority: accounts.forester_vault.to_bytes().into(),
        zone_creation_authority: accounts.zone_vault.to_bytes().into(),
        zone_creation_is_permissionless: false,
    }
    .instruction();
    let create_config = execute_sync_ix(
        &accounts.protocol_settings,
        0,
        &[authority.pubkey()],
        &[create_config],
    );
    let create_config_sig = send_transaction(
        &mut rpc,
        &[create_config],
        &payer.pubkey(),
        &[&payer, &authority],
    )?;
    print_signature("create_protocol_config", &create_config_sig);

    let tree = Keypair::new();
    let mut create_tree = create_tree_instructions_with_nullifier_params(
        &rpc,
        &payer.pubkey(),
        &accounts.tree_vault,
        &tree.pubkey(),
        tree_account_size() as u64,
        localnet_nullifier_params(),
    )?;
    let alloc_tree = create_tree.remove(0);
    let create_tree = execute_sync_ix(
        &accounts.tree_settings,
        0,
        &[tree_key.pubkey()],
        &create_tree,
    );
    let create_tree_sig = send_transaction(
        &mut rpc,
        &[alloc_tree, create_tree],
        &payer.pubkey(),
        &[&payer, &tree, &tree_key],
    )?;
    print_signature("create_tree_small_nullifier_batch", &create_tree_sig);
    let tree_pubkey = tree.pubkey();
    let tree_address = Address::new_from_array(tree_pubkey.to_bytes());
    let zero = [0u8; 32];
    let sender = shielded_ed25519_from_solana(&payer)?;
    let payer_public_key = sender.signing_pubkey();
    let payer_nullifier_key = sender.nullifier_key.clone();
    let payer_nullifier_pk = payer_nullifier_key.pubkey()?;
    let payer_owner_field = sender.owner_hash()?;
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let sender_address = sender.shielded_address()?;
    let assets = AssetRegistry::default();

    let queue_tx_count = LOCALNET_NULLIFIER_BATCH_UPDATE_COUNT * LOCALNET_NULLIFIER_ZKP_BATCH_SIZE
        / LOCALNET_NULLIFIERS_PER_QUEUE_TX;
    let mut queued_nullifiers =
        Vec::with_capacity((queue_tx_count * LOCALNET_NULLIFIERS_PER_QUEUE_TX) as usize);
    let mut fixture_transactions =
        Vec::with_capacity((2 + queue_tx_count + LOCALNET_NULLIFIER_BATCH_UPDATE_COUNT) as usize);
    let mut spendable_notes = VecDeque::new();

    for deposit_index in 0..2 {
        let blinding = stress_blinding(deposit_index);
        let utxo = Utxo {
            owner: payer_public_key,
            asset: SOL_MINT,
            amount: AMOUNT,
            blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let shield_data = ZolanaProgramTest::sol_shield_data(AMOUNT, payer_owner_field, blinding);
        let shield_ix = Deposit {
            tree: tree_pubkey,
            depositor: payer.pubkey(),
            spl: None,
            view_tag: shield_data.view_tag,
            owner: shield_data.owner,
            blinding: shield_data.blinding,
            public_amount: shield_data.public_amount,
            program: shield_data.program,
        }
        .instruction();
        let sig = send_transaction(&mut rpc, &[shield_ix], &payer.pubkey(), &[&payer])?;
        print_signature(&format!("seed_deposit_{deposit_index}"), &sig);
        let raw_tx = rpc.fetch_confirmed_transaction(&sig)?;
        fixture_transactions.push(PhotonSnapshotFixtureTx {
            signature: sig,
            slot: raw_tx.slot,
            kind: "deposit",
            order: deposit_index,
        });

        let note = RealSpendNote::new(utxo, &payer_nullifier_key, &payer_nullifier_pk, &zero)?;
        let indexed_deposit = wait_for_indexed_utxo(&indexer, shield_data.view_tag, sig)?;
        assert_eq!(indexed_deposit.output_slot.output_context.hash, note.hash);
        spendable_notes.push_back(note);
    }

    for i in 0..queue_tx_count {
        let roots = latest_tree_roots(&rpc, &tree_pubkey)?;
        assert_eq!(
            roots.nullifier_root_index, 0,
            "nullifier root should remain unchanged until the forester batch"
        );

        let first_note = spendable_notes
            .pop_front()
            .ok_or_else(|| anyhow!("missing first spendable note for queue tx {i}"))?;
        let second_note = spendable_notes
            .pop_front()
            .ok_or_else(|| anyhow!("missing second spendable note for queue tx {i}"))?;
        queued_nullifiers.push(first_note.nullifier);
        queued_nullifiers.push(second_note.nullifier);

        let first_state_proof = wait_for_merkle_proof(&indexer, tree_address, first_note.hash)?;
        let second_state_proof = wait_for_merkle_proof(&indexer, tree_address, second_note.hash)?;
        let first_nullifier_proof =
            wait_for_non_inclusion_proof(&indexer, tree_address, first_note.nullifier)?;
        let second_nullifier_proof =
            wait_for_non_inclusion_proof(&indexer, tree_address, second_note.nullifier)?;
        assert_eq!(
            first_state_proof.root, roots.utxo_root,
            "Photon state root must match on-chain before queue tx {i}"
        );
        assert_eq!(
            second_state_proof.root, roots.utxo_root,
            "Photon state root must match on-chain before queue tx {i}"
        );
        assert_eq!(
            first_nullifier_proof.root, roots.nullifier_root,
            "Photon nullifier root must match on-chain before queue tx {i}"
        );
        assert_eq!(
            second_nullifier_proof.root, roots.nullifier_root,
            "Photon nullifier root must match on-chain before queue tx {i}"
        );

        let total_amount = first_note
            .utxo
            .amount
            .checked_add(second_note.utxo.amount)
            .ok_or_else(|| anyhow!("queue tx {i} amount overflow"))?;
        if total_amount <= TRANSFER_AMOUNT {
            return Err(anyhow!(
                "queue tx {i} total amount {total_amount} cannot fund transfer amount {TRANSFER_AMOUNT}"
            ));
        }

        let wait_tag = payer_public_key.confidential_view_tag()?;
        let mut tx = ClientTransaction::new(
            sender_address,
            vec![
                SpendUtxo::from_keypair(first_note.utxo.clone(), &sender),
                SpendUtxo::from_keypair(second_note.utxo.clone(), &sender),
            ],
            payer_address,
        );
        tx.send(&sender_address, SOL_MINT, TRANSFER_AMOUNT)?;
        let signed = tx.sign(&sender, &assets)?;
        let commitments = signed.input_commitments()?;
        assert_eq!(commitments.len(), 2);
        assert_eq!(commitments[0].nullifier, first_note.nullifier);
        assert_eq!(commitments[1].nullifier, second_note.nullifier);

        let assembled = zolana_client::assemble(
            signed,
            &[
                SpendProof {
                    state: first_state_proof,
                    nullifier: first_nullifier_proof,
                },
                SpendProof {
                    state: second_state_proof,
                    nullifier: second_nullifier_proof,
                },
            ],
        )?;
        let proof = match &assembled.prover_inputs {
            ProverInputs::Eddsa(inputs) => ProverClient::local().prove_transfer(inputs)?,
            ProverInputs::P256(_) => {
                return Err(anyhow!(
                    "expected EdDSA prover inputs for a non-relayed confidential queue tx"
                ))
            }
        };
        let ix_data = assembled.with_proof(pack_proof(&proof)?);

        let tx_ix = Transact {
            payer: payer.pubkey(),
            tree: tree_pubkey,
            withdrawal: None,
            data: ix_data,
        }
        .instruction();
        let sig = send_transaction(&mut rpc, &[tx_ix], &payer.pubkey(), &[&payer])?;
        print_signature(&format!("queue_nullifiers_{i}"), &sig);
        let raw_tx = rpc.fetch_confirmed_transaction(&sig)?;
        fixture_transactions.push(PhotonSnapshotFixtureTx {
            signature: sig,
            slot: raw_tx.slot,
            kind: "queue",
            order: i,
        });

        let indexed = wait_for_indexed_transaction(&indexer, wait_tag, sig)?;
        assert_eq!(
            indexed.nullifiers,
            vec![first_note.nullifier, second_note.nullifier]
        );
        assert_eq!(indexed.nullifiers.len(), 2);
        assert_eq!(indexed.output_slots.len(), 3);
        assert!(!indexed.proofless);
        assert!(indexed.tx_viewing_pk.is_some());
        assert!(indexed.salt.is_some());
        assert!(
            !indexed.output_slots[0].payload.is_empty(),
            "sender bundle should carry encrypted change data"
        );
        assert!(
            indexed.output_slots[1].payload.is_empty(),
            "SOL change commitment is covered by the sender bundle"
        );
        assert!(
            !indexed.output_slots[2].payload.is_empty(),
            "recipient output should carry an encrypted UTXO payload"
        );

        let tx_viewing_pk = indexed
            .tx_viewing_pk
            .ok_or_else(|| anyhow!("indexed queue tx missing tx_viewing_pk"))?;
        let salt = indexed
            .salt
            .ok_or_else(|| anyhow!("indexed queue tx missing salt"))?;
        let first_nullifier = commitments
            .first()
            .ok_or_else(|| anyhow!("queue tx missing input commitment"))?
            .nullifier;
        let sender_slot = indexed
            .output_slots
            .first()
            .ok_or_else(|| anyhow!("indexed queue tx missing sender slot"))?;
        let sender_blob = match sender_slot
            .output_data()
            .ok_or_else(|| anyhow!("sender slot is not decodable output data"))?
        {
            OutputData::Encrypted(blob)
            | OutputData::VerifiablyEncrypted(blob)
            | OutputData::Plaintext(blob) => blob,
        };
        let (_scheme, sender_ciphertext) = sender_blob
            .split_first()
            .ok_or_else(|| anyhow!("sender bundle missing scheme byte"))?;
        let sender_plaintext = ConfidentialSenderBundle::decode(
            sender_ciphertext,
            &DecodeCx {
                viewing_key: &sender.viewing_key,
                tx_viewing_pk: Some(tx_viewing_pk),
                salt: Some(salt),
                slot_index: 0,
                first_nullifier: Some(first_nullifier),
            },
        )?;

        let change_note = Utxo {
            owner: payer_public_key,
            asset: SOL_MINT,
            amount: total_amount - TRANSFER_AMOUNT,
            blinding: derive_blinding(&sender_plaintext.blinding_seed, 1),
            zone_program_id: None,
            data: Data::default(),
        };
        let recipient_note = Utxo {
            owner: payer_public_key,
            asset: SOL_MINT,
            amount: TRANSFER_AMOUNT,
            blinding: derive_blinding(&sender_plaintext.blinding_seed, 2),
            zone_program_id: None,
            data: Data::default(),
        };
        let change_note = RealSpendNote::new(
            change_note,
            &payer_nullifier_key,
            &payer_nullifier_pk,
            &zero,
        )?;
        let recipient_note = RealSpendNote::new(
            recipient_note,
            &payer_nullifier_key,
            &payer_nullifier_pk,
            &zero,
        )?;
        assert_eq!(
            change_note.hash, indexed.output_slots[1].output_context.hash,
            "decrypted SOL change note should match output commitment"
        );
        assert_eq!(
            recipient_note.hash, indexed.output_slots[2].output_context.hash,
            "decrypted recipient note should match output commitment"
        );
        spendable_notes.push_back(change_note);
        spendable_notes.push_back(recipient_note);
    }

    let before_forester = latest_tree_roots(&rpc, &tree_pubkey)?;
    assert_eq!(
        before_forester.nullifier_root_index, 0,
        "queued nullifiers should not update the indexed tree root"
    );

    let mut forester = NullifierTestForester::default();
    let mut previous_forester_roots = before_forester;
    for batch_index in 0..LOCALNET_NULLIFIER_BATCH_UPDATE_COUNT {
        let forester_sig = forester.run(
            &mut rpc,
            ForesterAuthority {
                signer: &forester_key,
                settings: accounts.forester_settings,
                account_index: 0,
                vault: accounts.forester_vault,
            },
            tree_pubkey,
            &queued_nullifiers,
        )?;
        print_signature(
            &format!("batch_update_nullifier_tree_{batch_index}"),
            &forester_sig,
        );
        let raw_tx = rpc.fetch_confirmed_transaction(&forester_sig)?;
        fixture_transactions.push(PhotonSnapshotFixtureTx {
            signature: forester_sig,
            slot: raw_tx.slot,
            kind: "batch_update",
            order: batch_index,
        });

        let after_forester = latest_tree_roots(&rpc, &tree_pubkey)?;
        assert_ne!(
            after_forester.nullifier_root_index, previous_forester_roots.nullifier_root_index,
            "forester batch {batch_index} should advance the nullifier root"
        );

        let fresh_nullifier = fe(9_000 + batch_index);
        let fresh_proof = wait_for(
            format!("Photon nullifier root after batch {batch_index}"),
            || {
                let response =
                    indexer.get_non_inclusion_proofs(tree_address, vec![fresh_nullifier])?;
                Ok(response.proofs.into_iter().next().filter(|proof| {
                    proof.root == after_forester.nullifier_root
                        && proof.root_index == after_forester.nullifier_root_index
                }))
            },
        )?;
        assert_eq!(fresh_proof.leaf, fresh_nullifier);
        previous_forester_roots = after_forester;
    }
    assert_eq!(
        u64::from(previous_forester_roots.nullifier_root_index),
        LOCALNET_NULLIFIER_BATCH_UPDATE_COUNT,
        "all forester batches should advance the nullifier root"
    );

    for nullifier_index in [0, queued_nullifiers.len() / 2, queued_nullifiers.len() - 1] {
        wait_for(
            format!("forested nullifier {nullifier_index} rejected"),
            || match indexer
                .get_non_inclusion_proofs(tree_address, vec![queued_nullifiers[nullifier_index]])
            {
                Ok(response) if response.proofs.is_empty() => Ok(Some(())),
                Ok(_) => Ok(None),
                Err(_) => Ok(Some(())),
            },
        )?;
    }
    export_photon_snapshot_fixture(
        &rpc,
        tree_pubkey,
        queue_tx_count,
        &queued_nullifiers,
        &fixture_transactions,
    )?;

    println!(
        "localnet Photon nullifier forester test passed via rpc={rpc_url} indexer={indexer_url}"
    );
    Ok(())
}

struct IndexedSpendInputArgs<'a> {
    utxo: &'a Utxo,
    owner_field: &'a [u8; 32],
    state_proof: &'a IndexedMerkleProof,
    nullifier_proof: &'a IndexedNonInclusionProof,
    nullifier: &'a [u8; 32],
    owner_pk_hash: &'a [u8; 32],
    nullifier_key: &'a NullifierKey,
}

fn indexed_spend_input(args: IndexedSpendInputArgs<'_>) -> TestResult<TransferInput> {
    Ok(TransferInput {
        utxo: UtxoInputs::new(
            args.owner_field,
            &args.utxo.asset,
            args.utxo.amount,
            &args.utxo.blinding,
            &[0u8; 32],
            &[0u8; 32],
            &args.utxo.zone_program_id,
        )?,
        is_dummy: be(&fe(0)),
        state_path_elements: args.state_proof.path.iter().map(be).collect(),
        state_path_index: be(&fe(args.state_proof.leaf_index)),
        nullifier_low_value: be(&args.nullifier_proof.low_element),
        nullifier_next_value: be(&args.nullifier_proof.high_element),
        nullifier_low_path_elements: args.nullifier_proof.path.iter().map(be).collect(),
        nullifier_low_path_index: be(&fe(args.nullifier_proof.low_element_index)),
        utxo_tree_root: be(&args.state_proof.root),
        nullifier_tree_root: be(&args.nullifier_proof.root),
        nullifier: be(args.nullifier),
        owner_pk_hash: be(args.owner_pk_hash),
        nullifier_secret: be(&right_align_slice(args.nullifier_key.secret())?),
    })
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

struct LatestTreeRoots {
    utxo_root: [u8; 32],
    nullifier_root_index: u16,
    nullifier_root: [u8; 32],
}

struct RealSpendNote {
    utxo: Utxo,
    hash: [u8; 32],
    nullifier: [u8; 32],
}

impl RealSpendNote {
    fn new(
        utxo: Utxo,
        nullifier_key: &NullifierKey,
        nullifier_pk: &[u8; 32],
        zero: &[u8; 32],
    ) -> TestResult<Self> {
        let hash = utxo.hash(nullifier_pk, zero, zero)?;
        let nullifier = utxo.nullifier(&hash, nullifier_key)?;
        Ok(Self {
            utxo,
            hash,
            nullifier,
        })
    }
}

fn latest_tree_roots(rpc: &SolanaRpc, tree: &Pubkey) -> TestResult<LatestTreeRoots> {
    let address = Address::new_from_array(tree.to_bytes());
    let mut data = rpc
        .get_account(address)?
        .ok_or_else(|| anyhow!("tree account not found: {tree}"))?
        .data;
    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes())
        .map_err(|err| anyhow!("load tree account: {err:?}"))?;
    let utxo_root_index = account.utxo_tree().current_root_index();
    let utxo_root = account
        .get_utxo_tree_root(utxo_root_index)
        .map_err(|err| anyhow!("get utxo root {utxo_root_index}: {err:?}"))?;
    let (nullifier_root_index, nullifier_root) = {
        let nullifier_tree = account.nullifer_tree();
        let root_index = u16::try_from(nullifier_tree.get_root_index())
            .map_err(|_| anyhow!("nullifier root index does not fit in u16"))?;
        let root = nullifier_tree
            .get_root()
            .ok_or_else(|| anyhow!("nullifier tree has no current root"))?;
        (root_index, root)
    };
    Ok(LatestTreeRoots {
        utxo_root,
        nullifier_root_index,
        nullifier_root,
    })
}

fn localnet_nullifier_params() -> zolana_tree::InitAddressTreeAccountsInstructionData {
    let mut params = address_tree_params();
    let zkp_batch_count =
        ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE / ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE;
    params.input_queue_zkp_batch_size = LOCALNET_NULLIFIER_ZKP_BATCH_SIZE;
    params.input_queue_batch_size = LOCALNET_NULLIFIER_ZKP_BATCH_SIZE * zkp_batch_count;
    params
}

fn create_tree_instructions_with_nullifier_params(
    rpc: &SolanaRpc,
    payer: &Pubkey,
    authority: &Pubkey,
    tree: &Pubkey,
    account_size: u64,
    nullifier_params: zolana_tree::InitAddressTreeAccountsInstructionData,
) -> TestResult<Vec<solana_instruction::Instruction>> {
    let rent = rpc.get_minimum_balance_for_rent_exemption(account_size as usize)?;
    Ok(vec![
        system_create_account_ix(
            payer,
            tree,
            rent,
            account_size,
            &pda::shielded_pool_program_id(),
        ),
        CreateTree {
            authority: *authority,
            tree: *tree,
            owner: *authority,
        }
        .instruction_with_nullifier_params(nullifier_params),
    ])
}

fn stress_blinding(index: u64) -> [u8; 31] {
    let mut blinding = [0u8; 31];
    blinding[0] = 0x51;
    blinding[23..].copy_from_slice(&index.to_be_bytes());
    blinding
}

fn export_photon_snapshot_fixture(
    rpc: &SolanaRpc,
    tree: Pubkey,
    queue_tx_count: u64,
    queued_nullifiers: &[[u8; 32]],
    transactions: &[PhotonSnapshotFixtureTx],
) -> TestResult {
    let Ok(dir) = std::env::var(PHOTON_SNAPSHOT_FIXTURE_DIR_ENV) else {
        return Ok(());
    };

    let dir = Path::new(&dir);
    let tx_dir = dir.join("transactions");
    if tx_dir.exists() {
        fs::remove_dir_all(&tx_dir)?;
    }
    fs::create_dir_all(&tx_dir)?;

    for tx in transactions {
        let raw_tx = rpc.fetch_confirmed_transaction(&tx.signature)?;
        let path = tx_dir.join(tx.signature.to_string());
        fs::write(path, serde_json::to_string_pretty(&raw_tx)?)?;
    }

    let manifest = PhotonSnapshotFixtureManifest {
        version: 1,
        tree: tree.to_string(),
        seed_deposit_count: 2,
        queue_tx_count,
        batch_update_count: LOCALNET_NULLIFIER_BATCH_UPDATE_COUNT,
        nullifier_zkp_batch_size: LOCALNET_NULLIFIER_ZKP_BATCH_SIZE,
        nullifiers: queued_nullifiers.iter().map(hex::encode).collect(),
        transactions: transactions
            .iter()
            .map(|tx| PhotonSnapshotFixtureManifestTx {
                signature: tx.signature.to_string(),
                slot: tx.slot,
                kind: tx.kind,
                order: tx.order,
            })
            .collect(),
    };
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    println!(
        "exported Photon snapshot fixture with {} txs to {}",
        transactions.len(),
        dir.display()
    );
    Ok(())
}

fn account_lamports(rpc: &SolanaRpc, pubkey: &Pubkey) -> TestResult<u64> {
    let address = Address::new_from_array(pubkey.to_bytes());
    Ok(rpc
        .get_account(address)?
        .map(|account| account.lamports)
        .unwrap_or(0))
}

fn send_transaction(
    rpc: &mut SolanaRpc,
    ixs: &[solana_instruction::Instruction],
    payer: &Pubkey,
    signers: &[&Keypair],
) -> TestResult<Signature> {
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = Message::new(ixs, Some(payer));
    let transaction = Transaction::new(signers, message, blockhash);
    Ok(rpc.send_transaction(&transaction)?)
}

fn wait_for_indexed_utxo(
    indexer: &ZolanaIndexer,
    tag: [u8; 32],
    signature: Signature,
) -> TestResult<EncryptedUtxoMatch> {
    wait_for("indexed UTXO", || {
        let response = indexer.get_encrypted_utxos_by_tags(vec![tag], None, Some(50))?;
        Ok(response
            .matches
            .into_iter()
            .find(|item| item.tx_signature == signature))
    })
}

fn wait_for_indexed_transaction(
    indexer: &ZolanaIndexer,
    tag: [u8; 32],
    signature: Signature,
) -> TestResult<ShieldedTransaction> {
    wait_for("indexed transaction", || {
        let response = indexer.get_shielded_transactions_by_tags(vec![tag], None, Some(100))?;
        Ok(response
            .transactions
            .into_iter()
            .find(|item| item.tx_signature == signature))
    })
}

fn wait_for_merkle_proof(
    indexer: &ZolanaIndexer,
    tree: Address,
    leaf: [u8; 32],
) -> TestResult<IndexedMerkleProof> {
    wait_for("indexed merkle proof", || {
        let response = indexer.get_merkle_proofs(tree, vec![leaf])?;
        Ok(response.proofs.into_iter().next())
    })
}

fn wait_for_non_inclusion_proof(
    indexer: &ZolanaIndexer,
    tree: Address,
    leaf: [u8; 32],
) -> TestResult<IndexedNonInclusionProof> {
    wait_for("indexed non-inclusion proof", || {
        let response = indexer.get_non_inclusion_proofs(tree, vec![leaf])?;
        Ok(response.proofs.into_iter().next())
    })
}

fn wait_for<T>(
    label: impl AsRef<str>,
    mut poll: impl FnMut() -> Result<Option<T>, zolana_client::ClientError>,
) -> TestResult<T> {
    let label = label.as_ref();
    let started = Instant::now();
    let mut last_error = None;
    while started.elapsed() < INDEXER_TIMEOUT {
        match poll() {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => {}
            Err(error) => last_error = Some(error.to_string()),
        }
        sleep(Duration::from_millis(500));
    }
    Err(anyhow!(
        "timed out waiting for {label}; last indexer error: {}",
        last_error.unwrap_or_else(|| "none".to_string())
    ))
}

fn print_signature(label: &str, signature: &Signature) {
    println!("{label}: {signature}");
}

/// When `RINGS_FIXTURE_DIR` is set, write the confirmed transaction's
/// `getTransaction` JSON to `<dir>/<signature>` and print its slot. This
/// regenerates the photon-indexer parser fixtures in
/// `tests/data/transactions/rings_e2e/` against the current event
/// serialization. No-op when the env var is unset, so normal runs are
/// unaffected.
fn capture_fixture(rpc: &SolanaRpc, label: &str, signature: &Signature) {
    let Ok(dir) = std::env::var("RINGS_FIXTURE_DIR") else {
        return;
    };
    let json = rpc
        .fetch_confirmed_transaction_json(signature)
        .expect("fetch transaction json for fixture");
    let slot = rpc
        .fetch_confirmed_transaction_slot(signature)
        .expect("fetch transaction slot for fixture");
    let path = format!("{dir}/{signature}");
    std::fs::write(&path, json).expect("write rings fixture");
    println!("captured fixture {label}: slot={slot} path={path}");
}

fn shielded_ed25519_from_solana(signer: &Keypair) -> TestResult<ShieldedKeypair> {
    let seed: [u8; 32] = signer.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    Ok(ShieldedKeypair::from_ed25519(&seed, ViewingKey::new())?)
}

/// Restart a fresh validator + Photon indexer so each test runs against clean
/// chain state. The protocol config is a global singleton, so tests cannot share
/// a validator; combined with `#[serial]` this gives every test an isolated
/// localnet.
///
/// Drives the `zolana` CLI (the single source of truth for localnet
/// orchestration, including readiness checks). `--skip-prover` leaves the
/// persistent prover server untouched so its proving keys stay loaded.
fn restart_localnet() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| format!("{root}/target/debug/zolana"));
    let program_id =
        std::env::var("SHIELDED_POOL_PROGRAM_ID").expect("SHIELDED_POOL_PROGRAM_ID must be set");
    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".to_string());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".to_string());
    let program_so = format!("{root}/target/deploy/shielded_pool_program.so");
    let smart_account_id = smart_account::SMART_ACCOUNT_PROGRAM_ID.to_string();
    let smart_account_so = format!("{root}/target/deploy/squads_smart_account_program.so");
    let smart_account_account_dir = "/tmp/zolana-photon-smart-account-accounts";
    smart_account::write_program_config_fixture(smart_account_account_dir);

    let status = std::process::Command::new(&cli)
        .current_dir(root)
        .args([
            "test-validator",
            "--no-use-surfpool",
            "--with-photon",
            "--skip-prover",
            "--rpc-port",
            &rpc_port,
            "--photon-port",
            &photon_port,
            "--ledger",
            "/tmp/zolana-photon-test-ledger",
            "--sbf-program",
            &program_id,
            &program_so,
            "--sbf-program",
            &smart_account_id,
            &smart_account_so,
            "--account-dir",
            smart_account_account_dir,
        ])
        .status()
        .expect("run zolana test-validator");
    assert!(status.success(), "zolana test-validator restart failed");
}

/// End-to-end encrypted transfer: shield two sender UTXOs, transfer one private
/// output to a recipient using the high-level `Transaction` builder (real HPKE
/// encryption), then recover the recipient UTXO purely by DECRYPTING the
/// ciphertext the Photon indexer returns -- no plaintext reconstruction.
///
/// Two real inputs are used so the proof shape is exactly (2, 3), matching the
/// available `transfer_p256_2_3` key without padding the instruction with dummy
/// (zero) nullifiers that the program would reject on insertion.
#[test]
#[serial]
fn shield_encrypted_transfer_recovered_by_decryption() -> TestResult {
    shield_encrypted_transfer_recovered_by_decryption_for(SpendRail::P256)
}

#[test]
#[serial]
fn shield_encrypted_transfer_eddsa_recovered_by_decryption() -> TestResult {
    shield_encrypted_transfer_recovered_by_decryption_for(SpendRail::Eddsa)
}

fn shield_encrypted_transfer_recovered_by_decryption_for(expected_rail: SpendRail) -> TestResult {
    restart_localnet();
    start_prover()?;

    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());
    let indexer_url =
        std::env::var(INDEXER_URL_ENV).unwrap_or_else(|_| DEFAULT_INDEXER_URL.to_owned());

    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mut rpc = SolanaRpc::new(rpc_url.clone());
    let indexer = ZolanaIndexer::new(indexer_url.clone());
    rpc.assert_executable(&program_id)?;

    let payer = Keypair::new();
    let authority = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 20_000_000_000)?;
    rpc.airdrop(&authority.pubkey(), 1_000_000_000)?;

    let authority_bytes = authority.pubkey().to_bytes();
    let create_config = CreateProtocolConfig {
        authority: authority.pubkey(),
        protocol_authority: authority_bytes.into(),
        tree_creation_authority: authority_bytes.into(),
        tree_creation_is_permissionless: false,
        forester_authority: authority_bytes.into(),
        zone_creation_authority: authority_bytes.into(),
        zone_creation_is_permissionless: false,
    }
    .instruction();
    send_transaction(
        &mut rpc,
        &[create_config],
        &authority.pubkey(),
        &[&authority],
    )?;

    let tree = Keypair::new();
    let create_tree = create_tree_instructions(
        &rpc,
        &payer.pubkey(),
        &authority.pubkey(),
        &tree.pubkey(),
        tree_account_size() as u64,
    )?;
    send_transaction(
        &mut rpc,
        &create_tree,
        &payer.pubkey(),
        &[&payer, &tree, &authority],
    )?;
    let tree_pubkey = tree.pubkey();
    let tree_address = Address::new_from_array(tree_pubkey.to_bytes());
    let zero = [0u8; 32];

    let assets = AssetRegistry::default();
    let sender = match expected_rail {
        SpendRail::P256 => ShieldedKeypair::new()?,
        SpendRail::Eddsa => shielded_ed25519_from_solana(&payer)?,
    };
    let recipient = match expected_rail {
        SpendRail::P256 => ShieldedKeypair::new()?,
        SpendRail::Eddsa => shielded_ed25519_from_solana(&Keypair::new())?,
    };
    let recipient_address = recipient.shielded_address()?;
    let recipient_view_tag = recipient.signing_pubkey().confidential_view_tag()?;
    let sender_nullifier_key = NullifierKey::from_secret(*sender.nullifier_key.secret());
    let sender_nullifier_pk = sender_nullifier_key.pubkey()?;

    // ---- shield two sender-owned UTXOs (reconstructable from fixed blindings) ----
    let half = AMOUNT / 2;
    let deposit_blindings: [[u8; 31]; 2] = [[7u8; 31], [8u8; 31]];
    let mut spends = Vec::new();
    for blinding in deposit_blindings {
        let utxo = Utxo {
            owner: sender.signing_pubkey(),
            asset: SOL_MINT,
            amount: half,
            blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let owner_field = owner_hash(&utxo.owner, &sender_nullifier_pk)?;
        let shield_data = ZolanaProgramTest::sol_shield_data(half, owner_field, blinding);
        let shield_ix = Deposit {
            tree: tree_pubkey,
            depositor: payer.pubkey(),
            spl: None,
            view_tag: shield_data.view_tag,
            owner: shield_data.owner,
            blinding: shield_data.blinding,
            public_amount: shield_data.public_amount,
            program: shield_data.program,
        }
        .instruction();
        send_transaction(&mut rpc, &[shield_ix], &payer.pubkey(), &[&payer])?;
        let utxo_hash = utxo.hash(&sender_nullifier_pk, &zero, &zero)?;
        wait_for_merkle_proof(&indexer, tree_address, utxo_hash)?;
        spends.push(SpendUtxo::from_keypair(utxo, &sender));
    }

    // ---- build the encrypted transfer with the high-level client builder ----
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let mut tx = ClientTransaction::new(sender.shielded_address()?, spends, payer_address);
    tx.send(&recipient_address, SOL_MINT, TRANSFER_AMOUNT)?;
    let signed = tx.sign(&sender, &assets)?;

    let commitments = signed.input_commitments()?;
    let mut spend_proofs = Vec::new();
    for commitment in &commitments {
        let state = wait_for_merkle_proof(&indexer, tree_address, commitment.utxo_hash)?;
        let nullifier = wait_for_non_inclusion_proof(&indexer, tree_address, commitment.nullifier)?;
        spend_proofs.push(SpendProof { state, nullifier });
    }

    let assembled = zolana_client::assemble(signed, &spend_proofs)?;
    let proof = match (&assembled.prover_inputs, expected_rail) {
        (ProverInputs::P256(inputs), SpendRail::P256) => {
            ProverClient::local().prove_transfer_p256(inputs)?
        }
        (ProverInputs::Eddsa(inputs), SpendRail::Eddsa) => {
            ProverClient::local().prove_transfer(inputs)?
        }
        (ProverInputs::P256(_), SpendRail::Eddsa) => {
            return Err(anyhow!(
                "expected EdDSA prover inputs for an Ed25519 sender"
            ))
        }
        (ProverInputs::Eddsa(_), SpendRail::P256) => {
            return Err(anyhow!(
                "expected P256 prover inputs for a default P256 sender"
            ))
        }
    };
    let packed = pack_proof(&proof)?;
    let ix_data = assembled.with_proof(packed);

    let transfer_ix = Transact {
        payer: payer.pubkey(),
        tree: tree_pubkey,
        withdrawal: None,
        data: ix_data,
    }
    .instruction();
    // The P256 rail's Groth16 proof carries an extra BSB22 Pedersen-PoK pairing,
    // so verification exceeds the 200k default compute budget.
    let compute_budget =
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
            1_400_000,
        );
    let transfer_sig = send_transaction(
        &mut rpc,
        &[compute_budget, transfer_ix],
        &payer.pubkey(),
        &[&payer],
    )?;
    print_signature("encrypted_transfer", &transfer_sig);
    capture_fixture(&rpc, "encrypted_transfer", &transfer_sig);

    let indexed = wait_for_indexed_transaction(&indexer, recipient_view_tag, transfer_sig)?;
    assert!(
        indexed.tx_viewing_pk.is_some(),
        "encrypted transfer must carry a tx viewing key"
    );
    assert!(
        indexed.salt.is_some(),
        "encrypted transfer must carry a salt"
    );

    // ---- recover the recipient UTXO purely by decrypting the indexed ciphertext ----
    let tx_viewing_pk = indexed
        .tx_viewing_pk
        .ok_or_else(|| anyhow!("indexed transfer missing tx_viewing_pk"))?;
    let salt = indexed
        .salt
        .ok_or_else(|| anyhow!("indexed transfer missing salt"))?;
    let first_nullifier = commitments
        .first()
        .ok_or_else(|| anyhow!("no input commitment"))?
        .nullifier;

    // Independently reconstruct the expected recipient UTXO: the sender bundle in
    // slot 0 decrypts to the shared blinding seed, from which the recipient's
    // blinding (output position 2 = first recipient slot) derives. Each slot's
    // borsh `OutputData` carries a scheme byte plus the per-scheme ciphertext body.
    let sender_slot = indexed
        .output_slots
        .first()
        .ok_or_else(|| anyhow!("indexed transfer missing sender slot"))?;
    let sender_blob = match sender_slot
        .output_data()
        .ok_or_else(|| anyhow!("sender slot is not decodable output data"))?
    {
        OutputData::Encrypted(blob)
        | OutputData::VerifiablyEncrypted(blob)
        | OutputData::Plaintext(blob) => blob,
    };
    let (_scheme, sender_ciphertext) = sender_blob
        .split_first()
        .ok_or_else(|| anyhow!("sender bundle missing scheme byte"))?;
    let sender_plaintext = ConfidentialSenderBundle::decode(
        sender_ciphertext,
        &DecodeCx {
            viewing_key: &sender.viewing_key,
            tx_viewing_pk: Some(tx_viewing_pk),
            salt: Some(salt),
            slot_index: 0,
            first_nullifier: Some(first_nullifier),
        },
    )?;
    let expected_utxo = Utxo {
        owner: recipient_address.signing_pubkey,
        asset: SOL_MINT,
        amount: TRANSFER_AMOUNT,
        blinding: derive_blinding(&sender_plaintext.blinding_seed, 2),
        zone_program_id: None,
        data: Data::default(),
    };

    // The recipient wallet is handed only the on-chain ciphertext and recovers by
    // decrypting it. `Wallet::store` keeps only recipient-owned notes, so the
    // sender's change slot (encrypted to the sender) is not stored.
    let mut wallet = Wallet::new(recipient)?;
    wallet.sync(
        std::slice::from_ref(&indexed),
        &assets,
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    assert_eq!(
        wallet.utxos.len(),
        1,
        "recipient decrypts exactly its own transferred output"
    );
    let recovered = wallet
        .utxos
        .first()
        .ok_or_else(|| anyhow!("recipient did not recover the transferred UTXO by decryption"))?;

    // Full-struct comparison against an independently derived expected UTXO (hash
    // and nullifier computed the same way the wallet does). The output context is
    // located in the indexed transaction by the independently computed hash.
    let nullifier_pk = wallet.keypair.nullifier_key.pubkey()?;
    let expected_hash = expected_utxo.hash(&nullifier_pk, &zero, &zero)?;
    let output_context = indexed
        .output_slots
        .iter()
        .find(|slot| slot.output_context.hash == expected_hash)
        .map(|slot| slot.output_context.clone())
        .ok_or_else(|| anyhow!("expected output not found in indexed transfer"))?;
    let expected_nullifier =
        expected_utxo.nullifier(&output_context.hash, &wallet.keypair.nullifier_key)?;
    let expected = WalletUtxo {
        utxo: expected_utxo,
        output_context,
        nullifier: expected_nullifier,
        spent: false,
    };
    assert_eq!(*recovered, expected);

    // The decrypted note is the exact committed on-chain output, so its hash is
    // Merkle-provable (and therefore spendable by the recipient).
    wait_for_merkle_proof(&indexer, tree_address, recovered.output_context.hash)?;

    println!(
        "encrypted shield-transfer rail={} recovered by decryption via rpc={rpc_url} indexer={indexer_url}",
        expected_rail.label()
    );
    Ok(())
}
