//! Local-validator SOL cycle backed by a real Photon Zolana indexer.
//!
//! Run with `just test-localnet-e2e-photon`.

#[path = "common/transact.rs"]
#[allow(dead_code)]
mod transact_common;

use std::{
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::anyhow;
use light_hasher::{sha256::Sha256BE, Hasher};
use serial_test::serial;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_client::{
    private_transaction::field::{be, right_align_slice},
    EncryptedUtxoMatch, MerkleProof as IndexedMerkleProof,
    NonInclusionProof as IndexedNonInclusionProof, ProverClient, ProverInputs, Rpc,
    ShieldedTransaction, SolanaRpc, SpendProof, SpendUtxo, Transaction as ClientTransaction,
    TransferInput, TransferOutput, UtxoInputs, ZolanaIndexer,
};
use zolana_interface::{
    instruction::{
        CreateProtocolConfig, Deposit, Transact, TransactSolWithdrawal, TransactWithdrawal,
    },
    pda,
    state::tree_account_size,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{
    hash::owner_hash, pubkey::PublicKey, shielded::ShieldedKeypair, NullifierKey,
};
use zolana_program_test::{create_tree_instructions, rpc_state_root, ZolanaProgramTest};
use zolana_transaction::{
    transaction::private_tx_hash,
    transfer::{OutputCiphertext, TransferEncryptedUtxos, SENDER_SLOT_COUNT},
    utxo::derive_blinding,
    AssetRegistry, Data, OutputUtxo, SyncTransaction, TransactionEncryption, Utxo, Wallet,
    WalletUtxo, DEFAULT_TAG_WINDOW, SOL_MINT, TRANSFER,
};
use zolana_tree::TreeAccount;

use crate::transact_common::{
    build_transfer_prover_inputs, dummy_input, dummy_transfer_output, eddsa_input_utxo,
    external_data_hash, fe, ix_output_ciphertext, new_transact_ix_data, pack_proof,
    prove_and_verify_transfer, public_input_hash, public_sol_field, start_prover, transfer_output,
    TransferProverInputsArgs,
};

const RPC_URL_ENV: &str = "ZOLANA_LOCALNET_URL";
const INDEXER_URL_ENV: &str = "ZOLANA_INDEXER_URL";
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:8784";
const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
const AMOUNT: u64 = 1_000_000_000;
const TRANSFER_AMOUNT: u64 = 400_000_000;
const CHANGE_AMOUNT: u64 = AMOUNT - TRANSFER_AMOUNT;

type TestResult<T = ()> = anyhow::Result<T>;

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
        program_data_hash: shield_data.program_data_hash,
        program_data: shield_data.program_data,
        cpi_signer: shield_data.cpi_signer,
    }
    .instruction();
    let shield_sig = send_transaction(&mut rpc, &[shield_ix], &payer.pubkey(), &[&payer])?;
    print_signature("deposit", &shield_sig);

    let payer_utxo_hash = payer_utxo.hash(&payer_nullifier_pk, &zero, &zero)?;
    let indexed_deposit = wait_for_indexed_utxo(&indexer, shield_data.view_tag, shield_sig)?;
    assert_eq!(indexed_deposit.view_tag, shield_data.view_tag);
    assert_eq!(indexed_deposit.tx_signature, shield_sig);
    assert!(indexed_deposit.tx_viewing_pk.is_none());

    let payer_nullifier = payer_nullifier_key.nullifier(&payer_utxo_hash, &payer_blinding)?;
    let payer_state_proof = wait_for_merkle_proof(&indexer, tree_address, payer_utxo_hash)?;
    let payer_nullifier_proof =
        wait_for_non_inclusion_proof(&indexer, tree_address, payer_nullifier)?;
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

    let change_output = OutputUtxo {
        owner_hash: payer_owner_field,
        asset: SOL_MINT,
        amount: CHANGE_AMOUNT,
        blinding: [13u8; 31],
        ..Default::default()
    };
    let recipient_output = OutputUtxo {
        owner_hash: recipient_owner_field,
        asset: SOL_MINT,
        amount: TRANSFER_AMOUNT,
        blinding: [17u8; 31],
        ..Default::default()
    };
    let change_hash = change_output.hash()?;
    let recipient_hash = recipient_output.hash()?;
    let transfer_dummy_nullifier = fe(20);
    let transfer_roots = (payer_state_proof.root, payer_nullifier_proof.root);
    let (transfer_dummy_output, transfer_dummy_hash) = dummy_transfer_output(&[19u8; 31])
        .map_err(|err| anyhow!("transfer dummy output: {err}"))?;

    let mut transfer_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(payer_nullifier, payer_state_proof.root_index),
            eddsa_input_utxo(transfer_dummy_nullifier, payer_state_proof.root_index),
        ],
        None,
        vec![change_hash, recipient_hash, transfer_dummy_hash],
        vec![
            ix_output_ciphertext([1u8; 32]),
            ix_output_ciphertext([2u8; 32]),
        ],
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
        &[transfer_roots.0, transfer_roots.0],
        &[transfer_roots.1, transfer_roots.1],
        &transfer_private_tx,
        &transfer_external_hash,
        &zero,
        &payer_pubkey_hash,
        &[payer_owner_pk_hash, payer_owner_pk_hash],
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
        outputs: vec![
            transfer_output(&change_output)?,
            transfer_output(&recipient_output)?,
            transfer_dummy_output,
        ],
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
    let transfer_sig = send_transaction(&mut rpc, &[transfer_ix], &payer.pubkey(), &[&payer])?;
    print_signature("shielded_transfer", &transfer_sig);

    let indexed_transfer = wait_for_indexed_transaction(&indexer, [2u8; 32], transfer_sig)?;
    assert_eq!(indexed_transfer.nullifiers.len(), 2);
    assert_eq!(indexed_transfer.output_slots.len(), 3);
    assert!(!indexed_transfer.proofless);

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
    let withdraw_outputs: Vec<TransferOutput> = withdraw_dummy_outputs
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
        &[withdraw_roots.0, withdraw_roots.0],
        &[withdraw_roots.1, withdraw_roots.1],
        &withdraw_private_tx,
        &withdraw_external_hash,
        &public_sol_field,
        &recipient_pubkey_hash,
        &[recipient_owner_pk_hash, recipient_owner_pk_hash],
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
        cpi_signer: None,
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
    let indexed_withdraw = wait_for_indexed_transaction(&indexer, [0u8; 32], withdraw_sig)?;
    assert_eq!(indexed_withdraw.nullifiers.len(), 2);

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
        solana_owner_pk_hash: be(args.owner_pk_hash),
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
    label: &'static str,
    mut poll: impl FnMut() -> Result<Option<T>, zolana_client::ClientError>,
) -> TestResult<T> {
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
        merge_authority: authority_bytes.into(),
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
    let sender = ShieldedKeypair::new()?;
    let recipient = ShieldedKeypair::new()?;
    let recipient_address = recipient.shielded_address()?;
    let recipient_view_tag = recipient.recipient_bootstrap_view_tag();
    let sender_view_tag = sender.get_sender_view_tag(0)?;
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
            program_data_hash: shield_data.program_data_hash,
            program_data: shield_data.program_data,
            cpi_signer: shield_data.cpi_signer,
        }
        .instruction();
        send_transaction(&mut rpc, &[shield_ix], &payer.pubkey(), &[&payer])?;
        let utxo_hash = utxo.hash(&sender_nullifier_pk, &zero, &zero)?;
        wait_for_merkle_proof(&indexer, tree_address, utxo_hash)?;
        spends.push(SpendUtxo::from((utxo, &sender)));
    }

    // ---- build the encrypted transfer with the high-level client builder ----
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let mut tx = ClientTransaction::new(sender.shielded_address()?, spends, payer_address);
    tx.send(
        &recipient_address,
        SOL_MINT,
        TRANSFER_AMOUNT,
        recipient_view_tag,
    )?;
    let signed = tx.sign(&sender, &assets, sender_view_tag)?;

    let commitments = signed.input_commitments()?;
    let mut spend_proofs = Vec::new();
    for commitment in &commitments {
        let state = wait_for_merkle_proof(&indexer, tree_address, commitment.utxo_hash)?;
        let nullifier = wait_for_non_inclusion_proof(&indexer, tree_address, commitment.nullifier)?;
        spend_proofs.push(SpendProof { state, nullifier });
    }

    let assembled = signed.assemble(&spend_proofs)?;
    let proof = match &assembled.prover_inputs {
        ProverInputs::P256(inputs) => ProverClient::local().prove_transfer_p256(inputs)?,
        ProverInputs::Eddsa(_) => {
            return Err(anyhow!("expected the P256 rail for a keypair input"))
        }
    };
    let packed = pack_proof(&proof)?;
    let ix_data = assembled.with_proof(packed);

    let transfer_ix = Transact {
        payer: payer.pubkey(),
        tree: tree_pubkey,
        cpi_signer: None,
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
    let slots: Vec<OutputCiphertext> = indexed
        .output_slots
        .iter()
        .map(|slot| OutputCiphertext {
            view_tag: slot.view_tag,
            data: slot.payload.clone(),
        })
        .collect();
    let first_nullifier = commitments
        .first()
        .ok_or_else(|| anyhow!("no input commitment"))?
        .nullifier;

    // Independently reconstruct the expected recipient UTXO: the sender bundle in
    // slot 0 decrypts to the shared blinding seed, from which the recipient's
    // blinding (output position 2 = first recipient slot) derives.
    let blob = TransferEncryptedUtxos::from_output_ciphertexts(
        tx_viewing_pk,
        salt,
        &slots,
        SENDER_SLOT_COUNT,
    )?;
    let (sender_plaintext, _) = sender
        .viewing_key
        .decrypt_transfer(&first_nullifier, &blob)?;
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
    let sync_tx = SyncTransaction {
        scheme: TRANSFER,
        tx_viewing_pk,
        salt,
        output_slots: slots,
        nullifiers: indexed.nullifiers,
    };
    let mut wallet = Wallet::new(recipient)?;
    wallet.sync(&[sync_tx], &[], &assets, 0, DEFAULT_TAG_WINDOW)?;
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
    // and nullifier computed the same way the wallet does).
    let nullifier_pk = wallet.keypair.nullifier_key.pubkey()?;
    let expected_hash = expected_utxo.hash(&nullifier_pk, &zero, &zero)?;
    let expected_nullifier =
        expected_utxo.nullifier(&expected_hash, &wallet.keypair.nullifier_key)?;
    let expected = WalletUtxo {
        utxo: expected_utxo,
        hash: expected_hash,
        nullifier: expected_nullifier,
        spent: false,
    };
    assert_eq!(*recovered, expected);

    // The decrypted note is the exact committed on-chain output, so its hash is
    // Merkle-provable (and therefore spendable by the recipient).
    wait_for_merkle_proof(&indexer, tree_address, recovered.hash)?;

    println!(
        "encrypted shield-transfer recovered by decryption via rpc={rpc_url} indexer={indexer_url}"
    );
    Ok(())
}
