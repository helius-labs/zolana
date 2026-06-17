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
use solana_address::Address;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_client::private_transaction::field::{be, right_align_slice};
use zolana_client::{
    EncryptedUtxoMatch, MerkleProof as IndexedMerkleProof,
    NonInclusionProof as IndexedNonInclusionProof, Rpc, ShieldedTransaction, SolanaRpc,
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
use zolana_keypair::hash::owner_hash;
use zolana_keypair::pubkey::PublicKey;
use zolana_keypair::NullifierKey;
use zolana_program_test::{create_tree_instructions, rpc_state_root, ZolanaProgramTest};
use zolana_transaction::transaction::private_tx_hash;
use zolana_transaction::{Data, OutputUtxo, Utxo, SOL_MINT};
use zolana_tree::TreeAccount;

use crate::transact_common::{
    build_transfer_prover_inputs, dummy_input, dummy_ix_output, eddsa_input_utxo,
    external_data_hash, fe, ix_output, new_transact_ix_data, prove_and_verify_transfer,
    public_input_hash, public_sol_field, start_prover, transfer_output, TransferProverInputsArgs,
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
fn shield_transfer_unshield_sol_with_photon_indexer() -> TestResult {
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
    let owner_utxo_hash = payer_utxo.owner_utxo_hash(&payer_nullifier_pk)?;

    let shield_data = ZolanaProgramTest::sol_shield_data(AMOUNT, owner_utxo_hash);
    let shield_ix = Deposit {
        tree: tree_pubkey,
        depositor: payer.pubkey(),
        spl: None,
        view_tag: shield_data.view_tag,
        owner_utxo_hash: shield_data.owner_utxo_hash,
        salt: shield_data.salt,
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

    let mut transfer_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(payer_nullifier, payer_state_proof.root_index),
            eddsa_input_utxo(transfer_dummy_nullifier, payer_state_proof.root_index),
        ],
        None,
        ix_output([1u8; 32], change_hash),
        vec![ix_output([2u8; 32], recipient_hash), dummy_ix_output()],
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
        &[change_hash, recipient_hash, zero],
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
            TransferOutput::new_dummy(),
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

    let mut withdraw_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(recipient_nullifier, recipient_state_proof.root_index),
            eddsa_input_utxo(withdraw_dummy_nullifier, recipient_state_proof.root_index),
        ],
        Some(-(TRANSFER_AMOUNT as i64)),
        dummy_ix_output(),
        vec![dummy_ix_output(); 2],
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
        &[zero, zero, zero],
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
        outputs: vec![TransferOutput::new_dummy(); 3],
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
