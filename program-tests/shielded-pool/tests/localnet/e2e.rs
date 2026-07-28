//! Local-validator full-cycle SOL test.
//!
//! Flow: proofless shield into a private UTXO, transfer part of that value to a
//! second private owner, then unshield the transferred UTXO back to public SOL.

use anyhow::anyhow;
use num_bigint::BigUint;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{prover::field::right_align, SolanaRpc, STATE_TREE_HEIGHT};
use zolana_hasher::{sha256::Sha256BE, Hasher, Poseidon};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{InterfaceTransfer, ResolvedInterfaceTransfer},
        Deposit, Transact, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
    },
    pda, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::{rpc_state_root, single_deposit_view, TestIndexer, ZolanaProgramTest};
use zolana_transaction::{Data, Utxo, SOL_MINT};

use shielded_pool_tests::support::localnet::{
    account_lamports, build_sol_transfer_witness, dummy_witness_outputs, initialize_indexed_pool,
    on_chain_roots, print_signature, send_indexed, LocalnetPool, SolTransferWitnessArgs,
};

use zolana_test_utils::transact::{
    dummy_input, dummy_transfer_output, nullifier_tree, public_sol_field, real_output, spend_input,
    transfer_output, SpendInputArgs,
};

const RPC_URL_ENV: &str = "ZOLANA_LOCALNET_URL";
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const AMOUNT: u64 = 1_000_000_000;
const TRANSFER_AMOUNT: u64 = 400_000_000;
const CHANGE_AMOUNT: u64 = AMOUNT - TRANSFER_AMOUNT;

type TestResult<T = ()> = anyhow::Result<T>;

#[test]
fn shield_transfer_unshield_sol_on_localnet_prints_signatures() -> TestResult {
    zolana_test_utils::prover::spawn_workspace_prover();

    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());

    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mut rpc = SolanaRpc::new(rpc_url.clone());
    let mut indexer = TestIndexer::new();
    rpc.assert_executable(&program_id)?;

    let LocalnetPool {
        payer,
        authority: _authority,
        tree,
    } = initialize_indexed_pool(&mut rpc, &mut indexer, program_id)?;
    let recipient_owner = Keypair::new();
    print_signature(
        "airdrop recipient owner",
        &rpc.airdrop(&recipient_owner.pubkey(), 1_000_000)?,
    );

    let tree_pubkey = tree.pubkey();
    let zero = [0u8; 32];

    let payer_bytes = payer.pubkey().to_bytes();
    let payer_blinding = right_align(&[7u8; 31]);
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
    let payer_owner_pk_hash = payer_utxo.owner.owner_proof_input_hash()?;
    let payer_owner_field = owner_hash(&payer_utxo.owner, &payer_nullifier_pk)?;

    let shield_data = ZolanaProgramTest::sol_shield_data(AMOUNT, payer_owner_field, payer_blinding);
    let shield_ix = Deposit {
        tree: tree_pubkey,
        depositor: payer.pubkey(),
        deposits: vec![shield_data],
    }
    .instruction()?;
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
    let transfer_roots = (shield_utxo_root, nullifier_root);
    let (transfer_dummy_input, transfer_dummy_nullifier) =
        dummy_input(&[20u8; 31], &nf_tree, transfer_roots, &payer_owner_pk_hash)?;
    let (transfer_dummy_output, transfer_dummy_hash) = dummy_transfer_output(&[19u8; 31])
        .map_err(|err| anyhow!("transfer dummy output: {err}"))?;

    // Each real output's owner tag is its owner's `confidential_view_tag` so the
    // program's `hash_bytes(resolved_owner_tag)` matches that owner's
    // `owner_pk_field`.
    let change_view_tag = payer_utxo.owner.confidential_view_tag()?;
    let recipient_view_tag = recipient_public_key.confidential_view_tag()?;
    let transfer_ix_data = build_sol_transfer_witness(SolTransferWitnessArgs {
        spend_inputs: vec![payer_spend_input, transfer_dummy_input],
        nullifiers: [payer_nullifier, transfer_dummy_nullifier],
        root_index: 1,
        roots: transfer_roots,
        output_hashes: vec![change_hash, recipient_hash, transfer_dummy_hash],
        view_tags: vec![change_view_tag, recipient_view_tag, change_view_tag],
        outputs: vec![
            transfer_output(&change_output)?,
            transfer_output(&recipient_output)?,
            transfer_dummy_output,
        ],
        output_nullifier_pks: [payer_nullifier_pk, recipient_nullifier_pk, zero],
        interface_transfers: Vec::new(),
        resolved_transfers: Vec::new(),
        private_tx_inputs: [payer_utxo_hash, zero],
        private_tx_outputs: [change_hash, recipient_hash, zero],
        public_sol_amount: zero,
        payer_pubkey_hash: Sha256BE::hash(&payer_bytes)?,
        input_owner_pk_hash: payer_owner_pk_hash,
        label: "transfer",
    })?;

    let transfer_ix = Transact {
        payer: payer.pubkey(),
        input_tree: tree_pubkey,
        output_tree: tree_pubkey,
        interface_transfer_accounts: Vec::new(),
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
    let (transfer_utxo_root, transfer_nullifier_root) = on_chain_roots(&rpc, &tree_pubkey, 2)?;
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
    let recipient_owner_pk_hash = recipient_utxo.owner.owner_proof_input_hash()?;
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
    let (withdraw_dummy_input, withdraw_dummy_nullifier) = dummy_input(
        &[21u8; 31],
        &nf_tree,
        (transfer_utxo_root, transfer_nullifier_root),
        &recipient_owner_pk_hash,
    )?;
    let (withdraw_outputs, withdraw_output_hashes) =
        dummy_witness_outputs(&[[1u8; 31], [2u8; 31], [3u8; 31]])?;

    let withdraw_ix_data = build_sol_transfer_witness(SolTransferWitnessArgs {
        spend_inputs: vec![recipient_spend_input, withdraw_dummy_input],
        nullifiers: [recipient_nullifier, withdraw_dummy_nullifier],
        root_index: 2,
        roots: (transfer_utxo_root, transfer_nullifier_root),
        output_hashes: withdraw_output_hashes,
        view_tags: vec![recipient_view_tag; 3],
        outputs: withdraw_outputs,
        output_nullifier_pks: [zero, zero, zero],
        interface_transfers: vec![InterfaceTransfer::SolWithdrawal {
            amount: TRANSFER_AMOUNT,
        }],
        resolved_transfers: vec![ResolvedInterfaceTransfer::SolWithdrawal {
            amount: TRANSFER_AMOUNT,
            recipient: public_recipient.to_bytes(),
        }],
        private_tx_inputs: [recipient_hash, zero],
        private_tx_outputs: [zero, zero, zero],
        public_sol_amount: public_sol_field(Some(-(TRANSFER_AMOUNT as i64))),
        payer_pubkey_hash: Sha256BE::hash(&recipient_bytes)?,
        input_owner_pk_hash: recipient_owner_pk_hash,
        label: "withdraw",
    })?;

    let withdraw_ix = Transact {
        payer: recipient_owner.pubkey(),
        input_tree: tree_pubkey,
        output_tree: tree_pubkey,
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts {
                recipient: public_recipient,
            },
        )],
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
