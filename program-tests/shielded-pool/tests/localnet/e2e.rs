//! Local-validator full-cycle SOL test.
//!
//! Flow: proofless shield into a private UTXO, transfer part of that value to a
//! second private owner, then unshield the transferred UTXO back to public SOL.

use anyhow::anyhow;
use num_bigint::BigUint;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    prover::field::right_align, Rpc, SolanaRpc, TransferOutput, STATE_TREE_HEIGHT,
};
use zolana_hasher::{sha256::Sha256BE, Hasher, Poseidon};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{InterfaceTransfer, ResolvedInterfaceTransfer},
        tag, CreateProtocolConfig, Deposit, Transact, TransactInterfaceTransferAccounts,
        TransactSolTransferAccounts,
    },
    pda,
    state::tree_account_size,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::{rpc_state_root, single_deposit_view, TestIndexer, ZolanaProgramTest};
use zolana_transaction::{instructions::transact::PrivateTxHash, Data, Utxo, SOL_MINT};

use shielded_pool_tests::support::localnet::{
    account_lamports, initialize_indexed_pool, on_chain_roots, print_signature, send_indexed,
    LocalnetPool,
};

use zolana_test_utils::transact::{
    build_transfer_prover_inputs, dummy_input, dummy_transfer_output, eddsa_input_utxo,
    external_data_hash, inline_outputs, new_transact_ix_data, nullifier_tree,
    output_owner_pk_hashes, prove_and_verify_transfer, public_input_hash, public_sol_field,
    real_output, set_output_owner_tags, sol_public_slots, spend_input, transfer_output,
    SpendInputArgs, TransferProverInputsArgs,
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
    let transfer_view_tags = [change_view_tag, recipient_view_tag, change_view_tag];
    let mut transfer_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(payer_nullifier, 1),
            eddsa_input_utxo(transfer_dummy_nullifier, 1),
        ],
        Vec::new(),
        inline_outputs(
            &[change_hash, recipient_hash, transfer_dummy_hash],
            &transfer_view_tags,
        ),
    );
    let transfer_owner_pk_hashes = output_owner_pk_hashes(&transfer_ix_data.outputs)
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
    let transfer_external_hash = external_data_hash(&transfer_ix_data, &[])?;
    let transfer_private_tx = PrivateTxHash::new(
        &[payer_utxo_hash, zero],
        &[change_hash, recipient_hash, zero],
        &transfer_external_hash,
    )
    .hash()?;
    let payer_pubkey_hash = Sha256BE::hash(&payer_bytes)?;
    let (transfer_public_slot_assets, transfer_public_slot_amounts) = sol_public_slots(zero);
    let transfer_public_input_hash = public_input_hash(
        &[payer_nullifier, transfer_dummy_nullifier],
        &[change_hash, recipient_hash, transfer_dummy_hash],
        &[shield_utxo_root, shield_utxo_root],
        &[nullifier_root, nullifier_root],
        &transfer_private_tx,
        &transfer_external_hash,
        &transfer_public_slot_assets,
        &transfer_public_slot_amounts,
        &payer_pubkey_hash,
        &[payer_owner_pk_hash, payer_owner_pk_hash],
        &transfer_owner_pk_hashes,
    );
    let transfer_prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![payer_spend_input, transfer_dummy_input],
        outputs: transfer_outputs,
        nullifiers: &[payer_nullifier, transfer_dummy_nullifier],
        output_hashes: &[change_hash, recipient_hash, transfer_dummy_hash],
        utxo_roots: &[shield_utxo_root, shield_utxo_root],
        nullifier_tree_roots: &[nullifier_root, nullifier_root],
        private_tx_hash: transfer_private_tx,
        public_slot_assets: transfer_public_slot_assets,
        public_slot_amounts: transfer_public_slot_amounts,
        payer_pubkey_hash,
        input_owner_pk_hashes: &[payer_owner_pk_hash, payer_owner_pk_hash],
        output_owner_pk_hashes: &transfer_owner_pk_hashes,
    });
    let transfer_public_input_hash = transfer_proof_inputs.public_input_hash;
    let transfer_prover_inputs = transfer_proof_inputs.prover_inputs;
    transfer_ix_data.proof = prove_and_verify_transfer(
        &transfer_prover_inputs,
        transfer_public_input_hash,
        "transfer",
    )?;
    transfer_ix_data.private_tx_hash = transfer_private_tx;

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

    let withdraw_view_tags = [recipient_view_tag; 3];
    let mut withdraw_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(recipient_nullifier, 2),
            eddsa_input_utxo(withdraw_dummy_nullifier, 2),
        ],
        vec![InterfaceTransfer::SolWithdrawal {
            amount: TRANSFER_AMOUNT,
        }],
        inline_outputs(&withdraw_output_hashes, &withdraw_view_tags),
    );
    let withdraw_owner_pk_hashes = output_owner_pk_hashes(&withdraw_ix_data.outputs)
        .map_err(|err| anyhow!("withdraw output owner pk hashes: {err}"))?;
    set_output_owner_tags(
        &mut withdraw_outputs,
        &withdraw_owner_pk_hashes,
        &[zero, zero, zero],
    );
    let withdraw_resolved_transfers = [ResolvedInterfaceTransfer::SolWithdrawal {
        amount: TRANSFER_AMOUNT,
        recipient: public_recipient.to_bytes(),
    }];
    let withdraw_external_hash =
        external_data_hash(&withdraw_ix_data, &withdraw_resolved_transfers)?;
    let withdraw_private_tx = PrivateTxHash::new(
        &[recipient_hash, zero],
        &[zero, zero, zero],
        &withdraw_external_hash,
    )
    .hash()?;
    let public_sol_field = public_sol_field(Some(-(TRANSFER_AMOUNT as i64)));
    let (public_slot_assets, public_slot_amounts) = sol_public_slots(public_sol_field);
    let recipient_pubkey_hash = Sha256BE::hash(&recipient_bytes)?;
    let withdraw_public_input_hash = public_input_hash(
        &[recipient_nullifier, withdraw_dummy_nullifier],
        &withdraw_output_hashes,
        &[transfer_utxo_root, transfer_utxo_root],
        &[transfer_nullifier_root, transfer_nullifier_root],
        &withdraw_private_tx,
        &withdraw_external_hash,
        &public_slot_assets,
        &public_slot_amounts,
        &recipient_pubkey_hash,
        &[recipient_owner_pk_hash, recipient_owner_pk_hash],
        &withdraw_owner_pk_hashes,
    );
    let withdraw_prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![recipient_spend_input, withdraw_dummy_input],
        outputs: withdraw_outputs,
        nullifiers: &[recipient_nullifier, withdraw_dummy_nullifier],
        output_hashes: &withdraw_output_hashes,
        utxo_roots: &[transfer_utxo_root, transfer_utxo_root],
        nullifier_tree_roots: &[transfer_nullifier_root, transfer_nullifier_root],
        private_tx_hash: withdraw_private_tx,
        public_slot_assets,
        public_slot_amounts,
        payer_pubkey_hash: recipient_pubkey_hash,
        input_owner_pk_hashes: &[recipient_owner_pk_hash, recipient_owner_pk_hash],
        output_owner_pk_hashes: &withdraw_owner_pk_hashes,
    });
    let withdraw_public_input_hash = withdraw_proof_inputs.public_input_hash;
    let withdraw_prover_inputs = withdraw_proof_inputs.prover_inputs;
    withdraw_ix_data.proof = prove_and_verify_transfer(
        &withdraw_prover_inputs,
        withdraw_public_input_hash,
        "withdraw",
    )?;
    withdraw_ix_data.private_tx_hash = withdraw_private_tx;

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
