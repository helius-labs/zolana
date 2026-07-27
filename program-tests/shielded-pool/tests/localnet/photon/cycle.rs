use super::*;

#[test]
#[serial]
fn shield_transfer_unshield_sol_with_photon_indexer() -> TestResult {
    restart_localnet();
    spawn_workspace_prover();

    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());
    let indexer_url =
        std::env::var(INDEXER_URL_ENV).unwrap_or_else(|_| DEFAULT_INDEXER_URL.to_owned());

    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mut rpc = SolanaRpc::new(rpc_url.clone());
    let indexer = ZolanaIndexer::new(indexer_url.clone()).with_http_trace();
    rpc.assert_executable(&program_id)?;
    let unknown_transactions =
        indexer.get_shielded_transactions_by_tags(vec![[253u8; 32]], None, Some(10), None)?;
    assert!(
        unknown_transactions.transactions.is_empty(),
        "unknown tag should not return transactions"
    );

    let LocalnetPool {
        payer,
        authority: _authority,
        tree,
    } = initialize_pool(&mut rpc)?;
    let recipient_owner = Keypair::new();
    print_signature(
        "airdrop recipient owner",
        &rpc.airdrop(&recipient_owner.pubkey(), 1_000_000)?,
    );

    let tree_pubkey = tree.pubkey();
    let tree_address = Address::new_from_array(tree_pubkey.to_bytes());
    let zero = [0u8; 32];

    let payer_bytes = payer.pubkey().to_bytes();
    let payer_blinding: [u8; 32] = [7u8; 32];
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
    let shield_view_tag = shield_data.view_tag;
    let shield_ix = Deposit {
        tree: tree_pubkey,
        depositor: payer.pubkey(),
        deposits: vec![shield_data],
    }
    .instruction()
    .map_err(|err| anyhow!("deposit instruction: {err}"))?;
    let shield_sig = send_transaction(&mut rpc, &[shield_ix], &payer.pubkey(), &[&payer])?;
    print_signature("deposit", &shield_sig);

    let payer_utxo_hash = payer_utxo.hash(&payer_nullifier_pk, &zero, &zero)?;
    let indexed_deposit = wait_for_indexed_utxo(&indexer, shield_view_tag, shield_sig)?;
    assert_eq!(indexed_deposit.output_slot.view_tag, shield_view_tag);
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
    let unknown_utxos =
        indexer.get_encrypted_utxos_by_tags(vec![[254u8; 32]], None, Some(10), None)?;
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
        let response = indexer.get_non_inclusion_proofs(
            tree_address,
            vec![extra_nullifier_a, extra_nullifier_b],
            None,
        )?;
        if response.proofs.len() == 2 {
            Ok(Some(response.proofs))
        } else {
            Ok(None)
        }
    })?;
    assert_eq!(
        batched_non_inclusion
            .first()
            .expect("first non-inclusion proof")
            .leaf,
        extra_nullifier_a
    );
    assert_eq!(
        batched_non_inclusion
            .get(1)
            .expect("second non-inclusion proof")
            .leaf,
        extra_nullifier_b
    );
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
    let transfer_dummy_nullifier = dummy_nullifier(&[20u8; 31])
        .map_err(|err| anyhow!("transfer dummy nullifier: {err}"))?;
    let transfer_dummy_nf =
        wait_for_non_inclusion_proof(&indexer, tree_address, transfer_dummy_nullifier)?;
    let transfer_roots = (payer_state_proof.root, payer_nullifier_proof.root);
    let (transfer_dummy_output, transfer_dummy_hash) = dummy_transfer_output(&[19u8; 31])
        .map_err(|err| anyhow!("transfer dummy output: {err}"))?;

    // Each real output's owner tag is its owner's `confidential_view_tag` so the
    // program's `hash_field(resolved_owner_tag)` matches that owner's
    // `owner_pk_field`.
    let change_view_tag = payer_utxo.owner.confidential_view_tag()?;
    let recipient_view_tag = recipient_public_key.confidential_view_tag()?;
    let transfer_view_tags = [change_view_tag, recipient_view_tag, [3u8; 32]];
    let mut transfer_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(payer_nullifier, payer_state_proof.root_index),
            eddsa_input_utxo(transfer_dummy_nullifier, payer_state_proof.root_index),
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
        &[transfer_roots.0, transfer_roots.0],
        &[transfer_roots.1, transfer_roots.1],
        &transfer_private_tx,
        &transfer_external_hash,
        &transfer_public_slot_assets,
        &transfer_public_slot_amounts,
        &payer_pubkey_hash,
        &[payer_owner_pk_hash, payer_owner_pk_hash],
        &transfer_owner_pk_hashes,
    );
    let transfer_prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![
            payer_spend_input,
            dummy_input_with_proof(
                &[20u8; 31],
                &transfer_dummy_nf,
                transfer_roots,
                &payer_owner_pk_hash,
            )
            .map_err(|err| anyhow!("transfer dummy input: {err}"))?,
        ],
        outputs: transfer_outputs,
        external_data_hash: transfer_external_hash,
        private_tx_hash: transfer_private_tx,
        public_slot_assets: transfer_public_slot_assets,
        public_slot_amounts: transfer_public_slot_amounts,
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
        input_tree: tree_pubkey,
        output_tree: tree_pubkey,
        interface_transfer_accounts: Vec::new(),
        data: transfer_ix_data,
    }
    .instruction();
    let transfer_sig = send_transaction(&mut rpc, &[transfer_ix], &payer.pubkey(), &[&payer])?;
    print_signature("shielded_transfer", &transfer_sig);

    let indexed_transfer =
        wait_for_indexed_transaction(&indexer, recipient_view_tag, transfer_sig)?;
    assert_eq!(indexed_transfer.nullifiers.len(), 2);
    assert_eq!(indexed_transfer.output_slots.len(), 3);
    assert!(!indexed_transfer.proofless);
    assert_eq!(
        indexed_transfer
            .output_slots
            .first()
            .expect("first output slot")
            .output_context
            .hash,
        change_hash
    );
    assert_eq!(
        indexed_transfer
            .output_slots
            .get(1)
            .expect("second output slot")
            .output_context
            .hash,
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
    let recipient_owner_pk_hash = recipient_utxo.owner.owner_proof_input_hash()?;
    let recipient_nullifier =
        recipient_nullifier_key.nullifier(&recipient_hash, &recipient_utxo.blinding)?;
    let recipient_state_proof = wait_for_merkle_proof(&indexer, tree_address, recipient_hash)?;
    let recipient_nullifier_proof =
        wait_for_non_inclusion_proof(&indexer, tree_address, recipient_nullifier)?;
    let batched_state_proofs = wait_for("batched indexed merkle proofs", || {
        let response =
            indexer.get_merkle_proofs(tree_address, vec![payer_utxo_hash, recipient_hash], None)?;
        if response.proofs.len() == 2 {
            Ok(Some(response.proofs))
        } else {
            Ok(None)
        }
    })?;
    assert_eq!(
        batched_state_proofs
            .first()
            .expect("first state proof")
            .leaf,
        payer_utxo_hash
    );
    assert_eq!(
        batched_state_proofs
            .get(1)
            .expect("second state proof")
            .leaf,
        recipient_hash
    );
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
    let withdraw_dummy_nullifier = dummy_nullifier(&[21u8; 31])
        .map_err(|err| anyhow!("withdraw dummy nullifier: {err}"))?;
    let withdraw_dummy_nf =
        wait_for_non_inclusion_proof(&indexer, tree_address, withdraw_dummy_nullifier)?;
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

    let withdraw_view_tags = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let mut withdraw_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(recipient_nullifier, recipient_state_proof.root_index),
            eddsa_input_utxo(withdraw_dummy_nullifier, recipient_state_proof.root_index),
        ],
        vec![zolana_interface::instruction::instruction_data::transact::InterfaceTransfer::SolWithdrawal {
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
    let withdraw_resolved_transfers = [
        zolana_interface::instruction::instruction_data::transact::ResolvedInterfaceTransfer::SolWithdrawal {
            amount: TRANSFER_AMOUNT,
            recipient: public_recipient.to_bytes(),
        },
    ];
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
        &[withdraw_roots.0, withdraw_roots.0],
        &[withdraw_roots.1, withdraw_roots.1],
        &withdraw_private_tx,
        &withdraw_external_hash,
        &public_slot_assets,
        &public_slot_amounts,
        &recipient_pubkey_hash,
        &[recipient_owner_pk_hash, recipient_owner_pk_hash],
        &withdraw_owner_pk_hashes,
    );
    let withdraw_prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![
            recipient_spend_input,
            dummy_input_with_proof(
                &[21u8; 31],
                &withdraw_dummy_nf,
                withdraw_roots,
                &recipient_owner_pk_hash,
            )
            .map_err(|err| anyhow!("withdraw dummy input: {err}"))?,
        ],
        outputs: withdraw_outputs,
        external_data_hash: withdraw_external_hash,
        private_tx_hash: withdraw_private_tx,
        public_slot_assets,
        public_slot_amounts,
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
        input_tree: tree_pubkey,
        output_tree: tree_pubkey,
        interface_transfer_accounts: vec![
            zolana_interface::instruction::TransactInterfaceTransferAccounts::Sol(
                zolana_interface::instruction::TransactSolTransferAccounts {
                    recipient: public_recipient,
                },
            ),
        ],
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
    let indexed_withdraw = wait_for_indexed_transaction(&indexer, [1u8; 32], withdraw_sig)?;
    assert_eq!(indexed_withdraw.nullifiers.len(), 2);
    let first_page = wait_for("paginated indexed transactions", || {
        let response =
            indexer.get_shielded_transactions_by_tags(vec![[3u8; 32]], None, Some(1), None)?;
        if response.transactions.len() == 1 && response.next_cursor.is_some() {
            Ok(Some(response))
        } else {
            Ok(None)
        }
    })?;
    let second_page = indexer.get_shielded_transactions_by_tags(
        vec![[3u8; 32]],
        first_page.next_cursor,
        Some(1),
        None,
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
