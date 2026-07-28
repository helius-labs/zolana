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
    let transfer_dummy_nullifier =
        dummy_nullifier(&[20u8; 31]).map_err(|err| anyhow!("transfer dummy nullifier: {err}"))?;
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
    // Dummy outputs must name a transaction participant (AssertDummyTags).
    let transfer_ix_data = build_sol_transfer_witness(SolTransferWitnessArgs {
        spend_inputs: vec![
            payer_spend_input,
            dummy_input_with_proof(
                &[20u8; 31],
                &transfer_dummy_nf,
                transfer_roots,
                &payer_owner_pk_hash,
            )
            .map_err(|err| anyhow!("transfer dummy input: {err}"))?,
        ],
        nullifiers: [payer_nullifier, transfer_dummy_nullifier],
        root_index: payer_state_proof.root_index,
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
    let withdraw_dummy_nullifier =
        dummy_nullifier(&[21u8; 31]).map_err(|err| anyhow!("withdraw dummy nullifier: {err}"))?;
    let withdraw_dummy_nf =
        wait_for_non_inclusion_proof(&indexer, tree_address, withdraw_dummy_nullifier)?;
    let withdraw_roots = (recipient_state_proof.root, recipient_nullifier_proof.root);
    let (withdraw_outputs, withdraw_output_hashes) =
        dummy_witness_outputs(&[[1u8; 31], [2u8; 31], [3u8; 31]])?;

    // Dummy outputs must name a transaction participant (AssertDummyTags).
    let withdraw_ix_data = build_sol_transfer_witness(SolTransferWitnessArgs {
        spend_inputs: vec![
            recipient_spend_input,
            dummy_input_with_proof(
                &[21u8; 31],
                &withdraw_dummy_nf,
                withdraw_roots,
                &recipient_owner_pk_hash,
            )
            .map_err(|err| anyhow!("withdraw dummy input: {err}"))?,
        ],
        nullifiers: [recipient_nullifier, withdraw_dummy_nullifier],
        root_index: recipient_state_proof.root_index,
        roots: withdraw_roots,
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
    let withdraw_sig = send_transaction(
        &mut rpc,
        &[withdraw_ix],
        &payer.pubkey(),
        &[&payer, &recipient_owner],
    )?;
    print_signature("unshield", &withdraw_sig);
    // PR164 AssertDummyTags forces every dummy output to name a transaction
    // participant, so the withdraw's outputs all carry `recipient_view_tag`
    // (see `view_tags` in the witness args above) instead of per-slot
    // synthetic tags.
    let indexed_withdraw =
        wait_for_indexed_transaction(&indexer, recipient_view_tag, withdraw_sig)?;
    assert_eq!(indexed_withdraw.nullifiers.len(), 2);
    // `recipient_view_tag` matches both the shielded transfer and the withdraw,
    // so a limit-1 query must paginate across the two transactions.
    let first_page = wait_for("paginated indexed transactions", || {
        let response = indexer.get_shielded_transactions_by_tags(
            vec![recipient_view_tag],
            None,
            Some(1),
            None,
        )?;
        if response.transactions.len() == 1 && response.next_cursor.is_some() {
            Ok(Some(response))
        } else {
            Ok(None)
        }
    })?;
    let second_page = indexer.get_shielded_transactions_by_tags(
        vec![recipient_view_tag],
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
