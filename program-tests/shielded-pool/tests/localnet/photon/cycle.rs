use super::*;

#[test]
#[serial]
fn shield_transfer_unshield_sol_with_photon_indexer() -> TestResult {
    let mut env = phase_bootstrap()?;
    let shield = phase_shield(&mut env)?;
    let payer_proofs = phase_indexer_sync(&env, &shield)?;
    let transfer = phase_shielded_transfer(&mut env, &shield, payer_proofs)?;
    let unshield = phase_unshield(&mut env, &shield, &transfer)?;
    phase_unshield_indexer_assertions(&env, &transfer, &unshield)?;

    println!(
        "localnet Photon-backed shield-transfer-unshield SOL test passed via rpc={} indexer={}",
        env.rpc_url, env.indexer_url
    );
    Ok(())
}

/// Shared chain/indexer handles and signers for the shield -> transfer ->
/// unshield cycle, set up once by [`phase_bootstrap`].
struct CycleEnv {
    rpc_url: String,
    indexer_url: String,
    rpc: SolanaRpc,
    indexer: ZolanaIndexer,
    payer: Keypair,
    recipient_owner: Keypair,
    tree_pubkey: Pubkey,
    tree_address: Address,
}

/// Restart the localnet, connect the RPC + Photon indexer, create the pool
/// tree, and fund the recipient owner.
fn phase_bootstrap() -> TestResult<CycleEnv> {
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

    let tree_pubkey = tree;
    let tree_address = Address::new_from_array(tree_pubkey.to_bytes());
    Ok(CycleEnv {
        rpc_url,
        indexer_url,
        rpc,
        indexer,
        payer,
        recipient_owner,
        tree_pubkey,
        tree_address,
    })
}

/// The payer's freshly shielded UTXO plus the key material the later phases
/// spend it with; hashes, owner fields, and pubkeys are cheap recomputations
/// off these, so the phases derive them where needed.
struct PayerShield {
    utxo: Utxo,
    nullifier_key: NullifierKey,
    indexed_deposit: EncryptedUtxoMatch,
}

/// Shield `AMOUNT` lamports into a payer-owned UTXO and wait for Photon to
/// index the deposit.
fn phase_shield(env: &mut CycleEnv) -> TestResult<PayerShield> {
    let zero = [0u8; 32];

    let payer_bytes = env.payer.pubkey().to_bytes();
    let payer_nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let payer_nullifier_pk = payer_nullifier_key.pubkey()?;
    let payer_owner = PublicKey::from_ed25519(&payer_bytes);
    let payer_owner_field = owner_hash(&payer_owner, &payer_nullifier_pk)?;

    let shield_data = ZolanaProgramTest::sol_shield_data(AMOUNT, payer_owner_field);
    let shield_view_tag = shield_data.view_tag;
    let shield_ix = Deposit {
        tree: env.tree_pubkey,
        depositor: env.payer.pubkey(),
        deposits: vec![shield_data],
    }
    .instruction()
    .map_err(|err| anyhow!("deposit instruction: {err}"))?;
    let shield_sig = send_transaction(
        &mut env.rpc,
        &[shield_ix],
        &env.payer.pubkey(),
        &[&env.payer],
    )?;
    print_signature("deposit", &shield_sig);

    let indexed_deposit = wait_for_indexed_utxo(&env.indexer, shield_view_tag, shield_sig);
    // A proofless deposit publishes the SPP-derived blinding in the clear, so
    // Photon's indexed output carries it.
    let deposited = indexed_deposit
        .output_slot
        .proofless_output()
        .ok_or_else(|| anyhow!("indexed deposit output is not a proofless UTXO"))?;
    let payer_utxo = Utxo {
        owner: payer_owner,
        asset: Address::new_from_array(deposited.asset),
        amount: deposited.amount,
        blinding: deposited.blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    assert_eq!((payer_utxo.asset, payer_utxo.amount), (SOL_MINT, AMOUNT));
    let payer_utxo_hash = payer_utxo.hash(&payer_nullifier_pk, &zero, &zero)?;
    assert_eq!(indexed_deposit.output_slot.view_tag, shield_view_tag);
    assert_eq!(indexed_deposit.tx_signature, shield_sig);
    assert_eq!(
        indexed_deposit.output_slot.output_context.hash,
        payer_utxo_hash
    );
    assert_eq!(
        indexed_deposit.output_slot.output_context.tree,
        env.tree_address
    );
    assert!(indexed_deposit.tx_viewing_pk.is_none());
    let unknown_utxos =
        env.indexer
            .get_encrypted_utxos_by_tags(vec![[254u8; 32]], None, Some(10), None)?;
    assert!(
        unknown_utxos.matches.is_empty(),
        "unknown tag should not return encrypted UTXOs"
    );

    Ok(PayerShield {
        utxo: payer_utxo,
        nullifier_key: payer_nullifier_key,
        indexed_deposit,
    })
}

/// Photon's proofs for the shielded payer UTXO plus the spend input built
/// from them.
struct PayerProofs {
    state_proof: IndexedMerkleProof,
    nullifier_proof: IndexedNonInclusionProof,
    spend_input: TransferInput,
}

/// Wait for Photon's merkle/non-inclusion proofs of the payer UTXO, gate them
/// against the on-chain roots, and build the payer spend input.
fn phase_indexer_sync(env: &CycleEnv, shield: &PayerShield) -> TestResult<PayerProofs> {
    let zero = [0u8; 32];
    let indexer = &env.indexer;
    let tree_address = env.tree_address;
    let payer_nullifier_key = &shield.nullifier_key;
    let payer_nullifier_pk = payer_nullifier_key.pubkey()?;
    let payer_utxo_hash = shield.utxo.hash(&payer_nullifier_pk, &zero, &zero)?;
    let payer_blinding = shield.utxo.blinding;
    let payer_owner_field = owner_hash(&shield.utxo.owner, &payer_nullifier_pk)?;
    let payer_owner_pk_hash = shield.utxo.owner.owner_proof_input_hash()?;
    let indexed_deposit = &shield.indexed_deposit;

    let payer_nullifier = payer_nullifier_key.nullifier(&payer_utxo_hash, &payer_blinding)?;
    let payer_state_proof = wait_for_merkle_proof(indexer, tree_address, payer_utxo_hash);
    assert_eq!(
        indexed_deposit.output_slot.output_context.leaf_index,
        payer_state_proof.leaf_index
    );
    let payer_nullifier_proof =
        wait_for_non_inclusion_proof(indexer, tree_address, payer_nullifier);
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
    let (shield_utxo_root, nullifier_root) = on_chain_roots(&env.rpc, &env.tree_pubkey, 1)?;
    assert_eq!(payer_state_proof.root, shield_utxo_root, "shield root gate");
    assert_eq!(
        payer_nullifier_proof.root, nullifier_root,
        "nullifier root gate"
    );
    assert_eq!(
        rpc_state_root(&env.rpc, &env.tree_pubkey)?,
        payer_state_proof.root
    );
    let payer_spend_input = indexed_spend_input(IndexedSpendInputArgs {
        utxo: &shield.utxo,
        owner_field: &payer_owner_field,
        state_proof: &payer_state_proof,
        nullifier_proof: &payer_nullifier_proof,
        nullifier: &payer_nullifier,
        owner_pk_hash: &payer_owner_pk_hash,
        nullifier_key: payer_nullifier_key,
    })?;

    Ok(PayerProofs {
        state_proof: payer_state_proof,
        nullifier_proof: payer_nullifier_proof,
        spend_input: payer_spend_input,
    })
}

/// The recipient side of the shielded transfer: the transferred UTXO and the
/// nullifier key the unshield phase spends it with (hashes, view tags, and
/// owner fields are cheap recomputations off these).
struct TransferOutcome {
    recipient_utxo: Utxo,
    recipient_nullifier_key: NullifierKey,
}

/// Transfer `TRANSFER_AMOUNT` to the recipient (change back to the payer) and
/// verify Photon's indexed view of the transaction.
fn phase_shielded_transfer(
    env: &mut CycleEnv,
    shield: &PayerShield,
    payer_proofs: PayerProofs,
) -> TestResult<TransferOutcome> {
    let zero = [0u8; 32];
    let PayerProofs {
        state_proof: payer_state_proof,
        nullifier_proof: payer_nullifier_proof,
        spend_input: payer_spend_input,
    } = payer_proofs;
    let payer_utxo = &shield.utxo;
    let payer_nullifier_pk = shield.nullifier_key.pubkey()?;
    let payer_utxo_hash = payer_utxo.hash(&payer_nullifier_pk, &zero, &zero)?;
    let payer_bytes = env.payer.pubkey().to_bytes();

    let recipient_bytes = env.recipient_owner.pubkey().to_bytes();
    let recipient_nullifier_key = NullifierKey::from_secret([11u8; 31]);
    let recipient_nullifier_pk = recipient_nullifier_key.pubkey()?;
    let recipient_public_key = PublicKey::from_ed25519(&recipient_bytes);

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
        wait_for_non_inclusion_proof(&env.indexer, env.tree_address, transfer_dummy_nullifier);
    let transfer_roots = (payer_state_proof.root, payer_nullifier_proof.root);
    let (transfer_dummy_output, transfer_dummy_hash) = dummy_transfer_output(&[19u8; 31])
        .map_err(|err| anyhow!("transfer dummy output: {err}"))?;

    // Real outputs tag by owner (`confidential_view_tag`; see
    // `set_output_owner_tags`).
    let change_view_tag = payer_utxo.owner.confidential_view_tag()?;
    let recipient_view_tag = recipient_public_key.confidential_view_tag()?;
    // Dummy slots reuse a participant's tag (the AssertDummyTags rule; see
    // `set_output_owner_tags`).
    let transfer_ix_data = build_sol_transfer_witness(SolTransferWitnessArgs {
        spend_inputs: vec![
            payer_spend_input,
            dummy_input_with_proof(&[20u8; 31], &transfer_dummy_nf, transfer_roots)
                .map_err(|err| anyhow!("transfer dummy input: {err}"))?,
        ],
        root_index: payer_state_proof.root_index,
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
        payer_pubkey_hash: hash_bytes(&payer_bytes)?,
        label: "transfer",
    })?;

    let transfer_ix = Transact {
        payer: env.payer.pubkey(),
        input_tree: env.tree_pubkey,
        output_tree: env.tree_pubkey,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transfer_ix_data,
    }
    .instruction();
    let transfer_sig = send_transaction(
        &mut env.rpc,
        &[transfer_ix],
        &env.payer.pubkey(),
        &[&env.payer],
    )?;
    print_signature("shielded_transfer", &transfer_sig);

    let indexed_transfer =
        wait_for_indexed_transaction(&env.indexer, recipient_view_tag, transfer_sig);
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
        ring_program_id: None,
        data: Data::default(),
    };
    assert_eq!(
        recipient_hash,
        recipient_utxo.hash(&recipient_nullifier_pk, &zero, &zero)?
    );

    Ok(TransferOutcome {
        recipient_utxo,
        recipient_nullifier_key,
    })
}

/// The submitted unshield plus the lamport snapshots the final assertions
/// compare against.
struct UnshieldOutcome {
    withdraw_sig: Signature,
    public_recipient: Pubkey,
    public_recipient_before: u64,
    vault: Pubkey,
    vault_before: u64,
}

/// Unshield the transferred amount to a fresh public recipient through the
/// SOL interface withdrawal rail.
fn phase_unshield(
    env: &mut CycleEnv,
    shield: &PayerShield,
    transfer: &TransferOutcome,
) -> TestResult<UnshieldOutcome> {
    let zero = [0u8; 32];
    let indexer = &env.indexer;
    let tree_address = env.tree_address;
    let payer_nullifier_pk = shield.nullifier_key.pubkey()?;
    let payer_utxo_hash = shield.utxo.hash(&payer_nullifier_pk, &zero, &zero)?;
    let recipient_utxo = &transfer.recipient_utxo;
    let recipient_nullifier_key = &transfer.recipient_nullifier_key;
    let recipient_nullifier_pk = recipient_nullifier_key.pubkey()?;
    let recipient_hash = recipient_utxo.hash(&recipient_nullifier_pk, &zero, &zero)?;
    let recipient_view_tag = recipient_utxo.owner.confidential_view_tag()?;
    let recipient_bytes = env.recipient_owner.pubkey().to_bytes();
    let recipient_owner_field = owner_hash(&recipient_utxo.owner, &recipient_nullifier_pk)?;

    let recipient_owner_pk_hash = recipient_utxo.owner.owner_proof_input_hash()?;
    let recipient_nullifier =
        recipient_nullifier_key.nullifier(&recipient_hash, &recipient_utxo.blinding)?;
    let recipient_state_proof = wait_for_merkle_proof(indexer, tree_address, recipient_hash);
    let recipient_nullifier_proof =
        wait_for_non_inclusion_proof(indexer, tree_address, recipient_nullifier);
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
        on_chain_roots(&env.rpc, &env.tree_pubkey, recipient_state_proof.root_index)?;
    assert_eq!(
        recipient_state_proof.root, transfer_utxo_root,
        "transfer root gate"
    );
    assert_eq!(recipient_nullifier_proof.root, transfer_nullifier_root);
    let recipient_spend_input = indexed_spend_input(IndexedSpendInputArgs {
        utxo: recipient_utxo,
        owner_field: &recipient_owner_field,
        state_proof: &recipient_state_proof,
        nullifier_proof: &recipient_nullifier_proof,
        nullifier: &recipient_nullifier,
        owner_pk_hash: &recipient_owner_pk_hash,
        nullifier_key: recipient_nullifier_key,
    })?;

    let public_recipient = Keypair::new().pubkey();
    print_signature(
        "airdrop public recipient",
        &env.rpc.airdrop(&public_recipient, 1_000_000)?,
    );
    let public_recipient_before = account_lamports(&env.rpc, &public_recipient)?;
    let vault = pda::sol_interface();
    let vault_before = account_lamports(&env.rpc, &vault)?;
    let withdraw_dummy_nullifier =
        dummy_nullifier(&[21u8; 31]).map_err(|err| anyhow!("withdraw dummy nullifier: {err}"))?;
    let withdraw_dummy_nf =
        wait_for_non_inclusion_proof(indexer, tree_address, withdraw_dummy_nullifier);
    let withdraw_roots = (recipient_state_proof.root, recipient_nullifier_proof.root);
    let (withdraw_outputs, withdraw_output_hashes) =
        dummy_witness_outputs(&[[1u8; 31], [2u8; 31], [3u8; 31]])?;

    // Dummy slots reuse a participant's tag (the AssertDummyTags rule; see
    // `set_output_owner_tags`).
    let withdraw_ix_data = build_sol_transfer_witness(SolTransferWitnessArgs {
        spend_inputs: vec![
            recipient_spend_input,
            dummy_input_with_proof(&[21u8; 31], &withdraw_dummy_nf, withdraw_roots)
                .map_err(|err| anyhow!("withdraw dummy input: {err}"))?,
        ],
        root_index: recipient_state_proof.root_index,
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
        payer_pubkey_hash: hash_bytes(&recipient_bytes)?,
        label: "withdraw",
    })?;

    let withdraw_ix = Transact {
        payer: env.recipient_owner.pubkey(),
        input_tree: env.tree_pubkey,
        output_tree: env.tree_pubkey,
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts {
                recipient: public_recipient,
            },
        )],
        data: withdraw_ix_data,
    }
    .instruction();
    let withdraw_sig = send_transaction(
        &mut env.rpc,
        &[withdraw_ix],
        &env.payer.pubkey(),
        &[&env.payer, &env.recipient_owner],
    )?;
    print_signature("unshield", &withdraw_sig);
    // PR164 AssertDummyTags forces every dummy output to name a transaction
    // participant, so the withdraw's outputs all carry `recipient_view_tag`
    // (see `view_tags` in the witness args above) instead of per-slot
    // synthetic tags.
    Ok(UnshieldOutcome {
        withdraw_sig,
        public_recipient,
        public_recipient_before,
        vault,
        vault_before,
    })
}

/// Verify Photon's indexed view of the unshield (including tag-pagination
/// across the transfer and the withdraw) and the public lamport movements.
fn phase_unshield_indexer_assertions(
    env: &CycleEnv,
    transfer: &TransferOutcome,
    unshield: &UnshieldOutcome,
) -> TestResult {
    let indexer = &env.indexer;
    let recipient_view_tag = transfer.recipient_utxo.owner.confidential_view_tag()?;
    let indexed_withdraw =
        wait_for_indexed_transaction(indexer, recipient_view_tag, unshield.withdraw_sig);
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

    let public_recipient_after = account_lamports(&env.rpc, &unshield.public_recipient)?;
    let vault_after = account_lamports(&env.rpc, &unshield.vault)?;
    assert_eq!(
        public_recipient_after,
        unshield.public_recipient_before + TRANSFER_AMOUNT,
        "public recipient credited"
    );
    assert_eq!(
        vault_after,
        unshield.vault_before - TRANSFER_AMOUNT,
        "vault debited by transferred amount"
    );
    Ok(())
}
