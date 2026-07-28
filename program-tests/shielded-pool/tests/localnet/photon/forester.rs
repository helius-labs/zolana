use super::*;

/// Plumbing smoke for `forester run --dry-run`: stand up the validator + Photon,
/// create a fresh pool tree, and confirm the forester binary reconstructs the
/// reference nullifier tree from Photon and matches the on-chain root — no
/// proving or submitting, so no prover is needed.
///
/// Uses the workspace Photon started by the localnet recipe and requires a
/// separately built forester binary (`cargo build -p forester`). It is
/// `#[ignore]`d because Cargo does not build another package's binary for this
/// test target, and is run explicitly:
///   cargo test -p shielded-pool-tests --features localnet --test localnet_photon_e2e \
///     forester_dry_run_reconstructs_from_photon -- --ignored --nocapture
#[test]
#[ignore]
fn forester_dry_run_reconstructs_from_photon() -> TestResult {
    restart_localnet();

    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());
    let indexer_url =
        std::env::var(INDEXER_URL_ENV).unwrap_or_else(|_| DEFAULT_INDEXER_URL.to_owned());

    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mut rpc = SolanaRpc::new(rpc_url.clone());
    rpc.assert_executable(&program_id)?;

    let LocalnetPool {
        payer: _payer,
        authority: _authority,
        tree,
    } = initialize_pool(&mut rpc)?;
    let tree_pubkey = tree.pubkey();

    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let forester_bin = [
        manifest_dir.join("../../target/release/forester"),
        manifest_dir.join("../../target/debug/forester"),
    ]
    .into_iter()
    .find(|path| path.exists())
    .ok_or_else(|| anyhow!("forester binary not built; run `cargo build -p forester`"))?;

    // Photon indexes asynchronously (its Context needs at least one indexed
    // block), so retry the dry-run until it succeeds.
    let started = Instant::now();
    let stdout = loop {
        let output = std::process::Command::new(&forester_bin)
            .args(["run", "--dry-run", "--tree", &tree_pubkey.to_string()])
            .env("RPC_URL", &rpc_url)
            .env("PHOTON_URL", &indexer_url)
            .output()
            .map_err(|err| anyhow!("run forester {}: {err}", forester_bin.display()))?;
        if output.status.success() {
            break String::from_utf8_lossy(&output.stdout).into_owned();
        }
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if started.elapsed() >= INDEXER_TIMEOUT {
            return Err(anyhow!(
                "forester dry-run never succeeded; last error: {stderr}"
            ));
        }
        sleep(Duration::from_millis(500));
    };

    assert!(
        stdout.contains("matches on-chain"),
        "forester dry-run did not confirm root match:\n{stdout}"
    );

    let output = std::process::Command::new(&forester_bin)
        .args(["info", "--json", "--tree", &tree_pubkey.to_string()])
        .env("RPC_URL", &rpc_url)
        .output()
        .map_err(|err| anyhow!("run forester {}: {err}", forester_bin.display()))?;
    if !output.status.success() {
        return Err(anyhow!(
            "forester info --json failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let info: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        info.pointer("/nullifier_queue/ready_to_forest_zkp_batches"),
        Some(&serde_json::json!(0)),
        "fresh tree should have no ready nullifier zkp-batches"
    );
    assert!(
        info.pointer("/nullifier_queue/root")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "forester info JSON should include the nullifier root"
    );

    println!("forester dry-run plumbing smoke passed:\n{stdout}");
    Ok(())
}

#[test]
#[serial]
fn nullifier_test_forester_batches_queued_nullifiers_with_photon_indexer() -> TestResult {
    let mut env = phase_bootstrap()?;
    let queued_nullifiers = phase_queue_nullifiers(&mut env)?;
    phase_run_forester_batches(&mut env, &queued_nullifiers)?;
    phase_assert_forested_nullifiers(&env, &queued_nullifiers)?;

    println!(
        "localnet Photon nullifier forester test passed via rpc={} indexer={}",
        env.rpc_url, env.indexer_url
    );
    Ok(())
}

/// Shared chain/indexer handles, signers, and the smart-account/vault set for
/// the forester batch test, set up once by [`phase_bootstrap`].
struct ForesterEnv {
    rpc_url: String,
    indexer_url: String,
    rpc: SolanaRpc,
    indexer: ZolanaIndexer,
    payer: Keypair,
    forester_key: Keypair,
    accounts: smart_account::StandardAccounts,
    tree_pubkey: Pubkey,
    tree_address: Address,
}

/// Restart the localnet, then stand up the smart-account vaults, the protocol
/// config, and a pool tree with a small localnet nullifier batch.
fn phase_bootstrap() -> TestResult<ForesterEnv> {
    restart_localnet();
    spawn_workspace_prover();

    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());
    let indexer_url =
        std::env::var(INDEXER_URL_ENV).unwrap_or_else(|_| DEFAULT_INDEXER_URL.to_owned());

    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mut rpc = SolanaRpc::new(rpc_url.clone());
    let indexer = ZolanaIndexer::new(indexer_url.clone());
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
        spl_interface_creation_is_permissionless: false,
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

    Ok(ForesterEnv {
        rpc_url,
        indexer_url,
        rpc,
        indexer,
        payer,
        forester_key,
        accounts,
        tree_pubkey,
        tree_address,
    })
}

/// Sender context plus the UTXO pool the queue loop drains and refills.
struct QueueContext {
    sender: ShieldedKeypair,
    payer_public_key: PublicKey,
    payer_nullifier_key: NullifierKey,
    payer_nullifier_pk: [u8; 32],
    payer_owner_field: [u8; 32],
    payer_address: Address,
    sender_address: ShieldedAddress,
    assets: AssetRegistry,
    spendable_utxos: VecDeque<RealSpendUtxo>,
    queued_nullifiers: Vec<[u8; 32]>,
}

/// Fill the tree's nullifier queue: seed two spendable UTXOs, then run the
/// queue loop whose self-transfers each contribute two nullifiers. Returns
/// the nullifiers in queue order.
fn phase_queue_nullifiers(env: &mut ForesterEnv) -> TestResult<Vec<[u8; 32]>> {
    let zero = [0u8; 32];
    let sender = shielded_ed25519_from_solana(&env.payer)?;
    let payer_public_key = sender.signing_pubkey();
    let payer_nullifier_key = sender.nullifier_key.clone();
    let payer_nullifier_pk = payer_nullifier_key.pubkey()?;
    let payer_owner_field = sender.owner_hash()?;
    let payer_address = Address::new_from_array(env.payer.pubkey().to_bytes());
    let sender_address = sender.shielded_address()?;
    let assets = AssetRegistry::default();

    let queue_tx_count = LOCALNET_NULLIFIER_BATCH_UPDATE_COUNT * LOCALNET_NULLIFIER_ZKP_BATCH_SIZE
        / LOCALNET_NULLIFIERS_PER_QUEUE_TX;
    let mut ctx = QueueContext {
        sender,
        payer_public_key,
        payer_nullifier_key,
        payer_nullifier_pk,
        payer_owner_field,
        payer_address,
        sender_address,
        assets,
        spendable_utxos: VecDeque::new(),
        queued_nullifiers: Vec::with_capacity(
            (queue_tx_count * LOCALNET_NULLIFIERS_PER_QUEUE_TX) as usize,
        ),
    };

    for deposit_index in 0..2 {
        let blinding = stress_blinding(deposit_index);
        let utxo = Utxo {
            owner: ctx.payer_public_key,
            asset: SOL_MINT,
            amount: AMOUNT,
            blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let shield_data =
            ZolanaProgramTest::sol_shield_data(AMOUNT, ctx.payer_owner_field, blinding);
        let shield_view_tag = shield_data.view_tag;
        let shield_ix = Deposit {
            tree: env.tree_pubkey,
            depositor: env.payer.pubkey(),
            deposits: vec![shield_data],
        }
        .instruction()
        .map_err(|err| anyhow!("deposit instruction: {err}"))?;
        let sig = send_transaction(
            &mut env.rpc,
            &[shield_ix],
            &env.payer.pubkey(),
            &[&env.payer],
        )?;
        print_signature(&format!("seed_deposit_{deposit_index}"), &sig);

        let spendable_utxo = RealSpendUtxo::new(
            utxo,
            &ctx.payer_nullifier_key,
            &ctx.payer_nullifier_pk,
            &zero,
        )?;
        let indexed_deposit = wait_for_indexed_utxo(&env.indexer, shield_view_tag, sig)?;
        assert_eq!(
            indexed_deposit.output_slot.output_context.hash,
            spendable_utxo.hash
        );
        ctx.spendable_utxos.push_back(spendable_utxo);
    }

    for i in 0..queue_tx_count {
        queue_nullifiers_once(env, &mut ctx, i)?;
    }
    Ok(ctx.queued_nullifiers)
}

/// Queue one transaction's worth of nullifiers: pop two spendable UTXOs, gate
/// Photon's roots against the chain, then build, prove, send, and decrypt a
/// self-transfer whose change/recipient outputs refill the pool.
fn queue_nullifiers_once(env: &mut ForesterEnv, ctx: &mut QueueContext, i: u64) -> TestResult {
    let zero = [0u8; 32];
    let roots = latest_tree_roots(&env.rpc, &env.tree_pubkey)?;
    assert_eq!(
        roots.nullifier_root_index, 0,
        "nullifier root should remain unchanged until the forester batch"
    );

    let first_utxo = ctx
        .spendable_utxos
        .pop_front()
        .ok_or_else(|| anyhow!("missing first spendable UTXO for queue tx {i}"))?;
    let second_utxo = ctx
        .spendable_utxos
        .pop_front()
        .ok_or_else(|| anyhow!("missing second spendable UTXO for queue tx {i}"))?;
    ctx.queued_nullifiers.push(first_utxo.nullifier);
    ctx.queued_nullifiers.push(second_utxo.nullifier);

    let first_state_proof = wait_for_merkle_proof(&env.indexer, env.tree_address, first_utxo.hash)?;
    let second_state_proof =
        wait_for_merkle_proof(&env.indexer, env.tree_address, second_utxo.hash)?;
    let first_nullifier_proof =
        wait_for_non_inclusion_proof(&env.indexer, env.tree_address, first_utxo.nullifier)?;
    let second_nullifier_proof =
        wait_for_non_inclusion_proof(&env.indexer, env.tree_address, second_utxo.nullifier)?;
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

    let total_amount = first_utxo
        .utxo
        .amount
        .checked_add(second_utxo.utxo.amount)
        .ok_or_else(|| anyhow!("queue tx {i} amount overflow"))?;
    if total_amount <= TRANSFER_AMOUNT {
        return Err(anyhow!(
            "queue tx {i} total amount {total_amount} cannot fund transfer amount {TRANSFER_AMOUNT}"
        ));
    }

    let wait_tag = ctx.payer_public_key.confidential_view_tag()?;
    let mut transfer = ConfidentialTransfer::new(
        ctx.sender_address,
        vec![
            SppProofInputUtxo::new(first_utxo.utxo.clone(), &ctx.sender),
            SppProofInputUtxo::new(second_utxo.utxo.clone(), &ctx.sender),
        ],
        ctx.payer_address,
    );
    transfer.send(&ctx.sender_address, SOL_MINT, TRANSFER_AMOUNT)?;
    let proof_inputs = transfer.sign(&ctx.sender, &ctx.assets)?;
    let commitments = proof_inputs.input_utxo_hashes()?;
    assert_eq!(commitments.len(), 2);
    assert_eq!(
        commitments.first().expect("first commitment").nullifier,
        first_utxo.nullifier
    );
    assert_eq!(
        commitments.get(1).expect("second commitment").nullifier,
        second_utxo.nullifier
    );

    // Both inputs are real (no dummy slots), so no dummy nullifier proofs.
    let assembled = zolana_client::assemble(
        proof_inputs,
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
        &[],
    )?;
    let ProverInputs::Eddsa(inputs) = &assembled.prover_inputs;
    let proof = ProverClient::local().prove_transfer(inputs)?;
    let ix_data = assembled.with_proof(pack_proof(&proof)?);

    let tx_ix = Transact {
        payer: env.payer.pubkey(),
        input_tree: env.tree_pubkey,
        output_tree: env.tree_pubkey,
        interface_transfer_accounts: Vec::new(),
        data: ix_data,
    }
    .instruction();
    let sig = send_transaction(&mut env.rpc, &[tx_ix], &env.payer.pubkey(), &[&env.payer])?;
    print_signature(&format!("queue_nullifiers_{i}"), &sig);

    let indexed = wait_for_indexed_transaction(&env.indexer, wait_tag, sig)?;
    assert_eq!(
        indexed.nullifiers,
        vec![first_utxo.nullifier, second_utxo.nullifier]
    );
    assert_eq!(indexed.nullifiers.len(), 2);
    assert_eq!(indexed.output_slots.len(), 3);
    assert!(!indexed.proofless);
    assert!(indexed.tx_viewing_pk.is_some());
    assert!(indexed.salt.is_some());
    assert!(
        !indexed
            .output_slots
            .first()
            .expect("first output slot")
            .payload
            .is_empty(),
        "SPL change slot should carry a payload"
    );
    assert!(
        !indexed
            .output_slots
            .get(1)
            .expect("second output slot")
            .payload
            .is_empty(),
        "SOL change output should carry an encrypted UTXO payload"
    );
    assert!(
        !indexed
            .output_slots
            .get(2)
            .expect("third output slot")
            .payload
            .is_empty(),
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
    // Every output slot carries its own ciphertext; the author re-derives the
    // transaction viewing key and decrypts the SOL change (slot 1) and the
    // recipient (slot 2) directly, reading each committed blinding back out.
    let tx_key = ctx
        .sender
        .viewing_key
        .get_transaction_viewing_key(&first_nullifier)?;
    if tx_key.pubkey() != tx_viewing_pk {
        return Err(anyhow!("sender did not author the indexed queue tx"));
    }
    let decode_output = |slot_index: usize| -> TestResult<ConfidentialOutputPlaintext> {
        let slot = indexed
            .output_slots
            .get(slot_index)
            .ok_or_else(|| anyhow!("indexed queue tx missing output slot {slot_index}"))?;
        let blob = match slot
            .output_data()
            .ok_or_else(|| anyhow!("output slot {slot_index} is not decodable output data"))?
        {
            OutputDataEncoding::Encrypted(blob)
            | OutputDataEncoding::VerifiablyEncrypted(blob)
            | OutputDataEncoding::Plaintext(blob) => blob,
        };
        let (_scheme, body) = blob
            .split_first()
            .ok_or_else(|| anyhow!("output slot {slot_index} missing scheme byte"))?;
        Ok(Confidential::decrypt_with_tx_key(
            &tx_key,
            body,
            salt,
            slot_index as u32,
        )?)
    };
    let change_plaintext = decode_output(1)?;
    let recipient_plaintext = decode_output(2)?;

    let change_utxo = Utxo {
        owner: ctx.payer_public_key,
        asset: SOL_MINT,
        amount: total_amount - TRANSFER_AMOUNT,
        blinding: change_plaintext.blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let recipient_utxo = Utxo {
        owner: ctx.payer_public_key,
        asset: SOL_MINT,
        amount: TRANSFER_AMOUNT,
        blinding: recipient_plaintext.blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let change_utxo = RealSpendUtxo::new(
        change_utxo,
        &ctx.payer_nullifier_key,
        &ctx.payer_nullifier_pk,
        &zero,
    )?;
    let recipient_utxo = RealSpendUtxo::new(
        recipient_utxo,
        &ctx.payer_nullifier_key,
        &ctx.payer_nullifier_pk,
        &zero,
    )?;
    assert_eq!(
        change_utxo.hash,
        indexed
            .output_slots
            .get(1)
            .expect("change output slot")
            .output_context
            .hash,
        "decrypted SOL change UTXO should match output commitment"
    );
    assert_eq!(
        recipient_utxo.hash,
        indexed
            .output_slots
            .get(2)
            .expect("recipient output slot")
            .output_context
            .hash,
        "decrypted recipient UTXO should match output commitment"
    );
    ctx.spendable_utxos.push_back(change_utxo);
    ctx.spendable_utxos.push_back(recipient_utxo);
    Ok(())
}

/// Drain the queued nullifiers through the forester (the `FORESTER_BIN` binary
/// when set, otherwise the in-test forester), asserting the nullifier root
/// advances once per zkp-batch and that Photon tracks each new root.
fn phase_run_forester_batches(env: &mut ForesterEnv, queued_nullifiers: &[[u8; 32]]) -> TestResult {
    let before_forester = latest_tree_roots(&env.rpc, &env.tree_pubkey)?;
    assert_eq!(
        before_forester.nullifier_root_index, 0,
        "queued nullifiers should not update the indexed tree root"
    );

    // Default path drives the in-test forester. Set `FORESTER_BIN` to drain via
    // the real `forester` binary instead (a full end-to-end drain through the
    // smart-account vault: photon RPC -> reconstruct -> prove -> execute_sync
    // submit).
    if let Ok(forester_bin) = std::env::var("FORESTER_BIN") {
        let prover_url = std::env::var("ZOLANA_PROVER_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:3001".to_string());
        let payer_json = serde_json::to_string(&env.forester_key.to_bytes().to_vec())?;
        let max_batches = LOCALNET_NULLIFIER_BATCH_UPDATE_COUNT.to_string();
        let status = std::process::Command::new(&forester_bin)
            .args([
                "run",
                "--tree",
                &env.tree_pubkey.to_string(),
                "--settings",
                &env.accounts.forester_settings.to_string(),
                "--account-index",
                "0",
                "--max-batches",
                &max_batches,
                "--watch",
                "--poll-secs",
                "1",
            ])
            .env("RPC_URL", &env.rpc_url)
            .env("PROVER_URL", &prover_url)
            .env("PHOTON_URL", &env.indexer_url)
            .env("PAYER", payer_json)
            .status()
            .map_err(|err| anyhow!("run forester binary {forester_bin}: {err}"))?;
        assert!(status.success(), "forester binary drain failed");

        let after_forester = latest_tree_roots(&env.rpc, &env.tree_pubkey)?;
        assert_eq!(
            u64::from(after_forester.nullifier_root_index),
            LOCALNET_NULLIFIER_BATCH_UPDATE_COUNT,
            "forester binary should drain all queued zkp-batches"
        );
    } else {
        let mut forester = NullifierTestForester::default();
        let mut previous_forester_roots = before_forester;
        for batch_index in 0..LOCALNET_NULLIFIER_BATCH_UPDATE_COUNT {
            let forester_sig = forester.run(
                &mut env.rpc,
                ForesterAuthority {
                    signer: &env.forester_key,
                    settings: env.accounts.forester_settings,
                    account_index: 0,
                    vault: env.accounts.forester_vault,
                },
                env.tree_pubkey,
                queued_nullifiers,
            )?;
            print_signature(
                &format!("batch_update_nullifier_tree_{batch_index}"),
                &forester_sig,
            );
            assert_transaction_compute_units(
                &env.rpc,
                &forester_sig,
                &format!("batch nullifier-tree update {batch_index}"),
                BATCH_NULLIFIER_TREE_CU_LIMIT,
            )?;

            let after_forester = latest_tree_roots(&env.rpc, &env.tree_pubkey)?;
            assert_ne!(
                after_forester.nullifier_root_index, previous_forester_roots.nullifier_root_index,
                "forester batch {batch_index} should advance the nullifier root"
            );

            let fresh_nullifier = fe(9_000 + batch_index);
            let fresh_proof = wait_for(
                format!("Photon nullifier root after batch {batch_index}"),
                || {
                    let response = env.indexer.get_non_inclusion_proofs(
                        env.tree_address,
                        vec![fresh_nullifier],
                        None,
                    )?;
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
    }
    Ok(())
}

/// Confirm a sample of the queued nullifiers no longer has non-inclusion
/// proofs: they are spent and forested into the tree.
fn phase_assert_forested_nullifiers(
    env: &ForesterEnv,
    queued_nullifiers: &[[u8; 32]],
) -> TestResult {
    for nullifier_index in [0, queued_nullifiers.len() / 2, queued_nullifiers.len() - 1] {
        let nullifier = *queued_nullifiers
            .get(nullifier_index)
            .expect("sampled nullifier index is within the queued set");
        wait_for(
            format!("forested nullifier {nullifier_index} rejected"),
            || match env
                .indexer
                .get_non_inclusion_proofs(env.tree_address, vec![nullifier], None)
            {
                Ok(response) if response.proofs.is_empty() => Ok(Some(())),
                Ok(_) => Ok(None),
                Err(_) => Ok(Some(())),
            },
        )?;
    }
    Ok(())
}
