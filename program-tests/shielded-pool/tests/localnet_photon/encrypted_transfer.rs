use super::*;

/// End-to-end encrypted transfer: shield two sender UTXOs, transfer one private
/// output to a recipient using the high-level `Transaction` builder (real HPKE
/// encryption), then recover the recipient UTXO purely by DECRYPTING the
/// ciphertext the Photon indexer returns -- no plaintext reconstruction.
///
/// Two real inputs are used so the proof shape is exactly (2, 3), matching the
/// available `transfer_confidential_2_3` key without padding the instruction
/// with dummy nullifiers. The P256-rail twin of this test was removed with the
/// P256 transact rail (PR164).
#[test]
#[serial]
fn shield_encrypted_transfer_eddsa_recovered_by_decryption() -> TestResult {
    shield_encrypted_transfer_recovered_by_decryption()
}

fn shield_encrypted_transfer_recovered_by_decryption() -> TestResult {
    restart_localnet();
    spawn_workspace_prover();

    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());
    let indexer_url =
        std::env::var(INDEXER_URL_ENV).unwrap_or_else(|_| DEFAULT_INDEXER_URL.to_owned());

    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mut rpc = SolanaRpc::new(rpc_url.clone());
    let indexer = ZolanaIndexer::new(indexer_url.clone());
    rpc.assert_executable(&program_id)?;

    let LocalnetPool {
        payer,
        authority: _authority,
        tree,
    } = initialize_pool(&mut rpc)?;
    let tree_pubkey = tree.pubkey();
    let tree_address = Address::new_from_array(tree_pubkey.to_bytes());
    let zero = [0u8; 32];

    let assets = AssetRegistry::default();
    let sender = shielded_ed25519_from_solana(&payer)?;
    let recipient = shielded_ed25519_from_solana(&Keypair::new())?;
    let recipient_address = recipient.shielded_address()?;
    let recipient_view_tag = recipient.signing_pubkey().confidential_view_tag()?;
    let sender_nullifier_key = NullifierKey::from_secret(*sender.nullifier_key.secret());
    let sender_nullifier_pk = sender_nullifier_key.pubkey()?;

    // ---- shield two sender-owned UTXOs (reconstructable from fixed blindings) ----
    let half = AMOUNT / 2;
    let deposit_blindings: [[u8; 32]; 2] = [[7u8; 32], [8u8; 32]];
    let mut spends = Vec::new();
    for blinding in deposit_blindings {
        let utxo = Utxo {
            owner: sender.signing_pubkey(),
            asset: SOL_MINT,
            amount: half,
            blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        let owner_field = owner_hash(&utxo.owner, &sender_nullifier_pk)?;
        let shield_data = ZolanaProgramTest::sol_shield_data(half, owner_field, blinding);
        let shield_ix = Deposit {
            tree: tree_pubkey,
            depositor: payer.pubkey(),
            deposits: vec![shield_data],
        }
        .instruction()
        .map_err(|err| anyhow!("deposit instruction: {err}"))?;
        send_transaction(&mut rpc, &[shield_ix], &payer.pubkey(), &[&payer])?;
        let utxo_hash = utxo.hash(&sender_nullifier_pk, &zero, &zero)?;
        wait_for_merkle_proof(&indexer, tree_address, utxo_hash);
        spends.push(SppProofInputUtxo::new(utxo, &sender));
    }

    // ---- build the encrypted transfer with the high-level client builder ----
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let mut transfer = ConfidentialTransfer::new(sender.shielded_address()?, spends, payer_address);
    transfer.send(&recipient_address, SOL_MINT, TRANSFER_AMOUNT)?;
    let proof_inputs = transfer.sign(&sender, &assets)?;

    let commitments = proof_inputs.input_utxo_hashes()?;
    let mut spend_proofs = Vec::new();
    for commitment in &commitments {
        let state = wait_for_merkle_proof(&indexer, tree_address, commitment.utxo_hash);
        let nullifier = wait_for_non_inclusion_proof(&indexer, tree_address, commitment.nullifier);
        spend_proofs.push(SpendProof { state, nullifier });
    }

    // Both inputs are real (no dummy slots), so no dummy nullifier proofs.
    let assembled = zolana_client::assemble(proof_inputs, &spend_proofs, &[])?;
    let ProverInputs::Eddsa(inputs) = &assembled.prover_inputs;
    let proof = ProverClient::local().prove_transfer(inputs)?;
    let packed = pack_transact_proof(&proof)?;
    let ix_data = assembled.with_proof(packed);

    let transfer_ix = Transact {
        payer: payer.pubkey(),
        input_tree: tree_pubkey,
        output_tree: tree_pubkey,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: ix_data,
    }
    .instruction();
    // Proof verification needs more than the 200k default compute budget.
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

    let indexed = wait_for_indexed_transaction(&indexer, recipient_view_tag, transfer_sig);
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

    // Independently reconstruct the expected recipient UTXO: the author re-derives
    // the transaction viewing key and decrypts the recipient slot (output position
    // 2) directly, reading its committed blinding out. Each slot's borsh
    // `OutputDataEncoding` carries a scheme byte plus the per-scheme ciphertext
    // body.
    let tx_key = sender
        .viewing_key
        .get_transaction_viewing_key(&first_nullifier)?;
    if tx_key.pubkey() != tx_viewing_pk {
        return Err(anyhow!("sender did not author the indexed transfer"));
    }
    let recipient_slot = indexed
        .output_slots
        .get(2)
        .ok_or_else(|| anyhow!("indexed transfer missing recipient slot"))?;
    let recipient_blob = match recipient_slot
        .output_data()
        .ok_or_else(|| anyhow!("recipient slot is not decodable output data"))?
    {
        OutputDataEncoding::Encrypted(blob)
        | OutputDataEncoding::VerifiablyEncrypted(blob)
        | OutputDataEncoding::Plaintext(blob) => blob,
    };
    let (_scheme, recipient_ciphertext) = recipient_blob
        .split_first()
        .ok_or_else(|| anyhow!("recipient slot missing scheme byte"))?;
    let recipient_plaintext =
        Confidential::decrypt_with_tx_key(&tx_key, recipient_ciphertext, salt, 2)?;
    let expected_utxo = Utxo {
        owner: recipient_address.signing_pubkey,
        asset: SOL_MINT,
        amount: TRANSFER_AMOUNT,
        blinding: recipient_plaintext.blinding,
        ring_program_id: None,
        data: Data::default(),
    };

    // The recipient wallet is handed only the on-chain ciphertext and recovers by
    // decrypting it. `Wallet::store` keeps only recipient-owned UTXOs, so the
    // sender's change slot (encrypted to the sender) is not stored.
    let mut wallet = Wallet::new(recipient.shielded_address()?, AssetRegistry::default())?;
    let authority = LocalWalletAuthority::new(Pubkey::default(), &recipient);
    wallet.sync(
        &authority,
        std::slice::from_ref(&indexed),
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
    let nullifier_pk = recipient.nullifier_key.pubkey()?;
    let expected_hash = expected_utxo.hash(&nullifier_pk, &zero, &zero)?;
    let output_context = indexed
        .output_slots
        .iter()
        .find(|slot| slot.output_context.hash == expected_hash)
        .map(|slot| slot.output_context.clone())
        .ok_or_else(|| anyhow!("expected output not found in indexed transfer"))?;
    let expected_nullifier =
        expected_utxo.nullifier(&output_context.hash, &recipient.nullifier_key)?;
    let expected = WalletUtxo {
        utxo: expected_utxo,
        output_context,
        nullifier: expected_nullifier,
        data_hash: None,
        ring_data_hash: None,
        spent: false,
    };
    assert_eq!(*recovered, expected);

    // The decrypted UTXO is the exact committed on-chain output, so its hash is
    // Merkle-provable (and therefore spendable by the recipient).
    wait_for_merkle_proof(&indexer, tree_address, recovered.output_context.hash);

    println!(
        "encrypted shield-transfer rail=eddsa recovered by decryption via rpc={rpc_url} indexer={indexer_url}"
    );
    Ok(())
}
