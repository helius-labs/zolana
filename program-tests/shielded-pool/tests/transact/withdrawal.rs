//! Litesvm program-test for a SOL shield then unshield (withdrawal) via the
//! `transact` instruction with a real Groth16 proof.
//!
//! Flow: `deposit` deposits SOL into one UTXO owned by the payer's
//! Ed25519 key, then `transact` spends that UTXO (a real, non-dummy input) to
//! withdraw the full amount to an external account. The input carries a real
//! state-inclusion proof against the on-chain UTXO tree root and a real
//! nullifier non-inclusion proof against the on-chain nullifier tree root, both
//! built from in-test reference trees and gated against the on-chain roots. The
//! Solana-only eddsa rail is used: the payer signs and the program reconstructs
//! its owner hash.
//!
//! Requires `cargo build-sbf -p shielded-pool-program` to have produced the
//! `.so` binary.

use shielded_pool_tests::support::transact::{proof_env, tree_roots, Pool};

use borsh::BorshSerialize;
use num_bigint::BigUint;
use solana_clock::Clock;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    PublicInputs, PublicTransfers, TransferInput, TransferOutput, STATE_TREE_HEIGHT,
};
use zolana_event::{OutputDataEncoding, ProoflessOutput};
use zolana_hasher::{primitives::hash_bytes, Poseidon};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{InterfaceTransfer, ResolvedInterfaceTransfer},
        Transact, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
        TransactSplDepositAccounts, TransactSplWithdrawalAccounts,
    },
    pda,
};
use zolana_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey};
use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};
use zolana_program_test::{test_blinding, Rejection};
use zolana_transaction::{
    instructions::transact::PrivateTxHash, Data, SppProofOutputUtxo, Utxo, SOL_MINT,
};

use zolana_test_utils::transact::{
    build_spl_withdrawal, build_transfer_prover_inputs, dummy_input, dummy_transfer_output,
    eddsa_input_utxo, external_data_hash, external_data_hash_spl, fe, inline_outputs,
    new_transact_ix_data, nullifier_tree, output_owner_pk_hashes, prove_and_verify_transfer,
    public_sol_field, real_output, set_output_owner_tags, sol_public_slots, spend_input,
    spl_public_slots, transfer_output, SpendInputArgs, TransferProverInputsArgs,
};

const AMOUNT: u64 = 1_000_000_000;
const TRANSFER_AMOUNT: u64 = 400_000_000;
const CHANGE_AMOUNT: u64 = AMOUNT - TRANSFER_AMOUNT;

#[test]
fn shield_then_withdraw_spl_with_a_real_proof() {
    const SPL_AMOUNT: u64 = 1_000;
    let mut env = proof_env();
    let tree = env.tree.pubkey();
    let payer = env.rpc.payer.insecure_clone();

    let withdrawal =
        build_spl_withdrawal(&mut env.rpc, &env.authority, &tree, SPL_AMOUNT, [7u8; 32])
            .expect("build SPL withdrawal");
    let vault = withdrawal.vault;
    let user_token = withdrawal.user_token;
    assert_eq!(env.rpc.token_balance(&user_token), Some(0));
    assert_eq!(env.rpc.token_balance(&vault), Some(SPL_AMOUNT));

    let other_mint = env.rpc.create_mint().expect("create substitution mint");
    env.rpc
        .create_spl_interface(&env.authority, &other_mint)
        .expect("create substitution SPL interface");
    let other_user_token = env
        .rpc
        .create_token_account(&other_mint, &payer.pubkey())
        .expect("create substitution token account");
    let other_vault_bump = pda::spl_interface_bump(&other_mint.to_bytes());
    let mut substituted_data = withdrawal.data.clone();
    // Fully canonical settlement accounts for `other_mint`: the leg must carry
    // other_mint's own canonical vault bump, otherwise the program's
    // derive-and-compare rejects the address as `InvalidSettlementAccounts`
    // (which of the two bumps a random mint pair shares is nondeterministic).
    substituted_data.interface_transfers[0] = InterfaceTransfer::SplWithdrawal {
        amount: SPL_AMOUNT,
        spl_interface_bump: other_vault_bump,
    };
    let substituted = Transact {
        payer: payer.pubkey(),
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::SplWithdrawal(
            TransactSplWithdrawalAccounts {
                mint: other_mint,
                spl_interface: pda::spl_interface(&other_mint),
                user_token_account: other_user_token,
                token_program: zolana_program_test::ZolanaProgramTest::token_program_id(),
            },
        )],
        data: substituted_data,
    }
    .instruction();
    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[substituted], &[])
        .expect_err("proof bound to another mint must fail");
    // With mint B's canonical settlement accounts, validation passes and the
    // rejection is the proof binding: the public input carries
    // `hash_bytes(mint B)` while the proof was built for mint A (INV-TRANSACT-21).
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    env.rpc
        .last_transaction_trace()
        .expect("mint substitution trace")
        .assert_rolled_back_except(&[payer.pubkey()]);

    env.rpc
        .create_and_send_default_payer_transaction(&[withdrawal.instruction], &[])
        .expect("real-proof SPL withdrawal");
    assert_eq!(env.rpc.token_balance(&user_token), Some(SPL_AMOUNT));
    assert_eq!(env.rpc.token_balance(&vault), Some(0));
}

#[test]
fn shield_before_authority_rotation_then_withdraw_sol() {
    let mut env = proof_env();

    let tree = env.tree.pubkey();
    let payer = env.rpc.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];

    // The shielded UTXO is owned by the payer's Ed25519 key (eddsa rail). Fixed
    // blinding / nullifier secret keep the run deterministic.
    let blinding = test_blinding(7);
    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo = Utxo {
        owner: PublicKey::from_ed25519(&payer_bytes),
        asset: SOL_MINT,
        amount: AMOUNT,
        blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let owner_pk_hash = utxo.owner.owner_proof_input_hash().expect("owner pk hash");
    let owner_field = owner_hash(&utxo.owner, &nullifier_pk).expect("owner field");

    // Shield: deposit AMOUNT into the UTXO. The vault (cpi_authority) is funded.
    let event = env
        .rpc
        .deposit_sol(&tree, &payer, AMOUNT, owner_field, blinding)
        .expect("proofless deposit");

    let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
    assert_eq!(
        utxo_hash, event.utxo_hash,
        "client utxo hash must match on-chain"
    );

    // Evolution contract: rotating every protocol authority after creation must
    // not invalidate an existing UTXO or its historical tree root.
    let next_authority = Keypair::new();
    env.rpc
        .update_protocol_config(&env.authority, &next_authority)
        .expect("rotate protocol authorities after shielding");

    // The UTXO is leaf 0; its inclusion proof is against the root AFTER the
    // shield append (history index 1).
    let (utxo_root, nullifier_root) = tree_roots(&env.rpc, &tree, 1);

    // State inclusion proof (height 32) for leaf 0.
    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree.append(&utxo_hash).expect("append state leaf");
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(0, true)
        .expect("state proof")
        .to_vec();

    // Nullifier non-inclusion proof (height 40). The reference tree is seeded
    // with the BN254 p-1 sentinel, matching the on-chain NULLIFIER_TREE_INIT_ROOT.
    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let nullifier = nullifier_key
        .nullifier(&utxo_hash, &blinding)
        .expect("nullifier");
    let non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
        .expect("non inclusion proof");

    let roots = (utxo_root, nullifier_root);
    let (dummy_spend_input, dummy_nullifier) =
        dummy_input(&[2u8; 31], &nf_tree, roots).expect("dummy input");

    // The real input spending the shielded UTXO (is_dummy = 0).
    let payer_spend_input = spend_input(SpendInputArgs {
        utxo: &utxo,
        owner_field: &owner_field,
        state_path: &state_path,
        state_path_index: 0,
        non_inclusion: &non_inclusion,
        roots,
        nullifier: &nullifier,
        owner_pk_hash: &owner_pk_hash,
        nullifier_key: &nullifier_key,
    })
    .expect("real input");

    // Withdrawal: spend AMOUNT, no change. Recipient is an external SOL account.
    let recipient = Keypair::new().pubkey();
    env.rpc
        .airdrop(&recipient, 1_000_000)
        .expect("airdrop recipient");
    let recipient_before = env
        .rpc
        .svm
        .get_balance(&recipient)
        .expect("recipient balance");
    // SOL is custodied in the `sol_interface` PDA (funded by the deposit, drained
    // on withdrawal) — shared with the proofless-shield deposit path.
    let vault = pda::sol_interface();
    // Draining the full amount closes the vault (a system account at 0 lamports
    // is reaped), so read balances with `unwrap_or(0)`.
    let vault_before = env.rpc.svm.get_balance(&vault).unwrap_or(0);

    // The withdrawal spends the full amount, so all three outputs are dummies
    // (`owner_hash = 0`) with distinct blindings: each has a real `utxo_hash` the
    // program appends and the proof commits, and contributes `0` to private_tx_hash.
    let dummy_outputs: Vec<(TransferOutput, [u8; 32])> = [[1u8; 31], [2u8; 31], [3u8; 31]]
        .iter()
        .map(|blinding| dummy_transfer_output(blinding).expect("dummy output"))
        .collect();
    let output_hashes: Vec<[u8; 32]> = dummy_outputs.iter().map(|(_, hash)| *hash).collect();
    let mut outputs: Vec<TransferOutput> = dummy_outputs.into_iter().map(|(out, _)| out).collect();

    let view_tags = [payer_bytes; 3];
    let mut transact_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(nullifier, 1),
            eddsa_input_utxo(dummy_nullifier, 1),
        ],
        vec![InterfaceTransfer::SolWithdrawal { amount: AMOUNT }],
        inline_outputs(&output_hashes, &view_tags),
    );
    let boundary_clock = env.rpc.svm.get_sysvar::<Clock>();
    let expiry = u64::try_from(boundary_clock.unix_timestamp)
        .expect("LiteSVM clock timestamp must be non-negative");
    transact_ix_data.expiry_unix_ts = expiry;

    // All three outputs are dummies; stamp their confidential owner tags from the
    // program's `hash_bytes(resolved_owner_tag)` mapping (nullifier_pk 0 =
    // unconstrained).
    let owner_pk_hashes =
        output_owner_pk_hashes(&transact_ix_data.outputs).expect("output owner pk hashes");
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &[zero, zero, zero]);
    let resolved_transfers = [ResolvedInterfaceTransfer::SolWithdrawal {
        amount: AMOUNT,
        recipient: recipient.to_bytes(),
    }];
    let external_data_hash =
        external_data_hash(&transact_ix_data, &resolved_transfers).expect("external data hash");

    // private_tx_hash uses the real input's utxo hash; the dummy input and all
    // outputs contribute zero.
    let private_tx =
        PrivateTxHash::new(&[utxo_hash, zero], &[zero, zero, zero], &external_data_hash)
            .hash()
            .expect("private tx hash");
    let public_sol_field = public_sol_field(Some(-(AMOUNT as i64)));
    let (public_slot_assets, public_slot_amounts) = sol_public_slots(public_sol_field);
    let payer_pubkey_hash = hash_bytes(&payer_bytes).expect("payer hash");

    let public_input_hash = PublicInputs {
        nullifiers: &[nullifier, dummy_nullifier],
        output_hashes: &output_hashes,
        utxo_roots: &[utxo_root, utxo_root],
        nullifier_tree_roots: &[nullifier_root, nullifier_root],
        private_tx: &private_tx,
        external_data_hash: &external_data_hash,
        public_transfers: &PublicTransfers {
            assets: public_slot_assets,
            amounts: public_slot_amounts,
        },
        zone_program_id: &zero,
        allow_dummy_inputs: &fe(1),
        signer_pk_hashes: &[payer_pubkey_hash, zero, zero],
        output_owner_pk_hashes: Some(&owner_pk_hashes),
    }
    .hash()
    .expect("public input hash");

    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![payer_spend_input, dummy_spend_input],
        outputs,
        external_data_hash,
        private_tx_hash: private_tx,
        public_slot_assets,
        public_slot_amounts,
        signer_pk_hashes: vec![payer_pubkey_hash],
        public_input_hash,
    });
    transact_ix_data.proof =
        prove_and_verify_transfer(&prover_inputs, public_input_hash, "withdraw")
            .expect("prove withdraw");
    transact_ix_data.private_tx_hash = private_tx;

    // SOL withdrawal account layout: payer (signer/owner), tree, sol_interface
    // (the SOL-custody PDA), recipient, then the system program (settle_sol
    // Transfer CPI) and the program (emit_event self-CPI).
    let ix = Transact {
        payer: payer.pubkey(),
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts { recipient },
        )],
        data: transact_ix_data,
    }
    .instruction();

    // The proof is bound to this exact expiry. Submit it one second late first
    // and verify complete rollback, then restore the boundary clock and submit
    // the byte-identical instruction successfully. Rejection must not consume
    // the nullifiers or prevent a corrected retry.
    let mut expired_clock = boundary_clock.clone();
    expired_clock.unix_timestamp += 1;
    env.rpc.svm.set_sysvar(&expired_clock);
    let expired = env
        .rpc
        .create_and_send_default_payer_transaction(std::slice::from_ref(&ix), &[])
        .expect_err("transaction one second past expiry must fail");
    Rejection::pool(ShieldedPoolError::ExpiredTransaction).assert_litesvm(expired);
    env.rpc
        .last_transaction_trace()
        .expect("expired transaction trace")
        .assert_rolled_back_except(&[payer.pubkey()]);

    env.rpc.svm.set_sysvar(&boundary_clock);
    let result = env
        .rpc
        .create_and_send_default_payer_transaction(std::slice::from_ref(&ix), &[]);
    assert!(result.is_ok(), "transact withdrawal failed: {result:?}");

    let recipient_after = env.rpc.svm.get_balance(&recipient).unwrap_or(0);
    let vault_after = env.rpc.svm.get_balance(&vault).unwrap_or(0);
    assert_eq!(
        recipient_after,
        recipient_before + AMOUNT,
        "recipient credited"
    );
    assert_eq!(vault_after, vault_before - AMOUNT, "vault debited");

    // The successful spend inserted both input nullifiers. Replaying the exact
    // instruction must fail at the nullifier queue before any tree, vault, or
    // recipient mutation is committed.
    let replay = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("reusing a spent nullifier must fail");
    Rejection::pool(ShieldedPoolError::NullifierTreeUpdateFailed).assert_litesvm(replay);
    env.rpc
        .last_transaction_trace()
        .expect("replayed transaction trace")
        .assert_rolled_back_except(&[payer.pubkey()]);
}

/// INV-TRANSACT-26: a SOL deposit through `transact` (positive
/// `public_sol_amount` with a real Groth16 proof, not the proofless `deposit`
/// instruction) moves exactly the public amount from the depositor account
/// into the `sol_interface` custody PDA. Conservation holds in-circuit: two
/// dummy inputs plus the public deposit fund one real shielded output of the
/// full amount (plus two dummy outputs).
#[test]
fn transact_sol_deposit_settles_exact_lamport_deltas() {
    let mut env = proof_env();

    let tree = env.tree.pubkey();
    let payer = env.rpc.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];

    // The depositor is the SOL settlement account: on a deposit the program
    // transfers from it into the sol_interface PDA, so it must sign.
    let depositor = Keypair::new();
    env.rpc
        .airdrop(&depositor.pubkey(), 2 * AMOUNT)
        .expect("fund depositor");

    let (utxo_root, nullifier_root) = tree_roots(&env.rpc, &tree, 0);
    let roots = (utxo_root, nullifier_root);

    // Two circuit-dummy inputs with derived nullifiers and non-inclusion
    // witnesses (PR164 constrains dummies), owner identity pinned to zero.
    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    let (deposit_dummy_0, nullifier_0) =
        dummy_input(&[31u8; 31], &nf_tree, roots).expect("dummy input 0");
    let (deposit_dummy_1, nullifier_1) =
        dummy_input(&[32u8; 31], &nf_tree, roots).expect("dummy input 1");
    let nullifiers = [nullifier_0, nullifier_1];

    // The deposited value materializes as one real output owned by the payer's
    // Ed25519 key; the other two output slots are dummies.
    let nullifier_key = NullifierKey::from_secret([21u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let owner_public_key = PublicKey::from_ed25519(&payer_bytes);
    let shielded_output = real_output(owner_public_key, nullifier_pk, SOL_MINT, AMOUNT, [23u8; 31]);
    let shielded_hash = shielded_output.hash().expect("shielded output hash");
    let (dummy_output_a, dummy_hash_a) = dummy_transfer_output(&[1u8; 31]).expect("dummy output");
    let (dummy_output_b, dummy_hash_b) = dummy_transfer_output(&[2u8; 31]).expect("dummy output");
    let output_hashes = [shielded_hash, dummy_hash_a, dummy_hash_b];

    // The real output tags by owner (`confidential_view_tag`; see
    // `set_output_owner_tags`).
    let owner_view_tag = owner_public_key
        .confidential_view_tag()
        .expect("owner view tag");
    // Dummy slots share the real output's owner tag (the AssertDummyTags rule;
    // see `set_output_owner_tags`).
    let view_tags = [owner_view_tag; 3];
    let mut transact_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(nullifiers[0], 0),
            eddsa_input_utxo(nullifiers[1], 0),
        ],
        vec![InterfaceTransfer::SolDeposit { amount: AMOUNT }],
        inline_outputs(&output_hashes, &view_tags),
    );
    // A deposit-marked event's first output must carry the plaintext proofless
    // payload (the deposit convention indexers rely on); it is committed into
    // `external_data_hash` below, before proving.
    let proofless_payload = ProoflessOutput {
        owner: owner_hash(&owner_public_key, &nullifier_pk).expect("deposit owner field"),
        blinding: [23u8; 32],
        asset: SOL_MINT.to_bytes(),
        amount: AMOUNT,
        data_hash: None,
        utxo_data: None,
        zone_program_id: None,
        zone_data_hash: None,
        zone_data: None,
        memo: None,
    };
    let mut plaintext_blob = vec![OutputDataEncoding::PLAINTEXT_TAG];
    proofless_payload
        .serialize(&mut plaintext_blob)
        .expect("serialize proofless payload");
    transact_ix_data
        .outputs
        .get_mut(0)
        .expect("deposit output slot")
        .data = Some(
        borsh::to_vec(&OutputDataEncoding::Plaintext(plaintext_blob))
            .expect("encode plaintext output data"),
    );

    let owner_pk_hashes =
        output_owner_pk_hashes(&transact_ix_data.outputs).expect("output owner pk hashes");
    let mut outputs = vec![
        transfer_output(&shielded_output).expect("real transfer output"),
        dummy_output_a,
        dummy_output_b,
    ];
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &[nullifier_pk, zero, zero]);

    let resolved_transfers = [ResolvedInterfaceTransfer::SolDeposit {
        amount: AMOUNT,
        recipient: depositor.pubkey().to_bytes(),
    }];
    let external_data_hash =
        external_data_hash(&transact_ix_data, &resolved_transfers).expect("external data hash");
    let private_tx = PrivateTxHash::new(
        &[zero, zero],
        &[shielded_hash, zero, zero],
        &external_data_hash,
    )
    .hash()
    .expect("private tx hash");
    let public_sol_field = public_sol_field(Some(AMOUNT as i64));
    let (public_slot_assets, public_slot_amounts) = sol_public_slots(public_sol_field);
    let payer_pubkey_hash = hash_bytes(&payer_bytes).expect("payer hash");

    let public_input_hash = PublicInputs {
        nullifiers: &nullifiers,
        output_hashes: &output_hashes,
        utxo_roots: &[utxo_root, utxo_root],
        nullifier_tree_roots: &[nullifier_root, nullifier_root],
        private_tx: &private_tx,
        external_data_hash: &external_data_hash,
        public_transfers: &PublicTransfers {
            assets: public_slot_assets,
            amounts: public_slot_amounts,
        },
        zone_program_id: &zero,
        allow_dummy_inputs: &fe(1),
        signer_pk_hashes: &[payer_pubkey_hash, zero, zero],
        output_owner_pk_hashes: Some(&owner_pk_hashes),
    }
    .hash()
    .expect("public input hash");
    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![deposit_dummy_0, deposit_dummy_1],
        outputs,
        external_data_hash,
        private_tx_hash: private_tx,
        public_slot_assets,
        public_slot_amounts,
        signer_pk_hashes: vec![payer_pubkey_hash],
        public_input_hash,
    });
    transact_ix_data.proof =
        prove_and_verify_transfer(&prover_inputs, public_input_hash, "sol deposit")
            .expect("prove sol deposit");
    transact_ix_data.private_tx_hash = private_tx;

    let vault = pda::sol_interface();
    let vault_before = env.rpc.svm.get_balance(&vault).unwrap_or(0);
    let depositor_before = env
        .rpc
        .svm
        .get_balance(&depositor.pubkey())
        .expect("depositor balance");

    let ix = Transact {
        payer: payer.pubkey(),
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts {
                recipient: depositor.pubkey(),
            },
        )],
        data: transact_ix_data,
    }
    .instruction();
    // A deposit transfers FROM the settlement account; the builder already
    // marks the depositor meta as a signer.

    let result = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&depositor]);
    assert!(result.is_ok(), "transact SOL deposit failed: {result:?}");

    // Exact settlement deltas: the depositor is debited and the sol_interface
    // credited by precisely the public amount (the depositor pays no fee; the
    // default payer is the fee payer).
    let depositor_after = env
        .rpc
        .svm
        .get_balance(&depositor.pubkey())
        .expect("depositor balance after");
    let vault_after = env
        .rpc
        .svm
        .get_balance(&vault)
        .expect("sol interface funded");
    assert_eq!(
        depositor_after,
        depositor_before - AMOUNT,
        "depositor debited exactly the public amount"
    );
    assert_eq!(
        vault_after,
        vault_before + AMOUNT,
        "sol_interface credited exactly the public amount"
    );
}

#[test]
fn transact_spl_deposit_settles_exact_token_deltas() {
    const SPL_AMOUNT: u64 = 1_000;
    let mut env = proof_env();
    let tree = env.tree.pubkey();
    let payer = env.rpc.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];
    let mint = env.rpc.create_mint().expect("create mint");
    env.rpc
        .ensure_asset_counter(&env.authority)
        .expect("create asset counter");
    env.rpc
        .create_spl_interface(&env.authority, &mint)
        .expect("create SPL interface");
    let user_token = env
        .rpc
        .create_token_account(&mint, &payer.pubkey())
        .expect("create user token account");
    env.rpc
        .mint_to(&mint, &user_token, SPL_AMOUNT)
        .expect("mint tokens");
    let vault = pda::spl_interface(&mint);

    let (utxo_root, nullifier_root) = tree_roots(&env.rpc, &tree, 0);
    let roots = (utxo_root, nullifier_root);
    let nullifier_key = NullifierKey::from_secret([25u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let owner = PublicKey::from_ed25519(&payer_bytes);

    // Two circuit-dummy inputs (construction as above at :395).
    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    let (deposit_dummy_0, nullifier_0) =
        dummy_input(&[41u8; 31], &nf_tree, roots).expect("dummy input 0");
    let (deposit_dummy_1, nullifier_1) =
        dummy_input(&[42u8; 31], &nf_tree, roots).expect("dummy input 1");
    let nullifiers = [nullifier_0, nullifier_1];

    let asset = solana_address::Address::new_from_array(mint.to_bytes());
    let shielded_output = real_output(owner, nullifier_pk, asset, SPL_AMOUNT, [27u8; 31]);
    let shielded_hash = shielded_output.hash().expect("shielded output hash");
    let (dummy_a, dummy_hash_a) = dummy_transfer_output(&[1u8; 31]).expect("dummy output");
    let (dummy_b, dummy_hash_b) = dummy_transfer_output(&[2u8; 31]).expect("dummy output");
    let output_hashes = [shielded_hash, dummy_hash_a, dummy_hash_b];
    let owner_view_tag = owner.confidential_view_tag().expect("owner view tag");
    // Dummy slots share the real output's owner tag (the AssertDummyTags rule;
    // see `set_output_owner_tags`).
    let view_tags = [owner_view_tag; 3];
    let mut data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(nullifiers[0], 0),
            eddsa_input_utxo(nullifiers[1], 0),
        ],
        vec![InterfaceTransfer::SplDeposit {
            amount: SPL_AMOUNT,
            spl_interface_bump: pda::spl_interface_with_bump(&mint).1,
        }],
        inline_outputs(&output_hashes, &view_tags),
    );
    let proofless = ProoflessOutput {
        owner: owner_hash(&owner, &nullifier_pk).expect("owner field"),
        blinding: [27u8; 32],
        asset: mint.to_bytes(),
        amount: SPL_AMOUNT,
        data_hash: None,
        utxo_data: None,
        zone_program_id: None,
        zone_data_hash: None,
        zone_data: None,
        memo: None,
    };
    let mut plaintext = vec![OutputDataEncoding::PLAINTEXT_TAG];
    proofless
        .serialize(&mut plaintext)
        .expect("serialize output");
    data.outputs[0].data =
        Some(borsh::to_vec(&OutputDataEncoding::Plaintext(plaintext)).expect("encode output data"));
    let output_owner_hashes = output_owner_pk_hashes(&data.outputs).expect("output owner hashes");
    let mut outputs = vec![
        transfer_output(&shielded_output).expect("real output"),
        dummy_a,
        dummy_b,
    ];
    set_output_owner_tags(
        &mut outputs,
        &output_owner_hashes,
        &[nullifier_pk, zero, zero],
    );
    let external_hash = external_data_hash_spl(&data, &user_token.to_bytes(), &vault.to_bytes())
        .expect("external data hash");
    let private_tx =
        PrivateTxHash::new(&[zero, zero], &[shielded_hash, zero, zero], &external_hash)
            .hash()
            .expect("private transaction hash");
    let public_spl_field = public_sol_field(Some(SPL_AMOUNT as i64));
    let payer_hash = hash_bytes(&payer_bytes).expect("payer hash");
    let mint_bytes = mint.to_bytes();
    let (public_slot_assets, public_slot_amounts) =
        spl_public_slots(public_spl_field, &mint_bytes).expect("public SPL slots");
    let public_hash = PublicInputs {
        nullifiers: &nullifiers,
        output_hashes: &output_hashes,
        utxo_roots: &[utxo_root, utxo_root],
        nullifier_tree_roots: &[nullifier_root, nullifier_root],
        private_tx: &private_tx,
        external_data_hash: &external_hash,
        public_transfers: &PublicTransfers {
            assets: public_slot_assets,
            amounts: public_slot_amounts,
        },
        zone_program_id: &zero,
        allow_dummy_inputs: &fe(1),
        signer_pk_hashes: &[payer_hash, zero, zero],
        output_owner_pk_hashes: Some(&output_owner_hashes),
    }
    .hash()
    .expect("public input hash");
    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![deposit_dummy_0, deposit_dummy_1],
        outputs,
        external_data_hash: external_hash,
        private_tx_hash: private_tx,
        public_slot_assets,
        public_slot_amounts,
        signer_pk_hashes: vec![payer_hash],
        public_input_hash: public_hash,
    });
    data.proof = prove_and_verify_transfer(&prover_inputs, public_hash, "SPL deposit")
        .expect("prove SPL deposit");
    data.private_tx_hash = private_tx;
    let ix = Transact {
        payer: payer.pubkey(),
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::SplDeposit(
            TransactSplDepositAccounts {
                mint,
                spl_interface: vault,
                token_authority: payer.pubkey(),
                user_token_account: user_token,
                token_program: zolana_program_test::ZolanaProgramTest::token_program_id(),
            },
        )],
        data,
    }
    .instruction();
    env.rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect("real-proof SPL deposit");
    assert_eq!(env.rpc.token_balance(&user_token), Some(0));
    assert_eq!(env.rpc.token_balance(&vault), Some(SPL_AMOUNT));
}

/// End-to-end story told in named phases: the payer shields SOL
/// (`phase_shield_sol`), sends a pure shielded transfer to a recipient
/// (`phase_transfer_to_recipient`), the recipient withdraws the transferred
/// UTXO to a public SOL account (`phase_withdraw_recipient_utxo`), and the
/// exact settlement deltas are checked (`phase_verify_settlement`). Each
/// assertion lives in the phase that produces the state it checks.
#[test]
fn shield_transfer_then_withdraw_sol() {
    let mut env = proof_env();

    let tree = env.tree.pubkey();
    let payer = env.rpc.payer.insecure_clone();
    let recipient_owner = Keypair::new();
    env.rpc
        .airdrop(&recipient_owner.pubkey(), 1_000_000)
        .expect("airdrop recipient owner");

    let shield = phase_shield_sol(&mut env, tree, &payer);
    let transfer = phase_transfer_to_recipient(&mut env, tree, &payer, &recipient_owner, shield);
    let settlement = phase_withdraw_recipient_utxo(&mut env, tree, &recipient_owner, transfer);
    phase_verify_settlement(&env, settlement);
}

/// State handed from the shield phase to the transfer phase: the payer's
/// freshly-shielded UTXO, its spend witness, and the reference trees gated
/// against the on-chain roots.
struct ShieldedPayer {
    utxo: Utxo,
    nullifier_pk: [u8; 32],
    utxo_hash: [u8; 32],
    owner_pk_hash: [u8; 32],
    nullifier: [u8; 32],
    spend_input: TransferInput,
    state_tree: MerkleTree<Poseidon>,
    nf_tree: IndexedMerkleTree<Poseidon, usize>,
    utxo_root: [u8; 32],
    nullifier_root: [u8; 32],
}

/// State handed from the transfer phase to the withdrawal phase: the
/// recipient's transferred output plus the post-transfer tree state.
struct TransferredRecipient {
    output: SppProofOutputUtxo,
    public_key: PublicKey,
    nullifier_key: NullifierKey,
    nullifier_pk: [u8; 32],
    owner_field: [u8; 32],
    output_hash: [u8; 32],
    state_tree: MerkleTree<Poseidon>,
    nf_tree: IndexedMerkleTree<Poseidon, usize>,
    utxo_root: [u8; 32],
    nullifier_root: [u8; 32],
}

/// Balances captured before the withdrawal lands, asserted on in the verify
/// phase.
struct WithdrawalSettlement {
    public_recipient: Pubkey,
    public_recipient_before: u64,
    vault: Pubkey,
    vault_before: u64,
}

/// Phase 1 — shield: deposit AMOUNT into a Solana-owned UTXO controlled by the
/// payer, gate the in-test reference trees against the on-chain roots, and
/// assemble the payer's real spend input for the transfer phase.
fn phase_shield_sol(env: &mut Pool, tree: Pubkey, payer: &Keypair) -> ShieldedPayer {
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];

    let payer_blinding = test_blinding(7);
    let payer_nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let payer_nullifier_pk = payer_nullifier_key.pubkey().expect("payer nullifier pk");
    let payer_utxo = Utxo {
        owner: PublicKey::from_ed25519(&payer_bytes),
        asset: SOL_MINT,
        amount: AMOUNT,
        blinding: payer_blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let payer_owner_pk_hash = payer_utxo
        .owner
        .owner_proof_input_hash()
        .expect("payer owner pk hash");
    let payer_owner_field =
        owner_hash(&payer_utxo.owner, &payer_nullifier_pk).expect("payer owner field");

    let event = env
        .rpc
        .deposit_sol(&tree, payer, AMOUNT, payer_owner_field, payer_blinding)
        .expect("deposit");
    let payer_utxo_hash = payer_utxo
        .hash(&payer_nullifier_pk, &zero, &zero)
        .expect("payer utxo hash");
    assert_eq!(payer_utxo_hash, event.utxo_hash);

    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree
        .append(&payer_utxo_hash)
        .expect("append shield leaf");
    let (shield_utxo_root, nullifier_root) = tree_roots(&env.rpc, &tree, 1);
    assert_eq!(state_tree.root(), shield_utxo_root, "shield root gate");

    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");

    let payer_nullifier = payer_nullifier_key
        .nullifier(&payer_utxo_hash, &payer_blinding)
        .expect("payer nullifier");
    let payer_non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&payer_nullifier))
        .expect("payer non inclusion proof");
    let payer_state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(0, true)
        .expect("payer state proof")
        .to_vec();
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
    })
    .expect("payer real input");

    ShieldedPayer {
        utxo: payer_utxo,
        nullifier_pk: payer_nullifier_pk,
        utxo_hash: payer_utxo_hash,
        owner_pk_hash: payer_owner_pk_hash,
        nullifier: payer_nullifier,
        spend_input: payer_spend_input,
        state_tree,
        nf_tree,
        utxo_root: shield_utxo_root,
        nullifier_root,
    }
}

/// Phase 2 — transfer: a pure shielded transfer spends the payer's shielded
/// UTXO; the payer keeps the change and the recipient gets one UTXO carrying
/// TRANSFER_AMOUNT.
fn phase_transfer_to_recipient(
    env: &mut Pool,
    tree: Pubkey,
    payer: &Keypair,
    recipient_owner: &Keypair,
    shield: ShieldedPayer,
) -> TransferredRecipient {
    let ShieldedPayer {
        utxo: payer_utxo,
        nullifier_pk: payer_nullifier_pk,
        utxo_hash: payer_utxo_hash,
        owner_pk_hash: _,
        nullifier: payer_nullifier,
        spend_input: payer_spend_input,
        mut state_tree,
        nf_tree,
        utxo_root: shield_utxo_root,
        nullifier_root,
    } = shield;
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];

    let recipient_bytes = recipient_owner.pubkey().to_bytes();
    let recipient_nullifier_key = NullifierKey::from_secret([11u8; 31]);
    let recipient_nullifier_pk = recipient_nullifier_key
        .pubkey()
        .expect("recipient nullifier pk");
    let recipient_public_key = PublicKey::from_ed25519(&recipient_bytes);
    let recipient_owner_field =
        owner_hash(&recipient_public_key, &recipient_nullifier_pk).expect("recipient owner field");

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
    let change_hash = change_output.hash().expect("change output hash");
    let recipient_hash = recipient_output.hash().expect("recipient output hash");
    let transfer_roots = (shield_utxo_root, nullifier_root);
    let (transfer_dummy_input, transfer_dummy_nullifier) =
        dummy_input(&[20u8; 31], &nf_tree, transfer_roots).expect("transfer dummy input");
    // The transfer's third output is a dummy (`owner_hash = 0`): a real `utxo_hash`
    // the program appends and the proof commits, contributing `0` to private_tx_hash.
    let (transfer_dummy_output, transfer_dummy_hash) =
        dummy_transfer_output(&[19u8; 31]).expect("transfer dummy output");

    // Real outputs tag by owner; the dummy slot reuses the sender's tag (both
    // rules on `set_output_owner_tags`).
    let change_view_tag = payer_utxo
        .owner
        .confidential_view_tag()
        .expect("change view tag");
    let recipient_view_tag = recipient_public_key
        .confidential_view_tag()
        .expect("recipient view tag");
    let transfer_view_tags = [change_view_tag, recipient_view_tag, payer_bytes];
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
    let transfer_owner_pk_hashes =
        output_owner_pk_hashes(&transfer_ix_data.outputs).expect("transfer output owner pk hashes");
    let mut transfer_outputs = vec![
        transfer_output(&change_output).expect("change transfer output"),
        transfer_output(&recipient_output).expect("recipient transfer output"),
        transfer_dummy_output,
    ];
    // The real change/recipient outputs bind to their owner via `nullifier_pk`; the
    // dummy's owner is unconstrained (nullifier_pk 0).
    set_output_owner_tags(
        &mut transfer_outputs,
        &transfer_owner_pk_hashes,
        &[payer_nullifier_pk, recipient_nullifier_pk, zero],
    );
    let transfer_external_hash =
        external_data_hash(&transfer_ix_data, &[]).expect("transfer external data hash");
    let transfer_private_tx = PrivateTxHash::new(
        &[payer_utxo_hash, zero],
        &[change_hash, recipient_hash, zero],
        &transfer_external_hash,
    )
    .hash()
    .expect("transfer private tx hash");
    let payer_pubkey_hash = hash_bytes(&payer_bytes).expect("payer hash");
    let (transfer_public_slot_assets, transfer_public_slot_amounts) = sol_public_slots(zero);
    let transfer_public_input_hash = PublicInputs {
        nullifiers: &[payer_nullifier, transfer_dummy_nullifier],
        output_hashes: &[change_hash, recipient_hash, transfer_dummy_hash],
        utxo_roots: &[shield_utxo_root, shield_utxo_root],
        nullifier_tree_roots: &[nullifier_root, nullifier_root],
        private_tx: &transfer_private_tx,
        external_data_hash: &transfer_external_hash,
        public_transfers: &PublicTransfers {
            assets: transfer_public_slot_assets,
            amounts: transfer_public_slot_amounts,
        },
        zone_program_id: &zero,
        allow_dummy_inputs: &fe(1),
        signer_pk_hashes: &[payer_pubkey_hash, zero, zero],
        output_owner_pk_hashes: Some(&transfer_owner_pk_hashes),
    }
    .hash()
    .expect("public input hash");
    let transfer_prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![payer_spend_input, transfer_dummy_input],
        outputs: transfer_outputs,
        external_data_hash: transfer_external_hash,
        private_tx_hash: transfer_private_tx,
        public_slot_assets: transfer_public_slot_assets,
        public_slot_amounts: transfer_public_slot_amounts,
        signer_pk_hashes: vec![payer_pubkey_hash],
        public_input_hash: transfer_public_input_hash,
    });
    transfer_ix_data.proof = prove_and_verify_transfer(
        &transfer_prover_inputs,
        transfer_public_input_hash,
        "transfer",
    )
    .expect("prove transfer");
    transfer_ix_data.private_tx_hash = transfer_private_tx;

    let transfer_ix = Transact {
        payer: payer.pubkey(),
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transfer_ix_data,
    }
    .instruction();
    let result = env
        .rpc
        .create_and_send_default_payer_transaction(&[transfer_ix], &[]);
    assert!(result.is_ok(), "shielded transfer failed: {result:?}");

    state_tree.append(&change_hash).expect("append change leaf");
    state_tree
        .append(&recipient_hash)
        .expect("append recipient leaf");
    state_tree
        .append(&transfer_dummy_hash)
        .expect("append dummy leaf");
    // init=0, post-deposit=1, post-transfer=2.
    let (transfer_utxo_root, transfer_nullifier_root) = tree_roots(&env.rpc, &tree, 2);
    assert_eq!(state_tree.root(), transfer_utxo_root, "transfer root gate");
    assert_eq!(transfer_nullifier_root, nullifier_root);

    TransferredRecipient {
        output: recipient_output,
        public_key: recipient_public_key,
        nullifier_key: recipient_nullifier_key,
        nullifier_pk: recipient_nullifier_pk,
        owner_field: recipient_owner_field,
        output_hash: recipient_hash,
        state_tree,
        nf_tree,
        utxo_root: transfer_utxo_root,
        nullifier_root: transfer_nullifier_root,
    }
}

/// Phase 3 — withdraw: spend the transferred recipient UTXO, draining
/// TRANSFER_AMOUNT from the `sol_interface` vault to a public SOL account.
fn phase_withdraw_recipient_utxo(
    env: &mut Pool,
    tree: Pubkey,
    recipient_owner: &Keypair,
    transfer: TransferredRecipient,
) -> WithdrawalSettlement {
    let TransferredRecipient {
        output: recipient_output,
        public_key: recipient_public_key,
        nullifier_key: recipient_nullifier_key,
        nullifier_pk: recipient_nullifier_pk,
        owner_field: recipient_owner_field,
        output_hash: recipient_hash,
        state_tree,
        nf_tree,
        utxo_root: transfer_utxo_root,
        nullifier_root: transfer_nullifier_root,
    } = transfer;
    let recipient_bytes = recipient_owner.pubkey().to_bytes();
    let zero = [0u8; 32];

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
        recipient_utxo
            .hash(&recipient_nullifier_pk, &zero, &zero)
            .expect("recipient utxo hash")
    );
    let recipient_owner_pk_hash = recipient_utxo
        .owner
        .owner_proof_input_hash()
        .expect("recipient owner pk hash");
    let recipient_nullifier = recipient_nullifier_key
        .nullifier(&recipient_hash, &recipient_utxo.blinding)
        .expect("recipient nullifier");
    let recipient_non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&recipient_nullifier))
        .expect("recipient non inclusion proof");
    let recipient_state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(2, true)
        .expect("recipient state proof")
        .to_vec();
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
    })
    .expect("recipient real input");

    let public_recipient = Keypair::new().pubkey();
    env.rpc
        .airdrop(&public_recipient, 1_000_000)
        .expect("airdrop public recipient");
    let public_recipient_before = env
        .rpc
        .svm
        .get_balance(&public_recipient)
        .expect("public recipient balance");
    let vault = pda::sol_interface();
    let vault_before = env.rpc.svm.get_balance(&vault).unwrap_or(0);
    let (withdraw_dummy_input, withdraw_dummy_nullifier) = dummy_input(
        &[21u8; 31],
        &nf_tree,
        (transfer_utxo_root, transfer_nullifier_root),
    )
    .expect("withdraw dummy input");
    // The withdrawal spends the full transferred amount; all three outputs are
    // dummies with real, distinct hashes.
    let withdraw_dummy_outputs: Vec<(TransferOutput, [u8; 32])> = [[1u8; 31], [2u8; 31], [3u8; 31]]
        .iter()
        .map(|blinding| dummy_transfer_output(blinding).expect("withdraw dummy output"))
        .collect();
    let withdraw_output_hashes: Vec<[u8; 32]> = withdraw_dummy_outputs
        .iter()
        .map(|(_, hash)| *hash)
        .collect();
    let mut withdraw_outputs: Vec<TransferOutput> = withdraw_dummy_outputs
        .into_iter()
        .map(|(out, _)| out)
        .collect();

    let withdraw_view_tags = [recipient_bytes; 3];
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
    let withdraw_owner_pk_hashes =
        output_owner_pk_hashes(&withdraw_ix_data.outputs).expect("withdraw output owner pk hashes");
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
        external_data_hash(&withdraw_ix_data, &withdraw_resolved_transfers)
            .expect("withdraw external data hash");
    let withdraw_private_tx = PrivateTxHash::new(
        &[recipient_hash, zero],
        &[zero, zero, zero],
        &withdraw_external_hash,
    )
    .hash()
    .expect("withdraw private tx hash");
    let public_sol_field = public_sol_field(Some(-(TRANSFER_AMOUNT as i64)));
    let (public_slot_assets, public_slot_amounts) = sol_public_slots(public_sol_field);
    let recipient_pubkey_hash = hash_bytes(&recipient_bytes).expect("recipient payer hash");
    let withdraw_public_input_hash = PublicInputs {
        nullifiers: &[recipient_nullifier, withdraw_dummy_nullifier],
        output_hashes: &withdraw_output_hashes,
        utxo_roots: &[transfer_utxo_root, transfer_utxo_root],
        nullifier_tree_roots: &[transfer_nullifier_root, transfer_nullifier_root],
        private_tx: &withdraw_private_tx,
        external_data_hash: &withdraw_external_hash,
        public_transfers: &PublicTransfers {
            assets: public_slot_assets,
            amounts: public_slot_amounts,
        },
        zone_program_id: &zero,
        allow_dummy_inputs: &fe(1),
        signer_pk_hashes: &[recipient_pubkey_hash, zero, zero],
        output_owner_pk_hashes: Some(&withdraw_owner_pk_hashes),
    }
    .hash()
    .expect("public input hash");
    let withdraw_prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![recipient_spend_input, withdraw_dummy_input],
        outputs: withdraw_outputs,
        external_data_hash: withdraw_external_hash,
        private_tx_hash: withdraw_private_tx,
        public_slot_assets,
        public_slot_amounts,
        signer_pk_hashes: vec![recipient_pubkey_hash],
        public_input_hash: withdraw_public_input_hash,
    });
    withdraw_ix_data.proof = prove_and_verify_transfer(
        &withdraw_prover_inputs,
        withdraw_public_input_hash,
        "withdraw",
    )
    .expect("prove withdraw");
    withdraw_ix_data.private_tx_hash = withdraw_private_tx;

    let withdraw_ix = Transact {
        payer: recipient_owner.pubkey(),
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts {
                recipient: public_recipient,
            },
        )],
        data: withdraw_ix_data,
    }
    .instruction();
    let result = env
        .rpc
        .create_and_send_default_payer_transaction(&[withdraw_ix], &[recipient_owner]);
    assert!(result.is_ok(), "withdraw after transfer failed: {result:?}");

    WithdrawalSettlement {
        public_recipient,
        public_recipient_before,
        vault,
        vault_before,
    }
}

/// Phase 4 — verify: the public recipient is credited and the `sol_interface`
/// vault debited by exactly the transferred amount.
fn phase_verify_settlement(env: &Pool, settlement: WithdrawalSettlement) {
    let WithdrawalSettlement {
        public_recipient,
        public_recipient_before,
        vault,
        vault_before,
    } = settlement;

    let public_recipient_after = env.rpc.svm.get_balance(&public_recipient).unwrap_or(0);
    let vault_after = env.rpc.svm.get_balance(&vault).unwrap_or(0);
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
}
