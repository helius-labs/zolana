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
//! `.so` binary; the test skips (does not fail) when it is missing.

#[path = "../common/setup.rs"]
mod common;
#[path = "../common/transact.rs"]
mod transact_common;

use light_hasher::{sha256::Sha256BE, Hasher, Poseidon};
use zolana_merkle_tree::MerkleTree;
use num_bigint::BigUint;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{TransferOutput, STATE_TREE_HEIGHT};
use zolana_interface::instruction::{Transact, TransactSolWithdrawal, TransactWithdrawal};
use zolana_interface::pda;
use zolana_keypair::hash::owner_hash;
use zolana_keypair::pubkey::PublicKey;
use zolana_keypair::NullifierKey;
use zolana_program_test::ZolanaProgramTest;
use zolana_transaction::transaction::private_tx_hash;
use zolana_transaction::{Data, OutputUtxo, Utxo, SOL_MINT};
use zolana_tree::TreeAccount;

use crate::transact_common::{
    build_transfer_prover_inputs, dummy_input, dummy_ix_output, eddsa_input_utxo,
    external_data_hash, fe, ix_output, new_transact_ix_data, nullifier_tree,
    prove_and_verify_transfer, public_input_hash, public_sol_field, spend_input, start_prover,
    transfer_output, SpendInputArgs, TransferProverInputsArgs,
};

const AMOUNT: u64 = 1_000_000_000;

/// Read on-chain tree roots: the UTXO root at `utxo_index` and the nullifier
/// root at history index 0, exactly as the program reads them in `apply_tree`.
fn on_chain_roots(rpc: &ZolanaProgramTest, tree: &Pubkey, utxo_index: u16) -> ([u8; 32], [u8; 32]) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    (
        account.get_utxo_tree_root(utxo_index).expect("utxo root"),
        account.get_nullifier_tree_root(0).expect("nullifier root"),
    )
}

struct TransactEnv {
    rpc: ZolanaProgramTest,
    tree: Keypair,
}

impl TransactEnv {
    fn boot() -> Option<Self> {
        let mut rpc = common::program_test()?;
        start_prover().expect("start prover");
        let authority = Keypair::new();
        rpc.create_protocol_config(&authority)
            .expect("create protocol config");
        let tree = rpc
            .create_tree(common::tree_account_size(), &authority)
            .expect("create tree");
        Some(Self { rpc, tree })
    }
}

#[test]
fn shield_then_withdraw_sol() {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };

    let tree = env.tree.pubkey();
    let payer = env.rpc.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];

    // The shielded UTXO is owned by the payer's Ed25519 key (eddsa rail). Fixed
    // blinding / nullifier secret keep the run deterministic.
    let blinding: [u8; 31] = [7u8; 31];
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
    let owner_pk_hash = utxo.owner.hash().expect("owner pk hash");
    let owner_field = owner_hash(&utxo.owner, &nullifier_pk).expect("owner field");

    // Shield: deposit AMOUNT into the UTXO. The vault (cpi_authority) is funded.
    let owner_utxo_h = utxo
        .owner_utxo_hash(&nullifier_pk)
        .expect("owner utxo hash");
    let event = env
        .rpc
        .deposit_sol(&tree, &payer, AMOUNT, owner_utxo_h)
        .expect("proofless deposit");

    let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
    assert_eq!(
        utxo_hash, event.utxo_hash,
        "client utxo hash must match on-chain"
    );

    // The UTXO is leaf 0; its inclusion proof is against the root AFTER the
    // shield append (history index 1).
    let (utxo_root, nullifier_root) = on_chain_roots(&env.rpc, &tree, 1);

    // State inclusion proof (height 26) for leaf 0.
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
    let dummy_nullifier = fe(2);

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

    let mut transact_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(nullifier, 1),
            eddsa_input_utxo(dummy_nullifier, 1),
        ],
        Some(-(AMOUNT as i64)),
        dummy_ix_output(),
        vec![dummy_ix_output(); 2],
    );
    let external_data_hash =
        external_data_hash(&transact_ix_data, &recipient.to_bytes()).expect("external data hash");

    // private_tx_hash uses the real input's utxo hash; the dummy input and all
    // outputs contribute zero.
    let private_tx = private_tx_hash(&[utxo_hash, zero], &[zero, zero, zero], &external_data_hash)
        .expect("private tx hash");
    let public_sol_field = public_sol_field(transact_ix_data.public_sol_amount);
    let payer_pubkey_hash = Sha256BE::hash(&payer_bytes).expect("payer hash");

    let public_input_hash = public_input_hash(
        &[nullifier, dummy_nullifier],
        &[zero, zero, zero],
        &[utxo_root, utxo_root],
        &[nullifier_root, nullifier_root],
        &private_tx,
        &external_data_hash,
        &public_sol_field,
        &payer_pubkey_hash,
        &[owner_pk_hash, owner_pk_hash],
    );

    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![
            payer_spend_input,
            dummy_input(&dummy_nullifier, roots, &owner_pk_hash),
        ],
        outputs: vec![TransferOutput::new_dummy(); 3],
        external_data_hash,
        private_tx_hash: private_tx,
        public_sol_amount: public_sol_field,
        payer_pubkey_hash,
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
        tree,
        cpi_signer: None,
        withdrawal: Some(TransactWithdrawal::Sol(TransactSolWithdrawal { recipient })),
        data: transact_ix_data,
    }
    .instruction();

    let result = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[]);
    assert!(result.is_ok(), "transact withdrawal failed: {result:?}");

    let recipient_after = env.rpc.svm.get_balance(&recipient).unwrap_or(0);
    let vault_after = env.rpc.svm.get_balance(&vault).unwrap_or(0);
    assert_eq!(
        recipient_after,
        recipient_before + AMOUNT,
        "recipient credited"
    );
    assert_eq!(vault_after, vault_before - AMOUNT, "vault debited");
}

#[test]
fn shield_transfer_then_withdraw_sol() {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };

    const TRANSFER_AMOUNT: u64 = 400_000_000;
    const CHANGE_AMOUNT: u64 = AMOUNT - TRANSFER_AMOUNT;

    let tree = env.tree.pubkey();
    let payer = env.rpc.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let recipient_owner = Keypair::new();
    env.rpc
        .airdrop(&recipient_owner.pubkey(), 1_000_000)
        .expect("airdrop recipient owner");
    let zero = [0u8; 32];

    // 1. Shield into a Solana-owned UTXO controlled by the payer.
    let payer_blinding: [u8; 31] = [7u8; 31];
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
    let payer_owner_pk_hash = payer_utxo.owner.hash().expect("payer owner pk hash");
    let payer_owner_field =
        owner_hash(&payer_utxo.owner, &payer_nullifier_pk).expect("payer owner field");

    let owner_utxo_h = payer_utxo
        .owner_utxo_hash(&payer_nullifier_pk)
        .expect("payer owner utxo hash");
    let event = env
        .rpc
        .deposit_sol(&tree, &payer, AMOUNT, owner_utxo_h)
        .expect("deposit");
    let payer_utxo_hash = payer_utxo
        .hash(&payer_nullifier_pk, &zero, &zero)
        .expect("payer utxo hash");
    assert_eq!(payer_utxo_hash, event.utxo_hash);

    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree
        .append(&payer_utxo_hash)
        .expect("append shield leaf");
    let (shield_utxo_root, nullifier_root) = on_chain_roots(&env.rpc, &tree, 1);
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

    // 2. Pure shielded transfer: payer keeps change, recipient gets one UTXO.
    let recipient_bytes = recipient_owner.pubkey().to_bytes();
    let recipient_nullifier_key = NullifierKey::from_secret([11u8; 31]);
    let recipient_nullifier_pk = recipient_nullifier_key
        .pubkey()
        .expect("recipient nullifier pk");
    let recipient_public_key = PublicKey::from_ed25519(&recipient_bytes);
    let recipient_owner_field =
        owner_hash(&recipient_public_key, &recipient_nullifier_pk).expect("recipient owner field");

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
    let change_hash = change_output.hash().expect("change output hash");
    let recipient_hash = recipient_output.hash().expect("recipient output hash");
    let transfer_dummy_nullifier = fe(20);
    let transfer_roots = (shield_utxo_root, nullifier_root);

    let mut transfer_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(payer_nullifier, 1),
            eddsa_input_utxo(transfer_dummy_nullifier, 1),
        ],
        None,
        ix_output([1u8; 32], change_hash),
        vec![ix_output([2u8; 32], recipient_hash), dummy_ix_output()],
    );
    let transfer_external_hash =
        external_data_hash(&transfer_ix_data, &zero).expect("transfer external data hash");
    let transfer_private_tx = private_tx_hash(
        &[payer_utxo_hash, zero],
        &[change_hash, recipient_hash, zero],
        &transfer_external_hash,
    )
    .expect("transfer private tx hash");
    let payer_pubkey_hash = Sha256BE::hash(&payer_bytes).expect("payer hash");
    let transfer_public_input_hash = public_input_hash(
        &[payer_nullifier, transfer_dummy_nullifier],
        &[change_hash, recipient_hash, zero],
        &[shield_utxo_root, shield_utxo_root],
        &[nullifier_root, nullifier_root],
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
            transfer_output(&change_output).expect("change transfer output"),
            transfer_output(&recipient_output).expect("recipient transfer output"),
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
    )
    .expect("prove transfer");
    transfer_ix_data.private_tx_hash = transfer_private_tx;

    let transfer_ix = Transact {
        payer: payer.pubkey(),
        tree,
        cpi_signer: None,
        withdrawal: None,
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
    state_tree.append(&zero).expect("append dummy leaf");
    let (transfer_utxo_root, transfer_nullifier_root) = on_chain_roots(&env.rpc, &tree, 4);
    assert_eq!(state_tree.root(), transfer_utxo_root, "transfer root gate");
    assert_eq!(transfer_nullifier_root, nullifier_root);

    // 3. Withdraw the transferred recipient UTXO to a public SOL account.
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
        .hash()
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
    let withdraw_dummy_nullifier = fe(21);

    let mut withdraw_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(recipient_nullifier, 4),
            eddsa_input_utxo(withdraw_dummy_nullifier, 4),
        ],
        Some(-(TRANSFER_AMOUNT as i64)),
        dummy_ix_output(),
        vec![dummy_ix_output(); 2],
    );
    let withdraw_external_hash =
        external_data_hash(&withdraw_ix_data, &public_recipient.to_bytes())
            .expect("withdraw external data hash");
    let withdraw_private_tx = private_tx_hash(
        &[recipient_hash, zero],
        &[zero, zero, zero],
        &withdraw_external_hash,
    )
    .expect("withdraw private tx hash");
    let public_sol_field = public_sol_field(withdraw_ix_data.public_sol_amount);
    let recipient_pubkey_hash = Sha256BE::hash(&recipient_bytes).expect("recipient payer hash");
    let withdraw_public_input_hash = public_input_hash(
        &[recipient_nullifier, withdraw_dummy_nullifier],
        &[zero, zero, zero],
        &[transfer_utxo_root, transfer_utxo_root],
        &[transfer_nullifier_root, transfer_nullifier_root],
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
                (transfer_utxo_root, transfer_nullifier_root),
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
    )
    .expect("prove withdraw");
    withdraw_ix_data.private_tx_hash = withdraw_private_tx;

    let withdraw_ix = Transact {
        payer: recipient_owner.pubkey(),
        tree,
        cpi_signer: None,
        withdrawal: Some(TransactWithdrawal::Sol(TransactSolWithdrawal {
            recipient: public_recipient,
        })),
        data: withdraw_ix_data,
    }
    .instruction();
    let result = env
        .rpc
        .create_and_send_default_payer_transaction(&[withdraw_ix], &[&recipient_owner]);
    assert!(result.is_ok(), "withdraw after transfer failed: {result:?}");

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
