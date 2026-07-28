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
use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};
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
    let mut cycle = phase_setup()?;
    let shielded = phase_shield(&mut cycle)?;
    let transferred = phase_transfer(&mut cycle, &shielded)?;
    let unshielded = phase_unshield(&mut cycle, &transferred)?;
    phase_verify_output(&cycle, &unshielded)?;

    println!(
        "localnet shield-transfer-unshield SOL test passed via {}",
        cycle.rpc_url
    );
    Ok(())
}

/// RPC/indexer handles and local tree mirrors threaded through the phases.
struct SolCycle {
    rpc_url: String,
    program_id: Pubkey,
    rpc: SolanaRpc,
    indexer: TestIndexer,
    payer: Keypair,
    recipient_owner: Keypair,
    tree_pubkey: Pubkey,
    state_tree: MerkleTree<Poseidon>,
    nf_tree: IndexedMerkleTree<Poseidon, usize>,
}

/// The payer's shielded UTXO and everything later phases need to spend it.
struct ShieldedPayer {
    utxo: Utxo,
    utxo_hash: [u8; 32],
    nullifier_key: NullifierKey,
    nullifier_pk: [u8; 32],
    owner_pk_hash: [u8; 32],
    owner_field: [u8; 32],
    utxo_root: [u8; 32],
    nullifier_root: [u8; 32],
}

/// The recipient's transferred UTXO pieces and the tree roots it settles
/// against (its hash, view tag, owner field, and nullifier pubkey recompute
/// off these).
struct TransferredUtxo {
    public_key: PublicKey,
    nullifier_key: NullifierKey,
    blinding: [u8; 32],
    utxo_root: [u8; 32],
    nullifier_root: [u8; 32],
}

/// Lamport balances captured before the unshield, checked after it lands.
struct UnshieldOutcome {
    public_recipient: Pubkey,
    public_recipient_before: u64,
    vault_before: u64,
}

/// Boot the prover, connect to the local validator, create the pool, and fund
/// the recipient owner.
fn phase_setup() -> TestResult<SolCycle> {
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
    let state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    let nf_tree = nullifier_tree()?;
    Ok(SolCycle {
        rpc_url,
        program_id,
        rpc,
        indexer,
        payer,
        recipient_owner,
        tree_pubkey,
        state_tree,
        nf_tree,
    })
}

/// Shield `AMOUNT` public SOL into the payer's private UTXO and gate on the
/// resulting state/nullifier roots.
fn phase_shield(cycle: &mut SolCycle) -> TestResult<ShieldedPayer> {
    let zero = [0u8; 32];

    let payer_bytes = cycle.payer.pubkey().to_bytes();
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
        tree: cycle.tree_pubkey,
        depositor: cycle.payer.pubkey(),
        deposits: vec![shield_data],
    }
    .instruction()?;
    let shield_tx = send_indexed(
        &mut cycle.rpc,
        &mut cycle.indexer,
        cycle.program_id,
        &[shield_ix],
        &cycle.payer.pubkey(),
        &[&cycle.payer],
    )?;
    print_signature("deposit", &shield_tx.signature);

    let shield_view = single_deposit_view(&shield_tx.events)?;
    let payer_utxo_hash = payer_utxo.hash(&payer_nullifier_pk, &zero, &zero)?;
    assert_eq!(payer_utxo_hash, shield_view.utxo_hash);

    cycle.state_tree.append(&payer_utxo_hash)?;
    let (shield_utxo_root, nullifier_root) = on_chain_roots(&cycle.rpc, &cycle.tree_pubkey, 1)?;
    assert_eq!(
        cycle.state_tree.root(),
        shield_utxo_root,
        "shield root gate"
    );
    assert_eq!(
        rpc_state_root(&cycle.rpc, &cycle.tree_pubkey)?,
        cycle.indexer.root()
    );

    assert_eq!(cycle.nf_tree.root(), nullifier_root, "nullifier root gate");

    Ok(ShieldedPayer {
        utxo: payer_utxo,
        utxo_hash: payer_utxo_hash,
        nullifier_key: payer_nullifier_key,
        nullifier_pk: payer_nullifier_pk,
        owner_pk_hash: payer_owner_pk_hash,
        owner_field: payer_owner_field,
        utxo_root: shield_utxo_root,
        nullifier_root,
    })
}

/// Spend the shielded UTXO into a change output back to the payer and a
/// `TRANSFER_AMOUNT` output to the recipient, then gate on the new roots.
fn phase_transfer(cycle: &mut SolCycle, shielded: &ShieldedPayer) -> TestResult<TransferredUtxo> {
    let zero = [0u8; 32];

    let payer_nullifier = shielded
        .nullifier_key
        .nullifier(&shielded.utxo_hash, &shielded.utxo.blinding)?;
    let payer_non_inclusion = cycle
        .nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&payer_nullifier))?;
    let payer_state_path: Vec<[u8; 32]> = cycle.state_tree.get_proof_of_leaf(0, true)?.to_vec();
    let payer_spend_input = spend_input(SpendInputArgs {
        utxo: &shielded.utxo,
        owner_field: &shielded.owner_field,
        state_path: &payer_state_path,
        state_path_index: 0,
        non_inclusion: &payer_non_inclusion,
        roots: (shielded.utxo_root, shielded.nullifier_root),
        nullifier: &payer_nullifier,
        owner_pk_hash: &shielded.owner_pk_hash,
        nullifier_key: &shielded.nullifier_key,
    })?;

    let recipient_bytes = cycle.recipient_owner.pubkey().to_bytes();
    let recipient_nullifier_key = NullifierKey::from_secret([11u8; 31]);
    let recipient_nullifier_pk = recipient_nullifier_key.pubkey()?;
    let recipient_public_key = PublicKey::from_ed25519(&recipient_bytes);

    let change_output = real_output(
        shielded.utxo.owner,
        shielded.nullifier_pk,
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
    let transfer_roots = (shielded.utxo_root, shielded.nullifier_root);
    let (transfer_dummy_input, _) = dummy_input(
        &[20u8; 31],
        &cycle.nf_tree,
        transfer_roots,
        &shielded.owner_pk_hash,
    )?;
    let (transfer_dummy_output, transfer_dummy_hash) = dummy_transfer_output(&[19u8; 31])
        .map_err(|err| anyhow!("transfer dummy output: {err}"))?;

    // Each real output's owner tag is its owner's `confidential_view_tag` so the
    // program's `hash_bytes(resolved_owner_tag)` matches that owner's
    // `owner_pk_field`.
    let change_view_tag = shielded.utxo.owner.confidential_view_tag()?;
    let recipient_view_tag = recipient_public_key.confidential_view_tag()?;
    let payer_bytes = cycle.payer.pubkey().to_bytes();
    let transfer_ix_data = build_sol_transfer_witness(SolTransferWitnessArgs {
        spend_inputs: vec![payer_spend_input, transfer_dummy_input],
        root_index: 1,
        output_hashes: vec![change_hash, recipient_hash, transfer_dummy_hash],
        view_tags: vec![change_view_tag, recipient_view_tag, change_view_tag],
        outputs: vec![
            transfer_output(&change_output)?,
            transfer_output(&recipient_output)?,
            transfer_dummy_output,
        ],
        output_nullifier_pks: [shielded.nullifier_pk, recipient_nullifier_pk, zero],
        interface_transfers: Vec::new(),
        resolved_transfers: Vec::new(),
        private_tx_inputs: [shielded.utxo_hash, zero],
        private_tx_outputs: [change_hash, recipient_hash, zero],
        public_sol_amount: zero,
        payer_pubkey_hash: Sha256BE::hash(&payer_bytes)?,
        input_owner_pk_hash: shielded.owner_pk_hash,
        label: "transfer",
    })?;

    let transfer_ix = Transact {
        payer: cycle.payer.pubkey(),
        input_tree: cycle.tree_pubkey,
        output_tree: cycle.tree_pubkey,
        interface_transfer_accounts: Vec::new(),
        data: transfer_ix_data,
    }
    .instruction();
    let transfer_tx = send_indexed(
        &mut cycle.rpc,
        &mut cycle.indexer,
        cycle.program_id,
        &[transfer_ix],
        &cycle.payer.pubkey(),
        &[&cycle.payer],
    )?;
    print_signature("shielded_transfer", &transfer_tx.signature);

    cycle.state_tree.append(&change_hash)?;
    cycle.state_tree.append(&recipient_hash)?;
    cycle.state_tree.append(&transfer_dummy_hash)?;
    let (transfer_utxo_root, transfer_nullifier_root) =
        on_chain_roots(&cycle.rpc, &cycle.tree_pubkey, 2)?;
    assert_eq!(
        cycle.state_tree.root(),
        transfer_utxo_root,
        "transfer root gate"
    );
    assert_eq!(transfer_nullifier_root, shielded.nullifier_root);

    Ok(TransferredUtxo {
        public_key: recipient_public_key,
        nullifier_key: recipient_nullifier_key,
        blinding: recipient_output.blinding,
        utxo_root: transfer_utxo_root,
        nullifier_root: transfer_nullifier_root,
    })
}

/// Unshield the transferred UTXO: spend it through a withdrawal that pays
/// `TRANSFER_AMOUNT` public SOL out of the vault to a fresh public recipient.
fn phase_unshield(
    cycle: &mut SolCycle,
    transferred: &TransferredUtxo,
) -> TestResult<UnshieldOutcome> {
    let zero = [0u8; 32];

    let recipient_utxo = Utxo {
        owner: transferred.public_key,
        asset: SOL_MINT,
        amount: TRANSFER_AMOUNT,
        blinding: transferred.blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let recipient_nullifier_pk = transferred.nullifier_key.pubkey()?;
    let transferred_hash = recipient_utxo.hash(&recipient_nullifier_pk, &zero, &zero)?;
    let recipient_owner_field = owner_hash(&transferred.public_key, &recipient_nullifier_pk)?;
    let recipient_view_tag = transferred.public_key.confidential_view_tag()?;
    let recipient_owner_pk_hash = recipient_utxo.owner.owner_proof_input_hash()?;
    let recipient_nullifier = transferred
        .nullifier_key
        .nullifier(&transferred_hash, &recipient_utxo.blinding)?;
    let recipient_non_inclusion = cycle
        .nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&recipient_nullifier))?;
    let recipient_state_path: Vec<[u8; 32]> = cycle.state_tree.get_proof_of_leaf(2, true)?.to_vec();
    let recipient_spend_input = spend_input(SpendInputArgs {
        utxo: &recipient_utxo,
        owner_field: &recipient_owner_field,
        state_path: &recipient_state_path,
        state_path_index: 2,
        non_inclusion: &recipient_non_inclusion,
        roots: (transferred.utxo_root, transferred.nullifier_root),
        nullifier: &recipient_nullifier,
        owner_pk_hash: &recipient_owner_pk_hash,
        nullifier_key: &transferred.nullifier_key,
    })?;

    let public_recipient = Keypair::new().pubkey();
    print_signature(
        "airdrop public recipient",
        &cycle.rpc.airdrop(&public_recipient, 1_000_000)?,
    );
    let public_recipient_before = account_lamports(&cycle.rpc, &public_recipient)?;
    let vault = pda::sol_interface();
    let vault_before = account_lamports(&cycle.rpc, &vault)?;
    let (withdraw_dummy_input, _) = dummy_input(
        &[21u8; 31],
        &cycle.nf_tree,
        (transferred.utxo_root, transferred.nullifier_root),
        &recipient_owner_pk_hash,
    )?;
    let (withdraw_outputs, withdraw_output_hashes) =
        dummy_witness_outputs(&[[1u8; 31], [2u8; 31], [3u8; 31]])?;

    let recipient_bytes = cycle.recipient_owner.pubkey().to_bytes();
    let withdraw_ix_data = build_sol_transfer_witness(SolTransferWitnessArgs {
        spend_inputs: vec![recipient_spend_input, withdraw_dummy_input],
        root_index: 2,
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
        private_tx_inputs: [transferred_hash, zero],
        private_tx_outputs: [zero, zero, zero],
        public_sol_amount: public_sol_field(Some(-(TRANSFER_AMOUNT as i64))),
        payer_pubkey_hash: Sha256BE::hash(&recipient_bytes)?,
        input_owner_pk_hash: recipient_owner_pk_hash,
        label: "withdraw",
    })?;

    let withdraw_ix = Transact {
        payer: cycle.recipient_owner.pubkey(),
        input_tree: cycle.tree_pubkey,
        output_tree: cycle.tree_pubkey,
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts {
                recipient: public_recipient,
            },
        )],
        data: withdraw_ix_data,
    }
    .instruction();
    let withdraw_tx = send_indexed(
        &mut cycle.rpc,
        &mut cycle.indexer,
        cycle.program_id,
        &[withdraw_ix],
        &cycle.payer.pubkey(),
        &[&cycle.payer, &cycle.recipient_owner],
    )?;
    print_signature("unshield", &withdraw_tx.signature);

    Ok(UnshieldOutcome {
        public_recipient,
        public_recipient_before,
        vault_before,
    })
}

/// Check the unshield moved exactly `TRANSFER_AMOUNT` lamports from the vault
/// to the public recipient.
fn phase_verify_output(cycle: &SolCycle, outcome: &UnshieldOutcome) -> TestResult {
    let public_recipient_after = account_lamports(&cycle.rpc, &outcome.public_recipient)?;
    let vault_after = account_lamports(&cycle.rpc, &pda::sol_interface())?;
    assert_eq!(
        public_recipient_after,
        outcome.public_recipient_before + TRANSFER_AMOUNT,
        "public recipient credited"
    );
    assert_eq!(
        vault_after,
        outcome.vault_before - TRANSFER_AMOUNT,
        "vault debited by transferred amount"
    );
    Ok(())
}
