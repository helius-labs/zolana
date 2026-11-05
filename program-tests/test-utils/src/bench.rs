//! What the example programs' mollusk CU benches share: the fixture accounts,
//! the shielded-pool tree fixture with the spend proofs of its leaves, a timed
//! SPP proof, and the report tables.

use std::time::{Duration, Instant};

use light_program_profiler::report::SectionTable;
use num_bigint::BigUint;
use solana_account::Account;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use spr_client::{
    transaction_size, ComputeBudgetConfig, MerkleContext, MerkleProof, NonInclusionProof,
    ProverClient, ProverExt, SpendProof, STATE_TREE_HEIGHT,
};
use spr_hasher::Poseidon;
use spr_interface::{
    instruction::instruction_data::transact::TransactIxData,
    state::{
        default_tree_fees, discriminator::TREE_ACCOUNT_DISCRIMINATOR, nullifier_tree_params,
        tree_account_size, STATE_HEIGHT,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use spr_keypair::{NullifierKey, ShieldedKeypair, SigningKey};
use spr_merkle_tree::MerkleTree;
use spr_program_test::initial_nullifier_tree;
use spr_transaction::instructions::transact::SppProofInputs;
use spr_tree::TreeAccount;

use crate::utxo::{dummy_proofs, ProofKeys};

/// Raw id of the fixture tree. [`tree_fixture`] initializes the account with
/// this id, and every UTXO commitment folds it in.
pub const BENCH_TREE_ID: u16 = 0;

/// The loader-v3 account of the program `program_id`.
pub fn program_account(program_id: &Pubkey) -> (Pubkey, Account) {
    let account = mollusk_svm::program::create_program_account_loader_v3(program_id);
    (*program_id, account)
}

/// A plain, system-owned account. `lamports == 0` reads as "does not exist
/// yet" to a program creating an account at its address; `lamports > 0`
/// models an existing wallet.
pub fn system_owned_account(lamports: u64) -> Account {
    Account {
        lamports,
        data: Vec::new(),
        owner: Pubkey::default(),
        executable: false,
        rent_epoch: 0,
    }
}

/// The account of the tree `tree` holding the inclusion-proved inputs of
/// `proof_inputs` as its only leaves, and their spend proofs against it. The
/// program's `create_tree` initializes the account; the leaves land in slot 0,
/// the slot mollusk starts in.
pub fn tree_fixture(tree: &Pubkey, proof_inputs: &SppProofInputs) -> (Account, Vec<SpendProof>) {
    let commitments = proof_inputs.input_utxo_hashes().expect("input commitments");
    let leaves: Vec<[u8; 32]> = commitments.iter().map(|input| input.utxo_hash).collect();

    let mut data = vec![0u8; tree_account_size()];
    let (utxo_root, root_index, nullifier_root) = {
        let mut account = TreeAccount::init(
            &mut data,
            TREE_ACCOUNT_DISCRIMINATOR,
            STATE_HEIGHT as u8,
            tree.to_bytes(),
            BENCH_TREE_ID,
            nullifier_tree_params(),
            default_tree_fees(),
        )
        .expect("init tree account");
        let utxo_tree = account.utxo_tree();
        utxo_tree.append_batch(&leaves, 0).expect("append leaves");
        (
            utxo_tree.root(),
            utxo_tree.current_root_index(),
            account.get_nullifier_tree_root(0).expect("nullifier root"),
        )
    };

    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    for leaf in &leaves {
        state_tree.append(leaf).expect("append state leaf");
    }
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let nullifier_tree = initial_nullifier_tree();
    assert_eq!(nullifier_tree.root(), nullifier_root, "nullifier root gate");

    let merkle_context = MerkleContext {
        tree_type: 0,
        tree: *tree,
    };
    let spend_proofs = commitments
        .iter()
        .enumerate()
        .map(|(leaf_index, commitment)| {
            let state_path = state_tree
                .get_proof_of_leaf(leaf_index, true)
                .expect("state proof")
                .to_vec();
            let non_inclusion = nullifier_tree
                .get_non_inclusion_proof(&BigUint::from_bytes_be(&commitment.nullifier))
                .expect("non-inclusion proof");
            SpendProof {
                state: MerkleProof {
                    leaf: commitment.utxo_hash,
                    merkle_context: merkle_context.clone(),
                    path: state_path,
                    leaf_index: leaf_index as u64,
                    root: utxo_root,
                    root_seq: 0,
                    root_index,
                },
                nullifier: NonInclusionProof {
                    leaf: commitment.nullifier,
                    merkle_context: merkle_context.clone(),
                    path: non_inclusion.merkle_proof.to_vec(),
                    low_element: non_inclusion.leaf_lower_range_value,
                    low_element_index: non_inclusion.leaf_index as u64,
                    high_element: non_inclusion.leaf_higher_range_value,
                    high_element_index: 0,
                    root: nullifier_root,
                    root_seq: 0,
                    root_index: 0,
                },
            }
        })
        .collect();

    let account = Account {
        lamports: 1_000_000_000_000,
        data,
        owner: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        executable: false,
        rent_epoch: 0,
    };
    (account, spend_proofs)
}

/// The mollusk accounts of every account `ix` references: the shielded-pool
/// program's loader-v3 account for it (it is CPI'd into and appears again in
/// the forwarded account list), the system program for the default address,
/// the matching entry of `fixtures`, and a funded, empty, system-owned wallet
/// for anything else (fee payers, PDA signers whose address alone matters).
pub fn assemble_accounts(
    ix: &Instruction,
    spp_id: &Pubkey,
    fixtures: &[(Pubkey, Account)],
) -> Vec<(Pubkey, Account)> {
    let spp = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    ix.accounts
        .iter()
        .map(|meta| {
            if meta.pubkey == spp {
                program_account(spp_id)
            } else if meta.pubkey == Pubkey::default() {
                mollusk_svm::program::keyed_account_for_system_program()
            } else if let Some((_, account)) = fixtures.iter().find(|(key, _)| *key == meta.pubkey)
            {
                (meta.pubkey, account.clone())
            } else {
                (meta.pubkey, system_owned_account(1_000_000_000))
            }
        })
        .collect()
}

/// The shielded keypair whose signing key is the ed25519 key of `payer`.
pub fn keypair_from_payer(payer: &Keypair) -> ShieldedKeypair {
    let seed: [u8; 32] = payer.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&seed))
        .expect("keypair from payer")
}

/// Proves `proof_inputs` with the local prover and the time the proof took,
/// warm: a first proof loads the proving key.
pub fn prove_transact_timed(
    proof_inputs: SppProofInputs,
    spend_proofs: &[SpendProof],
    keys: &[&NullifierKey],
) -> (TransactIxData, Duration) {
    let prover = ProverClient::local();
    let dummy_proofs = dummy_proofs(&proof_inputs);
    prover
        .prove_transact(
            proof_inputs.clone(),
            spend_proofs,
            &dummy_proofs,
            &ProofKeys(keys),
        )
        .expect("warm prove transact");
    let start = Instant::now();
    let transact = prover
        .prove_transact(proof_inputs, spend_proofs, &dummy_proofs, &ProofKeys(keys))
        .expect("prove transact");
    (transact, start.elapsed())
}

/// The proving times of an instruction: the SPP transfer proof, and when the
/// program proves its own circuit, that proof under its column name and the
/// total.
pub fn proving_time_table(spp: Duration, circuit: Option<(&str, Duration)>) -> SectionTable {
    let ms = |duration: Duration| format!("{} ms", duration.as_millis());
    let mut headers = vec!["SPP transfer proof".to_string()];
    let mut row = vec![ms(spp)];
    if let Some((name, duration)) = circuit {
        headers.extend([name.to_string(), "Total".to_string()]);
        row.extend([ms(duration), ms(spp + duration)]);
    }
    SectionTable {
        title: "Proving Time".into(),
        headers,
        rows: vec![row],
    }
}

/// The size of the version 1 transaction `ix` is sent as. Its compute
/// ceilings live in the message header.
pub fn tx_size_table(ix: &Instruction, payer: &Pubkey) -> SectionTable {
    let v1 = transaction_size(
        payer,
        std::slice::from_ref(ix),
        ComputeBudgetConfig::new(1_400_000),
    )
    .expect("measure v1 transaction")
    .bytes;

    SectionTable {
        title: "Transaction Size".into(),
        headers: vec!["Instruction Data".into(), "Accounts".into(), "v1 Tx".into()],
        rows: vec![vec![
            format!("{} bytes", ix.data.len()),
            ix.accounts.len().to_string(),
            format!("{v1} bytes"),
        ]],
    }
}
