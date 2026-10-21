//! Litesvm program-test for the `ConfidentialEddsa` rail: the owner signs the
//! transaction message digest inside the proof and never signs the Solana
//! transaction, which another account pays for. Covers the relayed spend, a
//! selector naming another owner key, and a spend mixing an in-circuit owner
//! with a Solana co-signer.
//!
//! Requires `cargo build-sbf -p shielded-pool-program`.

use num_bigint::BigUint;
use shielded_pool_tests::support::{
    merge::{RealDeposit, ZeroDeposits},
    transact::{current_tree_roots, proof_env, tree_progress, Pool},
};
use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    assemble_confidential_eddsa, AssembledTransfer, ComputeBudgetConfig, MerkleContext,
    MerkleProof, NonInclusionProof, ProverClient, SpendProof, STATE_TREE_HEIGHT,
};
use zolana_hasher::Poseidon;
use zolana_interface::{
    error::ShieldedPoolError, instruction::instruction_data::transact::CircuitId, shape::Shape,
};
use zolana_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey, ShieldedKeypair};
use zolana_merkle_tree::{indexed::NonInclusionProof as IndexedNonInclusionProof, MerkleTree};
use zolana_program::instruction::Transact;
use zolana_program_test::Rejection;
use zolana_test_utils::{
    transact::nullifier_tree,
    utxo::{wallet, ProofKeys},
};
use zolana_transaction::{
    instructions::transact::{ConfidentialTransaction, SppProofInputs},
    WalletUtxo,
};

/// Zero-value deposits with one owner each, in one empty tree, with the
/// inclusion and non-inclusion witnesses a spend of every one needs.
struct OwnedDeposits {
    utxo_root: [u8; 32],
    utxo_root_index: u16,
    nullifier_root: [u8; 32],
    nullifier_tree: zolana_merkle_tree::indexed::IndexedMerkleTree<Poseidon, usize>,
    deposits: Vec<RealDeposit>,
}

fn owned_deposits(env: &mut Pool, owners: &[(PublicKey, &NullifierKey)]) -> OwnedDeposits {
    let payer = env.rpc.payer.insecure_clone();
    let (tree, tree_id) = (env.tree, env.tree_id);
    if let [(owner, nullifier_key)] = owners {
        let deposits = ZeroDeposits {
            rpc: &mut env.rpc,
            tree,
            depositor: &payer,
            owner: *owner,
            nullifier_key,
            tree_id,
            count: 1,
        }
        .deposit();
        return OwnedDeposits {
            utxo_root: deposits.utxo_root,
            utxo_root_index: deposits.utxo_root_index,
            nullifier_root: deposits.nullifier_root,
            nullifier_tree: deposits.nullifier_tree,
            deposits: deposits.deposits,
        };
    }
    let zero = [0u8; 32];
    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    let mut leaves = Vec::with_capacity(owners.len());
    for (owner, nullifier_key) in owners {
        let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
        let owner_field = owner_hash(owner, &nullifier_pk).expect("owner field");
        let event = env
            .rpc
            .deposit_sol(&tree, &payer, 0, owner_field)
            .expect("proofless zero deposit");
        let utxo = env
            .rpc
            .indexed_deposit_utxo(&event, *owner)
            .expect("indexed deposit UTXO");
        let utxo_hash = utxo
            .hash(&nullifier_pk, &zero, &zero, tree_id)
            .expect("utxo hash");
        state_tree.append(&utxo_hash).expect("append state leaf");
        leaves.push((utxo, utxo_hash, nullifier_key));
    }
    let (utxo_root_index, utxo_root, nullifier_root) = current_tree_roots(&env.rpc, &tree);
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let nullifier_tree = nullifier_tree().expect("indexed nullifier tree");
    assert_eq!(nullifier_tree.root(), nullifier_root, "nullifier root gate");
    let deposits = leaves
        .into_iter()
        .enumerate()
        .map(|(leaf_index, (utxo, utxo_hash, nullifier_key))| {
            let nullifier = nullifier_key
                .nullifier(&utxo_hash, &utxo.blinding)
                .expect("nullifier");
            RealDeposit {
                state_path: state_tree
                    .get_proof_of_leaf(leaf_index, true)
                    .expect("state proof")
                    .to_vec(),
                non_inclusion: nullifier_tree
                    .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
                    .expect("non-inclusion proof"),
                utxo,
                utxo_hash,
                leaf_index: leaf_index as u64,
                nullifier,
            }
        })
        .collect();
    OwnedDeposits {
        utxo_root,
        utxo_root_index,
        nullifier_root,
        nullifier_tree,
        deposits,
    }
}

impl OwnedDeposits {
    fn note(&self, index: usize, nullifier_key: &NullifierKey, tree_id: u16) -> WalletUtxo {
        let deposit = self.deposits.get(index).expect("deposit");
        wallet(
            deposit.utxo.clone(),
            nullifier_key,
            tree_id,
            deposit.leaf_index,
            None,
            None,
        )
        .expect("wallet utxo")
    }

    fn non_inclusion(
        &self,
        tree: Pubkey,
        leaf: [u8; 32],
        proof: &IndexedNonInclusionProof,
    ) -> NonInclusionProof {
        NonInclusionProof {
            leaf,
            merkle_context: MerkleContext {
                tree_type: 0,
                tree: Address::new_from_array(tree.to_bytes()),
            },
            path: proof.merkle_proof.to_vec(),
            low_element: proof.leaf_lower_range_value,
            low_element_index: proof.leaf_index as u64,
            high_element: proof.leaf_higher_range_value,
            high_element_index: 0,
            root: self.nullifier_root,
            root_seq: 0,
            root_index: 0,
        }
    }

    /// The spend proofs of every deposit, then the padding non-inclusion
    /// proofs the proof inputs ask for.
    fn witnesses(
        &self,
        tree: Pubkey,
        proof_inputs: &SppProofInputs,
    ) -> (Vec<SpendProof>, Vec<NonInclusionProof>) {
        let spends = self
            .deposits
            .iter()
            .map(|deposit| SpendProof {
                state: MerkleProof {
                    leaf: deposit.utxo_hash,
                    merkle_context: MerkleContext {
                        tree_type: 0,
                        tree: Address::new_from_array(tree.to_bytes()),
                    },
                    path: deposit.state_path.clone(),
                    leaf_index: deposit.leaf_index,
                    root: self.utxo_root,
                    root_seq: 0,
                    root_index: self.utxo_root_index,
                },
                nullifier: self.non_inclusion(tree, deposit.nullifier, &deposit.non_inclusion),
            })
            .collect();
        let padding = proof_inputs
            .dummy_nullifiers()
            .into_iter()
            .map(|nullifier| {
                let proof = self
                    .nullifier_tree
                    .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
                    .expect("padding non-inclusion proof");
                self.non_inclusion(tree, nullifier, &proof)
            })
            .collect();
        (spends, padding)
    }
}

/// The relayed spend of `notes`, padded to the rail's smallest shape, with
/// `owner` as the in-circuit owner and the pool payer paying.
fn assemble_relayed(
    env: &Pool,
    deposits: &OwnedDeposits,
    notes: Vec<WalletUtxo>,
    owner: &ShieldedKeypair,
) -> AssembledTransfer {
    let payer = Address::new_from_array(env.rpc.payer.pubkey().to_bytes());
    let mut transfer = ConfidentialTransaction::new(notes, payer)
        .expect("transfer")
        .with_output_tree_id(env.tree_id)
        .expect("output tree");
    transfer
        .pad_utxos(Shape::IN2_OUT8, &owner.shielded_address().expect("address"))
        .expect("pad to 2x8");
    let proof_inputs = transfer.encrypt(owner).expect("encrypt");
    let (spends, padding) = deposits.witnesses(env.tree, &proof_inputs);
    assemble_confidential_eddsa(proof_inputs, &spends, &padding, &owner.signing_key)
        .expect("assemble on the in-circuit EdDSA rail")
}

fn transact_ix(
    env: &Pool,
    owner_signers: Vec<Pubkey>,
    data: zolana_interface::instruction::TransactIxData,
) -> solana_instruction::Instruction {
    Transact {
        payer: env.rpc.payer.pubkey(),
        input_trees: vec![env.tree],
        output_tree: env.tree,
        owner_signers,
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction()
}

fn send(
    env: &mut Pool,
    ix: solana_instruction::Instruction,
) -> Result<(), zolana_program_test::ProgramTestError> {
    env.rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix],
            &[],
            ComputeBudgetConfig::new(1_400_000),
        )
        .map(|_| ())
}

/// The owner never signs the transaction: the payer is its only signer, the
/// selector carries the owner key and the proof's commitment, and SPP spends
/// the owner's note.
#[test]
fn a_relayer_pays_and_the_owner_signs_only_in_circuit() {
    let mut env = proof_env();
    let owner = ShieldedKeypair::new_ed25519().expect("owner keypair");
    let deposits = owned_deposits(&mut env, &[(owner.signing_pubkey(), &owner.nullifier_key)]);
    let note = deposits.note(0, &owner.nullifier_key, env.tree_id);
    let mut assembled = assemble_relayed(&env, &deposits, vec![note], &owner);
    let proof = assembled
        .prove(&ProverClient::local(), &owner)
        .expect("prove on the in-circuit EdDSA rail");
    let data = assembled.with_proof(proof);
    let owner_pk = owner.signing_pubkey().as_ed25519().expect("ed25519 owner");
    match data.circuit {
        CircuitId::ConfidentialEddsa(2, 8, 3, proof_data) => {
            assert_eq!(proof_data.owner_pk, owner_pk);
            assert_ne!(proof_data.bsb22_commitment.commitment, [0u8; 32]);
        }
        other => panic!("selector {other:?}"),
    }
    let nullifiers: Vec<[u8; 32]> = data
        .inputs
        .iter()
        .map(|input| input.nullifier_hash)
        .collect();
    let (utxo_next_before, nullifier_next_before) = tree_progress(&env.rpc, &env.tree);

    let ix = transact_ix(&env, Vec::new(), data);
    send(&mut env, ix).expect("relayed transact");

    // Random padding fills every slot: eight outputs appended, the owner's
    // nullifier and the padding input's queued.
    assert_eq!(
        tree_progress(&env.rpc, &env.tree),
        (utxo_next_before + 8, nullifier_next_before + 2),
        "every output slot appended and both input slots nullified"
    );
    zolana_test_utils::nullifier_pda::assert_nullifier_pdas(&env.rpc, &env.tree, &nullifiers)
        .expect("nullifier PDA for the relayed input");
}

/// The selector's owner key is a public input: a proof for one owner does not
/// verify under another owner's key, with or without that owner signing.
#[test]
fn a_selector_naming_another_owner_key_fails_verification() {
    let mut env = proof_env();
    let owner = ShieldedKeypair::new_ed25519().expect("owner keypair");
    let other = ShieldedKeypair::new_ed25519().expect("other keypair");
    let deposits = owned_deposits(&mut env, &[(owner.signing_pubkey(), &owner.nullifier_key)]);
    let note = deposits.note(0, &owner.nullifier_key, env.tree_id);
    let mut assembled = assemble_relayed(&env, &deposits, vec![note], &owner);
    let proof = assembled
        .prove(&ProverClient::local(), &owner)
        .expect("prove on the in-circuit EdDSA rail");
    let mut data = assembled.with_proof(proof);
    match &mut data.circuit {
        CircuitId::ConfidentialEddsa(_, _, _, proof_data) => {
            proof_data.owner_pk = other.signing_pubkey().as_ed25519().expect("ed25519 key");
        }
        other => panic!("selector {other:?}"),
    }
    let payer = env.rpc.payer.pubkey();

    let ix = transact_ix(&env, Vec::new(), data);
    let error =
        send(&mut env, ix).expect_err("a selector naming another owner key must be rejected");

    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    env.rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[payer]);
}

/// One input belongs to the in-circuit owner and the other to the payer, who
/// signs for it as an owner signer: the two authorizations hold in one proof
/// and SPP spends both notes.
#[test]
fn a_mixed_spend_authorizes_one_input_in_circuit_and_one_by_a_co_signer() {
    let mut env = proof_env();
    let owner = ShieldedKeypair::new_ed25519().expect("owner keypair");
    let co_signer = ShieldedKeypair::from_keypair(&env.rpc.payer).expect("payer keypair");
    let deposits = owned_deposits(
        &mut env,
        &[
            (owner.signing_pubkey(), &owner.nullifier_key),
            (co_signer.signing_pubkey(), &co_signer.nullifier_key),
        ],
    );
    let notes = vec![
        deposits.note(0, &owner.nullifier_key, env.tree_id),
        deposits.note(1, &co_signer.nullifier_key, env.tree_id),
    ];
    let mut assembled = assemble_relayed(&env, &deposits, notes, &owner);
    let proof = assembled
        .prove(
            &ProverClient::local(),
            &ProofKeys(&[&owner.nullifier_key, &co_signer.nullifier_key]),
        )
        .expect("prove the mixed spend");
    let data = assembled.with_proof(proof);
    let nullifiers: Vec<[u8; 32]> = data
        .inputs
        .iter()
        .map(|input| input.nullifier_hash)
        .collect();
    assert_eq!(nullifiers.len(), 2);
    let payer = env.rpc.payer.pubkey();
    let (utxo_next_before, nullifier_next_before) = tree_progress(&env.rpc, &env.tree);

    let ix = transact_ix(&env, vec![payer], data);
    send(&mut env, ix).expect("mixed transact");

    assert_eq!(
        tree_progress(&env.rpc, &env.tree),
        (utxo_next_before + 8, nullifier_next_before + 2),
        "every output slot appended and both notes nullified"
    );
    zolana_test_utils::nullifier_pda::assert_nullifier_pdas(&env.rpc, &env.tree, &nullifiers)
        .expect("nullifier PDAs for both inputs");
}

/// The co-signer's note is not authorized by the in-circuit owner: without
/// the co-signer among the owner signers the proof does not match SPP's
/// signer chain and the spend is rejected.
#[test]
fn a_co_signers_note_still_needs_the_co_signer_to_sign() {
    let mut env = proof_env();
    let owner = ShieldedKeypair::new_ed25519().expect("owner keypair");
    let co_signer = ShieldedKeypair::from_keypair(&env.rpc.payer).expect("payer keypair");
    let deposits = owned_deposits(
        &mut env,
        &[
            (owner.signing_pubkey(), &owner.nullifier_key),
            (co_signer.signing_pubkey(), &co_signer.nullifier_key),
        ],
    );
    let notes = vec![
        deposits.note(0, &owner.nullifier_key, env.tree_id),
        deposits.note(1, &co_signer.nullifier_key, env.tree_id),
    ];
    let mut assembled = assemble_relayed(&env, &deposits, notes, &owner);
    let proof = assembled
        .prove(
            &ProverClient::local(),
            &ProofKeys(&[&owner.nullifier_key, &co_signer.nullifier_key]),
        )
        .expect("prove the mixed spend");
    let data = assembled.with_proof(proof);
    let payer = env.rpc.payer.pubkey();

    let ix = transact_ix(&env, Vec::new(), data);
    let error = send(&mut env, ix).expect_err("paying does not authorize the payer's note");

    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    env.rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[payer]);
}
