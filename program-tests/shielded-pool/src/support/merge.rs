//! Real `merge_transact` proof construction, shared by every test binary that
//! needs a merge the program actually accepts.
//!
//! The merge shape is its declared input count, and the on-chain binding
//! depends on it: the public-input hash prefix folds three chains whose length
//! is that count, and the verifying key is selected from the same count. So a
//! caller that wants to exercise a shape needs a real proof at that shape, not
//! a dummy -- hence this lives in the support library rather than inside one
//! test binary.

use borsh::BorshSerialize;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use num_bigint::BigUint;
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    MergeProver, MerkleContext, MerkleProof, NonInclusionProof, ProofCompressed, ProverClient,
    SpendProof, TransferSpendInput, STATE_TREE_HEIGHT,
};
use zolana_hasher::Poseidon;
use zolana_interface::{
    instruction::{
        instruction_data::merge_transact::MERGE_SUPPORTED_INPUT_COUNTS, MergeTransact,
        MergeTransactIxData,
    },
    verifying_keys::{merge_36_1, merge_8_1},
};
use zolana_keypair::{hash::owner_hash, PublicKey, ShieldedKeypair, ShieldedKeypairTrait};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::{test_blinding, ZolanaProgramTest};
use zolana_test_utils::transact::nullifier_tree;
use zolana_transaction::{
    instructions::merge::{merge_dummy_nullifier, merge_output_blinding},
    Data, SppProofOutputUtxo, Utxo, SOL_MINT,
};
use zolana_user_registry_interface::{
    state::{UserRecord, NULLIFIER_PUBKEY_LEN, P256_PUBKEY_LEN},
    user_record_pda, USER_REGISTRY_PROGRAM_ID,
};

use super::fixtures::Pool;
use super::transact::{tree_progress, tree_roots};

/// The committed verifying key for a merge shape, selected exactly as the
/// program does (`merge/verify.rs`): merge instruction data carries no circuit
/// selector, so the declared input count *is* the shape.
pub fn merge_verifying_key(input_count: usize) -> &'static Groth16Verifyingkey<'static> {
    match input_count {
        8 => &merge_8_1::VERIFYINGKEY,
        36 => &merge_36_1::VERIFYINGKEY,
        other => panic!("no committed verifying key for a {other}-input merge"),
    }
}

/// Materialize a registry-owned `UserRecord` account directly in LiteSVM. The
/// merge instruction only reads the record, so fabricating it exercises the
/// same validation as a record created through the registry program.
pub fn write_user_record(
    rpc: &mut ZolanaProgramTest,
    owner: Pubkey,
    owner_p256: Option<[u8; P256_PUBKEY_LEN]>,
    merging_enabled: bool,
) -> Pubkey {
    // Compressed-point prefix 0x02 keeps `pk_field(viewing_pubkey)` computable.
    let mut viewing_pubkey = [7u8; P256_PUBKEY_LEN];
    if let Some(first) = viewing_pubkey.first_mut() {
        *first = 0x02;
    }
    // The program pins the record to its canonical registry PDA and bump.
    let (address, bump) = user_record_pda(&owner);
    let record = UserRecord {
        owner: solana_address::Address::new_from_array(owner.to_bytes()),
        bump,
        owner_p256,
        nullifier_pubkey: [11u8; NULLIFIER_PUBKEY_LEN],
        viewing_pubkey,
        merging_enabled,
    };
    let mut data = vec![UserRecord::DISCRIMINATOR];
    record
        .serialize(&mut data)
        .expect("serialize fabricated user record");
    // The registry requires the exact fixed record size; a `None` p256 key
    // serializes short, so zero-pad like the program's own writes do.
    data.resize(UserRecord::SIZE, 0);
    rpc.svm
        .set_account(
            address,
            Account {
                lamports: 1_000_000_000,
                data,
                owner: Pubkey::new_from_array(USER_REGISTRY_PROGRAM_ID),
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("write fabricated user record");
    address
}

/// A real merge, ready to send: instruction data with a verified proof, plus
/// the values a caller needs to assert against (nullifiers for the PDA
/// addresses, the registry record account, the public input).
pub struct RealMerge {
    /// Declared input count, and therefore the circuit shape.
    pub input_count: usize,
    /// Signed instruction data, proof attached.
    pub data: MergeTransactIxData,
    /// The published nullifiers, in instruction order: one real, the rest
    /// derived dummies.
    pub nullifiers: Vec<[u8; 32]>,
    /// The fabricated registry record the merge reads its owner identity from.
    pub user_record: Pubkey,
    /// The circuit's single public input, already gated against the committed
    /// verifying key.
    pub public_input_hash: [u8; 32],
}

impl RealMerge {
    /// The `merge_transact` instruction for this merge, merging the pool's tree
    /// into itself and paid for by the pool payer.
    pub fn instruction(&self, pool: &Pool) -> solana_instruction::Instruction {
        let payer = pool.rpc.payer.pubkey();
        MergeTransact {
            input_tree: pool.tree,
            output_tree: pool.tree,
            payer,
            user_record: self.user_record,
            data: self.data.clone(),
        }
        .instruction()
    }
}

/// Build a real merge proof at a chosen shape against a freshly initialized
/// pool.
///
/// The single real input is deposited by this builder, so the pool's UTXO tree
/// must still be empty when `build` runs: the state witness is reconstructed
/// from that one leaf alone. The remaining slots are dummies, whose merge
/// nullifiers are derived from the owner's nullifier secret and the real input's
/// nullifier and therefore still need non-inclusion witnesses.
///
/// The caller must already have a prover (`spawn_workspace_prover`); proving the
/// 36-input shape loads its own proving key.
pub struct RealMergeProof {
    /// Must be one of [`MERGE_SUPPORTED_INPUT_COUNTS`]; anything else has no
    /// committed verifying key and the program would refuse it.
    pub input_count: usize,
}

impl RealMergeProof {
    pub fn build(self, pool: &mut Pool) -> RealMerge {
        let input_count = self.input_count;
        assert!(
            MERGE_SUPPORTED_INPUT_COUNTS.contains(&input_count),
            "{input_count} is not a supported merge input count"
        );
        let (utxo_next, _) = tree_progress(&pool.rpc, &pool.tree);
        assert_eq!(
            utxo_next, 0,
            "RealMergeProof deposits its own input, so the pool's UTXO tree must still be empty"
        );

        let payer = pool.rpc.payer.insecure_clone();
        let payer_pk = payer.pubkey();
        let tree = pool.tree;
        let zero = [0u8; 32];

        // The merge owner IS the payer: the shielded keypair derives from the
        // payer's ed25519 secret, so the registry record binds the same key the
        // proof recomputes `signing_pk_field` from.
        let keypair = ShieldedKeypair::from_keypair(&payer).expect("shielded keypair");
        let user_record = write_user_record(&mut pool.rpc, payer_pk, None, true);

        // The real input: a zero-value SOL deposit owned by the payer's
        // shielded address (fixed blinding / nullifier secret keep the run
        // deterministic).
        let blinding = test_blinding(7);
        let nullifier_key = keypair.nullifier_key();
        let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
        let owner_public_key = keypair.signing_pubkey();
        let owner_field = owner_hash(&owner_public_key, &nullifier_pk).expect("owner field");
        let utxo = Utxo {
            owner: owner_public_key,
            asset: SOL_MINT,
            amount: 0,
            blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        pool.rpc
            .deposit_sol(&tree, &payer, 0, owner_field, blinding)
            .expect("proofless zero deposit");

        // Merkle witnesses against the on-chain roots, gated on the local
        // trees. The deposit consumed root-history slot 1.
        const UTXO_ROOT_INDEX: u16 = 1;
        let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
        let (utxo_root, nullifier_root) = tree_roots(&pool.rpc, &tree, UTXO_ROOT_INDEX);
        let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
        state_tree.append(&utxo_hash).expect("append state leaf");
        assert_eq!(state_tree.root(), utxo_root, "state root gate");
        let state_path: Vec<[u8; 32]> = state_tree
            .get_proof_of_leaf(0, true)
            .expect("state proof")
            .to_vec();
        let nf_tree = nullifier_tree().expect("indexed nullifier tree");
        assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
        let merkle_context = MerkleContext {
            tree_type: 0,
            tree: solana_address::Address::new_from_array(tree.to_bytes()),
        };

        let first_nullifier = nullifier_key
            .nullifier(&utxo_hash, &blinding)
            .expect("nullifier");
        let non_inclusion = nf_tree
            .get_non_inclusion_proof(&BigUint::from_bytes_be(&first_nullifier))
            .expect("non-inclusion proof");
        let to_non_inclusion =
            |leaf: [u8; 32], proof: &zolana_merkle_tree::indexed::NonInclusionProof| {
                NonInclusionProof {
                    leaf,
                    merkle_context: merkle_context.clone(),
                    path: proof.merkle_proof.to_vec(),
                    low_element: proof.leaf_lower_range_value,
                    low_element_index: proof.leaf_index as u64,
                    high_element: proof.leaf_higher_range_value,
                    high_element_index: 0,
                    root: nullifier_root,
                    root_seq: 0,
                    root_index: 0,
                }
            };

        // One real input at slot 0: its single-use nullifier seeds the derived
        // output blinding and every dummy nullifier, so it cannot be a dummy.
        let mut spends = Vec::with_capacity(input_count);
        spends.push(TransferSpendInput {
            utxo: utxo.clone(),
            nullifier_key: nullifier_key.clone(),
            data_hash: None,
            ring_data_hash: None,
            proof: Some(SpendProof {
                state: MerkleProof {
                    leaf: utxo_hash,
                    merkle_context: merkle_context.clone(),
                    path: state_path,
                    leaf_index: 0,
                    root: utxo_root,
                    root_seq: 0,
                    root_index: UTXO_ROOT_INDEX,
                },
                nullifier: to_non_inclusion(first_nullifier, &non_inclusion),
            }),
            nullifier_proof: None,
        });
        for slot in 1..input_count {
            let slot_tag = u8::try_from(slot).expect("merge slot fits a byte");
            let dummy_nullifier = merge_dummy_nullifier(&nullifier_key, &first_nullifier, slot_tag)
                .expect("dummy nullifier");
            let proof = nf_tree
                .get_non_inclusion_proof(&BigUint::from_bytes_be(&dummy_nullifier))
                .expect("dummy non-inclusion proof");
            spends.push(TransferSpendInput {
                utxo: Utxo {
                    owner: PublicKey::zeroed(),
                    asset: SOL_MINT,
                    amount: 0,
                    blinding: test_blinding(slot_tag.wrapping_add(10)),
                    ring_program_id: None,
                    data: Data::default(),
                },
                nullifier_key: nullifier_key.clone(),
                data_hash: None,
                ring_data_hash: None,
                proof: None,
                nullifier_proof: Some(to_non_inclusion(dummy_nullifier, &proof)),
            });
        }

        // The merged output's blinding is derived, not random: the circuit (and
        // the owner's wallet) reconstruct it from the nullifier secret and the
        // first input's nullifier.
        let mut output = SppProofOutputUtxo::new(
            SOL_MINT,
            0,
            keypair.shielded_address().expect("shielded address"),
        )
        .expect("merge output");
        output.blinding =
            merge_output_blinding(&nullifier_key, &first_nullifier).expect("output blinding");

        let result = MergeProver {
            inputs: spends,
            output,
            expiry_unix_ts: u64::MAX,
            signing_pubkey: owner_public_key,
            nullifier_key,
        }
        .build()
        .expect("build merge witness");
        assert_eq!(
            result.nullifiers.len(),
            input_count,
            "the built merge must keep the requested shape"
        );

        let proof = ProverClient::local()
            .prove_merge(&result.inputs)
            .expect("prove merge");
        // Local pairing gate against the committed merge verifying key: the
        // proof itself is valid, so an on-chain 7008 can only come from a
        // binding mismatch, not a bad proof.
        {
            let public_inputs = [result.public_input_hash];
            let mut verifier = Groth16Verifier::new(
                &proof.a,
                &proof.b,
                &proof.c,
                &public_inputs,
                merge_verifying_key(input_count),
            )
            .expect("construct merge verifier");
            verifier.verify().expect("merge proof verifies locally");
        }
        let merge_proof = ProofCompressed::try_from(proof)
            .expect("compress merge proof")
            .to_merge_proof()
            .expect("merge rail proof");

        RealMerge {
            input_count,
            data: result.instruction_data(merge_proof),
            nullifiers: result.nullifiers.clone(),
            user_record,
            public_input_hash: result.public_input_hash,
        }
    }
}
