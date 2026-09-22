use borsh::BorshSerialize;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use num_bigint::BigUint;
use solana_account::Account;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    MergeProver, MerkleContext, MerkleProof, NonInclusionProof, ProofCompressed, ProverClient,
    SpendProof, STATE_TREE_HEIGHT,
};
use zolana_hasher::Poseidon;
use zolana_interface::{
    instruction::{
        instruction_data::merge_transact::MERGE_SUPPORTED_INPUT_COUNTS, MergeTransact,
        MergeTransactIxData,
    },
    verifying_keys::{merge_36_1, merge_8_1},
};
use zolana_keypair::{
    hash::owner_hash, NullifierKey, PublicKey, ShieldedKeypair, ShieldedKeypairTrait,
};
use zolana_merkle_tree::indexed::{
    IndexedMerkleTree, NonInclusionProof as IndexedNonInclusionProof,
};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::transact::nullifier_tree;
use zolana_transaction::{instructions::merge::merge_dummy_nullifier, Utxo, SOL_MINT};
use zolana_user_registry_interface::{
    state::{UserRecord, NULLIFIER_PUBKEY_LEN, P256_PUBKEY_LEN},
    user_record_pda, USER_REGISTRY_PROGRAM_ID,
};

use super::fixtures::Pool;
use super::transact::{current_tree_roots, tree_progress};

pub fn merge_verifying_key(input_count: usize) -> &'static Groth16Verifyingkey<'static> {
    match input_count {
        8 => &merge_8_1::VERIFYINGKEY,
        36 => &merge_36_1::VERIFYINGKEY,
        other => panic!("no committed verifying key for a {other}-input merge"),
    }
}

pub fn write_user_record(
    rpc: &mut ZolanaProgramTest,
    owner: Pubkey,
    owner_p256: Option<[u8; P256_PUBKEY_LEN]>,
    merging_enabled: bool,
) -> Pubkey {
    let mut viewing_pubkey = [7u8; P256_PUBKEY_LEN];
    if let Some(first) = viewing_pubkey.first_mut() {
        *first = 0x02;
    }
    let (address, bump) = user_record_pda(&owner);
    let record = UserRecord {
        owner: Address::new_from_array(owner.to_bytes()),
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

pub struct RealDeposit {
    pub utxo: Utxo,
    pub utxo_hash: [u8; 32],
    pub leaf_index: u64,
    pub state_path: Vec<[u8; 32]>,
    pub nullifier: [u8; 32],
    pub non_inclusion: IndexedNonInclusionProof,
}

pub struct RealDeposits {
    pub owner_field: [u8; 32],
    pub utxo_root: [u8; 32],
    pub utxo_root_index: u16,
    pub nullifier_root: [u8; 32],
    pub nullifier_tree: IndexedMerkleTree<Poseidon, usize>,
    pub deposits: Vec<RealDeposit>,
}

impl RealDeposits {
    pub fn roots(&self) -> ([u8; 32], [u8; 32]) {
        (self.utxo_root, self.nullifier_root)
    }
}

pub struct ZeroDeposits<'a> {
    pub rpc: &'a mut ZolanaProgramTest,
    pub tree: Pubkey,
    pub depositor: &'a Keypair,
    pub owner: PublicKey,
    pub nullifier_key: &'a NullifierKey,
    pub tree_id: u16,
    pub count: usize,
}

impl ZeroDeposits<'_> {
    pub fn deposit(self) -> RealDeposits {
        assert!(self.count > 0, "at least one real deposit is required");
        let (utxo_next, _) = tree_progress(self.rpc, &self.tree);
        assert_eq!(utxo_next, 0, "the pool's UTXO tree must still be empty");

        let zero = [0u8; 32];
        let nullifier_pk = self.nullifier_key.pubkey().expect("nullifier pubkey");
        let owner_field = owner_hash(&self.owner, &nullifier_pk).expect("owner field");
        let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
        let mut utxos = Vec::with_capacity(self.count);
        for _ in 0..self.count {
            let event = self
                .rpc
                .deposit_sol(&self.tree, self.depositor, 0, owner_field)
                .expect("proofless zero deposit");
            let utxo = self
                .rpc
                .indexed_deposit_utxo(&event, self.owner)
                .expect("indexed deposit UTXO");
            assert_eq!((utxo.asset.asset, utxo.amount), (SOL_MINT, 0));
            let utxo_hash = utxo
                .hash(&nullifier_pk, &zero, &zero, self.tree_id)
                .expect("utxo hash");
            state_tree.append(&utxo_hash).expect("append state leaf");
            utxos.push((utxo, utxo_hash));
        }

        let (utxo_root_index, utxo_root, nullifier_root) = current_tree_roots(self.rpc, &self.tree);
        assert_eq!(state_tree.root(), utxo_root, "state root gate");
        let nullifier_tree = nullifier_tree().expect("indexed nullifier tree");
        assert_eq!(nullifier_tree.root(), nullifier_root, "nullifier root gate");

        let deposits = utxos
            .into_iter()
            .enumerate()
            .map(|(leaf_index, (utxo, utxo_hash))| {
                let state_path = state_tree
                    .get_proof_of_leaf(leaf_index, true)
                    .expect("state proof")
                    .to_vec();
                let nullifier = self
                    .nullifier_key
                    .nullifier(&utxo_hash, &utxo.blinding)
                    .expect("nullifier");
                let non_inclusion = nullifier_tree
                    .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
                    .expect("non-inclusion proof");
                RealDeposit {
                    utxo,
                    utxo_hash,
                    leaf_index: leaf_index as u64,
                    state_path,
                    nullifier,
                    non_inclusion,
                }
            })
            .collect();

        RealDeposits {
            owner_field,
            utxo_root,
            utxo_root_index,
            nullifier_root,
            nullifier_tree,
            deposits,
        }
    }
}

pub struct RealMerge {
    pub data: MergeTransactIxData,
    pub nullifiers: Vec<[u8; 32]>,
    pub user_record: Pubkey,
}

impl RealMerge {
    pub fn instruction(&self, pool: &Pool) -> solana_instruction::Instruction {
        MergeTransact {
            input_tree: pool.tree,
            output_tree: pool.tree,
            payer: pool.rpc.payer.pubkey(),
            user_record: self.user_record,
            data: self.data.clone(),
        }
        .instruction()
    }
}

pub struct RealMergeProof {
    pub input_count: usize,
    pub real_input_count: usize,
}

impl RealMergeProof {
    pub fn build(self, pool: &mut Pool) -> RealMerge {
        let RealMergeProof {
            input_count,
            real_input_count,
        } = self;
        assert!(
            MERGE_SUPPORTED_INPUT_COUNTS.contains(&input_count),
            "{input_count} is not a supported merge input count"
        );
        assert!(
            (1..=input_count).contains(&real_input_count),
            "{real_input_count} real inputs do not fit a {input_count}-input merge"
        );

        let payer = pool.rpc.payer.insecure_clone();
        let tree = pool.tree;
        let tree_id = pool.tree_id;
        let keypair = ShieldedKeypair::from_keypair(&payer).expect("shielded keypair");
        let user_record = write_user_record(&mut pool.rpc, payer.pubkey(), None, true);
        let nullifier_key = keypair.nullifier_key();
        let owner_public_key = keypair.signing_pubkey();

        let deposits = ZeroDeposits {
            rpc: &mut pool.rpc,
            tree,
            depositor: &payer,
            owner: owner_public_key,
            nullifier_key: &nullifier_key,
            tree_id,
            count: real_input_count,
        }
        .deposit();
        let nullifier_root = deposits.nullifier_root;
        let merkle_context = MerkleContext {
            tree_type: 0,
            tree: Address::new_from_array(tree.to_bytes()),
        };
        let to_non_inclusion =
            |leaf: [u8; 32], proof: &IndexedNonInclusionProof| NonInclusionProof {
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
            };

        let notes = deposits
            .deposits
            .iter()
            .map(|deposit| {
                zolana_test_utils::utxo::wallet(
                    deposit.utxo.clone(),
                    &nullifier_key,
                    tree_id,
                    deposit.leaf_index,
                    None,
                    None,
                )
                .expect("input")
            })
            .collect();
        let mut transaction = zolana_transaction::instructions::merge::MergeTransaction::new(notes)
            .expect("merge")
            .with_output_tree_id(tree_id)
            .encrypt(&keypair)
            .expect("encrypt merge");
        let first_nullifier = transaction
            .input_utxos
            .first()
            .expect("real input")
            .nullifier;
        // Explicit larger shapes exercise every supported verifier with real padding.
        for slot in transaction.input_utxos.len()..input_count {
            let mut dummy =
                zolana_transaction::utxo::SppProofInputUtxo::dummy(tree_id).expect("dummy");
            dummy.nullifier = merge_dummy_nullifier(&nullifier_key, &first_nullifier, slot as u8)
                .expect("dummy nullifier");
            transaction.input_utxos.push(dummy);
        }
        let proofs = deposits
            .deposits
            .iter()
            .map(|deposit| SpendProof {
                state: MerkleProof {
                    leaf: deposit.utxo_hash,
                    merkle_context: merkle_context.clone(),
                    path: deposit.state_path.clone(),
                    leaf_index: deposit.leaf_index,
                    root: deposits.utxo_root,
                    root_seq: 0,
                    root_index: deposits.utxo_root_index,
                },
                nullifier: to_non_inclusion(deposit.nullifier, &deposit.non_inclusion),
            })
            .collect();
        let dummy_nullifier_proofs = transaction
            .dummy_nullifiers()
            .into_iter()
            .map(|nullifier| {
                let proof = deposits
                    .nullifier_tree
                    .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
                    .expect("dummy proof");
                to_non_inclusion(nullifier, &proof)
            })
            .collect();
        let result = MergeProver {
            transaction,
            nullifier_key,
            proofs,
            dummy_nullifier_proofs,
        }
        .build()
        .expect("merge witness");
        assert_eq!(
            result.nullifiers.len(),
            input_count,
            "the built merge must keep the requested shape"
        );

        let proof = ProverClient::local()
            .prove_merge(&result.inputs)
            .expect("prove merge");
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
            data: result.instruction_data(merge_proof),
            nullifiers: result.nullifiers.clone(),
            user_record,
        }
    }
}
