use borsh::BorshSerialize;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use num_bigint::BigUint;
use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    prover::{MergeCacheTarget, MergeReceiptTarget, MergeRingCacheTarget},
    MergeProver, MergeRingProver, MerkleContext, MerkleProof, NonInclusionProof, Proof,
    ProofCompressed, ProverClient, SpendProof, TransferSpendInput, STATE_TREE_HEIGHT,
};
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::{
    instruction::{
        instruction_data::merge_transact::MERGE_SUPPORTED_INPUT_COUNTS, CreateReceipt,
        CreateReceiptData, MergeRing, MergeRingIxData, MergeTransact, MergeTransactIxData,
    },
    state::receipt::RECEIPT_CAPACITIES,
    verifying_keys::{merge_36_1, merge_8_1, merge_receipt_36_1, merge_receipt_8_1},
};
use zolana_keypair::{
    hash::owner_hash, NullifierKey, PublicKey, ShieldedKeypair, ShieldedKeypairTrait,
};
use zolana_merkle_tree::indexed::{
    IndexedMerkleTree, NonInclusionProof as IndexedNonInclusionProof,
};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::{test_blinding, ZolanaProgramTest, RING_TEST_PROGRAM_ID};
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
use super::receipt::{prove_receipt, RealReceipt};
use super::transact::{current_tree_roots, tree_progress};

pub fn merge_verifying_key(input_count: usize) -> &'static Groth16Verifyingkey<'static> {
    match input_count {
        8 => &merge_8_1::VERIFYINGKEY,
        36 => &merge_36_1::VERIFYINGKEY,
        other => panic!("no committed verifying key for a {other}-input merge"),
    }
}

pub fn merge_receipt_verifying_key(input_count: usize) -> &'static Groth16Verifyingkey<'static> {
    match input_count {
        8 => &merge_receipt_8_1::VERIFYINGKEY,
        36 => &merge_receipt_36_1::VERIFYINGKEY,
        other => panic!("no committed verifying key for a {other}-input receipt-backed merge"),
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
        owner,
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
            assert_eq!((utxo.asset, utxo.amount), (SOL_MINT, 0));
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
    pub cache: Option<Pubkey>,
    pub receipt: Option<Pubkey>,
}

impl RealMerge {
    pub fn instruction(&self, pool: &Pool) -> solana_instruction::Instruction {
        MergeTransact {
            input_tree: pool.tree,
            output_tree: pool.tree,
            payer: pool.rpc.payer.pubkey(),
            user_record: self.user_record,
            data: self.data.clone(),
            cache: self.cache,
            receipt: self.receipt,
        }
        .instruction()
    }
}

pub struct PaddedMerge {
    pub spends: Vec<TransferSpendInput>,
    pub output: SppProofOutputUtxo,
}

impl PaddedMerge {
    pub fn assemble(
        deposits: &RealDeposits,
        keypair: &ShieldedKeypair,
        tree: Pubkey,
        tree_id: u16,
        input_count: usize,
    ) -> Self {
        let nullifier_key = keypair.nullifier_key();
        let nullifier_root = deposits.nullifier_root;
        let merkle_context = MerkleContext { tree_type: 0, tree };
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

        let first_nullifier = deposits
            .deposits
            .first()
            .expect("at least one real input")
            .nullifier;
        let mut spends: Vec<TransferSpendInput> = deposits
            .deposits
            .iter()
            .map(|deposit| TransferSpendInput {
                utxo: deposit.utxo.clone(),
                nullifier_key: nullifier_key.clone(),
                data_hash: None,
                ring_data_hash: None,
                tree_id,
                proof: Some(SpendProof {
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
                }),
                nullifier_proof: None,
            })
            .collect();
        for slot in deposits.deposits.len()..input_count {
            let slot_tag = u8::try_from(slot).expect("merge slot fits a byte");
            let dummy_nullifier = merge_dummy_nullifier(&nullifier_key, &first_nullifier, slot_tag)
                .expect("dummy nullifier");
            let proof = deposits
                .nullifier_tree
                .get_non_inclusion_proof(&BigUint::from_bytes_be(&dummy_nullifier))
                .expect("dummy non-inclusion proof");
            spends.push(TransferSpendInput {
                utxo: Utxo {
                    owner: PublicKey::zeroed(),
                    asset: SOL_MINT,
                    amount: 0,
                    blinding: test_blinding(slot_tag.checked_add(10).expect("dummy blinding tag")),
                    ring_program_id: None,
                    data: Data::default(),
                },
                nullifier_key: nullifier_key.clone(),
                data_hash: None,
                ring_data_hash: None,
                tree_id,
                proof: None,
                nullifier_proof: Some(to_non_inclusion(dummy_nullifier, &proof)),
            });
        }

        let mut output = SppProofOutputUtxo::new(
            SOL_MINT,
            0,
            keypair.shielded_address().expect("shielded address"),
        )
        .expect("merge output");
        output.blinding =
            merge_output_blinding(&nullifier_key, &first_nullifier).expect("output blinding");

        Self { spends, output }
    }
}

pub struct RealMergeProof {
    pub input_count: usize,
    pub real_input_count: usize,
}

/// Deposits and the padded spend set a real merge proof is built from.
struct MergeSetup {
    input_count: usize,
    tree_id: u16,
    user_record: Pubkey,
    deposits: RealDeposits,
    spends: Vec<TransferSpendInput>,
    output: SppProofOutputUtxo,
    owner_public_key: PublicKey,
    nullifier_key: NullifierKey,
}

/// A receipt-backed merge with the receipt it spends from.
pub struct ReceiptBackedMerge {
    pub merge: RealMerge,
    pub receipt: RealReceipt,
}

impl RealMergeProof {
    pub fn build(self, pool: &mut Pool) -> RealMerge {
        self.build_with_cache(pool, None)
    }

    pub fn build_cached(self, pool: &mut Pool, cache: MergeCacheTarget) -> RealMerge {
        self.build_with_cache(pool, Some(cache))
    }

    fn setup(self, pool: &mut Pool) -> MergeSetup {
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

        let PaddedMerge { spends, output } =
            PaddedMerge::assemble(&deposits, &keypair, tree, tree_id, input_count);
        MergeSetup {
            input_count,
            tree_id,
            user_record,
            deposits,
            spends,
            output,
            owner_public_key,
            nullifier_key,
        }
    }

    fn build_with_cache(self, pool: &mut Pool, cache: Option<MergeCacheTarget>) -> RealMerge {
        let setup = self.setup(pool);
        let input_count = setup.input_count;
        let result = MergeProver {
            inputs: setup.spends,
            output: setup.output,
            expiry_unix_ts: u64::MAX,
            signing_pubkey: setup.owner_public_key,
            nullifier_key: setup.nullifier_key,
            output_tree_id: setup.tree_id,
            cache,
            receipt: None,
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
        verify_merge_locally(
            &proof,
            result.public_input_hash,
            merge_verifying_key(input_count),
        );
        let merge_proof = ProofCompressed::try_from(proof)
            .expect("compress merge proof")
            .to_merge_proof()
            .expect("merge rail proof");

        RealMerge {
            data: result.instruction_data(merge_proof),
            nullifiers: result.nullifiers.clone(),
            user_record: setup.user_record,
            cache: cache.map(|target| target.address),
            receipt: None,
        }
    }

    /// Build a receipt-backed merge: a receipt over the merge's nullifiers is
    /// proven (`nullifier-receipt`) and the merge itself is membership-only
    /// (`merge-receipt`). The receipt is not published; see
    /// [`RealReceipt::publish`].
    pub fn build_receipt_backed(self, pool: &mut Pool, nonce: u64) -> ReceiptBackedMerge {
        let setup = self.setup(pool);
        let input_count = setup.input_count;
        let capacity = *RECEIPT_CAPACITIES
            .iter()
            .find(|capacity| usize::from(**capacity) >= input_count)
            .expect("a receipt capacity fits the merge shape");
        let address = CreateReceipt {
            payer: pool.rpc.payer.pubkey(),
            tree: pool.tree,
            data: CreateReceiptData { nonce, capacity },
        }
        .receipt();

        let result = MergeProver {
            inputs: setup.spends,
            output: setup.output,
            expiry_unix_ts: u64::MAX,
            signing_pubkey: setup.owner_public_key,
            nullifier_key: setup.nullifier_key,
            output_tree_id: setup.tree_id,
            cache: None,
            receipt: Some(MergeReceiptTarget { address, offset: 0 }),
        }
        .build()
        .expect("build merge witness");
        assert_eq!(result.nullifiers.len(), input_count);

        let receipt = prove_receipt(
            pool,
            &setup.deposits.nullifier_tree,
            &result.nullifiers,
            usize::from(capacity),
            nonce,
        );
        assert_eq!(receipt.address, address);

        let proof = ProverClient::local()
            .prove_merge_receipt(&result.inputs)
            .expect("prove receipt-backed merge");
        verify_merge_locally(
            &proof,
            result.public_input_hash,
            merge_receipt_verifying_key(input_count),
        );
        let merge_proof = ProofCompressed::try_from(proof)
            .expect("compress merge proof")
            .to_merge_proof()
            .expect("merge rail proof");

        ReceiptBackedMerge {
            merge: RealMerge {
                data: result.instruction_data(merge_proof),
                nullifiers: result.nullifiers.clone(),
                user_record: setup.user_record,
                cache: None,
                receipt: Some(address),
            },
            receipt,
        }
    }
}

fn verify_merge_locally(
    proof: &Proof,
    public_input_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey<'static>,
) {
    let public_inputs = [public_input_hash];
    let mut verifier =
        Groth16Verifier::new(&proof.a, &proof.b, &proof.c, &public_inputs, verifying_key)
            .expect("construct merge verifier");
    verifier.verify().expect("merge proof verifies locally");
}

pub fn activate_ring_test_program(pool: &mut Pool) -> Pubkey {
    pool.rpc
        .load_ring_test_program()
        .expect("load the ring test program");
    let authority = pool.authority.insecure_clone();
    pool.rpc
        .create_activated_ring_config(&authority, &authority.pubkey(), &authority, true)
        .expect("create an activated ring config");
    Pubkey::new_from_array(RING_TEST_PROGRAM_ID)
}

pub fn ring_cache_identity(keypair: &ShieldedKeypair, operation_id: &[u8; 32]) -> [u8; 32] {
    let nullifier_pk = keypair.nullifier_key().pubkey().expect("nullifier pubkey");
    let user_owner_hash =
        owner_hash(&keypair.signing_pubkey(), &nullifier_pk).expect("user owner hash");
    Poseidon::hashv(&[&user_owner_hash, operation_id]).expect("ring cache identity")
}

pub struct RingZeroDeposits<'a> {
    pub rpc: &'a mut ZolanaProgramTest,
    pub tree: Pubkey,
    pub depositor: &'a Keypair,
    pub ring_program_id: Pubkey,
    pub owner: PublicKey,
    pub nullifier_key: &'a NullifierKey,
    pub tree_id: u16,
    pub count: usize,
}

impl RingZeroDeposits<'_> {
    pub fn deposit(self) -> RealDeposits {
        assert!(self.count > 0, "at least one real deposit is required");
        let (utxo_next, _) = tree_progress(self.rpc, &self.tree);
        assert_eq!(utxo_next, 0, "the pool's UTXO tree must still be empty");

        let zero = [0u8; 32];
        let ring = self.ring_program_id;
        let nullifier_pk = self.nullifier_key.pubkey().expect("nullifier pubkey");
        let owner_field = owner_hash(&self.owner, &nullifier_pk).expect("owner field");
        let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
        let mut utxos = Vec::with_capacity(self.count);
        for index in 0..self.count {
            let tag = u8::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(50))
                .expect("ring deposit blinding tag");
            let blinding = test_blinding(tag);
            let data = self.rpc.ring_sol_shield_data(0, owner_field, blinding);
            let event = self
                .rpc
                .ring_deposit(&self.tree, self.depositor, &data)
                .expect("proofless zero ring deposit");
            let utxo = Utxo {
                owner: self.owner,
                asset: SOL_MINT,
                amount: 0,
                blinding,
                ring_program_id: Some(ring),
                data: Data::default(),
            };
            let utxo_hash = utxo
                .hash(&nullifier_pk, &zero, &zero, self.tree_id)
                .expect("utxo hash");
            assert_eq!(utxo_hash, event.utxo_hash, "ring deposit leaf");
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

pub struct RealRingMerge {
    pub data: MergeRingIxData,
    pub nullifiers: Vec<[u8; 32]>,
    pub ring_program_id: Pubkey,
    pub cache: Option<Pubkey>,
}

impl RealRingMerge {
    pub fn instruction(&self, pool: &Pool) -> solana_instruction::Instruction {
        MergeRing {
            input_tree: pool.tree,
            output_tree: pool.tree,
            ring_program_id: self.ring_program_id,
            payer: pool.rpc.payer.pubkey(),
            data: self.data.merge.clone(),
            output_ring_data_hash: self.data.output_ring_data_hash,
            cache: self.cache,
        }
        .instruction()
    }
}

pub struct RealRingMergeProof {
    pub input_count: usize,
    pub real_input_count: usize,
}

impl RealRingMergeProof {
    pub fn build(self, pool: &mut Pool) -> RealRingMerge {
        self.build_with_cache(pool, None)
    }

    pub fn build_cached(self, pool: &mut Pool, cache: MergeRingCacheTarget) -> RealRingMerge {
        self.build_with_cache(pool, Some(cache))
    }

    fn build_with_cache(
        self,
        pool: &mut Pool,
        cache: Option<MergeRingCacheTarget>,
    ) -> RealRingMerge {
        let RealRingMergeProof {
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

        let ring_program_id = activate_ring_test_program(pool);
        let payer = pool.rpc.payer.insecure_clone();
        let depositor = pool.funded_signer(5_000_000_000);
        let tree = pool.tree;
        let tree_id = pool.tree_id;
        let keypair = ShieldedKeypair::from_keypair(&payer).expect("shielded keypair");
        let nullifier_key = keypair.nullifier_key();
        let owner_public_key = keypair.signing_pubkey();

        let deposits = RingZeroDeposits {
            rpc: &mut pool.rpc,
            tree,
            depositor: &depositor,
            ring_program_id,
            owner: owner_public_key,
            nullifier_key: &nullifier_key,
            tree_id,
            count: real_input_count,
        }
        .deposit();

        let PaddedMerge { spends, output } =
            PaddedMerge::assemble(&deposits, &keypair, tree, tree_id, input_count);

        let result = MergeRingProver {
            inputs: spends,
            output,
            expiry_unix_ts: u64::MAX,
            signing_pubkey: owner_public_key,
            nullifier_key,
            output_tree_id: tree_id,
            ring_program_id,
            cache,
        }
        .build()
        .expect("build ring merge witness");
        assert_eq!(
            result.nullifiers.len(),
            input_count,
            "the built ring merge must keep the requested shape"
        );

        let proof = ProverClient::local()
            .prove_merge_ring(&result.inputs)
            .expect("prove ring merge");
        let merge_proof = ProofCompressed::try_from(proof)
            .expect("compress ring merge proof")
            .to_merge_proof()
            .expect("merge rail proof");

        RealRingMerge {
            data: result.ring_instruction_data(merge_proof, [0u8; 32]),
            nullifiers: result.nullifiers.clone(),
            ring_program_id,
            cache: cache.map(|target| target.address),
        }
    }
}
