use std::{
    mem::size_of,
    ops::{Deref, DerefMut},
};

use crate::verify::{
    verify_batch_address_update, verify_batch_append_with_proofs, verify_batch_update,
    CompressedProof,
};
use crate::zero_copy::ZeroCopyError;
use light_account_checks::{
    checks::{check_account_info, check_discriminator},
    discriminator::Discriminator,
    AccountView,
};
use light_hasher::{
    hash_chain::create_hash_chain_from_array, hash_to_field_size::hash_to_bn254_field_size_be,
    Hasher, Poseidon,
};
use light_merkle_tree_metadata::{
    errors::MerkleTreeMetadataError,
    events::{batch::BatchEvent, MerkleTreeEvent},
    merkle_tree::MerkleTreeMetadata,
    QueueType, TreeType, ADDRESS_MERKLE_TREE_TYPE_V2, ADDRESS_QUEUE_TYPE_V2,
    INPUT_STATE_QUEUE_TYPE_V2, OUTPUT_STATE_QUEUE_TYPE_V2, STATE_MERKLE_TREE_TYPE_V2,
};
use solana_address::Address as Pubkey;

use super::batch::Batch;
use crate::{
    batch::BatchState,
    constants::ADDRESS_TREE_INIT_ROOT_40,
    errors::BatchedMerkleTreeError,
    merkle_tree_metadata::BatchedMerkleTreeMetadata,
    queue::{insert_into_current_queue_batch, BatchedQueueAccount},
    zero_copy::TreeAccountLayout,
    BorshDeserialize, BorshSerialize,
};

/// Public inputs:
/// 1. old root (last root in root history)
/// 2. new root (send to chain)
/// 3. leaf hash chain (in hash_chain store)
#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy, BorshDeserialize, BorshSerialize)]
pub struct InstructionDataBatchNullifyInputs {
    pub new_root: [u8; 32],
    pub compressed_proof: CompressedProof,
}

/// Public inputs:
/// 1. old root (last root in root history)
/// 2. new root (send to chain)
/// 3. leaf hash chain (in hash_chain store)
/// 4. next index (get from metadata)
pub type InstructionDataAddressAppendInputs = InstructionDataBatchNullifyInputs;

/// Public inputs:
/// 1. old root (last root in root history)
/// 2. new root (send to chain)
/// 3. leaf hash chain (in hash_chain store)
/// 4. start index (get from batch)
pub type InstructionDataBatchAppendInputs = InstructionDataBatchNullifyInputs;

/// Batched Merkle tree zero copy account.
/// The account is used for batched state and address Merkle trees,
/// plus the input and address queues.
///
/// Tree roots can be used in zk proofs
/// outside of Light Protocol programs.
///
/// To access a tree root by index use:
/// - get_root_by_index
pub struct BatchedMerkleTreeAccount<
    'a,
    const RH: usize,
    const NUM_ITERS: usize,
    const BLOOM: usize,
    const ZKP: usize,
> {
    pubkey: Pubkey,
    pub(crate) layout: &'a mut TreeAccountLayout<RH, NUM_ITERS, BLOOM, ZKP>,
}

fn create_nullifier(
    account_hash: &[u8; 32],
    leaf_index: u64,
    tx_hash: &[u8; 32],
) -> Result<[u8; 32], BatchedMerkleTreeError> {
    let mut leaf_index_bytes = [0u8; 32];
    leaf_index_bytes[24..].copy_from_slice(leaf_index.to_be_bytes().as_slice());
    Ok(Poseidon::hashv(&[
        account_hash.as_slice(),
        &leaf_index_bytes,
        tx_hash,
    ])?)
}

impl<const RH: usize, const NUM_ITERS: usize, const BLOOM: usize, const ZKP: usize> Discriminator
    for BatchedMerkleTreeAccount<'_, RH, NUM_ITERS, BLOOM, ZKP>
{
    const LIGHT_DISCRIMINATOR: [u8; 8] = *b"BatchMta";
    const LIGHT_DISCRIMINATOR_SLICE: &'static [u8] = b"BatchMta";
}

impl<const RH: usize, const NUM_ITERS: usize, const BLOOM: usize, const ZKP: usize> std::fmt::Debug
    for BatchedMerkleTreeAccount<'_, RH, NUM_ITERS, BLOOM, ZKP>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchedMerkleTreeAccount")
            .field("pubkey", &self.pubkey)
            .field("metadata", &self.layout.metadata)
            .finish()
    }
}

impl<const RH: usize, const NUM_ITERS: usize, const BLOOM: usize, const ZKP: usize> PartialEq
    for BatchedMerkleTreeAccount<'_, RH, NUM_ITERS, BLOOM, ZKP>
{
    fn eq(&self, other: &Self) -> bool {
        self.pubkey == other.pubkey
            && self.layout.discriminator == other.layout.discriminator
            && self.layout.metadata == other.layout.metadata
            && self.layout.root_history == other.layout.root_history
            && self.layout.bloom_filters == other.layout.bloom_filters
            && self.layout.hash_chains == other.layout.hash_chains
    }
}

impl<'a, const RH: usize, const NUM_ITERS: usize, const BLOOM: usize, const ZKP: usize>
    BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>
{
    /// Deserialize a batched state Merkle tree from account info.
    /// Should be used in solana programs.
    /// Checks that:
    /// 1. the account owner is `program_id`,
    /// 2. discriminator,
    /// 3. tree type is batched state tree type.
    pub fn state_from_account_info(
        program_id: &[u8; 32],
        account_info: &mut AccountView,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
        Self::from_account_info::<STATE_MERKLE_TREE_TYPE_V2>(program_id, account_info)
    }

    /// Deserialize a state BatchedMerkleTreeAccount from bytes.
    /// Checks the discriminator and tree type. Available on both host and
    /// Solana SBF targets; callers that also need program-owner enforcement
    /// should use `state_from_account_info`.
    pub fn state_from_bytes(
        account_data: &'a mut [u8],
        pubkey: &Pubkey,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
        check_discriminator::<Self>(account_data)?;
        Self::from_bytes::<STATE_MERKLE_TREE_TYPE_V2>(account_data, pubkey)
    }

    /// Deserialize a batched address Merkle tree from account info.
    /// Should be used in solana programs.
    /// Checks that:
    /// 1. the account owner is `program_id`,
    /// 2. discriminator,
    /// 3. tree type is batched address tree type.
    pub fn address_from_account_info(
        program_id: &[u8; 32],
        account_info: &mut AccountView,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
        Self::from_account_info::<ADDRESS_MERKLE_TREE_TYPE_V2>(program_id, account_info)
    }

    fn from_account_info<const TREE_TYPE: u64>(
        program_id: &[u8; 32],
        account_info: &mut AccountView,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
        check_account_info::<Self>(program_id, account_info)?;
        let pubkey = *account_info.address();
        let mut data = account_info.try_borrow_mut()?;

        // Necessary to convince the borrow checker.
        let data_slice: &'a mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(data.as_mut_ptr(), data.len()) };
        Self::from_bytes::<TREE_TYPE>(data_slice, &pubkey)
    }

    /// Deserialize an address BatchedMerkleTreeAccount from bytes. Checks
    /// the discriminator and tree type. Available on both host and Solana
    /// SBF targets; callers that also need program-owner enforcement should
    /// use `address_from_account_info`.
    pub fn address_from_bytes(
        account_data: &'a mut [u8],
        pubkey: &Pubkey,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
        Self::from_bytes::<ADDRESS_MERKLE_TREE_TYPE_V2>(account_data, pubkey)
    }

    fn from_bytes<const TREE_TYPE: u64>(
        account_data: &'a mut [u8],
        pubkey: &Pubkey,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
        let layout: &'a mut TreeAccountLayout<RH, NUM_ITERS, BLOOM, ZKP> =
            wincode::deserialize_mut(account_data).map_err(|_| ZeroCopyError::Size)?;
        if layout.metadata.tree_type != TREE_TYPE {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }
        Ok(BatchedMerkleTreeAccount {
            pubkey: *pubkey,
            layout,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn init(
        account_data: &'a mut [u8],
        pubkey: &Pubkey,
        metadata: MerkleTreeMetadata,
        root_history_capacity: u32,
        input_queue_batch_size: u64,
        input_queue_zkp_batch_size: u64,
        height: u32,
        tree_type: TreeType,
        // Init root for indexed (`AddressV2`) trees. `None` uses the default
        // address sentinel root (`ADDRESS_TREE_INIT_ROOT_40`). Pass `Some` to
        // seed an indexed tree with a different sentinel, e.g. the BN254 `p-1`
        // nullifier-tree root (`NULLIFIER_TREE_INIT_ROOT_40`). Ignored for
        // `StateV2` trees.
        address_init_root: Option<[u8; 32]>,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
        if account_data.len() != size_of::<TreeAccountLayout<RH, NUM_ITERS, BLOOM, ZKP>>() {
            return Err(ZeroCopyError::Size.into());
        }

        let layout: &'a mut TreeAccountLayout<RH, NUM_ITERS, BLOOM, ZKP> =
            wincode::deserialize_mut(account_data).map_err(|_| ZeroCopyError::Size)?;
        Self::init_from_layout(
            layout,
            pubkey,
            metadata,
            root_history_capacity,
            input_queue_batch_size,
            input_queue_zkp_batch_size,
            height,
            tree_type,
            address_init_root,
        )
    }

    pub fn from_layout(
        pubkey: &Pubkey,
        layout: &'a mut TreeAccountLayout<RH, NUM_ITERS, BLOOM, ZKP>,
    ) -> BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP> {
        BatchedMerkleTreeAccount {
            pubkey: *pubkey,
            layout,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn init_from_layout(
        layout: &'a mut TreeAccountLayout<RH, NUM_ITERS, BLOOM, ZKP>,
        pubkey: &Pubkey,
        metadata: MerkleTreeMetadata,
        root_history_capacity: u32,
        input_queue_batch_size: u64,
        input_queue_zkp_batch_size: u64,
        height: u32,
        tree_type: TreeType,
        address_init_root: Option<[u8; 32]>,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
        layout.discriminator = Self::LIGHT_DISCRIMINATOR;

        let account_metadata = &mut layout.metadata;

        // Precompute Merkle tree pubkey hash for use in system program.
        // The compressed account hash depends on the Merkle tree pubkey and leaf index.
        // Poseidon hashes required input size < bn254 field size.
        // To map 256bit pubkeys to < 254bit field size, we hash Pubkeys
        // and truncate the hash to 31 bytes/248 bits.
        account_metadata.hashed_pubkey = hash_to_bn254_field_size_be(&pubkey.to_bytes());
        account_metadata.metadata = metadata;
        account_metadata.root_history_capacity = root_history_capacity;
        account_metadata.height = height;
        account_metadata.tree_type = tree_type as u64;
        account_metadata.capacity = 2u64.pow(height);
        account_metadata
            .queue_batches
            .init(input_queue_batch_size, input_queue_zkp_batch_size)?;

        // Root history is read from zero-initialized account memory.
        // Zeroed roots enable unified logic to zero out roots,
        // an unitialized root history vector would be an edge case.
        //
        // Initialize root history array with initial root.
        // Batch zkp updates require an input Merkle root.
        // The initial root is written at index 0 and the write head advanced to 1.
        let init_root = if tree_type == TreeType::StateV2 {
            // Root for binary Merkle tree with all zero leaves.
            Some(light_hasher::Poseidon::zero_bytes()[height as usize])
        } else if tree_type == TreeType::AddressV2 {
            // Sanity check since init value is hardcoded.
            #[cfg(not(test))]
            if height != 40 {
                return Err(MerkleTreeMetadataError::InvalidHeight.into());
            }
            // The initialized indexed Merkle tree contains two elements.
            // 1. element:
            // H(0, 1, 452312848583266388373324160190187140051835877600158453279131187530910662655)
            // 2. element:
            // H(452312848583266388373324160190187140051835877600158453279131187530910662655, 0, 0)
            // ... other elements: 0
            layout.metadata.next_index = 1;
            // Initialized indexed Merkle tree root.
            // See https://github.com/helius-labs/privacy-program-libs/blob/c143c24f95c901e2eac96bc2bd498719958192cf/program-libs/indexed-merkle-tree/src/reference.rs#L69
            Some(address_init_root.unwrap_or(ADDRESS_TREE_INIT_ROOT_40))
        } else {
            None
        };
        if let Some(root) = init_root {
            if let Some(slot) = layout.root_history.get_mut(0) {
                *slot = root;
            }
            layout.metadata.root_history_current_index = 1;
        }
        let next_index = layout.metadata.next_index;

        for (i, batches) in layout.metadata.queue_batches.batches.iter_mut().enumerate() {
            *batches = Batch::new(
                input_queue_batch_size,
                input_queue_zkp_batch_size,
                input_queue_batch_size * (i as u64) + next_index,
            );
        }

        Ok(BatchedMerkleTreeAccount {
            pubkey: *pubkey,
            layout,
        })
    }

    /// Update the tree from the output queue account.
    /// 1. Checks that the tree and queue are associated.
    /// 2. Updates the tree with the output queue account.
    /// 3. Returns the batch append event.
    pub fn update_tree_from_output_queue_account_info<const QBATCH: usize, const QZKP: usize>(
        &mut self,
        program_id: &[u8; 32],
        queue_account_info: &mut AccountView,
        instruction_data: InstructionDataBatchAppendInputs,
    ) -> Result<MerkleTreeEvent, BatchedMerkleTreeError> {
        if self.tree_type != TreeType::StateV2 as u64 {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }
        let queue_account = &mut BatchedQueueAccount::<QBATCH, QZKP>::output_from_account_info(
            program_id,
            queue_account_info,
        )?;
        queue_account.check_is_associated(&self.pubkey)?;
        self.update_tree_from_output_queue_account(queue_account, instruction_data)
    }

    /// Update the tree from the output queue account.
    /// 1. Create public inputs hash.
    /// 2. Verify update proof and update tree account.
    ///    2.1. Verify proof.
    ///    2.2. Increment sequence number.
    ///    2.3. Increment next index.
    ///    2.4. Append new root to root history.
    /// 3. Mark zkp batch as inserted in the merkle tree.
    ///    3.1. Checks that the batch is ready.
    ///    3.2. Increment the number of inserted zkps.
    ///    3.3. If all zkps are inserted, set batch state to inserted.
    /// 4. Increment next full batch index if inserted.
    /// 5. Zero out previous batch bloom filter of input queue
    ///    if current batch is 50% inserted.
    /// 6. Return the batch append event.
    ///
    /// Note: when proving inclusion by index in
    /// value array we need to insert the value into a bloom_filter once it is
    /// inserted into the tree. Check this with get_num_inserted_zkps
    pub fn update_tree_from_output_queue_account<const QBATCH: usize, const QZKP: usize>(
        &mut self,
        queue_account: &mut BatchedQueueAccount<QBATCH, QZKP>,
        instruction_data: InstructionDataBatchAppendInputs,
    ) -> Result<MerkleTreeEvent, BatchedMerkleTreeError> {
        self.check_tree_is_full(Some(queue_account.batch_metadata.zkp_batch_size))?;
        let pending_batch_index = queue_account.batch_metadata.pending_batch_index as usize;
        let new_root = instruction_data.new_root;
        let circuit_batch_size = queue_account.batch_metadata.zkp_batch_size;
        let first_ready_zkp_batch_index = queue_account.batch_metadata.batches[pending_batch_index]
            .get_first_ready_zkp_batch()?;

        // 1. Create public inputs hash.
        let public_input_hash = {
            let leaves_hash_chain = *queue_account
                .layout
                .hash_chains
                .get(pending_batch_index)
                .and_then(|chain| chain.get(first_ready_zkp_batch_index as usize))
                .ok_or(BatchedMerkleTreeError::InvalidIndex)?;
            let old_root = self
                .get_latest_root()
                .ok_or(BatchedMerkleTreeError::InvalidIndex)?;
            let mut start_index_bytes = [0u8; 32];
            start_index_bytes[24..].copy_from_slice(&self.next_index.to_be_bytes());
            create_hash_chain_from_array([
                *old_root,
                new_root,
                leaves_hash_chain,
                start_index_bytes,
            ])?
        };

        // 2. Verify update proof and update tree account.
        let (old_next_index, new_next_index) = self.verify_update::<OUTPUT_STATE_QUEUE_TYPE_V2>(
            circuit_batch_size,
            instruction_data.compressed_proof,
            public_input_hash,
            new_root,
        )?;

        let root_index = self.latest_root_index() as u32;

        // Update metadata and batch.
        {
            // 3. Mark zkp batch as inserted in the merkle tree.
            let pending_batch_state = queue_account.batch_metadata.batches[pending_batch_index]
                .mark_as_inserted_in_merkle_tree(
                    self.sequence_number,
                    root_index,
                    self.root_history_capacity,
                )?;
            // 4. Increment next full batch index if inserted.
            queue_account
                .batch_metadata
                .increment_pending_batch_index_if_inserted(pending_batch_state);
            // 5. Zero out previous batch bloom filter
            //     if current batch is 50% inserted.
            // Needs to be executed post mark_as_inserted_in_merkle_tree.
            self.zero_out_previous_batch_bloom_filter()?;
        }
        // 6. Return the batch append event.
        Ok(MerkleTreeEvent::BatchAppend(BatchEvent {
            merkle_tree_pubkey: self.pubkey.to_bytes(),
            output_queue_pubkey: Some(queue_account.pubkey().to_bytes()),
            batch_index: pending_batch_index as u64,
            zkp_batch_size: circuit_batch_size,
            zkp_batch_index: first_ready_zkp_batch_index,
            new_root,
            root_index,
            sequence_number: self.sequence_number,
            old_next_index,
            new_next_index,
        }))
    }

    /// Update the tree from the input queue account.
    pub fn update_tree_from_input_queue(
        &mut self,
        instruction_data: InstructionDataBatchNullifyInputs,
    ) -> Result<MerkleTreeEvent, BatchedMerkleTreeError> {
        if self.tree_type != TreeType::StateV2 as u64 {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }
        Ok(MerkleTreeEvent::BatchNullify(
            self.update_input_queue::<INPUT_STATE_QUEUE_TYPE_V2>(instruction_data)?,
        ))
    }

    /// Update the tree from the address queue account.
    pub fn update_tree_from_address_queue(
        &mut self,
        instruction_data: InstructionDataAddressAppendInputs,
    ) -> Result<MerkleTreeEvent, BatchedMerkleTreeError> {
        if self.tree_type != TreeType::AddressV2 as u64 {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }
        self.check_tree_is_full(Some(self.queue_batches.zkp_batch_size))?;
        Ok(MerkleTreeEvent::BatchAddressAppend(
            self.update_input_queue::<ADDRESS_QUEUE_TYPE_V2>(instruction_data)?,
        ))
    }

    /// Update the tree from the input/address queue account.
    /// 1. Create public inputs hash.
    /// 2. Verify update proof and update tree account.
    ///    2.1. Verify proof.
    ///    2.2. Increment sequence number.
    ///    2.3. If address tree increment next index.
    ///    2.4. Append new root to root history.
    /// 3. Mark batch as inserted in the merkle tree.
    ///    3.1. Checks that the batch is ready.
    ///    3.2. Increment the number of inserted zkps.
    ///    3.3. If all zkps are inserted, set the state to inserted.
    /// 4. Zero out previous batch bloom filter if current batch is 50% inserted.
    /// 5. Increment next full batch index if inserted.
    /// 6. Return the batch nullify event.
    #[inline(always)]
    fn update_input_queue<const QUEUE_TYPE: u64>(
        &mut self,
        instruction_data: InstructionDataBatchNullifyInputs,
    ) -> Result<BatchEvent, BatchedMerkleTreeError> {
        let pending_batch_index = self.queue_batches.pending_batch_index as usize;
        let first_ready_zkp_batch_index =
            self.queue_batches.batches[pending_batch_index].get_first_ready_zkp_batch()?;
        let new_root = instruction_data.new_root;
        let circuit_batch_size = self.queue_batches.zkp_batch_size;

        // 1. Create public inputs hash.
        let public_input_hash = {
            let leaves_hash_chain = *self
                .layout
                .hash_chains
                .get(pending_batch_index)
                .and_then(|chain| chain.get(first_ready_zkp_batch_index as usize))
                .ok_or(BatchedMerkleTreeError::InvalidIndex)?;
            let old_root = self
                .get_latest_root()
                .ok_or(BatchedMerkleTreeError::InvalidIndex)?;

            if QueueType::from(QUEUE_TYPE) == QueueType::InputStateV2 {
                create_hash_chain_from_array([*old_root, new_root, leaves_hash_chain])?
            } else if QueueType::from(QUEUE_TYPE) == QueueType::AddressV2 {
                let mut next_index_bytes = [0u8; 32];
                next_index_bytes[24..].copy_from_slice(self.next_index.to_be_bytes().as_slice());
                create_hash_chain_from_array([
                    *old_root,
                    new_root,
                    leaves_hash_chain,
                    next_index_bytes,
                ])?
            } else {
                return Err(MerkleTreeMetadataError::InvalidQueueType.into());
            }
        };

        // 2. Verify update proof and update tree account.
        let (old_next_index, new_next_index) = self.verify_update::<QUEUE_TYPE>(
            circuit_batch_size,
            instruction_data.compressed_proof,
            public_input_hash,
            new_root,
        )?;

        let root_index = self.latest_root_index() as u32;

        // Update queue metadata.
        {
            let root_history_capacity = self.root_history_capacity;
            let sequence_number = self.sequence_number;
            // 3. Mark batch as inserted in the merkle tree.
            let pending_batch_state = self.queue_batches.batches[pending_batch_index]
                .mark_as_inserted_in_merkle_tree(
                    sequence_number,
                    root_index,
                    root_history_capacity,
                )?;
            // 4. Increment next full batch index if inserted.
            self.layout
                .metadata
                .queue_batches
                .increment_pending_batch_index_if_inserted(pending_batch_state);
            // 5. Zero out previous batch bloom filter
            //     if current batch is 50% inserted.
            // Needs to be executed post mark_as_inserted_in_merkle_tree.
            self.zero_out_previous_batch_bloom_filter()?;
        }

        // 6. Return the batch event.
        Ok(BatchEvent {
            merkle_tree_pubkey: self.pubkey.to_bytes(),
            batch_index: pending_batch_index as u64,
            zkp_batch_size: circuit_batch_size,
            zkp_batch_index: first_ready_zkp_batch_index,
            new_root,
            root_index,
            sequence_number: self.sequence_number,
            old_next_index,
            new_next_index,
            output_queue_pubkey: None,
        })
    }

    /// Verify update proof and update the tree.
    /// 1. Verify update proof.
    /// 2. Increment next index (unless queue type is BatchedInput).
    /// 3. Increment sequence number.
    /// 4. Append new root to root history.
    fn verify_update<const QUEUE_TYPE: u64>(
        &mut self,
        batch_size: u64,
        proof: CompressedProof,
        public_input_hash: [u8; 32],
        new_root: [u8; 32],
    ) -> Result<(u64, u64), BatchedMerkleTreeError> {
        // 1. Verify update proof.
        let (old_next_index, new_next_index) = if QUEUE_TYPE == QueueType::OutputStateV2 as u64 {
            verify_batch_append_with_proofs(batch_size, public_input_hash, &proof)?;
            let old_next_index = self.next_index;
            // 2. Increment next index.
            self.increment_merkle_tree_next_index(batch_size);
            (old_next_index, self.next_index)
        } else if QUEUE_TYPE == QueueType::InputStateV2 as u64 {
            let old_next_index = self.nullifier_next_index;
            verify_batch_update(batch_size, public_input_hash, &proof)?;
            // 2. incrementing nullifier next index.
            // This index is used by the indexer to remove elements from the database nullifier queue.
            // Nullifier next index is not used onchain.
            self.nullifier_next_index += batch_size;
            (old_next_index, self.nullifier_next_index)
        } else if QUEUE_TYPE == QueueType::AddressV2 as u64 {
            let old_next_index = self.next_index;
            verify_batch_address_update(batch_size, public_input_hash, &proof)?;
            // 2. Increment next index.
            self.increment_merkle_tree_next_index(batch_size);
            (old_next_index, self.next_index)
        } else {
            return Err(MerkleTreeMetadataError::InvalidQueueType.into());
        };
        // 3. Increment sequence number.
        self.sequence_number += 1;
        // 4. Append new root to root history.
        // root_history is a cyclic vec
        // it will overwrite the oldest root
        // once it is full.
        self.append_root(new_root);
        Ok((old_next_index, new_next_index))
    }

    /// Insert nullifier into current batch.
    /// 1. Check that the tree is a state tree.
    /// 2. Create nullifier Hash(value,leaf_index, tx_hash).
    /// 3. Insert nullifier into current batch.
    ///    3.1. Insert compressed_account_hash into bloom filter.
    ///    (bloom filter enables non-inclusion proofs in later txs)
    ///    3.2. Add nullifier to leaves hash chain.
    ///    (Nullification means, the compressed_account_hash in the tree,
    ///    is overwritten with a nullifier hash)
    ///    3.3. Check that compressed_account_hash
    ///    does not exist in any other bloom filter.
    pub fn insert_nullifier_into_queue(
        &mut self,
        compressed_account_hash: &[u8; 32],
        leaf_index: u64,
        tx_hash: &[u8; 32],
        current_slot: &u64,
    ) -> Result<(), BatchedMerkleTreeError> {
        // Note, no need to check whether the tree is full
        // since nullifier insertions update existing values
        // in the tree and do not append new values.

        // 1. Check that the tree is a state tree.
        if self.tree_type != TreeType::StateV2 as u64 {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }

        // 2. Create nullifier Hash(value,leaf_index, tx_hash).
        let nullifier = create_nullifier(compressed_account_hash, leaf_index, tx_hash)?;
        // 3. Insert nullifier into current batch.
        //      3.1. nullifier is inserted into the hash chain
        //          so that it can be inserted into the tree.
        //          It is ok that the nullifier is tx specific
        //          by depending on the tx_hash since we replace
        //          the compresed account hash with the nullifier
        //          (any value other than the hash itself would nullify it).
        //      3.2. Insert compressed_account_hash into bloom filter
        //          to prevent spending the same value twice.
        //          We cannot insert the nullifier into the bloom filter
        //          since it depends on the tx hash which changes.
        {
            let TreeAccountLayout {
                metadata,
                bloom_filters,
                hash_chains,
                ..
            } = &mut *self.layout;
            let [hc0, hc1] = hash_chains;
            let mut hash_chain_stores = [&mut hc0[..], &mut hc1[..]];
            insert_into_current_queue_batch(
                QueueType::InputStateV2 as u64,
                &mut metadata.queue_batches,
                &mut [],
                Some(bloom_filters),
                &mut hash_chain_stores,
                &nullifier,
                Some(compressed_account_hash),
                None,
                current_slot,
            )?;
        }
        // Increment queue next index so that the indexer can use it like a sequence number.
        self.increment_queue_next_index();
        Ok(())
    }

    pub fn insert_address_into_queue(
        &mut self,
        address: &[u8; 32],
        current_slot: &u64,
    ) -> Result<(), BatchedMerkleTreeError> {
        if self.tree_type != TreeType::AddressV2 as u64 {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }

        // Ensure that all elements that are inserted into the queue
        // can be inserted into the tree.
        self.check_queue_next_index_reached_tree_capacity()?;

        {
            let TreeAccountLayout {
                metadata,
                bloom_filters,
                hash_chains,
                ..
            } = &mut *self.layout;
            let [hc0, hc1] = hash_chains;
            let mut hash_chain_stores = [&mut hc0[..], &mut hc1[..]];
            insert_into_current_queue_batch(
                QueueType::InputStateV2 as u64,
                &mut metadata.queue_batches,
                &mut [],
                Some(bloom_filters),
                &mut hash_chain_stores,
                address,
                Some(address),
                None,
                current_slot,
            )?;
        }
        self.increment_queue_next_index();
        Ok(())
    }

    /// Zero out roots corresponding to batch.sequence numbers > tree.sequence_number.
    /// The batch.sequence_number indicates when roots no longer contain values
    /// from the queue's previous batch, as they've been overwritten by newer updates.
    /// Root from the previous batch can prove inclusion of nullified values.
    /// Hence these roots must not exists after the bloom filter has been zeroed.
    ///
    /// Steps:
    /// 1. Check whether overlapping roots exist.
    /// 2. If yes:
    ///    2.1. Get, first safe root index.
    ///    2.2. Zero out roots from the oldest root to first safe root.
    ///
    /// Note on security for root buffer:
    /// Account {
    ///   bloom_filter: [B0, B1],
    ///     roots: [R0, R1, R2, R3, R4, R5, R6, R7, R8, R9],
    /// }
    ///
    /// Timeslot 0:
    /// - insert into B0 until full
    ///
    /// Timeslot 1:
    /// - insert into B1 until full
    /// - update tree with B0 in 4 partial updates, don't clear B0 yet
    ///   -> R0 -> B0.1
    ///   -> R1 -> B0.2
    ///   -> R2 -> B0.3
    ///   -> R3 -> B0.4 - final B0 root
    ///   B0.sequence_number = 13 (3 + account.root.length)
    ///   B0.root_index = 3
    /// - execute some B1 root updates
    ///   -> R4 -> B1.1
    ///   -> R5 -> B1.2
    ///   -> R6 -> B1.3
    ///   -> R7 -> B1.4 - final B1 (update batch 0) root
    ///   B0.sequence_number = 17 (7 + account.root.length)
    ///   B0.root_index = 7
    ///   current_sequence_number = 8
    ///
    /// Timeslot 2:
    ///     - clear B0
    ///     - current_sequence_number < 14 -> zero out all roots until root index is 3
    ///     - R8 -> 0
    ///     - R9 -> 0
    ///     - R0 -> 0
    ///     - R1 -> 0
    ///     - R2 -> 0
    ///     - now all roots containing values nullified in the final B0 root update are zeroed
    ///     - B0 is safe to clear
    ///
    fn zero_out_roots(&mut self, sequence_number: u64, first_safe_root_index: u32) {
        let TreeAccountLayout {
            metadata,
            root_history,
            ..
        } = &mut *self.layout;
        // 1. Check whether overlapping roots exist.
        let overlapping_roots_exits = sequence_number > metadata.sequence_number;
        if overlapping_roots_exits {
            let mut oldest_root_index = metadata.root_history_current_index as usize;
            // 2.1. Get, num of remaining roots.
            //    Remaining roots have not been updated since
            //    the update of the previous batch therfore allow anyone to prove
            //    inclusion of values nullified in the previous batch.
            let num_remaining_roots = sequence_number - metadata.sequence_number;
            // 2.2. Zero out roots oldest to first safe root index.
            //      Skip one iteration we don't need to zero out
            //      the first safe root.
            for _ in 1..num_remaining_roots {
                if let Some(root) = root_history.get_mut(oldest_root_index) {
                    *root = [0u8; 32];
                }
                oldest_root_index += 1;
                oldest_root_index %= root_history.len();
            }
            // Defensive assert, it should never fail.
            assert_eq!(
                oldest_root_index, first_safe_root_index as usize,
                "Zeroing out roots failed."
            );
        }
    }

    /// Zero out bloom filter of previous batch if 50% of the
    /// current batch has been processed.
    ///
    /// Idea:
    /// 1. Zeroing out the bloom filter of the previous batch is expensive
    ///    -> the forester should do it.
    /// 2. We don't want to zero out the bloom filter when inserting
    ///    the last zkp of a batch for this might result in failing user tx.
    /// 3. Wait until next batch is 50% full as grace period for clients
    ///    to switch from proof by index to proof by zkp
    ///    for values inserted in the previous batch.
    ///
    /// Steps:
    /// 1. Previous batch must be inserted and bloom filter must not be zeroed out.
    /// 2. Current batch must be 50% full
    /// 3. if yes
    ///    3.1. mark bloom filter as zeroed
    ///    3.2. zero out bloom filter
    ///    3.3. zero out roots if needed
    ///
    ///   Initial state: 0 pending -> 1 previous pending even though it was never used
    ///   0 inserted -> 1 pending 0 -> 1 pending 50% - zero out 0 -> 1 inserted
    ///   0 pending -> 1 inserted
    fn zero_out_previous_batch_bloom_filter(&mut self) -> Result<(), BatchedMerkleTreeError> {
        let current_batch = self.queue_batches.pending_batch_index as usize;
        let batch_size = self.queue_batches.batch_size;
        let previous_pending_batch_index = if 0 == current_batch { 1 } else { 0 };
        let current_batch_is_half_full = {
            let current_batch_is_not_inserted =
                self.queue_batches.batches[current_batch].get_state() != BatchState::Inserted;
            let num_inserted_elements =
                self.queue_batches.batches[current_batch].get_num_inserted_elements();
            let current_batch_is_half_full = num_inserted_elements >= batch_size / 2;
            current_batch_is_half_full && current_batch_is_not_inserted
        };

        let previous_pending_batch = self
            .queue_batches
            .batches
            .get_mut(previous_pending_batch_index)
            .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;

        let previous_batch_is_inserted = previous_pending_batch.get_state() == BatchState::Inserted;
        let previous_batch_is_ready =
            previous_batch_is_inserted && !previous_pending_batch.bloom_filter_is_zeroed();

        // Current batch is at least half full, previous batch is inserted, and not zeroed.
        if current_batch_is_half_full && previous_batch_is_ready {
            // 3.1. Mark bloom filter zeroed.
            previous_pending_batch.set_bloom_filter_to_zeroed();
            let seq = previous_pending_batch.sequence_number;
            let root_index = previous_pending_batch.root_index;
            // 3.2. Zero out bloom filter.
            {
                let bloom_filter = self
                    .layout
                    .bloom_filters
                    .get_mut(previous_pending_batch_index)
                    .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;
                bloom_filter.zero();
            }
            // 3.3. Zero out roots if a root exists in root history
            // which allows to prove inclusion of a value
            // that was inserted into the bloom filter just zeroed out.
            {
                self.zero_out_roots(seq, root_index);
            }
        }

        Ok(())
    }

    fn latest_root_index(&self) -> usize {
        let capacity = self.layout.root_history.len();
        if capacity == 0 {
            return 0;
        }
        (self.layout.metadata.root_history_current_index as usize + capacity - 1) % capacity
    }

    fn get_latest_root(&self) -> Option<&[u8; 32]> {
        self.layout.root_history.get(self.latest_root_index())
    }

    fn append_root(&mut self, root: [u8; 32]) {
        let capacity = self.layout.root_history.len();
        if capacity == 0 {
            return;
        }
        let current_index = self.layout.metadata.root_history_current_index as usize;
        if let Some(slot) = self.layout.root_history.get_mut(current_index) {
            *slot = root;
        }
        self.layout.metadata.root_history_current_index = ((current_index + 1) % capacity) as u64;
    }

    /// Return the latest root index.
    pub fn get_root_index(&self) -> u32 {
        self.latest_root_index() as u32
    }

    /// Return the latest root of the tree.
    pub fn get_root(&self) -> Option<[u8; 32]> {
        self.get_latest_root().copied()
    }

    /// Return root from the root history by index.
    pub fn get_root_by_index(&self, index: usize) -> Option<&[u8; 32]> {
        self.layout.root_history.get(index)
    }

    /// Return the full root history.
    pub fn root_history(&self) -> &[[u8; 32]] {
        &self.layout.root_history
    }

    /// Return a reference to the metadata of the tree.
    pub fn get_metadata(&self) -> &BatchedMerkleTreeMetadata {
        &self.layout.metadata
    }

    /// Return a mutable reference to the metadata of the tree.
    pub fn get_metadata_mut(&mut self) -> &mut BatchedMerkleTreeMetadata {
        &mut self.layout.metadata
    }

    /// Check non-inclusion in all bloom filters
    /// which are not zeroed.
    pub fn check_input_queue_non_inclusion(
        &mut self,
        value: &[u8; 32],
    ) -> Result<(), BatchedMerkleTreeError> {
        let TreeAccountLayout {
            metadata,
            bloom_filters,
            ..
        } = &mut *self.layout;
        for i in 0..metadata.queue_batches.num_batches as usize {
            let bloom_filter = bloom_filters
                .get(i)
                .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;
            Batch::check_non_inclusion(value, bloom_filter)?;
        }
        Ok(())
    }

    /// Checks if the tree is full, optionally for a batch size.
    /// If batch_size is provided, checks if there is enough space for the batch.
    pub fn tree_is_full(&self, batch_size: Option<u64>) -> bool {
        self.next_index + batch_size.unwrap_or_default() >= self.capacity
    }

    pub fn check_queue_next_index_reached_tree_capacity(
        &self,
    ) -> Result<(), BatchedMerkleTreeError> {
        if self.queue_batches.next_index >= self.capacity {
            return Err(BatchedMerkleTreeError::TreeIsFull);
        }
        Ok(())
    }

    /// Checks if the tree is full, optionally for a batch size.
    /// If batch_size is provided, checks if there is enough space for the batch.
    pub fn check_tree_is_full(
        &self,
        batch_size: Option<u64>,
    ) -> Result<(), BatchedMerkleTreeError> {
        if self.tree_is_full(batch_size) {
            return Err(BatchedMerkleTreeError::TreeIsFull);
        }
        Ok(())
    }

    pub fn get_associated_queue(&self) -> &Pubkey {
        &self.layout.metadata.metadata.associated_queue
    }

    pub fn pubkey(&self) -> &Pubkey {
        &self.pubkey
    }

    fn increment_merkle_tree_next_index(&mut self, count: u64) {
        self.next_index += count;
    }

    fn increment_queue_next_index(&mut self) {
        self.queue_batches.next_index += 1;
    }
}

#[cfg(feature = "test-only")]
pub mod test_utils {
    use super::*;

    pub fn get_merkle_tree_account_size_default() -> usize {
        get_merkle_tree_account_size::<
            { crate::constants::STATE_TREE_DEFAULT_RH },
            { crate::constants::STATE_TREE_DEFAULT_NUM_ITERS },
            { crate::constants::STATE_TREE_DEFAULT_BLOOM },
            { crate::constants::STATE_TREE_DEFAULT_ZKP },
        >()
    }
}

impl<const RH: usize, const NUM_ITERS: usize, const BLOOM: usize, const ZKP: usize> Deref
    for BatchedMerkleTreeAccount<'_, RH, NUM_ITERS, BLOOM, ZKP>
{
    type Target = BatchedMerkleTreeMetadata;

    fn deref(&self) -> &Self::Target {
        &self.layout.metadata
    }
}

impl<const RH: usize, const NUM_ITERS: usize, const BLOOM: usize, const ZKP: usize> DerefMut
    for BatchedMerkleTreeAccount<'_, RH, NUM_ITERS, BLOOM, ZKP>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.layout.metadata
    }
}

/// Read the metadata and full root history from a batched Merkle tree account
/// without const-generic size parameters. Intended for off-chain readers
/// (indexers) that only need metadata fields and the roots. The root history
/// length is taken from `metadata.root_history_capacity`.
pub fn read_metadata_and_root_history(
    account_data: &[u8],
) -> Result<(&BatchedMerkleTreeMetadata, &[[u8; 32]]), BatchedMerkleTreeError> {
    let after_discriminator = account_data
        .get(light_account_checks::discriminator::DISCRIMINATOR_LEN..)
        .ok_or(ZeroCopyError::Size)?;
    let metadata_size = size_of::<BatchedMerkleTreeMetadata>();
    let metadata_bytes = after_discriminator
        .get(..metadata_size)
        .ok_or(ZeroCopyError::Size)?;
    let metadata: &BatchedMerkleTreeMetadata =
        bytemuck::try_from_bytes(metadata_bytes).map_err(|_| ZeroCopyError::InvalidConversion)?;
    let root_history_bytes_len = (metadata.root_history_capacity as usize)
        .checked_mul(size_of::<[u8; 32]>())
        .ok_or(ZeroCopyError::Size)?;
    let root_history_bytes = after_discriminator
        .get(metadata_size..metadata_size + root_history_bytes_len)
        .ok_or(ZeroCopyError::Size)?;
    let root_history: &[[u8; 32]] =
        bytemuck::try_cast_slice(root_history_bytes).map_err(|_| ZeroCopyError::Size)?;
    Ok((metadata, root_history))
}

/// The Merkle tree account is a single zero-copy cast, so its size is fully
/// determined by the layout const generics.
pub fn get_merkle_tree_account_size<
    const RH: usize,
    const NUM_ITERS: usize,
    const BLOOM: usize,
    const ZKP: usize,
>() -> usize {
    size_of::<TreeAccountLayout<RH, NUM_ITERS, BLOOM, ZKP>>()
}

pub fn assert_nullify_event<
    const RH: usize,
    const NUM_ITERS: usize,
    const BLOOM: usize,
    const ZKP: usize,
>(
    event: MerkleTreeEvent,
    new_root: [u8; 32],
    old_account: &BatchedMerkleTreeAccount<RH, NUM_ITERS, BLOOM, ZKP>,
    mt_pubkey: Pubkey,
) {
    let batch_index = old_account.queue_batches.pending_batch_index;
    let batch = old_account
        .queue_batches
        .batches
        .get(batch_index as usize)
        .unwrap();
    let ref_event = MerkleTreeEvent::BatchNullify(BatchEvent {
        merkle_tree_pubkey: mt_pubkey.to_bytes(),
        output_queue_pubkey: None,
        batch_index,
        zkp_batch_index: batch.get_num_inserted_zkps(),
        new_root,
        root_index: (old_account.get_root_index() + 1) % old_account.root_history_capacity,
        sequence_number: old_account.sequence_number + 1,
        zkp_batch_size: old_account.queue_batches.zkp_batch_size,
        // Next index is not modified by nullify.
        old_next_index: old_account.nullifier_next_index,
        new_next_index: old_account.nullifier_next_index + old_account.queue_batches.zkp_batch_size,
    });
    assert_eq!(event, ref_event);
}

#[allow(clippy::too_many_arguments)]
pub fn assert_batch_append_event_event<
    const RH: usize,
    const NUM_ITERS: usize,
    const BLOOM: usize,
    const ZKP: usize,
    const QBATCH: usize,
    const QZKP: usize,
>(
    event: MerkleTreeEvent,
    new_root: [u8; 32],
    old_output_queue_account: &BatchedQueueAccount<QBATCH, QZKP>,
    old_account: &BatchedMerkleTreeAccount<RH, NUM_ITERS, BLOOM, ZKP>,
    mt_pubkey: Pubkey,
) {
    let batch_index = old_output_queue_account.batch_metadata.pending_batch_index;
    let batch = old_output_queue_account
        .batch_metadata
        .batches
        .get(batch_index as usize)
        .unwrap();
    let ref_event = MerkleTreeEvent::BatchAppend(BatchEvent {
        merkle_tree_pubkey: mt_pubkey.to_bytes(),
        output_queue_pubkey: Some(old_output_queue_account.pubkey().to_bytes()),
        batch_index,
        zkp_batch_index: batch.get_num_inserted_zkps(),
        new_root,
        root_index: (old_account.get_root_index() + 1) % old_account.root_history_capacity,
        sequence_number: old_account.sequence_number + 1,
        zkp_batch_size: old_account.queue_batches.zkp_batch_size,
        old_next_index: old_account.next_index,
        new_next_index: old_account.next_index
            + old_output_queue_account.batch_metadata.zkp_batch_size,
    });
    assert_eq!(event, ref_event);
}

pub fn assert_batch_adress_event<
    const RH: usize,
    const NUM_ITERS: usize,
    const BLOOM: usize,
    const ZKP: usize,
>(
    event: MerkleTreeEvent,
    new_root: [u8; 32],
    old_account: &BatchedMerkleTreeAccount<RH, NUM_ITERS, BLOOM, ZKP>,
    mt_pubkey: Pubkey,
) {
    let batch_index = old_account.queue_batches.pending_batch_index;
    let batch = old_account
        .queue_batches
        .batches
        .get(batch_index as usize)
        .unwrap();
    let ref_event = MerkleTreeEvent::BatchAddressAppend(BatchEvent {
        merkle_tree_pubkey: mt_pubkey.to_bytes(),
        output_queue_pubkey: None,
        batch_index,
        zkp_batch_index: batch.get_num_inserted_zkps(),
        new_root,
        root_index: (old_account.get_root_index() + 1) % old_account.root_history_capacity,
        sequence_number: old_account.sequence_number + 1,
        zkp_batch_size: old_account.queue_batches.zkp_batch_size,
        old_next_index: old_account.next_index,
        new_next_index: old_account.next_index + batch.zkp_batch_size,
    });
    assert_eq!(event, ref_event);
}

#[cfg(feature = "test-only")]
#[cfg(test)]
mod test {
    use rand::{Rng, SeedableRng};

    use super::*;
    use crate::merkle_tree::test_utils::get_merkle_tree_account_size_default;

    #[test]
    fn test_read_metadata_and_root_history() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 3, 1000, 4>()];
        let pubkey = Pubkey::new_unique();
        let (expected_metadata, expected_root_history) = {
            let account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::init(
                &mut account_data,
                &pubkey,
                MerkleTreeMetadata::default(),
                10,
                4,
                1,
                40,
                TreeType::AddressV2,
                None,
            )
            .unwrap();
            (*account.get_metadata(), account.root_history().to_vec())
        };

        let (metadata, root_history) = read_metadata_and_root_history(&account_data).unwrap();
        assert_eq!(*metadata, expected_metadata);
        assert_eq!(root_history, expected_root_history.as_slice());
        assert_eq!(root_history.len(), 10);
        assert_eq!(
            root_history.first(),
            Some(&crate::constants::ADDRESS_TREE_INIT_ROOT_40)
        );
    }

    #[test]
    fn test_read_metadata_and_root_history_buffer_too_small() {
        let account_data = vec![0u8; 8];
        assert_eq!(
            read_metadata_and_root_history(&account_data).unwrap_err(),
            ZeroCopyError::Size.into()
        );
    }

    #[test]
    fn test_from_bytes_invalid_tree_type() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size_default()];
        let account = BatchedMerkleTreeAccount::<200, 3, 20000, 5>::from_bytes::<6>(
            &mut account_data,
            &Pubkey::default(),
        );
        assert_eq!(
            account.unwrap_err(),
            MerkleTreeMetadataError::InvalidTreeType.into()
        );
    }

    #[test]
    fn test_from_bytes_invalid_account_size() {
        let mut account_data = vec![0u8; 200];
        let account = BatchedMerkleTreeAccount::<200, 3, 20000, 5>::from_bytes::<
            STATE_MERKLE_TREE_TYPE_V2,
        >(&mut account_data, &Pubkey::default());
        assert!(matches!(
            account.unwrap_err(),
            crate::errors::BatchedMerkleTreeError::ZeroCopy(ZeroCopyError::Size)
        ));
    }

    #[test]
    fn test_init_invalid_account_size() {
        let mut account_data = vec![0u8; 200];
        let account = BatchedMerkleTreeAccount::<200, 3, 20000, 5>::from_bytes::<
            STATE_MERKLE_TREE_TYPE_V2,
        >(&mut account_data, &Pubkey::default());
        assert!(matches!(
            account.unwrap_err(),
            crate::errors::BatchedMerkleTreeError::ZeroCopy(ZeroCopyError::Size)
        ));
    }

    /// 1. No batch is ready -> nothing should happen.
    /// 2. Batch 0 is inserted but Batch 1 is empty -> nothing should happen.
    /// 3. Batch 0 is inserted but Batch 1 is 25% full (not the required half)
    ///    -> nothing should happen.
    /// 4. Batch 0 is inserted and Batch 1 is full
    ///    -> should zero out all existing roots except the last one.
    /// 5. Batch 1 is inserted and Batch 0 is empty
    ///    -> nothing should happen.
    /// 6. Batch 1 is inserted and Batch 0 is 25% full (not the required half)
    ///    -> nothing should happen.
    /// 7. Batch 1 is inserted and Batch 0 is half full and no overlapping roots exist
    ///    -> bloom filter is zeroed, roots are untouched.
    /// 8. Batch 1 is already zeroed -> nothing should happen
    /// 9. Batch 1 is inserted and Batch 0 is full and overlapping roots exist
    #[test]
    fn test_zero_out() {
        let current_slot = 1;
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 3, 1000, 4>()];
        let batch_size = 4;
        let zkp_batch_size = 1;
        let num_zkp_updates = batch_size / zkp_batch_size;
        let root_history_len = 10;
        let pubkey = Pubkey::new_unique();
        BatchedMerkleTreeAccount::<10, 3, 1000, 4>::init(
            &mut account_data,
            &pubkey,
            MerkleTreeMetadata::default(),
            root_history_len,
            batch_size,
            zkp_batch_size,
            40,
            TreeType::AddressV2,
            None,
        )
        .unwrap();
        let rng = &mut rand::rngs::StdRng::from_seed([0u8; 32]);
        let mut latest_root_0 = [0u8; 32];
        let mut latest_root_1 = [0u8; 32];

        // 1. No batch is ready
        //   -> nothing should happen.
        {
            let mut account = insert_rnd_addresses::<10, 3, 1000, 4>(
                &mut account_data,
                batch_size,
                rng,
                current_slot,
                &pubkey,
            )
            .unwrap();

            assert_eq!(
                account.queue_batches.batches[0].get_state(),
                BatchState::Full
            );
            // simulate batch insertion
            for _ in 0..num_zkp_updates {
                let rnd_root = rng.gen();
                account.append_root(rnd_root);
                latest_root_0 = rnd_root;
                account.layout.metadata.sequence_number += 1;
                let root_index = account.get_root_index();
                println!("root_index: {}", root_index);
                let sequence_number = account.sequence_number;

                let state = account.queue_batches.batches[0]
                    .mark_as_inserted_in_merkle_tree(sequence_number, root_index, root_history_len)
                    .unwrap();
                account
                    .queue_batches
                    .increment_pending_batch_index_if_inserted(state);
            }
            assert_eq!(
                account.queue_batches.batches[0].get_state(),
                BatchState::Inserted
            );
            assert_eq!(account.queue_batches.pending_batch_index, 1);
            let index = account.queue_batches.batches[0].root_index;
            assert_eq!(account.layout.root_history[index as usize], latest_root_0);
        }
        // 2. Batch 0 is inserted but Batch 1 is not half full
        //    -> nothing should happen.
        {
            let mut account_data = account_data.clone();
            let account_data_ref = account_data.clone();
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            account.zero_out_previous_batch_bloom_filter().unwrap();
            assert_eq!(account_data, account_data_ref);
        }

        // 3. Batch 0 is inserted but Batch 1 is not half full
        //    -> nothing should happen.
        {
            // Make Batch 1 almost half full
            {
                insert_rnd_addresses::<10, 3, 1000, 4>(
                    &mut account_data,
                    1,
                    rng,
                    current_slot,
                    &pubkey,
                )
                .unwrap();
            }
            let mut account_data = account_data.clone();
            let account_data_ref = account_data.clone();
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            account.zero_out_previous_batch_bloom_filter().unwrap();
            assert_eq!(account_data, account_data_ref);
        }
        // 4. Batch 0 is inserted and Batch 1 is half full
        //    -> should zero out all existing roots except the last one.
        {
            // Make Batch 1 half full
            {
                insert_rnd_addresses::<10, 3, 1000, 4>(
                    &mut account_data,
                    1,
                    rng,
                    current_slot,
                    &pubkey,
                )
                .unwrap();
            }
            let mut account_data = account_data.clone();
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            println!(
                "currently inserted elements: {:?}",
                account.queue_batches.batches[1].get_num_inserted_elements()
            );
            let previous_roots = account.layout.root_history.to_vec();
            account.zero_out_previous_batch_bloom_filter().unwrap();
            let current_roots = account.layout.root_history.to_vec();
            println!("previous_roots: {:?}", previous_roots);
            assert_ne!(previous_roots, current_roots);
            let root_index = account.queue_batches.batches[0].root_index;
            assert_eq!(
                account.layout.root_history[root_index as usize],
                previous_roots[root_index as usize]
            );
            assert_eq!(
                account.queue_batches.batches[0].get_state(),
                BatchState::Inserted
            );
            assert_eq!(account.queue_batches.batches[0].sequence_number, 14);
            assert_eq!(account.queue_batches.batches[0].root_index, 4);
            assert!(account.queue_batches.batches[0].bloom_filter_is_zeroed());
            assert_eq!(
                account.queue_batches.batches[0].get_num_inserted_zkps(),
                num_zkp_updates
            );

            for i in 0..root_history_len as usize {
                if i == root_index as usize {
                    assert_eq!(account.layout.root_history[i], latest_root_0);
                } else {
                    assert_eq!(account.layout.root_history[i], [0u8; 32]);
                }
            }
        }
        // Make Batch 1 full and insert
        {
            let mut account = insert_rnd_addresses::<10, 3, 1000, 4>(
                &mut account_data,
                2,
                rng,
                current_slot,
                &pubkey,
            )
            .unwrap();

            assert_eq!(
                account.queue_batches.batches[1].get_state(),
                BatchState::Full
            );
            // simulate batch insertion
            for _ in 0..num_zkp_updates {
                let rnd_root = rng.gen();
                account.append_root(rnd_root);
                latest_root_1 = rnd_root;
                account.layout.metadata.sequence_number += 1;
                let root_index = account.get_root_index();
                let sequence_number = account.sequence_number;

                let state = account.queue_batches.batches[1]
                    .mark_as_inserted_in_merkle_tree(sequence_number, root_index, root_history_len)
                    .unwrap();
                account
                    .queue_batches
                    .increment_pending_batch_index_if_inserted(state);
                account.zero_out_previous_batch_bloom_filter().unwrap();
            }
            assert_eq!(
                account.queue_batches.batches[1].get_state(),
                BatchState::Inserted
            );
            assert_eq!(account.queue_batches.pending_batch_index, 0);
            let index = account.queue_batches.batches[1].root_index;
            assert_eq!(account.layout.root_history[index as usize], latest_root_1);
        }
        println!("pre 4");
        // 5. Batch 1 is inserted and Batch 0 is empty
        // -> nothing should happen
        {
            let mut account_data = account_data.clone();
            let account_data_ref = account_data.clone();
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            for batch in account.queue_batches.batches.iter_mut() {
                println!("batch state: {:?}", batch);
            }
            account.zero_out_previous_batch_bloom_filter().unwrap();
            assert_eq!(account_data, account_data_ref);
        }
        println!("pre 5");
        let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
            &mut account_data,
            &pubkey,
        )
        .unwrap();
        for batch in account.queue_batches.batches.iter_mut() {
            println!("batch state: {:?}", batch);
        }
        // 6. Batch 1 is inserted and Batch 0 is almost half full
        // -> nothing should happen
        {
            // Make Batch 0 quater full
            {
                insert_rnd_addresses::<10, 3, 1000, 4>(
                    &mut account_data,
                    1,
                    rng,
                    current_slot,
                    &pubkey,
                )
                .unwrap();
            }
            let mut account_data = account_data.clone();
            let account_data_ref = account_data.clone();
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            account.zero_out_previous_batch_bloom_filter().unwrap();
            assert_eq!(account_data, account_data_ref);
        }
        println!("pre 6");
        // 7. Batch 1 is inserted and Batch 0 is half full but no overlapping roots exist
        // -> bloom filter zeroed, roots untouched
        {
            // Make Batch 0 half full
            {
                insert_rnd_addresses::<10, 3, 1000, 4>(
                    &mut account_data,
                    1,
                    rng,
                    current_slot,
                    &pubkey,
                )
                .unwrap();
            }
            // simulate 10 other batch insertions from an output queue
            {
                let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                    &mut account_data,
                    &pubkey,
                )
                .unwrap();
                for _ in 0..10 {
                    let rnd_root = rng.gen();
                    account.append_root(rnd_root);
                    account.layout.metadata.sequence_number += 1;
                }
            }
            let mut account_data_ref = account_data.clone();
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            account.zero_out_previous_batch_bloom_filter().unwrap();
            let mut account_ref = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data_ref,
                &pubkey,
            )
            .unwrap();
            account_ref.layout.bloom_filters[1].zero();
            account_ref.queue_batches.batches[1].set_bloom_filter_to_zeroed();
            assert_eq!(account.get_metadata(), account_ref.get_metadata());
            assert_eq!(account, account_ref);
        }
        // 8. Batch 1 is already zeroed -> nothing should happen
        {
            let mut account_data_ref = account_data.clone();
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            account.zero_out_previous_batch_bloom_filter().unwrap();
            let account_ref = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data_ref,
                &pubkey,
            )
            .unwrap();
            assert_eq!(account, account_ref);
        }
        // 9. Batch 0 is inserted and Batch 1 is full
        //    -> should zero out Batch 0s bloom filter and overlapping roots
        {
            // Make Batch 0 and 1 full
            {
                insert_rnd_addresses::<10, 3, 1000, 4>(
                    &mut account_data,
                    batch_size + 2,
                    rng,
                    current_slot,
                    &pubkey,
                )
                .unwrap();
            }
            // simulate batch 0 insertion
            {
                let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                    &mut account_data,
                    &pubkey,
                )
                .unwrap();
                for _ in 0..num_zkp_updates {
                    let rnd_root = rng.gen();
                    account.append_root(rnd_root);
                    account.layout.metadata.sequence_number += 1;
                    let root_index = account.get_root_index();
                    let sequence_number = account.sequence_number;

                    let state = account.queue_batches.batches[0]
                        .mark_as_inserted_in_merkle_tree(
                            sequence_number,
                            root_index,
                            root_history_len,
                        )
                        .unwrap();
                    account
                        .queue_batches
                        .increment_pending_batch_index_if_inserted(state);
                }
            }
            println!("pre 9");
            let mut account_data_ref = account_data.clone();
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            assert_eq!(
                account.queue_batches.batches[0].get_state(),
                BatchState::Inserted
            );
            assert_eq!(
                account.queue_batches.batches[1].get_state(),
                BatchState::Full
            );
            account.zero_out_previous_batch_bloom_filter().unwrap();
            let mut account_ref = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data_ref,
                &pubkey,
            )
            .unwrap();
            let root_index = account.queue_batches.batches[0].root_index;
            account_ref.layout.bloom_filters[0].zero();
            account_ref.queue_batches.batches[0].set_bloom_filter_to_zeroed();
            assert_eq!(account.get_metadata(), account_ref.get_metadata());
            for i in 0..root_history_len as usize {
                if i == root_index as usize {
                    continue;
                } else {
                    account_ref.layout.root_history[i] = [0u8; 32];
                }
            }
            assert_eq!(account, account_ref);
        }

        // simulate batch 1 insertion
        {
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            for _ in 0..num_zkp_updates {
                let rnd_root = rng.gen();
                account.append_root(rnd_root);
                account.layout.metadata.sequence_number += 1;
                let root_index = account.get_root_index();
                let sequence_number = account.sequence_number;

                let state = account.queue_batches.batches[1]
                    .mark_as_inserted_in_merkle_tree(sequence_number, root_index, root_history_len)
                    .unwrap();
                account
                    .queue_batches
                    .increment_pending_batch_index_if_inserted(state);
            }
            assert_eq!(
                account.queue_batches.batches[0].get_state(),
                BatchState::Inserted
            );
            assert_eq!(
                account.queue_batches.batches[1].get_state(),
                BatchState::Inserted
            );
            assert!(account.layout.bloom_filters[0].is_zeroed());
            assert!(!account.layout.bloom_filters[1].is_zeroed());
        }
        println!("pre 9.1");

        // Zero out batch 1 with user tx
        {
            // fill batch 0
            {
                insert_rnd_addresses::<10, 3, 1000, 4>(
                    &mut account_data,
                    batch_size,
                    rng,
                    current_slot,
                    &pubkey,
                )
                .unwrap();
            }
            println!("pre 9.2");
            // the insertion into batch 1 fails since the bloom filter of batch 0 is not zeroed out.
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            let address = rng.gen();
            let result = account.insert_address_into_queue(&address, &current_slot);
            assert_eq!(
                result.unwrap_err(),
                BatchedMerkleTreeError::BloomFilterNotZeroed
            );
        }
    }

    fn insert_rnd_addresses<
        'a,
        const RH: usize,
        const NUM_ITERS: usize,
        const BLOOM: usize,
        const ZKP: usize,
    >(
        account_data: &'a mut [u8],
        batch_size: u64,
        rng: &mut rand::prelude::StdRng,
        current_slot: u64,
        pubkey: &Pubkey,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
        let mut account =
            BatchedMerkleTreeAccount::<RH, NUM_ITERS, BLOOM, ZKP>::address_from_bytes(
                account_data,
                pubkey,
            )
            .unwrap();
        for i in 0..batch_size {
            println!("inserting address: {}", i);
            let address = rng.gen();
            account.insert_address_into_queue(&address, &current_slot)?;
        }
        Ok(account)
    }

    #[test]
    fn test_check_queue_next_index_reached_tree_capacity() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 3, 1000, 200>()];
        let batch_size = 200;
        let zkp_batch_size = 1;
        let root_history_len = 10;
        let current_slot = 1;
        let height = 4;
        let tree_capacity = 2u64.pow(height);
        let pubkey = Pubkey::new_unique();
        let account = BatchedMerkleTreeAccount::<10, 3, 1000, 200>::init(
            &mut account_data,
            &pubkey,
            MerkleTreeMetadata::default(),
            root_history_len,
            batch_size,
            zkp_batch_size,
            height,
            TreeType::AddressV2,
            None,
        )
        .unwrap();
        // 1. empty tree is not full
        assert!(account
            .check_queue_next_index_reached_tree_capacity()
            .is_ok());

        let rng = &mut rand::rngs::StdRng::from_seed([0u8; 32]);
        let account = insert_rnd_addresses::<10, 3, 1000, 200>(
            &mut account_data,
            tree_capacity - 1,
            rng,
            current_slot,
            &pubkey,
        )
        .unwrap();
        // 2. tree at capacity - 1 is not full
        assert!(account
            .check_queue_next_index_reached_tree_capacity()
            .is_ok());
        // 3. tree at capacity is full
        let account = insert_rnd_addresses::<10, 3, 1000, 200>(
            &mut account_data,
            1,
            rng,
            current_slot,
            &pubkey,
        )
        .unwrap();
        assert_eq!(
            account
                .check_queue_next_index_reached_tree_capacity()
                .unwrap_err(),
            BatchedMerkleTreeError::TreeIsFull
        );
    }

    #[test]
    fn test_check_non_inclusion() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 3, 1000, 5>()];
        let batch_size = 5;
        let zkp_batch_size = 1;
        let root_history_len = 10;
        let mut current_slot = 1;
        let height = 40;
        let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 5>::init(
            &mut account_data,
            &Pubkey::new_unique(),
            MerkleTreeMetadata::default(),
            root_history_len,
            batch_size,
            zkp_batch_size,
            height,
            TreeType::AddressV2,
            None,
        )
        .unwrap();
        // 1. empty tree is not full
        assert!(!account.tree_is_full(None));

        let mut inserted_elements = vec![];
        let rng = &mut rand::rngs::StdRng::from_seed([0u8; 32]);
        // fill batch 0
        for _ in 0..batch_size {
            let address = rng.gen();
            inserted_elements.push(address);
            account
                .insert_address_into_queue(&address, &current_slot)
                .unwrap();
            assert_eq!(
                account.queue_batches.batches[0].start_slot, 1,
                "Slot should not change unless batch is advanced from inserted to fill."
            );
            current_slot += 1;
        }
        // 1. Non inclusion of inserted elements should fail
        for address in inserted_elements.iter() {
            assert_eq!(
                account
                    .check_input_queue_non_inclusion(address)
                    .unwrap_err(),
                BatchedMerkleTreeError::NonInclusionCheckFailed
            );
        }
        // 2. Non inclusion of random address should pass
        for _ in 0..100 {
            let address = rng.gen();
            account.check_input_queue_non_inclusion(&address).unwrap();
        }
        // fill batch 1
        for _ in 0..batch_size {
            current_slot += 1;
            let address = rng.gen();
            inserted_elements.push(address);
            account
                .insert_address_into_queue(&address, &current_slot)
                .unwrap();
        }
        // 3. Non inclusion of inserted elements should fail
        for address in inserted_elements.iter() {
            assert_eq!(
                account
                    .check_input_queue_non_inclusion(address)
                    .unwrap_err(),
                BatchedMerkleTreeError::NonInclusionCheckFailed
            );
        }
        // clear bloom filter 0
        account.layout.bloom_filters[0].zero();
        // 4. Non inclusion of batch 0 inserted elements should pass
        for address in inserted_elements.iter().take(batch_size as usize) {
            account.check_input_queue_non_inclusion(address).unwrap();
        }
        // 5. Non inclusion of batch 1 inserted elements should fail
        for address in inserted_elements[batch_size as usize..].iter() {
            assert_eq!(
                account
                    .check_input_queue_non_inclusion(address)
                    .unwrap_err(),
                BatchedMerkleTreeError::NonInclusionCheckFailed
            );
        }
        // clear bloom filter 1
        account.layout.bloom_filters[1].zero();
        // 6. Non inclusion of batch 0 inserted elements should pass
        for address in inserted_elements.iter() {
            account.check_input_queue_non_inclusion(address).unwrap();
        }
    }

    #[test]
    fn test_tree_is_full() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 3, 1000, 5>()];
        let batch_size = 5;
        let zkp_batch_size = 1;
        let root_history_len = 10;
        let height = 4;
        let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 5>::init(
            &mut account_data,
            &Pubkey::new_unique(),
            MerkleTreeMetadata::default(),
            root_history_len,
            batch_size,
            zkp_batch_size,
            height,
            TreeType::AddressV2,
            None,
        )
        .unwrap();
        // 1. empty tree is not full
        assert!(!account.tree_is_full(None));
        assert!(account.check_tree_is_full(None).is_ok());
        assert!(!account.tree_is_full(Some(1)));
        assert!(account.check_tree_is_full(Some(1)).is_ok());
        account.next_index = account.capacity - 2;
        assert!(!account.tree_is_full(None));
        assert!(account.check_tree_is_full(None).is_ok());
        assert!(!account.tree_is_full(Some(1)));
        assert!(account.check_tree_is_full(Some(1)).is_ok());
        account.next_index = account.capacity - 1;
        assert!(!account.tree_is_full(None));
        assert!(account.check_tree_is_full(None).is_ok());
        assert!(account.tree_is_full(Some(1)));
        assert!(account.check_tree_is_full(Some(1)).is_err());
        account.next_index = account.capacity;
        assert!(account.tree_is_full(None));
        assert!(account.check_tree_is_full(None).is_err());
        assert!(account.tree_is_full(Some(1)));
        assert!(account.check_tree_is_full(Some(1)).is_err());
        account.next_index = account.capacity + 1;
        assert!(account.tree_is_full(None));
        assert!(account.check_tree_is_full(None).is_err());
        assert!(account.tree_is_full(Some(1)));
        assert!(account.check_tree_is_full(Some(1)).is_err());
    }
    #[test]
    fn test_increment_next_index() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 3, 1000, 5>()];
        let batch_size = 5;
        let zkp_batch_size = 1;
        let root_history_len = 10;
        let height = 40;
        let pubkey = Pubkey::new_unique();
        let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 5>::init(
            &mut account_data,
            &pubkey,
            MerkleTreeMetadata::default(),
            root_history_len,
            batch_size,
            zkp_batch_size,
            height,
            TreeType::AddressV2,
            None,
        )
        .unwrap();
        let previous_next_index = account.next_index;
        let previous_queue_next_index = account.queue_batches.next_index;
        account.increment_merkle_tree_next_index(10);
        assert_eq!(account.next_index, previous_next_index + 10);
        assert_eq!(account.queue_batches.next_index, previous_queue_next_index);
        let previous_next_index = account.next_index;
        let previous_queue_next_index = account.queue_batches.next_index;
        account.increment_queue_next_index();
        assert_eq!(account.next_index, previous_next_index);
        assert_eq!(
            account.queue_batches.next_index,
            previous_queue_next_index + 1
        );
    }

    #[test]
    fn test_get_pubkey_and_associated_queue() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 3, 1000, 5>()];
        let batch_size = 5;
        let zkp_batch_size = 1;
        let root_history_len = 10;
        let height = 40;
        let pubkey = Pubkey::new_unique();
        let associated_queue = Pubkey::new_unique();
        let account = BatchedMerkleTreeAccount::<10, 3, 1000, 5>::init(
            &mut account_data,
            &pubkey,
            MerkleTreeMetadata {
                associated_queue,
                ..MerkleTreeMetadata::default()
            },
            root_history_len,
            batch_size,
            zkp_batch_size,
            height,
            TreeType::AddressV2,
            None,
        )
        .unwrap();
        assert_eq!(*account.pubkey(), pubkey);
        assert_eq!(*account.get_associated_queue(), associated_queue);
    }
}
