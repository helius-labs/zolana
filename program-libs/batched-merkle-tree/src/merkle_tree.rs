use std::{
    mem::size_of,
    ops::{Deref, DerefMut},
};

use crate::{
    batch::BatchState,
    constants::{ADDRESS_TREE_INIT_ROOT_40, NUM_BATCHES},
    errors::{BatchedMerkleTreeError, MerkleTreeMetadataError},
    merkle_tree_metadata::{BatchedMerkleTreeMetadata, TreeType},
    queue::insert_into_current_queue_batch,
    queue_batch_metadata::QueueBatches,
    verify::CompressedProof,
    zero_copy::{TreeAccountLayout, ZeroCopyError},
    BorshDeserialize, BorshSerialize,
};
use solana_address::Address as Pubkey;
use zolana_account_checks::discriminator::Discriminator;
use zolana_hasher::primitives::is_canonical_bn254_scalar_be;

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy, BorshDeserialize, BorshSerialize)]
pub struct InstructionDataBatchNullifyInputs {
    pub new_root: [u8; 32],
    pub old_root: [u8; 32],
    pub zkp_batch_index: u16,
    pub compressed_proof: CompressedProof,
}

pub type InstructionDataAddressAppendInputs = InstructionDataBatchNullifyInputs;

/// Batched Merkle tree zero copy account.
/// The account is used for batched state and address Merkle trees,
/// plus the input and address queues.
///
/// Tree roots can be used in zk proofs
/// outside of Light Protocol programs.
///
/// To access a tree root by index use:
/// - get_root_by_index
pub struct BatchedMerkleTreeAccount<'a, const ZKP: usize> {
    pubkey: Pubkey,
    pub(crate) layout: &'a mut TreeAccountLayout<ZKP>,
}

impl<const ZKP: usize> Discriminator for BatchedMerkleTreeAccount<'_, ZKP> {
    const LIGHT_DISCRIMINATOR: [u8; 8] = *b"BatchMta";
    const LIGHT_DISCRIMINATOR_SLICE: &'static [u8] = b"BatchMta";
}

impl<const ZKP: usize> std::fmt::Debug for BatchedMerkleTreeAccount<'_, ZKP> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchedMerkleTreeAccount")
            .field("pubkey", &self.pubkey)
            .field("metadata", &self.layout.metadata)
            .finish()
    }
}

impl<const ZKP: usize> PartialEq for BatchedMerkleTreeAccount<'_, ZKP> {
    fn eq(&self, other: &Self) -> bool {
        self.pubkey == other.pubkey && self.layout == other.layout
    }
}

impl<'a, const ZKP: usize> BatchedMerkleTreeAccount<'a, ZKP> {
    pub fn init(
        account_data: &'a mut [u8],
        pubkey: &Pubkey,
        input_queue_batch_size: u64,
        input_queue_zkp_batch_size: u64,
        height: u32,
        tree_type: TreeType,
        // Init root for indexed (`AddressV2`) trees. `None` uses the default
        // address sentinel root (`ADDRESS_TREE_INIT_ROOT_40`). Pass `Some` to
        // seed an indexed tree with a different sentinel, e.g. the BN254 `p-1`
        // nullifier-tree root (`NULLIFIER_TREE_INIT_ROOT_40`).
        address_init_root: Option<[u8; 32]>,
    ) -> Result<BatchedMerkleTreeAccount<'a, ZKP>, BatchedMerkleTreeError> {
        if account_data.len() != size_of::<TreeAccountLayout<ZKP>>() {
            return Err(ZeroCopyError::Size.into());
        }

        let layout: &'a mut TreeAccountLayout<ZKP> =
            wincode::deserialize_mut(account_data).map_err(|_| ZeroCopyError::Size)?;
        Self::init_from_layout(
            layout,
            pubkey,
            input_queue_batch_size,
            input_queue_zkp_batch_size,
            height,
            tree_type,
            address_init_root,
        )
    }

    /// Constructs a view over a typed layout already validated by its owning
    /// account loader.
    pub fn from_layout(
        pubkey: &Pubkey,
        layout: &'a mut TreeAccountLayout<ZKP>,
    ) -> BatchedMerkleTreeAccount<'a, ZKP> {
        BatchedMerkleTreeAccount {
            pubkey: *pubkey,
            layout,
        }
    }

    pub fn init_from_layout(
        layout: &'a mut TreeAccountLayout<ZKP>,
        pubkey: &Pubkey,
        input_queue_batch_size: u64,
        input_queue_zkp_batch_size: u64,
        height: u32,
        tree_type: TreeType,
        address_init_root: Option<[u8; 32]>,
    ) -> Result<BatchedMerkleTreeAccount<'a, ZKP>, BatchedMerkleTreeError> {
        QueueBatches::validate_configuration::<ZKP>(
            input_queue_batch_size,
            input_queue_zkp_batch_size,
        )?;
        let capacity = 1u64
            .checked_shl(height)
            .ok_or(MerkleTreeMetadataError::InvalidHeight)?;

        let (next_index, init_root) = if tree_type == TreeType::AddressV2 {
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
            (
                1,
                Some(address_init_root.unwrap_or(ADDRESS_TREE_INIT_ROOT_40)),
            )
        } else {
            (0, None)
        };
        let queue_batches = QueueBatches::new(
            input_queue_batch_size,
            input_queue_zkp_batch_size,
            next_index,
        )?;

        layout.discriminator = Self::LIGHT_DISCRIMINATOR;
        layout.metadata = BatchedMerkleTreeMetadata {
            tree_type: tree_type as u64,
            sequence_number: 0,
            next_index,
            height,
            _padding: [0u8; 4],
            capacity,
            queue_batches,
            close_before_index: 0,
        };

        // Initialize root history array with initial root.
        // Batch zkp updates require an input Merkle root.
        // The initial root is written at index 0 and the write head advanced to 1.
        // Indexed trees use their sentinel root. See the upstream reference:
        // https://github.com/helius-labs/privacy-program-libs/blob/c143c24f95c901e2eac96bc2bd498719958192cf/program-libs/indexed-merkle-tree/src/reference.rs#L69
        // The cursor wraps modulo ZKP so a single-slot root history seeds back to
        // index 0 instead of an out-of-range 1 that no load would accept.
        layout.root_history.current_index = 0;
        if let Some(root) = init_root {
            if let Some(slot) = layout.root_history.roots.get_mut(0) {
                *slot = root;
            }
            layout.root_history.current_index = 1 % ZKP as u64;
        }
        Ok(BatchedMerkleTreeAccount {
            pubkey: *pubkey,
            layout,
        })
    }

    /// Validates the invariants required for safe queue rotation and natural
    /// root-history overwrite.
    pub fn validate_layout(layout: &TreeAccountLayout<ZKP>) -> Result<(), BatchedMerkleTreeError> {
        let queue = &layout.metadata.queue_batches;
        QueueBatches::validate_configuration::<ZKP>(queue.batch_size, queue.zkp_batch_size)?;

        if layout.root_history.current_index >= ZKP as u64 {
            return Err(MerkleTreeMetadataError::InvalidRootHistoryCapacity.into());
        }

        if queue.currently_processing_batch_index >= NUM_BATCHES as u64
            || queue.pending_batch_index >= NUM_BATCHES as u64
        {
            return Err(BatchedMerkleTreeError::InvalidBatchIndex);
        }
        if queue.reserved != NUM_BATCHES as u64
            || queue.batches.iter().any(|batch| {
                batch.batch_size != queue.batch_size || batch.zkp_batch_size != queue.zkp_batch_size
            })
        {
            return Err(BatchedMerkleTreeError::InvalidBatchConfiguration);
        }
        Ok(())
    }

    pub fn insert_nullifier_into_queue(
        &mut self,
        nullifier: &[u8; 32],
    ) -> Result<u64, BatchedMerkleTreeError> {
        if self.tree_type != TreeType::AddressV2 as u64 {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }
        if !is_canonical_bn254_scalar_be(nullifier) {
            return Err(BatchedMerkleTreeError::NonCanonicalFieldElement);
        }

        let queue_index = self.queue_batches.next_index;
        let leaf_index = queue_index
            .checked_add(1)
            .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)?;
        if leaf_index != self.next_queued_leaf_index()? {
            return Err(BatchedMerkleTreeError::QueueIndexMismatch);
        }
        self.check_queue_next_index_reached_tree_capacity()?;

        {
            let TreeAccountLayout {
                metadata,
                hash_chains,
                ..
            } = &mut *self.layout;
            insert_into_current_queue_batch(&mut metadata.queue_batches, hash_chains, nullifier)?;
        }
        self.increment_queue_next_index();
        Ok(queue_index)
    }

    fn latest_root_index(&self) -> usize {
        let capacity = self.layout.root_history.roots.len();
        if capacity == 0 {
            return 0;
        }
        (self.layout.root_history.current_index as usize + capacity - 1) % capacity
    }

    fn get_latest_root(&self) -> Option<&[u8; 32]> {
        self.layout.root_history.roots.get(self.latest_root_index())
    }

    pub(crate) fn append_root(&mut self, root: [u8; 32]) -> Result<(), BatchedMerkleTreeError> {
        let current_index = self.layout.root_history.current_index as usize;
        let capacity = self.layout.root_history.roots.len();
        let slot = self
            .layout
            .root_history
            .roots
            .get_mut(current_index)
            .ok_or(MerkleTreeMetadataError::InvalidRootHistoryCapacity)?;
        *slot = root;
        self.layout.root_history.current_index = ((current_index + 1) % capacity) as u64;
        Ok(())
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
        self.layout.root_history.roots.get(index)
    }

    /// Return the full root history.
    pub fn root_history(&self) -> &[[u8; 32]] {
        &self.layout.root_history.roots
    }

    /// Return a stored queue hash-chain for a pending ZKP batch.
    pub fn get_hash_chain(&self, batch_index: usize, zkp_batch_index: usize) -> Option<[u8; 32]> {
        self.layout
            .hash_chains
            .get(batch_index)
            .and_then(|chain| chain.get(zkp_batch_index))
            .copied()
    }

    /// Return a reference to the metadata of the tree.
    pub fn get_metadata(&self) -> &BatchedMerkleTreeMetadata {
        &self.layout.metadata
    }

    /// Return a mutable reference to the metadata of the tree.
    pub fn get_metadata_mut(&mut self) -> &mut BatchedMerkleTreeMetadata {
        &mut self.layout.metadata
    }

    /// Checks whether `num_leaves` values fit in the remaining tree capacity.
    pub fn tree_is_full(&self, num_leaves: u64) -> bool {
        match self.next_index.checked_add(num_leaves) {
            Some(end_index) => end_index > self.capacity,
            None => true,
        }
    }

    /// Checks that the next queued value still fits into the tree. Queued
    /// values are appended in queue order starting at the current batch's
    /// `start_index` (the init element occupies leaf 0, so queue sequence
    /// numbers are one behind tree leaf indices); the value fits iff that
    /// leaf index is below `capacity`.
    pub fn check_queue_next_index_reached_tree_capacity(
        &self,
    ) -> Result<(), BatchedMerkleTreeError> {
        let leaf_index = self.next_queued_leaf_index()?;
        if leaf_index >= self.capacity {
            return Err(BatchedMerkleTreeError::TreeIsFull);
        }
        Ok(())
    }

    /// Leaf index reserved by the next queue insertion. This includes values
    /// already queued but not yet applied to the Merkle tree. An `Inserted`
    /// current batch is about to be reused one rotation ahead, so its next
    /// leaf is `start_index + NUM_BATCHES * batch_size`. A `Full` current
    /// batch means both batches are full: the next value can only go into this
    /// batch once it is inserted and reused, so it reserves the same leaf.
    pub fn next_queued_leaf_index(&self) -> Result<u64, BatchedMerkleTreeError> {
        let queue = &self.queue_batches;
        let current_batch = queue.get_current_batch()?;
        let offset = match current_batch.checked_state()? {
            BatchState::Fill => current_batch.get_num_inserted_elements(),
            BatchState::Full | BatchState::Inserted => queue.rotation()?,
        };
        current_batch
            .start_index
            .checked_add(offset)
            .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)
    }

    /// Number of leaves not yet reserved by the queue.
    pub fn remaining_queue_capacity(&self) -> Result<u64, BatchedMerkleTreeError> {
        self.capacity
            .checked_sub(self.next_queued_leaf_index()?)
            .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)
    }

    /// Checks whether `num_leaves` values fit in the remaining tree capacity.
    pub fn check_tree_is_full(&self, num_leaves: u64) -> Result<(), BatchedMerkleTreeError> {
        if self.tree_is_full(num_leaves) {
            return Err(BatchedMerkleTreeError::TreeIsFull);
        }
        Ok(())
    }

    pub fn pubkey(&self) -> &Pubkey {
        &self.pubkey
    }

    pub(crate) fn increment_merkle_tree_next_index(&mut self, count: u64) {
        self.next_index += count;
    }

    fn increment_queue_next_index(&mut self) {
        self.queue_batches.next_index += 1;
    }
}

impl<const ZKP: usize> Deref for BatchedMerkleTreeAccount<'_, ZKP> {
    type Target = BatchedMerkleTreeMetadata;

    fn deref(&self) -> &Self::Target {
        &self.layout.metadata
    }
}

impl<const ZKP: usize> DerefMut for BatchedMerkleTreeAccount<'_, ZKP> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.layout.metadata
    }
}

/// The Merkle tree account is a single zero-copy cast, so its size is fully
/// determined by the layout const generics.
pub fn get_merkle_tree_account_size<const ZKP: usize>() -> usize {
    size_of::<TreeAccountLayout<ZKP>>()
}

#[cfg(feature = "test-only")]
#[cfg(test)]
mod test {
    use rand::{Rng, SeedableRng};

    use super::*;
    use crate::zero_copy::CachedTreeUpdate;

    fn random_nullifier(rng: &mut rand::prelude::StdRng) -> [u8; 32] {
        let mut value: [u8; 32] = rng.gen();
        value[0] = 0;
        value
    }

    #[test]
    fn test_init_invalid_account_size() {
        let mut account_data = vec![0u8; 200];
        let account = BatchedMerkleTreeAccount::<5>::init(
            &mut account_data,
            &Pubkey::default(),
            10,
            10,
            40,
            TreeType::AddressV2,
            None,
        );
        assert!(matches!(
            account.unwrap_err(),
            crate::errors::BatchedMerkleTreeError::ZeroCopy(ZeroCopyError::Size)
        ));
    }

    #[test]
    fn test_cached_tree_update_region_layout_and_size() {
        let update_size = core::mem::size_of::<crate::zero_copy::CachedTreeUpdate>();
        assert_eq!(update_size, 65);

        const ZKP: usize = 4;
        let full = get_merkle_tree_account_size::<ZKP>();
        let cached_tree_update_bytes = core::mem::size_of::<[[CachedTreeUpdate; ZKP]; 2]>();
        assert_eq!(cached_tree_update_bytes, 2 * ZKP * update_size);

        let mut old_sized = vec![0u8; full - cached_tree_update_bytes];
        let account = BatchedMerkleTreeAccount::<ZKP>::init(
            &mut old_sized,
            &Pubkey::default(),
            4,
            1,
            40,
            TreeType::AddressV2,
            None,
        );
        assert!(matches!(
            account.unwrap_err(),
            crate::errors::BatchedMerkleTreeError::ZeroCopy(ZeroCopyError::Size)
        ));
    }

    #[test]
    fn test_state_struct_sizes() {
        assert_eq!(core::mem::size_of::<crate::batch::Batch>(), 72);
        assert_eq!(
            core::mem::size_of::<crate::queue_batch_metadata::QueueBatches>(),
            192
        );
        assert_eq!(core::mem::size_of::<BatchedMerkleTreeMetadata>(), 240);
    }

    /// Re-submitting a proof for a zkp batch that has already been applied
    /// (its StartIndex lies behind the account next index) is a no-op: the proof
    /// is not re-verified (an invalid proof still returns Ok) and no cached
    /// update is written.
    #[test]
    fn test_replay_after_apply_is_noop() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<4>()];
        let pubkey = Pubkey::new_unique();
        let mut account = BatchedMerkleTreeAccount::<4>::init(
            &mut account_data,
            &pubkey,
            4,
            1,
            40,
            TreeType::AddressV2,
            None,
        )
        .unwrap();

        // Two zkp batches finalized, one already inserted -> num_inserted = 1.
        {
            let batch = account.queue_batches.batches.get_mut(0).unwrap();
            batch.num_full_zkp_batches = 2;
            batch.advance_state_to_full().unwrap();
            batch.mark_as_inserted_in_merkle_tree().unwrap();
        }
        assert_eq!(
            account
                .queue_batches
                .batches
                .first()
                .unwrap()
                .get_num_inserted_zkps(),
            1
        );

        // Replay zkp batch 0, which is behind the live next index, with an
        // invalid proof. Verification must be skipped, so the call succeeds.
        let result = account
            .update_tree_from_address_queue(InstructionDataAddressAppendInputs {
                new_root: [3u8; 32],
                old_root: [2u8; 32],
                zkp_batch_index: 0,
                compressed_proof: CompressedProof::default(),
            })
            .unwrap();

        assert!(result.is_none());
        let cached_update = account
            .layout
            .cached_tree_updates
            .first()
            .and_then(|updates| updates.first())
            .unwrap();
        assert_eq!(cached_update.occupied, 0);
    }

    /// Re-submitting a proof for a zkp batch that is already cached (an occupied
    /// slot ahead of the inserted count) is verified like any other proof: an
    /// invalid proof is rejected and the existing cached update is preserved.
    #[test]
    fn test_replay_while_cached_verifies_and_keeps_update_on_failure() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<4>()];
        let pubkey = Pubkey::new_unique();
        let mut account = BatchedMerkleTreeAccount::<4>::init(
            &mut account_data,
            &pubkey,
            4,
            1,
            40,
            TreeType::AddressV2,
            None,
        )
        .unwrap();

        // Finalize a zkp batch so zkp_batch_index 0 passes the readiness guard.
        account
            .queue_batches
            .batches
            .get_mut(0)
            .unwrap()
            .num_full_zkp_batches = 2;

        // Cache an update at zkp batch 0 of a freshly initialized address tree.
        let cached = CachedTreeUpdate {
            old_root: [9u8; 32],
            new_root: [8u8; 32],
            occupied: 1,
        };
        *account
            .layout
            .cached_tree_updates
            .get_mut(0)
            .and_then(|updates| updates.get_mut(0))
            .unwrap() = cached;

        // Re-submit zkp batch 0 with different roots and an invalid proof. The
        // occupied slot is ahead of the inserted count, so the proof is verified
        // and rejected; the stored update is preserved unchanged.
        let result = account.update_tree_from_address_queue(InstructionDataAddressAppendInputs {
            new_root: [3u8; 32],
            old_root: [2u8; 32],
            zkp_batch_index: 0,
            compressed_proof: CompressedProof::default(),
        });

        assert!(matches!(
            result.unwrap_err(),
            BatchedMerkleTreeError::VerifierErrorError(_)
        ));
        let cached_update = account
            .layout
            .cached_tree_updates
            .first()
            .and_then(|updates| updates.first())
            .copied()
            .unwrap();
        assert_eq!(cached_update, cached);
    }

    fn insert_rnd_addresses<'a, const ZKP: usize>(
        account_data: &'a mut [u8],
        batch_size: u64,
        rng: &mut rand::prelude::StdRng,
        pubkey: &Pubkey,
    ) -> Result<BatchedMerkleTreeAccount<'a, ZKP>, BatchedMerkleTreeError> {
        let layout: &'a mut TreeAccountLayout<ZKP> =
            wincode::deserialize_mut(account_data).map_err(|_| ZeroCopyError::Size)?;
        if layout.metadata.tree_type != TreeType::AddressV2 as u64 {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }
        BatchedMerkleTreeAccount::validate_layout(layout)?;
        let mut account = BatchedMerkleTreeAccount::from_layout(pubkey, layout);
        for i in 0..batch_size {
            println!("inserting address: {}", i);
            let address = random_nullifier(rng);
            account.insert_nullifier_into_queue(&address)?;
        }
        Ok(account)
    }

    #[test]
    fn test_check_queue_next_index_reached_tree_capacity() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<200>()];
        let batch_size = 200;
        let zkp_batch_size = 1;
        let height = 4;
        let tree_capacity = 2u64.pow(height);
        let pubkey = Pubkey::new_unique();
        let account = BatchedMerkleTreeAccount::<200>::init(
            &mut account_data,
            &pubkey,
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
        // The init element occupies leaf 0, so only capacity - 1 values fit.
        let account =
            insert_rnd_addresses::<200>(&mut account_data, tree_capacity - 2, rng, &pubkey)
                .unwrap();
        // 2. one free leaf left: not full
        assert!(account
            .check_queue_next_index_reached_tree_capacity()
            .is_ok());
        // 3. the last value fills the last leaf: full
        let mut account = insert_rnd_addresses::<200>(&mut account_data, 1, rng, &pubkey).unwrap();
        assert_eq!(
            account
                .check_queue_next_index_reached_tree_capacity()
                .unwrap_err(),
            BatchedMerkleTreeError::TreeIsFull
        );
        // 4. one more value does not fit and must be rejected.
        assert_eq!(
            account
                .insert_nullifier_into_queue(&random_nullifier(rng))
                .unwrap_err(),
            BatchedMerkleTreeError::TreeIsFull
        );
    }

    #[test]
    fn test_tree_is_full() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<5>()];
        let batch_size = 5;
        let zkp_batch_size = 1;
        let height = 4;
        let mut account = BatchedMerkleTreeAccount::<5>::init(
            &mut account_data,
            &Pubkey::new_unique(),
            batch_size,
            zkp_batch_size,
            height,
            TreeType::AddressV2,
            None,
        )
        .unwrap();
        // 1. empty tree is not full
        assert!(!account.tree_is_full(1));
        assert!(account.check_tree_is_full(1).is_ok());
        account.next_index = account.capacity - 2;
        assert!(!account.tree_is_full(1));
        assert!(account.check_tree_is_full(1).is_ok());
        // A batch of 2 fills the last two leaves exactly: not full.
        assert!(!account.tree_is_full(2));
        assert!(account.check_tree_is_full(2).is_ok());
        // A batch of 3 would write past the last leaf: full.
        assert!(account.tree_is_full(3));
        assert!(account.check_tree_is_full(3).is_err());
        account.next_index = account.capacity - 1;
        // The final leaf still fits a single value (or a batch of 1).
        assert!(!account.tree_is_full(1));
        assert!(account.check_tree_is_full(1).is_ok());
        assert!(account.tree_is_full(2));
        assert!(account.check_tree_is_full(2).is_err());
        account.next_index = account.capacity;
        assert!(account.tree_is_full(1));
        assert!(account.check_tree_is_full(1).is_err());
        account.next_index = account.capacity + 1;
        assert!(account.tree_is_full(1));
        assert!(account.check_tree_is_full(1).is_err());
        account.next_index = u64::MAX;
        assert!(account.tree_is_full(1));
        assert!(account.check_tree_is_full(1).is_err());
    }
    #[test]
    fn test_increment_next_index() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<5>()];
        let batch_size = 5;
        let zkp_batch_size = 1;
        let height = 40;
        let pubkey = Pubkey::new_unique();
        let mut account = BatchedMerkleTreeAccount::<5>::init(
            &mut account_data,
            &pubkey,
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
    fn test_get_pubkey() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<5>()];
        let batch_size = 5;
        let zkp_batch_size = 1;
        let height = 40;
        let pubkey = Pubkey::new_unique();
        let account = BatchedMerkleTreeAccount::<5>::init(
            &mut account_data,
            &pubkey,
            batch_size,
            zkp_batch_size,
            height,
            TreeType::AddressV2,
            None,
        )
        .unwrap();
        assert_eq!(*account.pubkey(), pubkey);
    }
}
