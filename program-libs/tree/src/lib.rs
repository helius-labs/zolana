//! Clean tree types for the shielded pool.
pub mod smt;

use core::mem::{size_of, MaybeUninit};

pub use smt::{TreeError, UtxoTreeLayout};
pub use zolana_batched_merkle_tree::initialize_address_tree::InitAddressTreeAccountsInstructionData;

use pinocchio::{AccountView, Address};
use wincode::{
    config::{ConfigCore, ZeroCopy},
    io::Reader,
    ReadResult, SchemaRead, TypeMeta,
};
use zolana_batched_merkle_tree::initialize_address_tree::init_batched_nullifier_merkle_tree_into_layout;
use zolana_batched_merkle_tree::merkle_tree::BatchedMerkleTreeAccount;
use zolana_batched_merkle_tree::zero_copy::TreeAccountLayout as NullifierLayout;

use zolana_batched_merkle_tree::constants::{
    ADDRESS_BLOOM_FILTER_CAPACITY, ADDRESS_BLOOM_FILTER_NUM_HASHES,
    DEFAULT_ADDRESS_BATCH_ROOT_HISTORY_LEN, DEFAULT_ADDRESS_BATCH_SIZE,
    DEFAULT_ADDRESS_ZKP_BATCH_SIZE,
};

const POOL_UTXO_HEIGHT: usize = 32;

const NULLIFIER_RH: usize = DEFAULT_ADDRESS_BATCH_ROOT_HISTORY_LEN as usize;
const NULLIFIER_NUM_ITERS: usize = ADDRESS_BLOOM_FILTER_NUM_HASHES as usize;
const NULLIFIER_BLOOM: usize = (ADDRESS_BLOOM_FILTER_CAPACITY / 8) as usize;
const NULLIFIER_ZKP: usize = (DEFAULT_ADDRESS_BATCH_SIZE / DEFAULT_ADDRESS_ZKP_BATCH_SIZE) as usize;

/// `state` byte values. Writes to the tree are only allowed in `INITIALIZED`.
pub const UNINITIALIZED: u8 = 0;
pub const INITIALIZED: u8 = 1;
pub const PAUSED: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TreeAccountLayout<
    const UTXO_HEIGHT: usize,
    const RH: usize,
    const NUM_ITERS: usize,
    const BLOOM: usize,
    const ZKP: usize,
> {
    pub discriminator: u8,
    pub state: u8,
    pub _padding: [u8; 6],
    pub utxo: UtxoTreeLayout<UTXO_HEIGHT>,
    pub nullifier: NullifierLayout<RH, NUM_ITERS, BLOOM, ZKP>,
}

unsafe impl<
        C: ConfigCore,
        const UH: usize,
        const RH: usize,
        const NUM_ITERS: usize,
        const BLOOM: usize,
        const ZKP: usize,
    > ZeroCopy<C> for TreeAccountLayout<UH, RH, NUM_ITERS, BLOOM, ZKP>
{
}

unsafe impl<
        'de,
        C: ConfigCore,
        const UH: usize,
        const RH: usize,
        const NUM_ITERS: usize,
        const BLOOM: usize,
        const ZKP: usize,
    > SchemaRead<'de, C> for TreeAccountLayout<UH, RH, NUM_ITERS, BLOOM, ZKP>
{
    type Dst = Self;
    const TYPE_META: TypeMeta = TypeMeta::Static {
        size: size_of::<Self>(),
        zero_copy: true,
    };

    fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<Self>) -> ReadResult<()> {
        unsafe { Ok(reader.copy_into_t(dst)?) }
    }
}

type PoolTreeLayout = TreeAccountLayout<
    POOL_UTXO_HEIGHT,
    NULLIFIER_RH,
    NULLIFIER_NUM_ITERS,
    NULLIFIER_BLOOM,
    NULLIFIER_ZKP,
>;

pub struct TreeAccount<'a> {
    pubkey: [u8; 32],
    layout: &'a mut PoolTreeLayout,
}

impl<'a> TreeAccount<'a> {
    /// Total account byte length. The account allocator must use this so `init`
    /// does not run out of buffer.
    pub fn account_size() -> usize {
        size_of::<PoolTreeLayout>()
    }

    /// Byte offset of the state (utxo) tree's current root within the account.
    /// The utxo tree starts right after the account header and stores its root
    /// at [`smt::ROOT_OFFSET`].
    pub const fn state_root_offset() -> usize {
        core::mem::offset_of!(PoolTreeLayout, utxo) + smt::ROOT_OFFSET
    }

    pub fn init(
        bytes: &'a mut [u8],
        discriminator: u8,
        utxo_tree_height: u8,
        owner: [u8; 32],
        pubkey: [u8; 32],
        nullifier_params: InitAddressTreeAccountsInstructionData,
    ) -> Result<Self, TreeError> {
        if utxo_tree_height as usize != POOL_UTXO_HEIGHT {
            return Err(TreeError::HeightTooLarge);
        }
        if nullifier_params.root_history_capacity as usize != NULLIFIER_RH
            || (nullifier_params.input_queue_batch_size
                / nullifier_params.input_queue_zkp_batch_size) as usize
                != NULLIFIER_ZKP
        {
            return Err(TreeError::AddressInit);
        }
        if bytes.len() != size_of::<PoolTreeLayout>() {
            return Err(TreeError::BufferTooSmall);
        }

        let layout: &'a mut PoolTreeLayout =
            wincode::deserialize_mut(bytes).map_err(|_| TreeError::Deserialize)?;
        if layout.state != UNINITIALIZED {
            return Err(TreeError::AlreadyInitialized);
        }
        layout.discriminator = discriminator;
        layout.state = INITIALIZED;

        layout.utxo.init(utxo_tree_height as usize)?;

        init_batched_nullifier_merkle_tree_into_layout::<
            NULLIFIER_RH,
            NULLIFIER_NUM_ITERS,
            NULLIFIER_BLOOM,
            NULLIFIER_ZKP,
        >(
            owner.into(),
            nullifier_params,
            &mut layout.nullifier,
            0,
            pubkey.into(),
        )
        .map_err(|_| TreeError::AddressInit)?;

        Ok(Self { pubkey, layout })
    }

    pub fn from_bytes(bytes: &'a mut [u8], pubkey: [u8; 32]) -> Result<Self, TreeError> {
        let layout: &'a mut PoolTreeLayout =
            wincode::deserialize_mut(bytes).map_err(|_| TreeError::Deserialize)?;
        if layout.utxo.subtrees_len as usize != POOL_UTXO_HEIGHT
            || layout.utxo.root_history_capacity as usize != smt::ROOT_HISTORY_CAPACITY
        {
            return Err(TreeError::Deserialize);
        }
        Ok(Self { pubkey, layout })
    }

    /// Load a writable tree from its account, checking program ownership, the
    /// discriminator, and that the tree is not paused. Use this on every write
    /// path that must be frozen while paused.
    pub fn from_account_view_mut(
        account: &'a mut AccountView,
        program_id: &Address,
        discriminator: u8,
    ) -> Result<Self, TreeError> {
        let tree = Self::load_checked(account, program_id, discriminator)?;
        if tree.is_paused() {
            return Err(TreeError::Paused);
        }
        Ok(tree)
    }

    /// Like [`Self::from_account_view_mut`] but does not reject a paused tree.
    /// `pause_tree` needs this to load a paused tree in order to unpause it.
    pub fn from_account_view_mut_allow_paused(
        account: &'a mut AccountView,
        program_id: &Address,
        discriminator: u8,
    ) -> Result<Self, TreeError> {
        Self::load_checked(account, program_id, discriminator)
    }

    fn load_checked(
        account: &'a mut AccountView,
        program_id: &Address,
        discriminator: u8,
    ) -> Result<Self, TreeError> {
        if !account.is_writable() {
            return Err(TreeError::NotWritable);
        }
        if !account.owned_by(program_id) {
            return Err(TreeError::InvalidOwner);
        }
        let pubkey = account.address().to_bytes();
        // SAFETY: `account` is borrowed exclusively (`&mut`), so no other live
        // borrow of its data exists while the returned view is in scope.
        let bytes = unsafe { account.borrow_unchecked_mut() }; // TODO: refactor this it is not necessary we can use ref mut
        if bytes.first() != Some(&discriminator) {
            return Err(TreeError::InvalidDiscriminator);
        }
        Self::from_bytes(bytes, pubkey)
    }

    pub fn utxo_tree(&mut self) -> &mut UtxoTreeLayout<POOL_UTXO_HEIGHT> {
        &mut self.layout.utxo
    }

    pub fn nullifer_tree(
        &mut self,
    ) -> BatchedMerkleTreeAccount<
        '_,
        NULLIFIER_RH,
        NULLIFIER_NUM_ITERS,
        NULLIFIER_BLOOM,
        NULLIFIER_ZKP,
    > {
        BatchedMerkleTreeAccount::from_layout(&self.pubkey.into(), &mut self.layout.nullifier)
    }

    pub fn get_utxo_tree_root(&self, index: u16) -> Result<[u8; 32], TreeError> {
        self.layout.utxo.root_by_index(index)
    }

    pub fn get_nullifier_tree_root(&self, index: u16) -> Result<[u8; 32], TreeError> {
        let root = *self
            .layout
            .nullifier
            .root_history
            .data
            .get(usize::from(index))
            .ok_or(TreeError::InvalidRootIndex)?;
        if root == [0u8; 32] {
            return Err(TreeError::InvalidRootIndex);
        }
        Ok(root)
    }

    pub fn discriminator(&self) -> u8 {
        self.layout.discriminator
    }

    pub fn state(&self) -> u8 {
        self.layout.state
    }

    pub fn is_paused(&self) -> bool {
        self.layout.state == PAUSED
    }

    pub fn set_paused(&mut self, paused: bool) {
        self.layout.state = if paused { PAUSED } else { INITIALIZED };
    }
}

#[cfg(test)]
mod layout_equivalence {
    use super::*;

    const HEADER_LEN: usize = 8;

    fn old_utxo_size(height: usize) -> usize {
        UtxoTreeLayout::<0>::serialized_size(height).next_multiple_of(8)
    }

    #[test]
    fn size_and_offset_match_old_layout() {
        let old_account_size = HEADER_LEN
            + old_utxo_size(POOL_UTXO_HEIGHT)
            + size_of::<
                NullifierLayout<NULLIFIER_RH, NULLIFIER_NUM_ITERS, NULLIFIER_BLOOM, NULLIFIER_ZKP>,
            >();
        assert_eq!(size_of::<PoolTreeLayout>(), old_account_size);

        let old_nullifier_offset = HEADER_LEN + old_utxo_size(POOL_UTXO_HEIGHT);
        assert_eq!(
            core::mem::offset_of!(PoolTreeLayout, nullifier),
            old_nullifier_offset
        );

        assert_eq!(core::mem::offset_of!(PoolTreeLayout, utxo), HEADER_LEN);
        assert_eq!(
            size_of::<UtxoTreeLayout<POOL_UTXO_HEIGHT>>(),
            UtxoTreeLayout::<POOL_UTXO_HEIGHT>::serialized_size(POOL_UTXO_HEIGHT)
        );
    }

    #[test]
    fn deserialize_mut_round_trip() {
        let mut bytes = vec![0u8; size_of::<PoolTreeLayout>()];
        {
            let layout: &mut PoolTreeLayout = wincode::deserialize_mut(&mut bytes).expect("cast");
            layout.utxo.init(POOL_UTXO_HEIGHT).unwrap();
            let mut leaf = [0u8; 32];
            leaf[31] = 9;
            layout.utxo.append(leaf);
            layout.nullifier.root_history.data[3] = [7u8; 32];
        }
        let reloaded: &mut PoolTreeLayout = wincode::deserialize_mut(&mut bytes).expect("reload");
        assert_eq!(reloaded.utxo.next_index(), 1);
        assert_eq!(reloaded.nullifier.root_history.data[3], [7u8; 32]);
    }
}
