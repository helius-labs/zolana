//! Clean tree types for the shielded pool.
pub mod error;
pub mod smt;

use core::mem::{size_of, MaybeUninit};

pub use error::TreeError;
use pinocchio::{account::RefMut, AccountView, Address};
pub use smt::UtxoTreeLayout;
use wincode::{
    config::{ConfigCore, ZeroCopy},
    io::Reader,
    ReadResult, SchemaRead, TypeMeta,
};
pub use zolana_batched_merkle_tree::initialize_address_tree::InitAddressTreeAccountsInstructionData;
use zolana_batched_merkle_tree::{
    constants::{
        ADDRESS_BLOOM_FILTER_CAPACITY, ADDRESS_BLOOM_FILTER_NUM_HASHES,
        DEFAULT_ADDRESS_BATCH_ROOT_HISTORY_LEN, DEFAULT_ADDRESS_BATCH_SIZE,
        DEFAULT_ADDRESS_ZKP_BATCH_SIZE, DEFAULT_BATCH_ADDRESS_TREE_HEIGHT,
    },
    initialize_address_tree::{init_batched_nullifier_merkle_tree_into_layout, match_circuit_size},
    merkle_tree::BatchedMerkleTreeAccount,
    zero_copy::TreeAccountLayout as NullifierLayout,
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

type SppTreeLayout = TreeAccountLayout<
    POOL_UTXO_HEIGHT,
    NULLIFIER_RH,
    NULLIFIER_NUM_ITERS,
    NULLIFIER_BLOOM,
    NULLIFIER_ZKP,
>;

/// The layout reference either borrows caller-provided bytes (`init`,
/// `from_bytes`) or owns the account-data borrow guard, so the account's
/// borrow flag stays set for as long as the `TreeAccount` is alive.
enum LayoutRef<'a> {
    Raw(&'a mut SppTreeLayout),
    Account(RefMut<'a, SppTreeLayout>),
}

pub struct TreeAccount<'a> {
    pubkey: [u8; 32],
    layout: LayoutRef<'a>,
}

impl<'a> TreeAccount<'a> {
    /// Total account byte length. The account allocator must use this so `init`
    /// does not run out of buffer.
    pub fn account_size() -> usize {
        size_of::<SppTreeLayout>()
    }

    /// Byte offset of the state (utxo) tree's current root within the account.
    /// The utxo tree starts right after the account header and stores its root
    /// at [`smt::ROOT_OFFSET`].
    pub const fn state_root_offset() -> usize {
        core::mem::offset_of!(SppTreeLayout, utxo) + smt::ROOT_OFFSET
    }

    pub fn init(
        bytes: &'a mut [u8],
        discriminator: u8,
        utxo_tree_height: u8,
        pubkey: [u8; 32],
        nullifier_params: InitAddressTreeAccountsInstructionData,
    ) -> Result<Self, TreeError> {
        if utxo_tree_height as usize != POOL_UTXO_HEIGHT {
            return Err(TreeError::HeightTooLarge);
        }
        // Validate before dividing: the params are untrusted instruction data,
        // so a zero zkp batch size must not reach the quotient below (or the
        // `%` in `QueueBatches::init`), and an arbitrary height must not reach
        // `2u64.pow(height)` in the nullifier init. The zkp batch size must
        // have a verifying key, otherwise no batch update can ever be proven
        // and the queue wedges once both batches fill.
        if nullifier_params.height != DEFAULT_BATCH_ADDRESS_TREE_HEIGHT
            || nullifier_params.input_queue_batch_size == 0
            || !match_circuit_size(nullifier_params.input_queue_zkp_batch_size)
            || !nullifier_params
                .input_queue_batch_size
                .is_multiple_of(nullifier_params.input_queue_zkp_batch_size)
            || nullifier_params.root_history_capacity as usize != NULLIFIER_RH
            || (nullifier_params.input_queue_batch_size
                / nullifier_params.input_queue_zkp_batch_size) as usize
                != NULLIFIER_ZKP
        {
            return Err(TreeError::AddressInit);
        }
        if bytes.len() != size_of::<SppTreeLayout>() {
            return Err(TreeError::InvalidBufferSize);
        }

        let layout: &'a mut SppTreeLayout =
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
        >(nullifier_params, &mut layout.nullifier, pubkey.into())
        .map_err(|_| TreeError::AddressInit)?;

        Ok(Self {
            pubkey,
            layout: LayoutRef::Raw(layout),
        })
    }

    pub fn from_bytes(bytes: &'a mut [u8], pubkey: [u8; 32]) -> Result<Self, TreeError> {
        let layout: &'a mut SppTreeLayout =
            wincode::deserialize_mut(bytes).map_err(|_| TreeError::Deserialize)?;
        check_layout(layout)?;
        Ok(Self {
            pubkey,
            layout: LayoutRef::Raw(layout),
        })
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
        let bytes = account.try_borrow_mut().map_err(|_| TreeError::Borrowed)?;
        if bytes.first() != Some(&discriminator) {
            return Err(TreeError::InvalidDiscriminator);
        }
        let layout: RefMut<'a, SppTreeLayout> =
            RefMut::filter_map(bytes, |bytes| wincode::deserialize_mut(bytes).ok())
                .map_err(|_| TreeError::Deserialize)?;
        check_layout(&layout)?;
        Ok(Self {
            pubkey,
            layout: LayoutRef::Account(layout),
        })
    }

    #[inline(always)]
    fn layout(&self) -> &SppTreeLayout {
        match &self.layout {
            LayoutRef::Raw(layout) => layout,
            LayoutRef::Account(layout) => layout,
        }
    }

    #[inline(always)]
    fn layout_mut(&mut self) -> &mut SppTreeLayout {
        match &mut self.layout {
            LayoutRef::Raw(layout) => layout,
            LayoutRef::Account(layout) => layout,
        }
    }

    pub fn utxo_tree(&mut self) -> &mut UtxoTreeLayout<POOL_UTXO_HEIGHT> {
        &mut self.layout_mut().utxo
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
        let pubkey = self.pubkey;
        BatchedMerkleTreeAccount::from_layout(&pubkey.into(), &mut self.layout_mut().nullifier)
    }

    pub fn get_utxo_tree_root(&self, index: u16) -> Result<[u8; 32], TreeError> {
        self.layout().utxo.root_by_index(index)
    }

    pub fn get_nullifier_tree_root(&self, index: u16) -> Result<[u8; 32], TreeError> {
        let root = *self
            .layout()
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
        self.layout().discriminator
    }

    pub fn state(&self) -> u8 {
        self.layout().state
    }

    pub fn is_paused(&self) -> bool {
        self.layout().state == PAUSED
    }

    pub fn set_paused(&mut self, paused: bool) {
        self.layout_mut().state = if paused { PAUSED } else { INITIALIZED };
    }
}

fn check_layout(layout: &SppTreeLayout) -> Result<(), TreeError> {
    if layout.utxo.subtrees_len as usize != POOL_UTXO_HEIGHT
        || layout.utxo.root_history_capacity as usize != smt::ROOT_HISTORY_CAPACITY
    {
        return Err(TreeError::Deserialize);
    }
    Ok(())
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
        assert_eq!(size_of::<SppTreeLayout>(), old_account_size);

        let old_nullifier_offset = HEADER_LEN + old_utxo_size(POOL_UTXO_HEIGHT);
        assert_eq!(
            core::mem::offset_of!(SppTreeLayout, nullifier),
            old_nullifier_offset
        );

        assert_eq!(core::mem::offset_of!(SppTreeLayout, utxo), HEADER_LEN);
        assert_eq!(
            size_of::<UtxoTreeLayout<POOL_UTXO_HEIGHT>>(),
            UtxoTreeLayout::<POOL_UTXO_HEIGHT>::serialized_size(POOL_UTXO_HEIGHT)
        );
    }

    #[test]
    fn deserialize_mut_round_trip() {
        let mut bytes = vec![0u8; size_of::<SppTreeLayout>()];
        {
            let layout: &mut SppTreeLayout = wincode::deserialize_mut(&mut bytes).expect("cast");
            layout.utxo.init(POOL_UTXO_HEIGHT).unwrap();
            let mut leaf = [0u8; 32];
            leaf[31] = 9;
            layout.utxo.append(leaf).unwrap();
            layout.nullifier.root_history.data[3] = [7u8; 32];
        }
        let reloaded: &mut SppTreeLayout = wincode::deserialize_mut(&mut bytes).expect("reload");
        assert_eq!(reloaded.utxo.next_index(), 1);
        assert_eq!(reloaded.nullifier.root_history.data[3], [7u8; 32]);
    }
}
