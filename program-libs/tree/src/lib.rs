//! # zolana-tree
//!
//! The shielded pool's tree account. A single Solana account holds both trees
//! the pool maintains, cast in place as one [`TreeAccountLayout`]: an
//! append-only UTXO state tree of height 32, and a batched indexed nullifier
//! tree of height 40 with its input queue.
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`smt`] | [`UtxoTreeLayout`], the append-only state tree |
//! | [`nullifier_tree`] | The batched indexed nullifier tree and its input queue |
//! | [`error`] | [`TreeError`], the account-level error type |
//!
//! ## Loading
//!
//! [`TreeAccount`] is the loader for both subtrees. It checks program
//! ownership, the discriminator, and the pause flag, then returns `&mut`
//! access to [`TreeAccount::utxo_tree`] or [`TreeAccount::nullifier_tree`].
//! Under the `account-view` feature it also loads straight from a pinocchio
//! `AccountView`: `from_account_view_mut` rejects a paused tree, which freezes
//! the write paths, and `pause_tree` loads through
//! `from_account_view_mut_allow_paused` so it can unpause.
//!
//! ## State tree
//!
//! [`smt::UtxoTreeLayout`] appends output commitments one leaf at a time and
//! keeps a cyclic root history of [`smt::ROOT_HISTORY_CAPACITY`] roots for
//! validity proofs. Its height is pinned to [`UTXO_TREE_HEIGHT`], and
//! [`TreeAccount::init`] rejects any other value.
//!
//! ## Nullifier tree
//!
//! [`nullifier_tree`] is an indexed Merkle tree with an integrated input
//! queue. Spent-note nullifiers are queued instead of being applied a leaf at
//! a time, and a queued batch is applied to the tree with a Groth16 proof that
//! the values append correctly. A per-nullifier PDA
//! (`zolana_interface::state::NullifierPda`) records the queue index a value
//! reserved, and rejects a second insertion of the same nullifier while it is
//! pending. `nullifier_tree_spec.md` is the normative description of queue
//! insertion, batch append, and PDA cleanup.
//!
//! Both trees are sized by const generics, so the account is one zero-copy
//! cast and [`TreeAccount::account_size`] is the length the allocator must
//! use.
//!
//! ## Features
//!
//! Nothing is on by default: deserializing a tree account out of bytes needs
//! neither a Solana runtime nor a proof verifier, and a client that only reads
//! the account should not link one.
//!
//! | Feature | Adds | Pulls in |
//! |---------|------|----------|
//! | `account-view` | `TreeAccount::from_account_view_mut` and its allow-paused twin | `pinocchio` |
//! | `verify` | `nullifier_tree::verify` and `NullifierTreeLayout::update_tree_from_queue` | `groth16-solana` |
//!
//! [`TreeAccount::from_bytes`], [`TreeAccount::init`], both subtree layouts
//! and [`nullifier_tree::proof::CompressedProof`] are always available, so
//! indexers and foresters build a batch update without a verifier.
//!
//! ## Testing
//!
//! `just test-tree` runs every test that needs no prover.
//!
//! The nullifier-tree suite drives the layout through byte slices, so all of
//! it except `tests/nullifier_tree/init_roots.rs` is gated on the `test-only`
//! feature. That feature also relaxes the height-40 check in
//! [`nullifier_tree::init`], letting tests build small trees;
//! [`TreeAccount::init`] still rejects any height but 40, and the
//! shielded-pool build leaves `test-only` off. The `prover_e2e` module
//! additionally needs a prover at `ZOLANA_PROVER_URL`.
pub mod error;
pub mod nullifier_tree;
pub mod smt;

use core::mem::{size_of, MaybeUninit};

pub use error::TreeError;
pub use nullifier_tree::init::NullifierTreeInitParams;
use nullifier_tree::{
    constants::{DEFAULT_NULLIFIER_TREE_HEIGHT, NULLIFIER_TREE_ZKP_BATCHES},
    init::match_circuit_size,
    layout::NullifierTreeLayout,
};
#[cfg(feature = "account-view")]
use pinocchio::{account::RefMut, AccountView, Address};
pub use smt::UtxoTreeLayout;
use wincode::{
    config::{ConfigCore, ZeroCopy},
    io::Reader,
    ReadResult, SchemaRead, TypeMeta,
};

/// Height of the pool's UTXO state tree. `TreeAccount::init` rejects any
/// other height; exported so programs/tests initialize trees with the same
/// value instead of pinning a literal by comment.
pub const UTXO_TREE_HEIGHT: usize = 32;

/// `state` byte values. Writes to the tree are only allowed in `INITIALIZED`.
pub const UNINITIALIZED: u8 = 0;
pub const INITIALIZED: u8 = 1;
pub const PAUSED: u8 = 2;

/// Bytes reserved in the account header for future tree metadata.
pub const TREE_RESERVED_BYTES: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TreeAccountLayout<const UTXO_HEIGHT: usize, const ZKP_BATCHES: usize> {
    pub discriminator: u8,
    pub state: u8,
    pub _padding: [u8; 6],
    pub _reserved: [u8; TREE_RESERVED_BYTES],
    pub utxo: UtxoTreeLayout<UTXO_HEIGHT>,
    pub nullifier: NullifierTreeLayout<ZKP_BATCHES>,
}

unsafe impl<C: ConfigCore, const UH: usize, const ZKP_BATCHES: usize> ZeroCopy<C>
    for TreeAccountLayout<UH, ZKP_BATCHES>
{
}

unsafe impl<'de, C: ConfigCore, const UH: usize, const ZKP_BATCHES: usize> SchemaRead<'de, C>
    for TreeAccountLayout<UH, ZKP_BATCHES>
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

type SppTreeLayout = TreeAccountLayout<UTXO_TREE_HEIGHT, NULLIFIER_TREE_ZKP_BATCHES>;

/// The layout reference either borrows caller-provided bytes (`init`,
/// `from_bytes`) or owns the account-data borrow guard, so the account's
/// borrow flag stays set for as long as the `TreeAccount` is alive.
enum LayoutRef<'a> {
    Raw(&'a mut SppTreeLayout),
    #[cfg(feature = "account-view")]
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
        nullifier_params: NullifierTreeInitParams,
    ) -> Result<Self, TreeError> {
        if utxo_tree_height as usize != UTXO_TREE_HEIGHT {
            return Err(TreeError::HeightTooLarge);
        }
        // The zkp batch size must have a verifying key, otherwise no batch
        // update can ever be proven and the queue wedges once both batches
        // fill. Batch and root-history configuration is validated by the
        // nullifier tree init below.
        if nullifier_params.height != DEFAULT_NULLIFIER_TREE_HEIGHT
            || !match_circuit_size(nullifier_params.input_queue_zkp_batch_size)
        {
            return Err(TreeError::NullifierInit);
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
        layout._reserved = [0u8; TREE_RESERVED_BYTES];

        layout.utxo.init(utxo_tree_height as usize)?;

        layout
            .nullifier
            .init(
                nullifier_params.input_queue_batch_size,
                nullifier_params.input_queue_zkp_batch_size,
                nullifier_params.height,
            )
            .map_err(|_| TreeError::NullifierInit)?;

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
    #[cfg(feature = "account-view")]
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
    #[cfg(feature = "account-view")]
    pub fn from_account_view_mut_allow_paused(
        account: &'a mut AccountView,
        program_id: &Address,
        discriminator: u8,
    ) -> Result<Self, TreeError> {
        Self::load_checked(account, program_id, discriminator)
    }

    #[cfg(feature = "account-view")]
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
            #[cfg(feature = "account-view")]
            LayoutRef::Account(layout) => layout,
        }
    }

    #[inline(always)]
    fn layout_mut(&mut self) -> &mut SppTreeLayout {
        match &mut self.layout {
            LayoutRef::Raw(layout) => layout,
            #[cfg(feature = "account-view")]
            LayoutRef::Account(layout) => layout,
        }
    }

    pub fn utxo_tree(&mut self) -> &mut UtxoTreeLayout<UTXO_TREE_HEIGHT> {
        &mut self.layout_mut().utxo
    }

    pub fn pubkey(&self) -> [u8; 32] {
        self.pubkey
    }

    pub fn nullifier_tree(&mut self) -> &mut NullifierTreeLayout<NULLIFIER_TREE_ZKP_BATCHES> {
        &mut self.layout_mut().nullifier
    }

    pub fn close_before_index(&self) -> u64 {
        self.layout().nullifier.close_before_index
    }

    /// Whether a proof may contain dummy input slots at the current tree state.
    ///
    /// Nullifier capacity counts queue reservations, not only leaves already
    /// applied by the forester. Equality is allowed; dummies are disabled only
    /// once the nullifier tree has strictly fewer leaves left than the state
    /// tree.
    pub fn allow_dummy_inputs(&mut self) -> Result<bool, TreeError> {
        let utxo_tree = self.utxo_tree();
        let state_remaining = utxo_tree
            .capacity()
            .checked_sub(utxo_tree.next_index())
            .ok_or(TreeError::InvalidCapacity)?;
        let nullifier_remaining = self
            .nullifier_tree()
            .remaining_queue_capacity()
            .map_err(|_| TreeError::InvalidCapacity)?;
        Ok(dummy_inputs_allowed(nullifier_remaining, state_remaining))
    }

    pub fn get_utxo_tree_root(&self, index: u16) -> Result<[u8; 32], TreeError> {
        self.layout().utxo.root_by_index(index)
    }

    pub fn get_nullifier_tree_root(&self, index: u16) -> Result<[u8; 32], TreeError> {
        self.layout()
            .nullifier
            .root_by_index(index)
            .ok_or(TreeError::InvalidRootIndex)
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

#[inline]
const fn dummy_inputs_allowed(nullifier_remaining: u64, state_remaining: u64) -> bool {
    nullifier_remaining >= state_remaining
}

fn check_layout(layout: &SppTreeLayout) -> Result<(), TreeError> {
    if layout.utxo.subtrees_len as usize != UTXO_TREE_HEIGHT
        || layout.utxo.root_history_capacity as usize != smt::ROOT_HISTORY_CAPACITY
    {
        return Err(TreeError::Deserialize);
    }
    layout
        .nullifier
        .validate()
        .map_err(|_| TreeError::Deserialize)?;
    Ok(())
}

#[cfg(test)]
mod layout_equivalence {
    use super::*;

    const STATIC_METADATA_LEN: usize = 8;
    const HEADER_LEN: usize = STATIC_METADATA_LEN + TREE_RESERVED_BYTES;
    const EXPECTED_ACCOUNT_SIZE: usize = 34_856;
    const EXPECTED_NULLIFIER_OFFSET: usize = 7_544;
    const EXPECTED_STATE_ROOT_OFFSET: usize = 80;

    fn aligned_utxo_size(height: usize) -> usize {
        UtxoTreeLayout::<0>::serialized_size(height).next_multiple_of(8)
    }

    #[test]
    fn size_and_offsets_include_reserved_header() {
        let account_size_without_reserved = STATIC_METADATA_LEN
            + aligned_utxo_size(UTXO_TREE_HEIGHT)
            + size_of::<NullifierTreeLayout<NULLIFIER_TREE_ZKP_BATCHES>>();
        assert_eq!(size_of::<SppTreeLayout>(), EXPECTED_ACCOUNT_SIZE);
        assert_eq!(
            size_of::<SppTreeLayout>(),
            account_size_without_reserved + TREE_RESERVED_BYTES
        );

        let nullifier_offset = HEADER_LEN + aligned_utxo_size(UTXO_TREE_HEIGHT);
        assert_eq!(nullifier_offset, EXPECTED_NULLIFIER_OFFSET);
        assert_eq!(
            core::mem::offset_of!(SppTreeLayout, nullifier),
            nullifier_offset
        );

        assert_eq!(
            core::mem::offset_of!(SppTreeLayout, _reserved),
            STATIC_METADATA_LEN
        );
        assert_eq!(core::mem::offset_of!(SppTreeLayout, utxo), HEADER_LEN);
        assert_eq!(TreeAccount::state_root_offset(), EXPECTED_STATE_ROOT_OFFSET);
        assert_eq!(EXPECTED_STATE_ROOT_OFFSET, HEADER_LEN + smt::ROOT_OFFSET);
        assert_eq!(
            size_of::<UtxoTreeLayout<UTXO_TREE_HEIGHT>>(),
            UtxoTreeLayout::<UTXO_TREE_HEIGHT>::serialized_size(UTXO_TREE_HEIGHT)
        );
    }

    #[test]
    fn init_zeroes_reserved_header() {
        let mut bytes = vec![0u8; size_of::<SppTreeLayout>()];
        {
            let layout: &mut SppTreeLayout =
                wincode::deserialize_mut(&mut bytes).expect("cast layout");
            layout._reserved.fill(0xa5);
        }

        TreeAccount::init(
            &mut bytes,
            7,
            UTXO_TREE_HEIGHT as u8,
            [2u8; 32],
            NullifierTreeInitParams::default(),
        )
        .expect("initialize tree");

        let layout: &mut SppTreeLayout =
            wincode::deserialize_mut(&mut bytes).expect("reload layout");
        assert_eq!(layout._reserved, [0u8; TREE_RESERVED_BYTES]);
    }

    #[test]
    fn deserialize_mut_round_trip() {
        let mut bytes = vec![0u8; size_of::<SppTreeLayout>()];
        {
            let layout: &mut SppTreeLayout = wincode::deserialize_mut(&mut bytes).expect("cast");
            layout.utxo.init(UTXO_TREE_HEIGHT).unwrap();
            let mut leaf = [0u8; 32];
            leaf[31] = 9;
            layout.utxo.append(leaf).unwrap();
            *layout.nullifier.root_history.roots.get_mut(3).unwrap() = [7u8; 32];
        }
        let reloaded: &mut SppTreeLayout = wincode::deserialize_mut(&mut bytes).expect("reload");
        assert_eq!(reloaded.utxo.next_index(), 1);
        assert_eq!(
            reloaded.nullifier.root_history.roots.get(3),
            Some(&[7u8; 32])
        );
    }

    #[test]
    fn dummy_input_policy_disables_only_after_nullifier_capacity_falls_behind() {
        assert!(dummy_inputs_allowed(10, 9));
        assert!(dummy_inputs_allowed(10, 10));
        assert!(!dummy_inputs_allowed(9, 10));
    }
}
