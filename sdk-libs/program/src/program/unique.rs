use core::ops::{Deref, DerefMut};

use spr_interface::instruction::instruction_data::transact::TreeContext;
use wincode::{SchemaRead, SchemaWrite};

use crate::hasher::{unique_data_hash, DataHasher};

use super::{utxo::DataUtxo, AddressSeed, CompressedAccountError, NewAddress, PdaOwner, UtxoKey};

/// What a client sends about a compressed account's current UTXO besides its
/// state. Wrong values yield a UTXO hash or nullifier no proof can match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct UtxoMeta {
    /// The account's address, reserved when it was created.
    pub address: [u8; 32],
    /// Blinding of the current UTXO. It derives from the transaction that
    /// created the UTXO, which a later instruction does not see.
    pub blinding: [u8; 32],
    /// Root indexes the current UTXO is proven against.
    pub tree_context: TreeContext,
}

/// A unique state UTXO owned by a program PDA, with zero SOL and no ring.
/// The address is immutable metadata; dereferencing exposes only application state.
/// A write to one account: [`Self::new_init`] creates the account
/// and [`Self::new_mut`] updates it. It derefs to the account's state, which
/// the program changes before [`super::SppTransactCpi`] turns the writes of one
/// instruction into one shielded-pool transaction.
#[must_use]
pub struct UniqueDataUtxo<'a, S> {
    pub(super) owner: &'a PdaOwner,
    pub(super) input: UtxoInput,
    /// Raw id of the tree the input is spent from.
    pub(super) tree_id: u16,
    pub(super) tree_context: TreeContext,
    pub(super) address: [u8; 32],
    pub(super) state: S,
}

pub(super) enum UtxoInput {
    /// Create: the address slot, which reserves the address.
    Address(NewAddress),
    /// Update: the account's current UTXO.
    Current(UtxoKey),
}

impl UtxoInput {
    /// The address on create, the current UTXO's nullifier on update.
    pub(super) fn nullifier(&self) -> &[u8; 32] {
        match self {
            Self::Address(address) => address.address(),
            Self::Current(key) => key.nullifier(),
        }
    }
}

impl<'a, S: Default> UniqueDataUtxo<'a, S> {
    /// Derives and reserves the owner-and-seed address in the protocol's address
    /// tree, and starts with the default application state.
    pub fn new_init(
        owner: &'a PdaOwner,
        seed: AddressSeed,
        tree_context: TreeContext,
    ) -> Result<Self, CompressedAccountError> {
        let address = NewAddress::derive(owner, seed)?;
        Ok(Self {
            owner,
            address: *address.address(),
            tree_id: address.tree_id(),
            input: UtxoInput::Address(address),
            tree_context,
            state: S::default(),
        })
    }
}

impl<'a, S: DataHasher> UniqueDataUtxo<'a, S> {
    /// Updates the account by spending its current UTXO: `input_account` with
    /// the address and blinding `meta` names, in the tree with the raw id
    /// `tree_id`, which a program reads from the tree account.
    pub fn new_mut(
        owner: &'a PdaOwner,
        meta: &UtxoMeta,
        input_account: S,
        tree_id: u16,
    ) -> Result<Self, CompressedAccountError> {
        let current = Self::state_key(owner, meta, &input_account, tree_id)?;
        Ok(Self {
            owner,
            input: UtxoInput::Current(current),
            address: meta.address,
            tree_id,
            tree_context: meta.tree_context,
            state: input_account,
        })
    }

    /// The reserved address, preserved independently of mutable program state.
    pub fn address(&self) -> &[u8; 32] {
        &self.address
    }

    /// The address-bound state commitment, matching the circuit's `UniqueDataUtxo`.
    pub fn data_hash(&self) -> Result<[u8; 32], CompressedAccountError> {
        Ok(unique_data_hash(&self.address, &self.state.hash()?)?)
    }

    pub(super) fn state_key(
        owner: &PdaOwner,
        meta: &UtxoMeta,
        state: &S,
        tree_id: u16,
    ) -> Result<UtxoKey, CompressedAccountError> {
        DataUtxo {
            owner,
            data_hash: unique_data_hash(&meta.address, &state.hash()?)?,
            blinding: meta.blinding,
        }
        .key(tree_id)
    }

    /// The input's nullifier: the address on create, the current UTXO's
    /// nullifier on update. Its nullifier PDA is the one the transaction
    /// creates.
    pub fn input_nullifier(&self) -> &[u8; 32] {
        self.input.nullifier()
    }
}

impl<S> Deref for UniqueDataUtxo<'_, S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.state
    }
}

impl<S> DerefMut for UniqueDataUtxo<'_, S> {
    fn deref_mut(&mut self) -> &mut S {
        &mut self.state
    }
}
