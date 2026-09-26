use core::ops::{Deref, DerefMut};

use borsh::BorshSerialize;
use pinocchio::error::ProgramError;
use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::instruction::instruction_data::transact::TreeContext;

use super::{DataUtxo, NewAddress, PdaOwner, UtxoKey};

/// Program state kept as a compressed account. The SDK publishes it as
/// plaintext borsh and commits to it through [`Self::data_hash`].
///
/// The state stores its address and the blinding of the UTXO it lives in, and
/// its data hash commits to both. The SDK fills them in: the address from the
/// meta or the new address, the blinding from the meta or the one the
/// transaction derives for the new UTXO, so readers can spend the UTXO from
/// the published state alone.
pub trait CompressedAccountData: BorshSerialize {
    /// Commits to the state, a type tag and the address.
    fn data_hash(&self) -> Result<[u8; 32], ProgramError>;
    fn address_mut(&mut self) -> &mut [u8; 32];
    fn blinding_mut(&mut self) -> &mut [u8; 32];
}

/// What a client sends about a compressed account's current UTXO besides its
/// state. Wrong values yield a UTXO hash or nullifier no proof can match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CompressedAccountMeta {
    /// The account's address, reserved when it was created.
    pub address: [u8; 32],
    /// Blinding of the current UTXO. It derives from the transaction that
    /// created the UTXO, which a later instruction does not see.
    pub blinding: [u8; 32],
    /// Root indexes the current UTXO is proven against.
    pub tree_context: TreeContext,
}

/// A write to one compressed account: [`Self::new_init`] creates the account
/// and [`Self::new_mut`] updates it. It derefs to the account's state, which
/// the program changes before [`super::SppTransactCpi`] turns the writes of one
/// instruction into one shielded-pool transaction.
pub struct CompressedAccount<'a, A> {
    pub(super) owner: &'a PdaOwner,
    pub(super) input: AccountInput,
    /// Raw id of the tree the input is spent from.
    pub(super) tree_id: u16,
    pub(super) tree_context: TreeContext,
    pub(super) account: A,
}

pub(super) enum AccountInput {
    /// Create: the address slot, which reserves the address.
    Address(NewAddress),
    /// Update: the account's current UTXO.
    Current(UtxoKey),
}

impl AccountInput {
    /// The address on create, the current UTXO's nullifier on update.
    pub(super) fn nullifier(&self) -> &[u8; 32] {
        match self {
            Self::Address(address) => address.address(),
            Self::Current(key) => key.nullifier(),
        }
    }
}

impl<'a, A: CompressedAccountData> CompressedAccount<'a, A> {
    /// Creates the account at `address` by spending its address slot, starting
    /// from the default state. `tree_context` holds the address tree's root
    /// indexes.
    pub fn new_init(owner: &'a PdaOwner, address: NewAddress, tree_context: TreeContext) -> Self
    where
        A: Default,
    {
        let mut account = A::default();
        *account.address_mut() = *address.address();
        Self {
            owner,
            tree_id: address.tree_id(),
            input: AccountInput::Address(address),
            tree_context,
            account,
        }
    }

    /// Updates the account by spending its current UTXO: `input_account` with
    /// the address and blinding `meta` names, in the tree with the raw id
    /// `tree_id`, which a program reads from the tree account.
    pub fn new_mut(
        owner: &'a PdaOwner,
        meta: &CompressedAccountMeta,
        mut input_account: A,
        tree_id: u16,
    ) -> Result<Self, ProgramError> {
        *input_account.address_mut() = meta.address;
        *input_account.blinding_mut() = meta.blinding;
        let current = DataUtxo {
            owner,
            data_hash: input_account.data_hash()?,
            blinding: meta.blinding,
        }
        .key(tree_id)?;
        Ok(Self {
            owner,
            input: AccountInput::Current(current),
            tree_id,
            tree_context: meta.tree_context,
            account: input_account,
        })
    }

    /// The input's nullifier: the address on create, the current UTXO's
    /// nullifier on update. Its nullifier PDA is the one the transaction
    /// creates.
    pub fn input_nullifier(&self) -> &[u8; 32] {
        self.input.nullifier()
    }
}

impl<A> Deref for CompressedAccount<'_, A> {
    type Target = A;

    fn deref(&self) -> &A {
        &self.account
    }
}

impl<A> DerefMut for CompressedAccount<'_, A> {
    fn deref_mut(&mut self) -> &mut A {
        &mut self.account
    }
}
