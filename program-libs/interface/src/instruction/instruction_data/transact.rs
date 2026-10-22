use alloc::vec::Vec;
use arrayvec::ArrayVec;
use solana_program_error::ProgramError;
use thiserror::Error;
use wincode::{containers, len::FixIntLen, ReadError, SchemaRead, SchemaWrite};
pub use zolana_event::{
    confidential_encrypted_output_body, is_confidential_encrypted_output,
    ring_anonymous_encrypted_output_body, ring_confidential_delivered_output_body,
    ring_confidential_encrypted_output_body, ring_confidential_packed_output_body, MessageData,
    OutputUtxo, RingPackedBody,
};
use zolana_hasher::{
    primitives::{hash_bytes, right_align, solana_owner_identity, BN254_SCALAR_MODULUS_BE},
    sha256::Sha256BE,
    Hasher, HasherError,
};

pub use crate::verifying_keys::{
    AnonymousRingEddsaProofData, Bsb22Commitment, CacheAccess, CacheWrite, CircuitId,
    MAX_CACHE_WRITES,
};
use crate::{
    error::ShieldedPoolError, MAX_INPUT_TREES, MAX_INTERFACE_TRANSFERS, MAX_OUTPUTS,
    N_PUBLIC_SLOTS, SOL_ASSET_ADDRESS, SOL_ASSET_FIELD,
};

/// The Groth16 proof carried by a `transact` instruction: `a` and `c` are
/// compressed G1 points (32 bytes each), `b` is the raw big-endian G2 point
/// (128 bytes), 192 bytes in total.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactProof {
    pub a: [u8; 32],
    pub b: [u8; 128],
    pub c: [u8; 32],
}

impl TransactProof {
    /// A zeroed proof, used as a placeholder before the real proof is attached
    /// and as a dummy in tests.
    pub const fn zeroed() -> Self {
        Self {
            a: [0u8; 32],
            b: [0u8; 128],
            c: [0u8; 32],
        }
    }
}

/// One input tree's root indexes (spec: `transact` `TreeContext`). The
/// instruction declares one context per tree its inputs are spent from, in
/// account order; an input selects its context by index.
pub const NO_UTXO_ROOT: u16 = u16::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TreeContext {
    pub utxo_tree_root_index: u16,
    pub nullifier_tree_root_index: u16,
}

/// One spent input UTXO (spec: `transact` `InputUtxo`). `tree_index` selects
/// the input's tree from `TransactIxData::tree_contexts`; the proof binds the
/// same index, so an input cannot be proven against one tree and nullified in
/// another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct InputUtxo {
    pub nullifier_hash: [u8; 32],
    pub tree_index: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
pub enum InterfaceTransfer {
    SolDeposit {
        amount: u64,
    },
    SolWithdrawal {
        amount: u64,
    },
    SplDeposit {
        amount: u64,
        /// Canonical bump of the initialized per-mint SPL interface PDA.
        spl_interface_bump: u8,
    },
    SplWithdrawal {
        amount: u64,
        /// Canonical bump of the initialized per-mint SPL interface PDA.
        spl_interface_bump: u8,
    },
}

impl InterfaceTransfer {
    pub const fn amount(self) -> u64 {
        match self {
            Self::SolDeposit { amount }
            | Self::SolWithdrawal { amount }
            | Self::SplDeposit { amount, .. }
            | Self::SplWithdrawal { amount, .. } => amount,
        }
    }

    pub const fn is_spl(self) -> bool {
        matches!(self, Self::SplDeposit { .. } | Self::SplWithdrawal { .. })
    }

    pub const fn is_deposit(self) -> bool {
        matches!(self, Self::SolDeposit { .. } | Self::SplDeposit { .. })
    }

    fn signed_amount(self) -> i128 {
        let amount = i128::from(self.amount());
        if self.is_deposit() {
            amount
        } else {
            -amount
        }
    }

    /// Accounts in this leg's settlement group. Settlement groups terminate a
    /// `transact` account list, in leg order, except for the cache and, when
    /// writing, its signing writer that a cached selector appends after them;
    /// readers of a confirmed instruction locate them with
    /// [`settlement_accounts`].
    pub const fn settlement_account_count(self) -> usize {
        match self {
            // sol_interface, recipient
            Self::SolDeposit { .. } | Self::SolWithdrawal { .. } => 2,
            // mint, spl_interface, token_authority, user_token_account, token_program
            Self::SplDeposit { .. } => 5,
            // cpi_authority, mint, spl_interface, user_token_account, token_program
            Self::SplWithdrawal { .. } => 5,
        }
    }

    /// Position of the mint account within this leg's settlement group; `None`
    /// for SOL legs.
    pub const fn mint_account_position(self) -> Option<usize> {
        match self {
            Self::SolDeposit { .. } | Self::SolWithdrawal { .. } => None,
            Self::SplDeposit { .. } => Some(0),
            Self::SplWithdrawal { .. } => Some(1),
        }
    }

    /// Position of the signer a deposit moves funds from, `None` for a withdrawal.
    pub const fn funder_account_position(self) -> Option<usize> {
        match self {
            Self::SolDeposit { .. } => Some(1),
            Self::SplDeposit { .. } => Some(2),
            Self::SolWithdrawal { .. } | Self::SplWithdrawal { .. } => None,
        }
    }
}

/// The settlement account groups of a `transact` account list, in leg order and
/// sized by [`InterfaceTransfer::settlement_account_count`]. They terminate the
/// list, except for the optional cache and, when writing, its signer immediately
/// afterwards. `None` when the
/// list is shorter than the declared legs require. Every reader that recovers
/// settlements from a confirmed instruction must go through this: locating them
/// from the end of the account list alone silently reads each group one account
/// late once a cache is present.
pub fn settlement_accounts<'a, T>(
    transfers: &[InterfaceTransfer],
    circuit: CircuitId,
    accounts: &'a [T],
) -> Option<&'a [T]> {
    let total = transfers.iter().try_fold(0usize, |total, transfer| {
        total.checked_add(transfer.settlement_account_count())
    })?;
    let cache_accounts = circuit.cache_access().map_or(0, |access| {
        usize::from(access.read_bitmap != 0) + 2 * usize::from(access.writes_cache())
    });
    let end = accounts.len().checked_sub(cache_accounts)?;
    accounts.get(end.checked_sub(total)?..end)
}

/// `groups` is the window [`settlement_accounts`] returns.
pub fn settlement_mints<'a, T>(
    transfers: &'a [InterfaceTransfer],
    groups: &'a [T],
) -> impl Iterator<Item = Result<Option<&'a T>, ShieldedPoolError>> + 'a {
    let mut start = 0usize;
    transfers.iter().map(move |transfer| {
        let group = start
            .checked_add(transfer.settlement_account_count())
            .and_then(|end| groups.get(start..end))
            .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
        start += group.len();
        transfer
            .mint_account_position()
            .map(|position| {
                group
                    .get(position)
                    .ok_or(ShieldedPoolError::InvalidSettlementAccounts)
            })
            .transpose()
    })
}

pub fn validate_interface_transfers(
    transfers: &[InterfaceTransfer],
) -> Result<(), ShieldedPoolError> {
    if transfers.len() > MAX_INTERFACE_TRANSFERS {
        return Err(ShieldedPoolError::TooManyInterfaceTransfers);
    }
    if transfers.iter().any(|transfer| transfer.amount() == 0) {
        return Err(ShieldedPoolError::ZeroInterfaceTransferAmount);
    }
    Ok(())
}

/// Assets in first-seen leg order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublicSlots {
    slots: ArrayVec<PublicSlot, N_PUBLIC_SLOTS>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PublicSlot {
    asset: [u8; 32],
    net: i128,
}

/// A refused fold, `asset` the zero address for SOL.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PublicSlotError {
    #[error("an asset needs a public slot past the last")]
    TooManyAssets { asset: [u8; 32] },
    #[error("the net public amount of an asset exceeds a u64 magnitude")]
    AmountOverflow { asset: [u8; 32] },
    #[error("the interface transfers of an asset net to zero")]
    ZeroNet { asset: [u8; 32] },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicLeg {
    pub transfer: InterfaceTransfer,
    /// The raw mint address, never an asset field, `None` for SOL.
    pub mint: Option<[u8; 32]>,
}

impl PublicSlots {
    pub fn fold<E: From<PublicSlotError>>(
        legs: impl IntoIterator<Item = Result<PublicLeg, E>>,
    ) -> Result<Self, E> {
        let mut slots = Self::default();
        for leg in legs {
            let PublicLeg { transfer, mint } = leg?;
            slots.add(mint.unwrap_or(SOL_ASSET_ADDRESS), transfer.signed_amount())?;
        }
        if let Some(slot) = slots.slots.iter().find(|slot| slot.net == 0) {
            return Err(PublicSlotError::ZeroNet { asset: slot.asset }.into());
        }
        Ok(slots)
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Zero past the used slots.
    pub fn asset_fields(&self) -> Result<[[u8; 32]; N_PUBLIC_SLOTS], HasherError> {
        let mut fields = [[0u8; 32]; N_PUBLIC_SLOTS];
        for (field, slot) in fields.iter_mut().zip(&self.slots) {
            *field = match slot.asset {
                SOL_ASSET_ADDRESS => SOL_ASSET_FIELD,
                mint => hash_bytes(&mint)?,
            };
        }
        Ok(fields)
    }

    /// Zero past the used slots.
    pub fn amounts(&self) -> [i128; N_PUBLIC_SLOTS] {
        core::array::from_fn(|index| self.slots.get(index).map_or(0, |slot| slot.net))
    }

    /// Zero past the used slots.
    pub fn amount_fields(&self) -> Result<[[u8; 32]; N_PUBLIC_SLOTS], PublicSlotError> {
        let mut fields = [[0u8; 32]; N_PUBLIC_SLOTS];
        for (field, slot) in fields.iter_mut().zip(&self.slots) {
            *field = amount_field(slot.net)
                .map_err(|_| PublicSlotError::AmountOverflow { asset: slot.asset })?;
        }
        Ok(fields)
    }

    fn add(&mut self, asset: [u8; 32], amount: i128) -> Result<(), PublicSlotError> {
        match self.slots.iter_mut().find(|slot| slot.asset == asset) {
            Some(slot) => *slot = slot.credit(amount)?,
            None => self
                .slots
                .try_push(PublicSlot { asset, net: 0 }.credit(amount)?)
                .map_err(|_| PublicSlotError::TooManyAssets { asset })?,
        }
        Ok(())
    }
}

impl PublicSlot {
    fn credit(self, amount: i128) -> Result<Self, PublicSlotError> {
        // The circuit range-checks each public amount to a u64 magnitude.
        let net = self
            .net
            .checked_add(amount)
            .filter(|net| u64::try_from(net.unsigned_abs()).is_ok())
            .ok_or(PublicSlotError::AmountOverflow { asset: self.asset })?;
        Ok(Self { net, ..self })
    }
}

impl From<PublicSlotError> for ShieldedPoolError {
    fn from(error: PublicSlotError) -> Self {
        match error {
            PublicSlotError::TooManyAssets { .. } => Self::TooManyPublicAssets,
            PublicSlotError::AmountOverflow { .. } => Self::PublicAssetAmountOverflow,
            PublicSlotError::ZeroNet { .. } => Self::ZeroNetInterfaceTransferAmount,
        }
    }
}

impl From<PublicSlotError> for ProgramError {
    fn from(error: PublicSlotError) -> Self {
        ShieldedPoolError::from(error).into()
    }
}

/// Low half of the BN254 scalar modulus, above every u64 magnitude.
const MODULUS_LOW: u128 = match BN254_SCALAR_MODULUS_BE.last_chunk() {
    Some(low) => u128::from_be_bytes(*low),
    None => 0,
};
const _: () = assert!(MODULUS_LOW > u64::MAX as u128);

/// A signed public amount as a field element, a withdrawal as `q - |amount|`.
pub fn amount_field(amount: i128) -> Result<[u8; 32], ShieldedPoolError> {
    let magnitude = u64::try_from(amount.unsigned_abs())
        .map_err(|_| ShieldedPoolError::PublicAssetAmountOverflow)?;
    if !amount.is_negative() {
        return Ok(right_align(&magnitude.to_be_bytes()));
    }
    let mut field = BN254_SCALAR_MODULUS_BE;
    field[16..].copy_from_slice(&(MODULUS_LOW - u128::from(magnitude)).to_be_bytes());
    Ok(field)
}

/// Validate the declared input trees against the inputs that reference them and
/// return each declared tree's input count, zero past the declared trees.
///
/// Inputs may reference their trees in any order, but every input must
/// reference a declared context and every declared context must be referenced
/// by at least one input, so the counts cover every input.
pub fn validate_input_tree_contexts(
    inputs: &[InputUtxo],
    tree_contexts: &[TreeContext],
) -> Result<[usize; MAX_INPUT_TREES], ShieldedPoolError> {
    let mut counts = [0usize; MAX_INPUT_TREES];
    let declared = counts
        .get_mut(..tree_contexts.len())
        .filter(|declared| !declared.is_empty())
        .ok_or(ShieldedPoolError::InvalidTreeContextCount)?;
    for input in inputs {
        *declared
            .get_mut(usize::from(input.tree_index))
            .ok_or(ShieldedPoolError::InputTreeIndexOutOfRange)? += 1;
    }
    if declared.contains(&0) {
        return Err(ShieldedPoolError::UnreferencedTreeContext);
    }
    Ok(counts)
}

/// How an output's owner tag is carried on the wire (spec: `transact`
/// `OwnerTag`). The resolved 32-byte value is hashed into the OWNER public input
/// and republished as the event `view_tag`. `Inline` embeds the tag directly
/// (recipient signing pubkey, ring HKDF tag, dummy tag); `Account` indexes the
/// raw account list so an address-lookup table can compress self-owned outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
pub enum OwnerTag {
    Inline([u8; 32]),
    Account(u8),
}

/// One output slot in `transact` instruction data (spec: `transact`
/// `TransactOutput`): the output commitment, its owner tag, and an optional
/// ciphertext. `data: None` marks a slot covered by a preceding `Some` bundle
/// (a client/wallet placement convention); the program does not parse `data`.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactOutput {
    pub utxo_hash: [u8; 32],
    pub owner_tag: OwnerTag,
    #[wincode(with = "Option<containers::Vec<u8, FixIntLen<u16>>>")]
    pub data: Option<Vec<u8>>,
}

/// `transact` instruction data (spec: SPP `transact`). The fields through
/// `messages` are the serialized prefix that `external_data_hash` commits to.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactIxData {
    pub expiry_unix_ts: u64,
    /// Tagged X25519 viewing key (`0x04 || u`) shared by every output ciphertext in
    /// this transaction; bound into `external_data_hash` and copied verbatim
    /// into the logged `GeneralEvent` so an indexer need not parse the
    /// per-output `data`.
    pub tx_viewing_pk: [u8; 33],
    /// Per-transaction encryption salt shared by every output ciphertext;
    /// bound into `external_data_hash` and copied into the logged
    /// `GeneralEvent` so wallets can derive the AES key/nonce without parsing
    /// the per-output `data`.
    pub salt: [u8; 16],
    #[wincode(with = "containers::Vec<InterfaceTransfer, FixIntLen<u8>>")]
    pub interface_transfers: Vec<InterfaceTransfer>,
    /// Optional transaction-level application- and ring-specific external data
    /// digests folded into `external_data_hash`; `None` for a default-ring
    /// `transact`. Distinct from the per-UTXO `data_hash` / `ring_data_hash` in
    /// the UTXO body.
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
    /// All `M` outputs in tree-append order (SPL change, SOL change, then
    /// recipients / dummies). Each carries its commitment, owner tag, and an
    /// optional ciphertext. Commitments are appended to the UTXO tree and folded
    /// into the proof's output hash chain; dummy outputs carry real-looking
    /// hashes and ciphertexts, so the vector does not reveal the recipient count.
    /// A `None` `data` marks a slot covered by a preceding bundle.
    #[wincode(with = "containers::Vec<TransactOutput, FixIntLen<u8>>")]
    pub outputs: Vec<TransactOutput>,
    /// Published ciphertexts bound to no output commitment. Folded into
    /// `external_data_hash` and republished verbatim in the `GeneralEvent`.
    #[wincode(with = "containers::Vec<MessageData, FixIntLen<u8>>")]
    pub messages: Vec<MessageData>,
    pub private_tx_hash: [u8; 32],
    pub circuit: CircuitId,
    pub proof: TransactProof,
    #[wincode(with = "containers::Vec<InputUtxo, FixIntLen<u8>>")]
    pub inputs: Vec<InputUtxo>,
    /// One entry per input tree, in the order the tree accounts are passed.
    /// Sits after `inputs` so it stays outside the external-data prefix.
    #[wincode(with = "containers::Vec<TreeContext, FixIntLen<u8>>")]
    pub tree_contexts: Vec<TreeContext>,
}

impl TransactIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        validate_interface_transfers(&self.interface_transfers)
            .map_err(|_| wincode::WriteError::Custom("invalid interface transfers"))?;
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Read config for the borrowed views: identical to the default config used by
/// [`TransactIxData::serialize`], except sequences without an explicit
/// `FixIntLen` carry a `u16` length prefix. This matches the byte vectors
/// (`TransactOutput::data`, `MessageData::data`) the owned structs write with
/// `FixIntLen<u16>`, while the element vectors keep their explicit `FixIntLen<u8>`
/// override.
type RefConfig = wincode::config::Configuration<
    true,
    { wincode::config::DEFAULT_PREALLOCATION_SIZE_LIMIT },
    FixIntLen<u16>,
>;

/// Borrowed view of a [`TransactOutput`]; `data` aliases the instruction buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct TransactOutputRef<'a> {
    pub utxo_hash: &'a [u8; 32],
    pub owner_tag: OwnerTag,
    pub data: Option<&'a [u8]>,
}

/// Borrowed view of a [`zolana_event::MessageData`]; `data` aliases the buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct OutputDataRef<'a> {
    pub view_tag: &'a [u8; 32],
    pub data: &'a [u8],
}

/// Borrowed view of [`TransactIxData`], in the same serialized field order.
/// Ciphertexts and fixed byte-array references alias the instruction buffer;
/// the proof and small element vectors are read owned.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct TransactIxDataRef<'a> {
    pub expiry_unix_ts: u64,
    pub tx_viewing_pk: &'a [u8; 33],
    pub salt: &'a [u8; 16],
    #[wincode(with = "containers::Vec<InterfaceTransfer, FixIntLen<u8>>")]
    pub interface_transfers: Vec<InterfaceTransfer>,
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
    #[wincode(with = "containers::Vec<TransactOutputRef<'a>, FixIntLen<u8>>")]
    pub outputs: Vec<TransactOutputRef<'a>>,
    #[wincode(with = "containers::Vec<OutputDataRef<'a>, FixIntLen<u8>>")]
    pub messages: Vec<OutputDataRef<'a>>,
    pub private_tx_hash: &'a [u8; 32],
    pub circuit: CircuitId,
    pub proof: TransactProof,
    #[wincode(with = "containers::Vec<InputUtxo, FixIntLen<u8>>")]
    pub inputs: Vec<InputUtxo>,
    #[wincode(with = "containers::Vec<TreeContext, FixIntLen<u8>>")]
    pub tree_contexts: Vec<TreeContext>,
}

/// Payer, co-signer and exit destination, the circuit's party order.
pub const ANONYMOUS_PARTIES: usize = 3;

/// The public parties an anonymous spend proves distinct from its hidden owner.
pub struct AnonymousParties<'a> {
    pub payer: &'a [u8; 32],
    pub cosigner: Option<&'a [u8; 32]>,
    pub exit_destination: Option<&'a [u8; 32]>,
}

impl AnonymousParties<'_> {
    /// All withdrawals name the same key, `None` without a withdrawal.
    pub fn exit_destination<'a>(
        mut withdrawals: impl Iterator<Item = &'a [u8; 32]>,
    ) -> Result<Option<&'a [u8; 32]>, ShieldedPoolError> {
        let exit = withdrawals.next();
        if withdrawals.any(|destination| Some(destination) != exit) {
            return Err(ShieldedPoolError::AnonymousExitDestinationsDiffer);
        }
        Ok(exit)
    }

    /// Solana owner identities, zero for an absent party.
    pub fn identities(&self) -> Result<[[u8; 32]; ANONYMOUS_PARTIES], HasherError> {
        let identity =
            |party: Option<&[u8; 32]>| party.map_or(Ok([0u8; 32]), solana_owner_identity);
        Ok([
            identity(Some(self.payer))?,
            identity(self.cosigner)?,
            identity(self.exit_destination)?,
        ])
    }
}

pub struct ParsedTransactIxData<'a> {
    pub ix: TransactIxDataRef<'a>,
    /// The bytes before `private_tx_hash`, the first field outside the external data.
    pub external_data_prefix: &'a [u8],
    /// The bytes after the instruction, the ring program's control tail.
    pub tail: &'a [u8],
}

impl<'a> TransactIxDataRef<'a> {
    /// Decodes once, the prefix ends where the borrowed `private_tx_hash` starts.
    pub fn parse_with_tail(data: &'a [u8]) -> Result<ParsedTransactIxData<'a>, ReadError> {
        let mut rest = data;
        let ix = <Self as SchemaRead<'a, RefConfig>>::get(&mut rest)?;
        let external_data_prefix = ix
            .private_tx_hash
            .as_ptr()
            .addr()
            .checked_sub(data.as_ptr().addr())
            .and_then(|len| data.get(..len))
            .ok_or(ReadError::Custom(
                "external data prefix is outside instruction data",
            ))?;
        Ok(ParsedTransactIxData {
            ix,
            external_data_prefix,
            tail: rest,
        })
    }

    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ReadError> {
        wincode::config::deserialize_exact(data, RefConfig::new())
    }
}

/// Resolve an [`OwnerTag`] to its concrete 32-byte owner tag. The interface
/// crate has no account access, so callers pass an account-address lookup; both
/// the program and the client resolve through this one function so the OWNER
/// public input, the event `view_tag`, and `external_data_hash` agree.
pub fn fetch_tag(
    tag: &OwnerTag,
    account_address: impl Fn(u8) -> Option<[u8; 32]>,
) -> Result<[u8; 32], ShieldedPoolError> {
    match tag {
        OwnerTag::Inline(bytes) => Ok(*bytes),
        OwnerTag::Account(index) => {
            account_address(*index).ok_or(ShieldedPoolError::OwnerTagAccountMissing)
        }
    }
}

/// An output whose owner tag has been resolved to concrete bytes for proof
/// inputs, events, and the external-data hash's account-owner suffix.
pub struct ResolvedOutput<'a> {
    pub utxo_hash: &'a [u8; 32],
    pub owner_tag: [u8; 32],
    pub data: Option<&'a [u8]>,
}

impl TransactOutput {
    /// Resolve this output's owner tag against the transaction context.
    pub fn into_resolved(
        &self,
        account_address: impl Fn(u8) -> Option<[u8; 32]>,
    ) -> Result<ResolvedOutput<'_>, ShieldedPoolError> {
        Ok(ResolvedOutput {
            utxo_hash: &self.utxo_hash,
            owner_tag: fetch_tag(&self.owner_tag, account_address)?,
            data: self.data.as_deref(),
        })
    }
}

impl<'a> TransactOutputRef<'a> {
    /// Resolve this output's owner tag against the transaction context. The
    /// resolved output aliases the same instruction buffer as `self`.
    pub fn into_resolved(
        &self,
        account_address: impl Fn(u8) -> Option<[u8; 32]>,
    ) -> Result<ResolvedOutput<'a>, ShieldedPoolError> {
        Ok(ResolvedOutput {
            utxo_hash: self.utxo_hash,
            owner_tag: fetch_tag(&self.owner_tag, account_address)?,
            data: self.data,
        })
    }
}

/// Slices in the `external_data_hash` preimage: the instruction tag, the
/// serialized external-data prefix, two settlement addresses per interface
/// transfer, and one resolved owner address per account-referenced output.
pub const MAX_EXTERNAL_DATA_HASH_SLICES: usize = 2 + 2 * MAX_INTERFACE_TRANSFERS + MAX_OUTPUTS;

const _: () = assert!(MAX_EXTERNAL_DATA_HASH_SLICES >= 2);

/// Preimage of the `external_data_hash` public input (spec: `transact`
/// external_data_hash): the SPP instruction discriminator, the serialized
/// external-data prefix of the instruction, then the account addresses the
/// proof commits to, hashed once with `Sha256BE`. Holds only borrowed slices,
/// so neither the program nor a client copies preimage bytes. The prefix
/// encoding is self-delimiting and the number of appended addresses is a
/// function of the prefix alone (two per interface transfer, one per output
/// whose owner tag references an account), which keeps the preimage injective.
pub struct ExternalDataPreimage<'a> {
    slices: ArrayVec<&'a [u8], MAX_EXTERNAL_DATA_HASH_SLICES>,
}

impl<'a> ExternalDataPreimage<'a> {
    pub fn new(spp_instruction_discriminator: &'a [u8; 1], external_data_prefix: &'a [u8]) -> Self {
        let mut slices = ArrayVec::new();
        slices.push(spp_instruction_discriminator.as_slice());
        slices.push(external_data_prefix);
        Self { slices }
    }

    fn push_address(&mut self, address: &'a [u8; 32]) -> Result<(), HasherError> {
        let provided = self.slices.len() + 1;
        self.slices
            .try_push(address.as_slice())
            .map_err(|_| HasherError::InvalidInputLength(MAX_EXTERNAL_DATA_HASH_SLICES, provided))
    }

    /// Appends one interface transfer's committed accounts: the asset account
    /// (mint, or the SOL interface PDA) then the user account (user token
    /// account, or the SOL recipient), in interface-transfer order.
    pub fn push_settlement(
        &mut self,
        asset_account: &'a [u8; 32],
        user_account: &'a [u8; 32],
    ) -> Result<(), HasherError> {
        self.push_address(asset_account)?;
        self.push_address(user_account)
    }

    /// Appends the resolved owner of an `OwnerTag::Account` output; inline tags
    /// are already part of the serialized prefix and contribute nothing here.
    pub fn push_owner_tag(
        &mut self,
        tag: &OwnerTag,
        resolved_owner_tag: &'a [u8; 32],
    ) -> Result<(), HasherError> {
        match tag {
            OwnerTag::Inline(_) => Ok(()),
            OwnerTag::Account(_) => self.push_address(resolved_owner_tag),
        }
    }

    pub fn finish(&self) -> Result<[u8; 32], HasherError> {
        Sha256BE::hashv(&self.slices)
    }
}
