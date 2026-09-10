use arrayvec::ArrayVec;
use wincode::{containers, len::FixIntLen, ReadError, SchemaRead, SchemaWrite};
pub use zolana_event::{
    confidential_encrypted_output_body, is_confidential_encrypted_output,
    ring_confidential_encrypted_output_body, MessageData, OutputUtxo,
};
use zolana_hasher::{sha256::Sha256BE, Hasher, HasherError};

pub use crate::verifying_keys::{Bsb22Commitment, CircuitId, RingP256ProofData};
use crate::{error::ShieldedPoolError, MAX_INTERFACE_TRANSFERS, MAX_OUTPUTS};

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

/// One spent input UTXO (spec: `transact` `InputUtxo`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct InputUtxo {
    pub nullifier_hash: [u8; 32],
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

    /// Accounts in this leg's settlement group. Settlement groups are the last
    /// accounts of a `transact` instruction, in leg order; the program's account
    /// parser and the event parser both size them with this.
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
    /// SEC1-compressed P256 viewing key shared by every output ciphertext in
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
    pub utxo_tree_root_index: u16,
    pub nullifier_tree_root_index: u16,
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
    pub utxo_tree_root_index: u16,
    pub nullifier_tree_root_index: u16,
}

impl<'a> TransactIxDataRef<'a> {
    /// Decode once and borrow the bytes before `private_tx_hash`, the first
    /// field outside the external-data prefix. Its reference points directly
    /// into `data`, so the boundary needs no separate schema or size calculation.
    pub fn parse_with_external_data_prefix(data: &'a [u8]) -> Result<(Self, &'a [u8]), ReadError> {
        let parsed = Self::from_bytes(data)?;
        let external_data_prefix = parsed
            .private_tx_hash
            .as_ptr()
            .addr()
            .checked_sub(data.as_ptr().addr())
            .and_then(|len| data.get(..len))
            .ok_or(ReadError::Custom(
                "external data prefix is outside instruction data",
            ))?;
        Ok((parsed, external_data_prefix))
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
