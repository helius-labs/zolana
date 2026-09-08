use wincode::{
    config::{Configuration, DEFAULT_PREALLOCATION_SIZE_LIMIT},
    containers,
    len::FixIntLen,
    SchemaRead, SchemaWrite,
};
use zolana_hasher::{sha256::Sha256BE, Hasher, HasherError};

type DepositRefConfig = Configuration<true, DEFAULT_PREALLOCATION_SIZE_LIMIT, FixIntLen<u16>>;

/// Application data committed into the deposited UTXO's `data_hash`. The deposit
/// is authorized by the payer (non-ring) or the `RingConfig` account (ring); the
/// UTXO is not program-owned.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct UtxoData {
    pub data_hash: [u8; 32],
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub data: Vec<u8>,
}

/// Maximum number of distinct assets (settlement groups) per `deposit` batch.
pub const MAX_DEPOSIT_ASSETS: usize = 5;

/// Domain tag separating the deposit blinding derivation from every other
/// SHA-256 derivation in the protocol.
pub const DEPOSIT_BLINDING_DOMAIN: &[u8] = b"Deposit";

/// Blinding of the deposit output landing at `leaf_index` in `tree`.
/// `(tree, leaf_index)` does not repeat, so no two deposits share a blinding, a
/// `utxo_hash`, or a nullifier. `Sha256BE` zeroes the leading byte, keeping the
/// result below the BN254 modulus. Clients read the blinding from the indexer;
/// recompute it here only to check an indexed record.
pub fn deposit_blinding(tree: &[u8; 32], leaf_index: u64) -> Result<[u8; 32], HasherError> {
    Sha256BE::hashv(&[
        DEPOSIT_BLINDING_DOMAIN,
        tree.as_slice(),
        &leaf_index.to_be_bytes(),
    ])
}

/// Kind of one settlement group, declaring how many accounts it consumes and how
/// they are validated: `Sol` takes (`system_program`, `sol_interface`), `Spl`
/// takes (`token_program`, `mint`, `user_token`, `spl_interface`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
pub enum DepositAssetKind {
    Sol,
    Spl {
        /// Canonical bump of the initialized per-mint SPL interface PDA.
        spl_interface_bump: u8,
    },
}

/// One output of a batched public deposit (see [`DepositIxData`]).
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct DepositEntry {
    /// Index into [`DepositIxData::assets`]. Selects the asset this entry
    /// deposits and the settlement group that funds it.
    pub asset_index: u8,
    /// Indexing tag for this output slot; chosen per the spec's View Tag
    /// Selection.
    pub view_tag: [u8; 32],
    /// Recipient `owner_hash`; the program nests it with the blinding it
    /// derives via [`deposit_blinding`] into the UTXO's `owner_utxo_hash`.
    pub owner: [u8; 32],
    /// Deposited amount of the asset selected by `asset_index`.
    pub amount: u64,
    /// Application data committed into the UTXO's `data_hash`, authorized by the
    /// payer; `None` for a plain user deposit. Policy-ring deposits use
    /// [`RingDepositIxData`].
    pub utxo_data: Option<UtxoData>,
    /// Optional free-form memo emitted in the clear with the proofless output.
    /// Not committed into any hash, so it is informational only.
    #[wincode(with = "Option<containers::Vec<u8, FixIntLen<u16>>>")]
    pub memo: Option<Vec<u8>>,
}

/// Batched public deposit without a proof (spec: `deposit`, tag 11).
///
/// Each entry appends one output UTXO. Entries deposit into at most
/// [`MAX_DEPOSIT_ASSETS`] distinct assets; per-asset amounts are summed so each
/// asset settles with a single transfer, and the program emits one
/// [`crate::event::GeneralEvent`] carrying every proofless output for wallet
/// discovery.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct DepositIxData {
    /// Settlement groups in account order. The program reads the accounts each
    /// kind names, in this order, so the account layout is declared rather than
    /// inferred from the account count.
    #[wincode(with = "containers::Vec<DepositAssetKind, FixIntLen<u8>>")]
    pub assets: Vec<DepositAssetKind>,
    #[wincode(with = "containers::Vec<DepositEntry, FixIntLen<u8>>")]
    pub deposits: Vec<DepositEntry>,
}

impl DepositIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Borrowed view of [`UtxoData`]. The payload aliases the instruction buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct UtxoDataRef<'a> {
    pub data_hash: &'a [u8; 32],
    pub data: &'a [u8],
}

/// Borrowed view of [`DepositEntry`]. Variable-size data aliases the
/// instruction buffer rather than allocating per entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct DepositEntryRef<'a> {
    pub asset_index: u8,
    pub view_tag: &'a [u8; 32],
    pub owner: &'a [u8; 32],
    pub amount: u64,
    pub utxo_data: Option<UtxoDataRef<'a>>,
    pub memo: Option<&'a [u8]>,
}

/// Self-contained recipient-encryption envelope for one ring-deposit output.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct EncryptedRingDepositData {
    pub tx_viewing_pk: [u8; 33],
    pub salt: [u8; 16],
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub ciphertext: Vec<u8>,
}

/// One output of a batched policy-ring deposit.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct RingDepositEntry {
    /// Index into [`RingDepositIxData::assets`].
    pub asset_index: u8,
    /// Opaque indexing tag supplied by the ring. SPP does not derive or
    /// validate it.
    pub view_tag: [u8; 32],
    /// `Poseidon(owner_hash, blinding)`. The owner hash and blinding preimage
    /// are deliberately absent from the public instruction.
    pub owner_utxo_hash: [u8; 32],
    /// Deposited amount of the asset selected by `asset_index`.
    pub amount: u64,
    /// Hash of the encrypted application-data preimage, when present.
    pub data_hash: Option<[u8; 32]>,
    /// Ring-defined data committed into `ring_hash`. The ring's `program_id` is
    /// NOT in instruction data: it is read from the `RingConfig` account (the
    /// signing `ring_auth` PDA) the ring forwards.
    pub ring_data_hash: [u8; 32],
    /// Contains the encrypted blinding and private data preimages together with
    /// the public key and salt needed by the recipient.
    pub encrypted: EncryptedRingDepositData,
}

/// Batched policy-ring analog of [`DepositIxData`] (spec: `ring_deposit`, tag
/// 15). A ring program CPIs into SPP signing with its `ring_auth` PDA. Every
/// output is owned by that ring, while policy data is specified per output.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct RingDepositIxData {
    #[wincode(with = "containers::Vec<DepositAssetKind, FixIntLen<u8>>")]
    pub assets: Vec<DepositAssetKind>,
    #[wincode(with = "containers::Vec<RingDepositEntry, FixIntLen<u8>>")]
    pub deposits: Vec<RingDepositEntry>,
}

impl RingDepositIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Borrowed view of [`RingDepositEntry`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct RingDepositEntryRef<'a> {
    pub asset_index: u8,
    pub view_tag: &'a [u8; 32],
    pub owner_utxo_hash: &'a [u8; 32],
    pub amount: u64,
    pub data_hash: Option<&'a [u8; 32]>,
    pub ring_data_hash: &'a [u8; 32],
    pub encrypted: EncryptedRingDepositDataRef<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct EncryptedRingDepositDataRef<'a> {
    pub tx_viewing_pk: &'a [u8; 33],
    pub salt: &'a [u8; 16],
    pub ciphertext: &'a [u8],
}

/// Borrowed on-chain view of [`DepositIxData`]. Entry payloads alias the
/// instruction buffer.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct DepositIxDataRef<'a> {
    #[wincode(with = "containers::Vec<DepositAssetKind, FixIntLen<u8>>")]
    pub assets: Vec<DepositAssetKind>,
    #[wincode(with = "containers::Vec<DepositEntryRef<'a>, FixIntLen<u8>>")]
    pub deposits: Vec<DepositEntryRef<'a>>,
}

impl<'a> DepositIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> wincode::ReadResult<Self> {
        wincode::config::deserialize_exact(data, DepositRefConfig::new())
    }
}

/// Borrowed on-chain view of [`RingDepositIxData`]. Entry payloads alias the
/// instruction buffer.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct RingDepositIxDataRef<'a> {
    #[wincode(with = "containers::Vec<DepositAssetKind, FixIntLen<u8>>")]
    pub assets: Vec<DepositAssetKind>,
    #[wincode(with = "containers::Vec<RingDepositEntryRef<'a>, FixIntLen<u8>>")]
    pub deposits: Vec<RingDepositEntryRef<'a>>,
}

impl<'a> RingDepositIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> wincode::ReadResult<Self> {
        wincode::config::deserialize_exact(data, DepositRefConfig::new())
    }
}

#[cfg(test)]
mod tests {
    use super::deposit_blinding;

    /// Pinned cross-language vector; the TypeScript `depositBlinding` mirror
    /// asserts the same bytes.
    #[test]
    fn deposit_blinding_is_pinned() {
        let blinding = deposit_blinding(&[1u8; 32], 7).expect("derive");
        assert_eq!(
            blinding,
            [
                0x00, 0x4d, 0x1e, 0x40, 0xd2, 0x14, 0x24, 0x11, 0xb3, 0x9e, 0x40, 0xc7, 0x63, 0xdb,
                0x9d, 0xef, 0xb6, 0xca, 0x70, 0xab, 0xea, 0xad, 0x20, 0x67, 0x44, 0x43, 0xd3, 0x3f,
                0x88, 0xbe, 0x67, 0x3a,
            ]
        );
    }

    /// The leaf index is what makes a deposit leaf unique, so it must change the
    /// blinding, and so must the tree.
    #[test]
    fn deposit_blinding_separates_tree_and_leaf_index() {
        let base = deposit_blinding(&[1u8; 32], 7).expect("derive");
        assert_ne!(base, deposit_blinding(&[1u8; 32], 8).expect("derive"));
        assert_ne!(base, deposit_blinding(&[2u8; 32], 7).expect("derive"));
        assert_eq!(
            base[0], 0,
            "leading byte is zeroed to stay below the modulus"
        );
    }
}
