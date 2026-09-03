use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
pub use zolana_event::{
    confidential_encrypted_output_body, is_confidential_encrypted_output,
    ring_confidential_encrypted_output_body, MessageData, OutputUtxo,
};
use zolana_hasher::{sha256::Sha256BE, Hasher, HasherError};

pub use crate::verifying_keys::{Bsb22Commitment, CircuitId, RingP256ProofData};
use crate::{error::ShieldedPoolError, MAX_INTERFACE_TRANSFERS};

/// The compressed Groth16 proof carried by a `transact` instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactProof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}

impl TransactProof {
    /// A zeroed proof, used as a placeholder before the real proof is attached
    /// and as a dummy in tests.
    pub const fn zeroed() -> Self {
        Self {
            a: [0u8; 32],
            b: [0u8; 64],
            c: [0u8; 32],
        }
    }
}

/// One spent input UTXO (spec: `transact` `InputUtxo`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct InputUtxo {
    pub nullifier_hash: [u8; 32],
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
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

/// `transact` instruction data (spec: SPP `transact`).
/// The proof-bound region of `transact` instruction data: everything
/// `external_data_hash` covers, in one contiguous run immediately after the
/// instruction tag. Splitting it from the tail makes the binding boundary a
/// type, so a field added on the wrong side is a compile-time decision rather
/// than a silent change to what the proof commits to.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactIxBound {
    /// Expire proof for transactions with relayer.
    pub expiry_unix_ts: u64,
    /// SEC1-compressed P256 viewing key shared by every output ciphertext in
    /// this transaction; copied verbatim into the logged `GeneralEvent` so an
    /// indexer need not parse the per-output `data`.
    pub tx_viewing_pk: [u8; 33],
    /// Per-transaction encryption salt shared by every output ciphertext;
    /// copied into the logged `GeneralEvent` so wallets can derive the AES
    /// key/nonce without parsing the per-output `data`.
    pub salt: [u8; 16],
    #[wincode(with = "containers::Vec<InterfaceTransfer, FixIntLen<u8>>")]
    pub interface_transfers: Vec<InterfaceTransfer>,
    /// All `M` outputs in tree-append order (SPL change, SOL change, then
    /// recipients / dummies). Each carries its commitment, owner tag, and an
    /// optional ciphertext. Commitments are appended to the UTXO tree and folded
    /// into the proof's output hash chain; dummy outputs carry real-looking
    /// hashes and ciphertexts, so the vector does not reveal the recipient count.
    /// A `None` `data` marks a slot covered by a preceding bundle.
    #[wincode(with = "containers::Vec<TransactOutput, FixIntLen<u8>>")]
    pub outputs: Vec<TransactOutput>,
    /// Published ciphertexts bound to no output commitment, republished
    /// verbatim in the `GeneralEvent`.
    #[wincode(with = "containers::Vec<MessageData, FixIntLen<u8>>")]
    pub messages: Vec<MessageData>,
}

/// The fields `external_data_hash` does not cover. Each is bound by another
/// public input -- `circuit` selects the verifying key, `private_tx_hash` and
/// `inputs` are bound through the proof -- or is unbound (`data_hash`,
/// `ring_data_hash`).
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactIxTail {
    pub circuit: CircuitId,
    pub proof: TransactProof,
    pub private_tx_hash: [u8; 32],
    #[wincode(with = "containers::Vec<InputUtxo, FixIntLen<u8>>")]
    pub inputs: Vec<InputUtxo>,
    /// Optional transaction-level application- and ring-specific external data
    /// digests; `None` (`[0; 32]`) for a default-ring `transact`. Distinct from
    /// the per-UTXO `data_hash` / `ring_data_hash` in the UTXO body.
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>, // TODO: check whether we use this at all.
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactIxData {
    pub bound: TransactIxBound,
    pub tail: TransactIxTail,
}

impl TransactIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        validate_interface_transfers(&self.bound.interface_transfers)
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

/// Zero-copy view of [`TransactIxData`]. The large payloads (`proof` and the
/// output ciphertexts) alias the instruction buffer; only the small element
/// vectors are read owned.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct TransactIxBoundRef<'a> {
    pub expiry_unix_ts: u64,
    pub tx_viewing_pk: &'a [u8; 33],
    pub salt: &'a [u8; 16],
    #[wincode(with = "containers::Vec<InterfaceTransfer, FixIntLen<u8>>")]
    pub interface_transfers: Vec<InterfaceTransfer>,
    #[wincode(with = "containers::Vec<TransactOutputRef<'a>, FixIntLen<u8>>")]
    pub outputs: Vec<TransactOutputRef<'a>>,
    #[wincode(with = "containers::Vec<OutputDataRef<'a>, FixIntLen<u8>>")]
    pub messages: Vec<OutputDataRef<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct TransactIxTailRef<'a> {
    pub circuit: CircuitId,
    pub proof: TransactProof,
    pub private_tx_hash: &'a [u8; 32],
    #[wincode(with = "containers::Vec<InputUtxo, FixIntLen<u8>>")]
    pub inputs: Vec<InputUtxo>,
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
}

/// Borrowed view of `transact` instruction data.
///
/// Deliberately has no `SchemaRead` derive: [`Self::parse_bound`] is the only
/// way to read one, and it is also the only source of the bound byte slice.
/// That removes the failure mode where a caller parses the instruction one way
/// and hashes a different range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactIxDataRef<'a> {
    pub bound: TransactIxBoundRef<'a>,
    pub tail: TransactIxTailRef<'a>,
}

impl<'a> TransactIxDataRef<'a> {
    /// Parse the instruction and return it together with the exact bound prefix
    /// the proof commits to.
    ///
    /// The prefix is measured by the parse rather than declared by a length
    /// field, so it cannot disagree with the fields the program then acts on. A
    /// slice is returned rather than an offset because an offset can be applied
    /// to the wrong buffer -- one that still carries the tag byte, say -- and
    /// that mistake is silent.
    pub fn parse_bound(data: &'a [u8]) -> Result<(Self, &'a [u8]), wincode::ReadError> {
        use wincode::SchemaRead;

        let mut cursor: &'a [u8] = data;
        let bound = <TransactIxBoundRef<'a> as SchemaRead<'a, RefConfig>>::get(&mut cursor)?;
        let bound_len = data
            .len()
            .checked_sub(cursor.len())
            .ok_or(wincode::ReadError::Custom("bound region length underflow"))?;
        let bound_bytes = data
            .get(..bound_len)
            .ok_or(wincode::ReadError::Custom("bound region out of range"))?;
        let tail = <TransactIxTailRef<'a> as SchemaRead<'a, RefConfig>>::get(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(wincode::ReadError::Custom("trailing bytes"));
        }
        Ok((Self { bound, tail }, bound_bytes))
    }

    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        Self::parse_bound(data).map(|(parsed, _)| parsed)
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

/// An output whose owner tag has been resolved to concrete bytes: the only form
/// the resolution `external_data_hash` needs, so the hash covers the resolved tag rather than
/// its wire encoding and stays fail-closed against account-list tampering.
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

/// `view_tag`/`data` byte accessors shared by the owned [`MessageData`] and the
/// borrowed [`OutputDataRef`], so the same code path handles either message
/// representation.
pub trait OutputDataBytes {
    fn view_tag(&self) -> &[u8; 32];
    fn data(&self) -> &[u8];
}

impl OutputDataBytes for MessageData {
    fn view_tag(&self) -> &[u8; 32] {
        &self.view_tag
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
}

impl OutputDataBytes for OutputDataRef<'_> {
    fn view_tag(&self) -> &[u8; 32] {
        self.view_tag
    }
    fn data(&self) -> &[u8] {
        self.data
    }
}

/// `external_data_hash` public input (spec: `transact` external_data_hash). The
/// program recomputes it from the instruction and the committed Solana accounts;
/// the client computes the identical value when building the proof. It covers the
/// instruction's external fields, the resolved outputs, and the messages, but
/// never `private_tx_hash` (which already commits this hash) or the input UTXOs
/// (bound through `private_tx_hash`). Used in both the program and the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedInterfaceTransfer {
    SolDeposit {
        amount: u64,
        recipient: [u8; 32],
    },
    SolWithdrawal {
        amount: u64,
        recipient: [u8; 32],
    },
    SplDeposit {
        amount: u64,
        user_token_account: [u8; 32],
        spl_interface: [u8; 32],
    },
    SplWithdrawal {
        amount: u64,
        user_token_account: [u8; 32],
        spl_interface: [u8; 32],
    },
}

/// `external_data_hash` public input: SHA-256 over the instruction
/// discriminator, the contiguous proof-bound region of the raw instruction
/// data, and a digest of the account addresses the proof must commit to.
///
/// No preimage copy: the bound bytes are hashed in place out of the instruction
/// buffer. The addresses are folded into a single digest first so this
/// function's stack frame is a fixed three-slot array rather than one pointer
/// per leg and output, which would grow with the shape.
///
/// Injective. The bound region's encoding is self-delimiting, so it is
/// recoverable from the preimage by reading it; the number of appended
/// addresses is then a function of the bound region alone (one per SOL leg, two
/// per SPL leg, one per output whose owner tag names an account), so the
/// address digest cannot absorb or shed an entry.
///
/// `addresses` must yield, in order: each interface transfer's settlement
/// accounts in leg order, then the resolved owner of every `OwnerTag::Account`
/// output in output order.
pub fn external_data_hash<'a>(
    spp_instruction_discriminator: u8,
    bound: &[u8],
    addresses: impl Iterator<Item = &'a [u8; 32]>,
) -> Result<[u8; 32], HasherError> {
    let mut address_digest = [0u8; 32];
    for address in addresses {
        address_digest = Sha256BE::hashv(&[&address_digest, address])?;
    }
    Sha256BE::hashv(&[&[spp_instruction_discriminator], bound, &address_digest])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The selector is a 2-byte little-endian enum tag followed by its three
    /// one-byte dimensions; unknown tags are rejected fail-closed.
    #[test]
    fn circuit_id_wire_layout_and_unknown_rejection() {
        let vanilla_ids = [
            CircuitId::ConfidentialEddsa(1, 2, 3),
            CircuitId::RingEddsa(2, 3, 3),
            CircuitId::RingAuthority(4, 4, 3),
        ];
        for (value, id) in vanilla_ids.into_iter().enumerate() {
            let bytes = wincode::serialize(&id).unwrap();
            let mut expected = (value as u16).to_le_bytes().to_vec();
            expected.extend_from_slice(&[
                id.num_inputs(),
                id.num_outputs(),
                id.num_public_asset_slots(),
            ]);
            assert_eq!(bytes, expected);
            assert_eq!(wincode::deserialize_exact::<CircuitId>(&bytes).unwrap(), id);
        }

        let commitment = Bsb22Commitment {
            commitment: [4u8; 32],
            commitment_pok: [5u8; 32],
        };
        let proof_data = crate::verifying_keys::RingP256ProofData {
            bsb22_commitment: commitment,
            default_owner_tag: None,
        };
        let p256 = CircuitId::RingP256(2, 3, 3, proof_data);
        let bytes = wincode::serialize(&p256).unwrap();
        let mut expected = 3u16.to_le_bytes().to_vec();
        expected.extend_from_slice(&[2, 3, 3]);
        expected.extend_from_slice(&commitment.commitment);
        expected.extend_from_slice(&commitment.commitment_pok);
        expected.push(0);
        expected.extend_from_slice(&[0u8; 32]);
        assert_eq!(bytes, expected);
        assert_eq!(
            wincode::deserialize_exact::<CircuitId>(&bytes).unwrap(),
            p256
        );

        let tagged = CircuitId::RingP256(
            2,
            3,
            3,
            RingP256ProofData {
                bsb22_commitment: commitment,
                default_owner_tag: Some([7u8; 32]),
            },
        );
        let tagged_bytes = wincode::serialize(&tagged).unwrap();
        assert_eq!(tagged_bytes[tagged_bytes.len() - 33], 1);
        assert_eq!(&tagged_bytes[tagged_bytes.len() - 32..], &[7u8; 32]);
        assert_eq!(
            wincode::deserialize_exact::<CircuitId>(&tagged_bytes).unwrap(),
            tagged
        );

        let mut noncanonical_none = bytes;
        *noncanonical_none.last_mut().unwrap() = 1;
        assert!(wincode::deserialize_exact::<CircuitId>(&noncanonical_none).is_err());

        let unknown = 4u16.to_le_bytes();
        assert!(wincode::deserialize_exact::<CircuitId>(&unknown).is_err());
    }

    fn proof() -> TransactProof {
        TransactProof {
            a: [1u8; 32],
            b: [2u8; 64],
            c: [3u8; 32],
        }
    }

    #[test]
    fn transact_proof_round_trips() {
        let proof = proof();
        let bytes = wincode::serialize(&proof).unwrap();
        let decoded: TransactProof = wincode::deserialize_exact(&bytes).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn proof_has_expected_wire_size() {
        let proof = wincode::serialize(&proof()).unwrap();
        assert_eq!(proof.len(), 128);
    }

    fn mixed_outputs() -> Vec<TransactOutput> {
        vec![
            TransactOutput {
                utxo_hash: [10u8; 32],
                owner_tag: OwnerTag::Inline([11u8; 32]),
                data: Some(vec![1, 2, 3]),
            },
            TransactOutput {
                utxo_hash: [12u8; 32],
                owner_tag: OwnerTag::Account(2),
                data: None,
            },
            TransactOutput {
                utxo_hash: [13u8; 32],
                owner_tag: OwnerTag::Inline([14u8; 32]),
                data: Some(vec![4, 5, 6, 7]),
            },
        ]
    }

    fn ix_data(proof: TransactProof) -> TransactIxData {
        TransactIxData {
            bound: TransactIxBound {
                expiry_unix_ts: 7,
                interface_transfers: vec![
                    InterfaceTransfer::SolWithdrawal { amount: 5 },
                    InterfaceTransfer::SplDeposit {
                        amount: 7,
                        spl_interface_bump: 42,
                    },
                ],
                tx_viewing_pk: [4u8; 33],
                salt: [6u8; 16],
                outputs: mixed_outputs(),
                messages: vec![MessageData {
                    view_tag: [30u8; 32],
                    data: vec![8, 9],
                }],
            },
            tail: TransactIxTail {
                proof,
                private_tx_hash: [9u8; 32],
                circuit: CircuitId::ConfidentialEddsa(1, 3, 3),
                inputs: vec![InputUtxo {
                    nullifier_hash: [1u8; 32],
                    nullifier_tree_root_index: 2,
                    utxo_tree_root_index: 3,
                }],
                data_hash: None,
                ring_data_hash: None,
            },
        }
    }

    /// Every field of the borrowed view aliases the same bytes the owned struct
    /// serialized, so the swap program's owned-reserialize CPI path is byte-exact.
    fn assert_ref_matches_owned(view: &TransactIxDataRef, owned: &TransactIxData) {
        assert_eq!(view.bound.expiry_unix_ts, owned.bound.expiry_unix_ts);
        assert_eq!(view.tail.private_tx_hash, &owned.tail.private_tx_hash);
        assert_eq!(view.tail.circuit, owned.tail.circuit);
        assert_eq!(view.bound.tx_viewing_pk, &owned.bound.tx_viewing_pk);
        assert_eq!(view.bound.salt, &owned.bound.salt);
        assert_eq!(view.tail.proof, owned.tail.proof);
        assert_eq!(view.tail.inputs, owned.tail.inputs);
        assert_eq!(
            view.bound.interface_transfers,
            owned.bound.interface_transfers
        );
        assert_eq!(view.tail.data_hash, owned.tail.data_hash);
        assert_eq!(view.tail.ring_data_hash, owned.tail.ring_data_hash);
        assert_eq!(view.bound.outputs.len(), owned.bound.outputs.len());
        for (got, want) in view.bound.outputs.iter().zip(owned.bound.outputs.iter()) {
            assert_eq!(got.utxo_hash, &want.utxo_hash);
            assert_eq!(got.owner_tag, want.owner_tag);
            assert_eq!(got.data, want.data.as_deref());
        }
        assert_eq!(view.bound.messages.len(), owned.bound.messages.len());
        for (got, want) in view.bound.messages.iter().zip(owned.bound.messages.iter()) {
            assert_eq!(got.view_tag, &want.view_tag);
            assert_eq!(got.data, want.data.as_slice());
        }
    }

    #[test]
    fn ix_data_round_trips_owned_and_ref() {
        let owned = ix_data(proof());
        let bytes = owned.serialize().unwrap();
        assert_eq!(TransactIxData::deserialize(&bytes).unwrap(), owned);
        let view = TransactIxDataRef::from_bytes(&bytes).unwrap();
        assert_ref_matches_owned(&view, &owned);
    }

    /// Serialize owned, parse the borrowed view, and confirm every field matches:
    /// the owned and Ref encodings are byte-identical, guarding the swap program's
    /// owned-reserialize CPI path.
    #[test]
    fn owned_serialize_matches_ref_parse() {
        let owned = ix_data(proof());
        let bytes = owned.serialize().unwrap();
        let view = TransactIxDataRef::from_bytes(&bytes).unwrap();
        assert_ref_matches_owned(&view, &owned);
    }

    #[test]
    fn rejects_retired_field_bearing_payload() {
        let owned = ix_data(proof());
        let current = owned.serialize().unwrap();
        // expiry(8) || private_tx_hash(32) || CircuitId tag/shape(5), followed
        // by the retired Option<[u8; 32]> encoding.
        let field_offset = 8 + 32 + 5;
        let mut retired = Vec::with_capacity(current.len() + 33);
        retired.extend_from_slice(&current[..field_offset]);
        retired.push(1);
        retired.extend_from_slice(&[20u8; 32]);
        retired.extend_from_slice(&current[field_offset..]);
        assert!(TransactIxData::deserialize(&retired).is_err());
        assert!(TransactIxDataRef::from_bytes(&retired).is_err());
    }

    #[test]
    fn rejects_retired_owner_tag_discriminant() {
        assert!(wincode::deserialize_exact::<OwnerTag>(&[2]).is_err());
    }

    #[test]
    fn interface_transfer_sizes_and_helpers_are_stable() {
        let sol = InterfaceTransfer::SolWithdrawal { amount: u64::MAX };
        let spl = InterfaceTransfer::SplDeposit {
            amount: 9,
            spl_interface_bump: 42,
        };
        let variants = [
            InterfaceTransfer::SolDeposit { amount: 1 },
            InterfaceTransfer::SolWithdrawal { amount: 1 },
            InterfaceTransfer::SplDeposit {
                amount: 1,
                spl_interface_bump: 42,
            },
            InterfaceTransfer::SplWithdrawal {
                amount: 1,
                spl_interface_bump: 42,
            },
        ];
        for (expected_tag, transfer) in variants.into_iter().enumerate() {
            assert_eq!(
                wincode::serialize(&transfer).unwrap()[0],
                expected_tag as u8
            );
        }
        assert_eq!(wincode::serialize(&sol).unwrap().len(), 9);
        assert_eq!(wincode::serialize(&spl).unwrap().len(), 10);
        assert_eq!(sol.amount(), u64::MAX);
        assert_eq!(spl.amount(), 9);
        assert!(!sol.is_spl());
        assert!(spl.is_spl());
        assert!(!sol.is_deposit());
        assert!(spl.is_deposit());
    }

    #[test]
    fn interface_transfer_validation_accepts_many_transfers_up_to_limit() {
        let repeated = vec![InterfaceTransfer::SolDeposit { amount: 1 }; MAX_INTERFACE_TRANSFERS];
        assert_eq!(validate_interface_transfers(&repeated), Ok(()));

        let too_many = vec![
            InterfaceTransfer::SplWithdrawal {
                amount: 1,
                spl_interface_bump: 42,
            };
            MAX_INTERFACE_TRANSFERS + 1
        ];
        assert_eq!(
            validate_interface_transfers(&too_many),
            Err(ShieldedPoolError::TooManyInterfaceTransfers)
        );
        assert_eq!(
            validate_interface_transfers(&[InterfaceTransfer::SolDeposit { amount: 0 }]),
            Err(ShieldedPoolError::ZeroInterfaceTransferAmount)
        );
    }

    /// The protocol bound on interface transfers is enforced where the count is
    /// still a count: serialization and the program's account parsing. The hash
    /// no longer re-checks it, because it hashes the already-validated bytes
    /// rather than rebuilding a preimage from a slice.
    #[test]
    fn interface_transfer_count_rejects_protocol_overflow_during_serialization() {
        let mut data = ix_data(proof());
        data.bound.interface_transfers =
            vec![InterfaceTransfer::SolDeposit { amount: 1 }; MAX_INTERFACE_TRANSFERS + 1];
        assert!(data.serialize().is_err());

        assert!(validate_interface_transfers(&data.bound.interface_transfers).is_err());
    }

    /// Per-`OwnerTag` serialized size of a single `None`-data output:
    /// utxo_hash(32) || enum tag(1) [+32 Inline / +1 Account] ||
    /// Option presence(1).
    #[test]
    fn transact_output_serialized_sizes_per_owner_tag() {
        let inline = TransactOutput {
            utxo_hash: [0u8; 32],
            owner_tag: OwnerTag::Inline([0u8; 32]),
            data: None,
        };
        let account = TransactOutput {
            utxo_hash: [0u8; 32],
            owner_tag: OwnerTag::Account(0),
            data: None,
        };
        assert_eq!(wincode::serialize(&inline).unwrap().len(), 32 + 34);
        assert_eq!(wincode::serialize(&account).unwrap().len(), 32 + 3);

        // Some(data) adds the enum presence byte's 1 plus u16 length prefix and
        // the payload on top of the None cases above.
        let inline_some = TransactOutput {
            utxo_hash: [0u8; 32],
            owner_tag: OwnerTag::Inline([0u8; 32]),
            data: Some(vec![1, 2, 3]),
        };
        assert_eq!(
            wincode::serialize(&inline_some).unwrap().len(),
            32 + 33 + 1 + 2 + 3
        );
    }

    #[test]
    fn fetch_tag_resolves_every_variant() {
        let accounts = |i: u8| if i == 2 { Some([22u8; 32]) } else { None };

        assert_eq!(
            fetch_tag(&OwnerTag::Inline([7u8; 32]), accounts),
            Ok([7u8; 32])
        );
        assert_eq!(fetch_tag(&OwnerTag::Account(2), accounts), Ok([22u8; 32]));
        assert_eq!(
            fetch_tag(&OwnerTag::Account(5), accounts),
            Err(ShieldedPoolError::OwnerTagAccountMissing)
        );
    }

    /// Bound regions that differ must hash differently. The properties below
    /// used to need hand-built count and length prefixes; they now follow from
    /// the instruction encoding being self-delimiting, so these tests pin that
    /// the encoding really has that property rather than that a preimage
    /// builder remembered to add framing.
    fn bound(outputs: Vec<TransactOutput>, messages: Vec<MessageData>) -> TransactIxBound {
        TransactIxBound {
            expiry_unix_ts: 7,
            tx_viewing_pk: [4u8; 33],
            salt: [6u8; 16],
            interface_transfers: vec![],
            outputs,
            messages,
        }
    }

    fn hash_bound(bound: &TransactIxBound, addresses: &[[u8; 32]]) -> [u8; 32] {
        let bytes = wincode::serialize(bound).expect("serialize bound region");
        external_data_hash(crate::instruction::tag::TRANSACT, &bytes, addresses.iter())
            .expect("external data hash")
    }

    fn output(utxo_hash: [u8; 32], owner_tag: OwnerTag, data: Option<Vec<u8>>) -> TransactOutput {
        TransactOutput {
            utxo_hash,
            owner_tag,
            data,
        }
    }

    #[test]
    fn external_data_hash_binds_the_encryption_context() {
        let base = bound(
            vec![output([1u8; 32], OwnerTag::Inline([2u8; 32]), None)],
            vec![],
        );
        let baseline = hash_bound(&base, &[]);

        let mut other_pk = base.clone();
        other_pk.tx_viewing_pk = [5u8; 33];
        assert_ne!(baseline, hash_bound(&other_pk, &[]));

        let mut other_salt = base.clone();
        other_salt.salt = [7u8; 16];
        assert_ne!(baseline, hash_bound(&other_salt, &[]));

        let mut other_expiry = base.clone();
        other_expiry.expiry_unix_ts = 8;
        assert_ne!(baseline, hash_bound(&other_expiry, &[]));
    }

    #[test]
    fn external_data_hash_is_injective_across_the_output_message_boundary() {
        // The same bytes, once as an output ciphertext and once as a message
        // payload, must not collide.
        let as_output = bound(
            vec![output(
                [1u8; 32],
                OwnerTag::Inline([2u8; 32]),
                Some(vec![9, 9]),
            )],
            vec![],
        );
        let as_message = bound(
            vec![output([1u8; 32], OwnerTag::Inline([2u8; 32]), None)],
            vec![MessageData {
                view_tag: [2u8; 32],
                data: vec![9, 9],
            }],
        );
        assert_ne!(hash_bound(&as_output, &[]), hash_bound(&as_message, &[]));
    }

    #[test]
    fn external_data_hash_distinguishes_empty_data_from_none() {
        let none = bound(
            vec![output([1u8; 32], OwnerTag::Inline([2u8; 32]), None)],
            vec![],
        );
        let empty = bound(
            vec![output([1u8; 32], OwnerTag::Inline([2u8; 32]), Some(vec![]))],
            vec![],
        );
        assert_ne!(hash_bound(&none, &[]), hash_bound(&empty, &[]));
    }

    #[test]
    fn external_data_hash_is_injective_across_the_owner_tag_data_boundary() {
        // A 32-byte value cannot migrate between the owner tag and the
        // ciphertext without changing the digest.
        let a = bound(
            vec![output(
                [1u8; 32],
                OwnerTag::Inline([3u8; 32]),
                Some(vec![4; 32]),
            )],
            vec![],
        );
        let b = bound(
            vec![output(
                [1u8; 32],
                OwnerTag::Inline([4u8; 32]),
                Some(vec![3; 32]),
            )],
            vec![],
        );
        assert_ne!(hash_bound(&a, &[]), hash_bound(&b, &[]));
    }

    #[test]
    fn external_data_hash_freezes_the_owner_tag_encoding() {
        // Behaviour change from the old preimage, which covered only the
        // resolved tag: `Inline(x)` and `Account(i)` resolving to the same `x`
        // are now distinct, so a relayer cannot rewrite one into the other.
        let inline = bound(
            vec![output([1u8; 32], OwnerTag::Inline([9u8; 32]), None)],
            vec![],
        );
        let by_account = bound(vec![output([1u8; 32], OwnerTag::Account(3), None)], vec![]);
        assert_ne!(
            hash_bound(&inline, &[]),
            hash_bound(&by_account, &[[9u8; 32]])
        );
    }

    #[test]
    fn external_data_hash_binds_appended_address_order() {
        let base = bound(
            vec![output([1u8; 32], OwnerTag::Inline([2u8; 32]), None)],
            vec![],
        );
        let forward = hash_bound(&base, &[[7u8; 32], [8u8; 32]]);
        let swapped = hash_bound(&base, &[[8u8; 32], [7u8; 32]]);
        assert_ne!(
            forward, swapped,
            "reordering settlement accounts must change the digest"
        );
        assert_ne!(
            forward,
            hash_bound(&base, &[[7u8; 32]]),
            "dropping an address must change the digest"
        );
    }

    #[test]
    fn external_data_hash_binds_the_instruction_discriminator() {
        let base = bound(
            vec![output([1u8; 32], OwnerTag::Inline([2u8; 32]), None)],
            vec![],
        );
        let bytes = wincode::serialize(&base).expect("serialize bound region");
        assert_ne!(
            external_data_hash(crate::instruction::tag::TRANSACT, &bytes, [].iter()).unwrap(),
            external_data_hash(crate::instruction::tag::RING_TRANSACT, &bytes, [].iter()).unwrap(),
        );
    }
}
