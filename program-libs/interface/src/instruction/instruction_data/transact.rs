use arrayvec::ArrayVec;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_hasher::{sha256::Sha256BE, Hasher, HasherError};

pub use crate::output_data::MessageData;

pub use crate::verifying_keys::{Bsb22Commitment, CircuitId, RingP256ProofData};
use crate::{
    error::ShieldedPoolError, MAX_EXTERNAL_DATA_HASH_SLICES, MAX_INTERFACE_TRANSFERS,
    MAX_TRANSACT_INPUTS, MAX_TRANSACT_OUTPUTS,
};

use super::borrowed::{finish, read, BorrowedList, DecodeError};

/// The compressed Groth16 proof carried by a `transact` instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactProof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}

/// Borrowed view of [`TransactProof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct TransactProofRef<'a> {
    pub a: &'a [u8; 32],
    pub b: &'a [u8; 64],
    pub c: &'a [u8; 32],
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

/// Borrowed view of [`InputUtxo`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct InputUtxoRef<'a> {
    pub nullifier_hash: &'a [u8; 32],
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

    /// Accounts in this transfer's settlement group: `[sol_interface, user]`
    /// for SOL legs, `[mint | cpi_authority, .., token_program]` for SPL legs.
    pub const fn settlement_account_count(self) -> usize {
        match self {
            Self::SolDeposit { .. } | Self::SolWithdrawal { .. } => 2,
            Self::SplDeposit { .. } | Self::SplWithdrawal { .. } => 5,
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

/// Borrowed view of [`OwnerTag`]. Inline bytes alias instruction data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
#[wincode(tag_encoding = "u8")]
pub enum OwnerTagRef<'a> {
    Inline(&'a [u8; 32]),
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

/// Flat `transact` instruction data (spec: SPP `transact`).
///
/// Fields through `messages` form the contiguous prefix covered by
/// `external_data_hash`. Within that prefix, and within the remaining fields,
/// relative order is preserved from the original flat instruction layout.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactIxData {
    /// Expire proof for transactions with relayer.
    pub expiry_unix_ts: u64,
    /// SEC1-compressed P256 viewing key shared by every output ciphertext in
    /// this transaction; bound into `external_data_hash` and copied verbatim
    /// into the reconstructed `GeneralEvent`.
    pub tx_viewing_pk: [u8; 33],
    /// Per-transaction encryption salt shared by every output ciphertext;
    /// bound into `external_data_hash` and copied into the reconstructed
    /// `GeneralEvent`.
    pub salt: [u8; 16],
    #[wincode(with = "containers::Vec<InterfaceTransfer, FixIntLen<u8>>")]
    pub interface_transfers: Vec<InterfaceTransfer>,
    /// Optional transaction-level application- and ring-specific external-data
    /// digests. Distinct from the per-UTXO hashes in the UTXO body.
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
    /// All outputs in tree-append order. A `None` `data` marks a slot covered
    /// by a preceding ciphertext bundle.
    #[wincode(with = "containers::Vec<TransactOutput, FixIntLen<u8>>")]
    pub outputs: Vec<TransactOutput>,
    /// Published ciphertexts bound to no output position.
    #[wincode(with = "containers::Vec<MessageData, FixIntLen<u8>>")]
    pub messages: Vec<MessageData>,
    pub private_tx_hash: [u8; 32],
    pub circuit: CircuitId,
    pub proof: TransactProof,
    #[wincode(with = "containers::Vec<InputUtxo, FixIntLen<u8>>")]
    pub inputs: Vec<InputUtxo>,
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

/// Borrowed view of a [`TransactOutput`]; `data` aliases the instruction buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct TransactOutputRef<'a> {
    pub utxo_hash: &'a [u8; 32],
    pub owner_tag: OwnerTagRef<'a>,
    pub data: Option<&'a [u8]>,
}

/// Borrowed view of a [`MessageData`]; `data` aliases the instruction buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct MessageDataRef<'a> {
    pub view_tag: &'a [u8; 32],
    pub data: &'a [u8],
}

/// Flat, allocation-free borrowed view of [`TransactIxData`]. Lists retain
/// their encoded bytes and decode one record at a time during iteration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactIxDataRef<'a> {
    pub expiry_unix_ts: u64,
    pub tx_viewing_pk: &'a [u8; 33],
    pub salt: &'a [u8; 16],
    pub interface_transfers: BorrowedList<'a, InterfaceTransfer>,
    pub data_hash: Option<&'a [u8; 32]>,
    pub ring_data_hash: Option<&'a [u8; 32]>,
    pub outputs: BorrowedList<'a, TransactOutputRef<'a>>,
    pub messages: BorrowedList<'a, MessageDataRef<'a>>,
    pub private_tx_hash: &'a [u8; 32],
    pub circuit: CircuitId,
    pub proof: TransactProofRef<'a>,
    pub inputs: BorrowedList<'a, InputUtxoRef<'a>>,
}

impl<'a> TransactIxDataRef<'a> {
    /// Parse the flat instruction, visiting the exact serialized prefix covered
    /// by `external_data_hash` immediately after its final field (`messages`)
    /// and before parsing the rest of the instruction.
    ///
    /// The parser records its cursor immediately after `messages`, before it
    /// reads `private_tx_hash`. The callback also receives the already-validated
    /// transfer and output views needed to select account addresses. No field is
    /// cloned or reserialized.
    pub fn parse_with_external_data<R>(
        data: &'a [u8],
        visit: impl FnOnce(
            &'a [u8],
            BorrowedList<'a, InterfaceTransfer>,
            BorrowedList<'a, TransactOutputRef<'a>>,
        ) -> R,
    ) -> Result<(Self, R), DecodeError> {
        let mut cursor = data;
        let expiry_unix_ts = read::<u64>(&mut cursor)?;
        let tx_viewing_pk = read::<&[u8; 33]>(&mut cursor)?;
        let salt = read::<&[u8; 16]>(&mut cursor)?;
        let interface_transfers = BorrowedList::read::<InterfaceTransfer>(
            &mut cursor,
            MAX_INTERFACE_TRANSFERS,
            ShieldedPoolError::TooManyInterfaceTransfers,
        )?;
        let data_hash = read::<Option<&[u8; 32]>>(&mut cursor)?;
        let ring_data_hash = read::<Option<&[u8; 32]>>(&mut cursor)?;
        let outputs = BorrowedList::read::<TransactOutputRef<'a>>(
            &mut cursor,
            MAX_TRANSACT_OUTPUTS,
            ShieldedPoolError::InvalidTransactShape,
        )?;
        let messages = BorrowedList::read::<MessageDataRef<'a>>(
            &mut cursor,
            u8::MAX.into(),
            ShieldedPoolError::InvalidInstructionData,
        )?;

        let external_data_len =
            data.len()
                .checked_sub(cursor.len())
                .ok_or(wincode::ReadError::Custom(
                    "instruction cursor moved backwards",
                ))?;
        let external_data_prefix =
            data.get(..external_data_len)
                .ok_or(wincode::ReadError::Custom(
                    "external-data prefix is outside instruction data",
                ))?;
        let visited = visit(external_data_prefix, interface_transfers, outputs);

        let private_tx_hash = read::<&[u8; 32]>(&mut cursor)?;
        let circuit = read::<CircuitId>(&mut cursor)?;
        let proof = read::<TransactProofRef<'a>>(&mut cursor)?;
        let inputs = BorrowedList::read::<InputUtxoRef<'a>>(
            &mut cursor,
            MAX_TRANSACT_INPUTS,
            ShieldedPoolError::InvalidTransactShape,
        )?;
        finish(cursor)?;

        let parsed = Self {
            expiry_unix_ts,
            tx_viewing_pk,
            salt,
            interface_transfers,
            data_hash,
            ring_data_hash,
            outputs,
            messages,
            private_tx_hash,
            circuit,
            proof,
            inputs,
        };
        Ok((parsed, visited))
    }

    /// Parse the flat instruction and return the borrowed external-data prefix.
    pub fn parse_with_external_data_prefix(
        data: &'a [u8],
    ) -> Result<(Self, &'a [u8]), DecodeError> {
        Self::parse_with_external_data(data, |prefix, _, _| prefix)
    }

    pub fn from_bytes(data: &'a [u8]) -> Result<Self, DecodeError> {
        Self::parse_with_external_data_prefix(data).map(|(parsed, _)| parsed)
    }
}

/// Resolve an [`OwnerTag`] to its concrete 32-byte owner tag. The interface
/// crate has no account access, so off-chain decoders pass an account-address
/// lookup. The on-chain program resolves borrowed account addresses directly.
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

const _: () = assert!(MAX_EXTERNAL_DATA_HASH_SLICES >= 4);

/// Preimage of the `external_data_hash` public input (spec: `transact`
/// external_data_hash): the instruction discriminator, the contiguous
/// external-data prefix of the raw instruction data, the input and output tree
/// addresses, then the account addresses the proof commits to, hashed once.
///
/// Holds only borrowed slice descriptors, so neither the program nor a client
/// copies preimage bytes. The framing is unambiguous: the prefix encoding is
/// self-delimiting, the tree addresses are fixed width, and the number of
/// appended addresses is a function of the prefix alone (one per SOL leg, two
/// per SPL leg, one per output whose owner tag names an account).
pub struct ExternalDataPreimage<'a> {
    slices: ArrayVec<&'a [u8], MAX_EXTERNAL_DATA_HASH_SLICES>,
}

impl<'a> ExternalDataPreimage<'a> {
    pub fn new(
        spp_instruction_discriminator: &'a [u8; 1],
        external_data_prefix: &'a [u8],
        input_tree: &'a [u8; 32],
        output_tree: &'a [u8; 32],
    ) -> Self {
        let mut slices = ArrayVec::new();
        slices.push(spp_instruction_discriminator.as_slice());
        slices.push(external_data_prefix);
        slices.push(input_tree.as_slice());
        slices.push(output_tree.as_slice());
        Self { slices }
    }

    /// Appends the next committed address: each interface transfer's settlement
    /// accounts in leg order, then the resolved owner of every
    /// `OwnerTag::Account` output in output order.
    pub fn push_address(&mut self, address: &'a [u8; 32]) -> Result<(), HasherError> {
        let provided = self.slices.len() + 1;
        self.slices
            .try_push(address.as_slice())
            .map_err(|_| HasherError::InvalidInputLength(MAX_EXTERNAL_DATA_HASH_SLICES, provided))
    }

    pub fn finish(&self) -> Result<[u8; 32], HasherError> {
        Sha256BE::hashv(&self.slices)
    }
}

/// `external_data_hash` over a complete, already resolved address list; see
/// [`ExternalDataPreimage`] for the framing.
pub fn hash_external_data<'a>(
    spp_instruction_discriminator: u8,
    external_data_prefix: &[u8],
    input_tree: &[u8; 32],
    output_tree: &[u8; 32],
    addresses: impl Iterator<Item = &'a [u8; 32]>,
) -> Result<[u8; 32], HasherError> {
    let discriminator = [spp_instruction_discriminator];
    let mut preimage = ExternalDataPreimage::new(
        &discriminator,
        external_data_prefix,
        input_tree,
        output_tree,
    );
    for address in addresses {
        preimage.push_address(address)?;
    }
    preimage.finish()
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
            data_hash: None,
            ring_data_hash: None,
            proof,
            private_tx_hash: [9u8; 32],
            circuit: CircuitId::ConfidentialEddsa(1, 3, 3),
            inputs: vec![InputUtxo {
                nullifier_hash: [1u8; 32],
                nullifier_tree_root_index: 2,
                utxo_tree_root_index: 3,
            }],
        }
    }

    /// Every field of the borrowed view aliases the same bytes the owned struct
    /// serialized, so the swap program's owned-reserialize CPI path is byte-exact.
    fn assert_ref_matches_owned(view: &TransactIxDataRef, owned: &TransactIxData) {
        assert_eq!(view.expiry_unix_ts, owned.expiry_unix_ts);
        assert_eq!(view.private_tx_hash, &owned.private_tx_hash);
        assert_eq!(view.circuit, owned.circuit);
        assert_eq!(view.tx_viewing_pk, &owned.tx_viewing_pk);
        assert_eq!(view.salt, &owned.salt);
        assert_eq!(view.proof.a, &owned.proof.a);
        assert_eq!(view.proof.b, &owned.proof.b);
        assert_eq!(view.proof.c, &owned.proof.c);
        assert_eq!(view.inputs.len(), owned.inputs.len());
        for (got, want) in view.inputs.try_iter().zip(&owned.inputs) {
            let got = got.unwrap();
            assert_eq!(got.nullifier_hash, &want.nullifier_hash);
            assert_eq!(
                got.nullifier_tree_root_index,
                want.nullifier_tree_root_index
            );
            assert_eq!(got.utxo_tree_root_index, want.utxo_tree_root_index);
        }
        assert_eq!(
            view.interface_transfers.len(),
            owned.interface_transfers.len()
        );
        for (got, want) in view
            .interface_transfers
            .try_iter()
            .zip(&owned.interface_transfers)
        {
            assert_eq!(got.unwrap(), *want);
        }
        assert_eq!(view.data_hash, owned.data_hash.as_ref());
        assert_eq!(view.ring_data_hash, owned.ring_data_hash.as_ref());
        assert_eq!(view.outputs.len(), owned.outputs.len());
        for (got, want) in view.outputs.try_iter().zip(&owned.outputs) {
            let got = got.unwrap();
            assert_eq!(got.utxo_hash, &want.utxo_hash);
            match (got.owner_tag, want.owner_tag) {
                (OwnerTagRef::Inline(got), OwnerTag::Inline(want)) => assert_eq!(got, &want),
                (OwnerTagRef::Account(got), OwnerTag::Account(want)) => assert_eq!(got, want),
                _ => panic!("owner-tag variants differ"),
            }
            assert_eq!(got.data, want.data.as_deref());
        }
        assert_eq!(view.messages.len(), owned.messages.len());
        for (got, want) in view.messages.try_iter().zip(&owned.messages) {
            let got = got.unwrap();
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
    fn rejects_unknown_owner_tag_discriminant() {
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
        data.interface_transfers =
            vec![InterfaceTransfer::SolDeposit { amount: 1 }; MAX_INTERFACE_TRANSFERS + 1];
        assert!(data.serialize().is_err());

        assert!(validate_interface_transfers(&data.interface_transfers).is_err());
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

    /// External-data regions that differ must hash differently. The properties below
    /// used to need hand-built count and length prefixes; they now follow from
    /// the instruction encoding being self-delimiting, so these tests pin that
    /// the encoding really has that property rather than that a preimage
    /// builder remembered to add framing.
    fn external_data(outputs: Vec<TransactOutput>, messages: Vec<MessageData>) -> TransactIxData {
        TransactIxData {
            expiry_unix_ts: 7,
            tx_viewing_pk: [4u8; 33],
            salt: [6u8; 16],
            interface_transfers: vec![],
            outputs,
            messages,
            data_hash: None,
            ring_data_hash: None,
            circuit: CircuitId::ConfidentialEddsa(0, 0, 0),
            proof: TransactProof::zeroed(),
            private_tx_hash: [0u8; 32],
            inputs: Vec::new(),
        }
    }

    const INPUT_TREE: [u8; 32] = [2u8; 32];
    const OUTPUT_TREE: [u8; 32] = [3u8; 32];

    fn hash_ix_external_data(data: &TransactIxData, addresses: &[[u8; 32]]) -> [u8; 32] {
        let bytes = data.serialize().expect("serialize instruction");
        let (_, external_data) =
            TransactIxDataRef::parse_with_external_data_prefix(&bytes).expect("parse instruction");
        hash_external_data(
            crate::instruction::tag::TRANSACT,
            external_data,
            &INPUT_TREE,
            &OUTPUT_TREE,
            addresses.iter(),
        )
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
        let base = external_data(
            vec![output([1u8; 32], OwnerTag::Inline([2u8; 32]), None)],
            vec![],
        );
        let baseline = hash_ix_external_data(&base, &[]);

        let mut other_pk = base.clone();
        other_pk.tx_viewing_pk = [5u8; 33];
        assert_ne!(baseline, hash_ix_external_data(&other_pk, &[]));

        let mut other_salt = base.clone();
        other_salt.salt = [7u8; 16];
        assert_ne!(baseline, hash_ix_external_data(&other_salt, &[]));

        let mut other_expiry = base.clone();
        other_expiry.expiry_unix_ts = 8;
        assert_ne!(baseline, hash_ix_external_data(&other_expiry, &[]));
    }

    #[test]
    fn external_data_hash_is_injective_across_the_output_message_boundary() {
        // The same bytes, once as an output ciphertext and once as a message
        // payload, must not collide.
        let as_output = external_data(
            vec![output(
                [1u8; 32],
                OwnerTag::Inline([2u8; 32]),
                Some(vec![9, 9]),
            )],
            vec![],
        );
        let as_message = external_data(
            vec![output([1u8; 32], OwnerTag::Inline([2u8; 32]), None)],
            vec![MessageData {
                view_tag: [2u8; 32],
                data: vec![9, 9],
            }],
        );
        assert_ne!(
            hash_ix_external_data(&as_output, &[]),
            hash_ix_external_data(&as_message, &[])
        );
    }

    #[test]
    fn external_data_hash_distinguishes_empty_data_from_none() {
        let none = external_data(
            vec![output([1u8; 32], OwnerTag::Inline([2u8; 32]), None)],
            vec![],
        );
        let empty = external_data(
            vec![output([1u8; 32], OwnerTag::Inline([2u8; 32]), Some(vec![]))],
            vec![],
        );
        assert_ne!(
            hash_ix_external_data(&none, &[]),
            hash_ix_external_data(&empty, &[])
        );
    }

    #[test]
    fn external_data_hash_is_injective_across_the_owner_tag_data_boundary() {
        // A 32-byte value cannot migrate between the owner tag and the
        // ciphertext without changing the digest.
        let a = external_data(
            vec![output(
                [1u8; 32],
                OwnerTag::Inline([3u8; 32]),
                Some(vec![4; 32]),
            )],
            vec![],
        );
        let b = external_data(
            vec![output(
                [1u8; 32],
                OwnerTag::Inline([4u8; 32]),
                Some(vec![3; 32]),
            )],
            vec![],
        );
        assert_ne!(
            hash_ix_external_data(&a, &[]),
            hash_ix_external_data(&b, &[])
        );
    }

    #[test]
    fn external_data_hash_freezes_the_owner_tag_encoding() {
        // Behaviour change from the old preimage, which covered only the
        // resolved tag: `Inline(x)` and `Account(i)` resolving to the same `x`
        // are now distinct, so a relayer cannot rewrite one into the other.
        let inline = external_data(
            vec![output([1u8; 32], OwnerTag::Inline([9u8; 32]), None)],
            vec![],
        );
        let by_account = external_data(vec![output([1u8; 32], OwnerTag::Account(3), None)], vec![]);
        assert_ne!(
            hash_ix_external_data(&inline, &[]),
            hash_ix_external_data(&by_account, &[[9u8; 32]])
        );
    }

    #[test]
    fn external_data_hash_binds_appended_address_order() {
        let base = external_data(
            vec![output([1u8; 32], OwnerTag::Inline([2u8; 32]), None)],
            vec![],
        );
        let forward = hash_ix_external_data(&base, &[[7u8; 32], [8u8; 32]]);
        let swapped = hash_ix_external_data(&base, &[[8u8; 32], [7u8; 32]]);
        assert_ne!(
            forward, swapped,
            "reordering settlement accounts must change the digest"
        );
        assert_ne!(
            forward,
            hash_ix_external_data(&base, &[[7u8; 32]]),
            "dropping an address must change the digest"
        );
    }

    #[test]
    fn external_data_hash_slice_capacity_matches_protocol_limits() {
        let base = external_data(Vec::new(), Vec::new());
        let bytes = base.serialize().expect("serialize instruction");
        let (_, external_data) =
            TransactIxDataRef::parse_with_external_data_prefix(&bytes).expect("parse instruction");
        let addresses = [[1u8; 32]; MAX_EXTERNAL_DATA_HASH_SLICES - 4];
        hash_external_data(
            crate::instruction::tag::TRANSACT,
            external_data,
            &INPUT_TREE,
            &OUTPUT_TREE,
            addresses.iter(),
        )
        .expect("protocol maximum fits the fixed-capacity preimage");

        let too_many = [[1u8; 32]; MAX_EXTERNAL_DATA_HASH_SLICES - 3];
        assert_eq!(
            hash_external_data(
                crate::instruction::tag::TRANSACT,
                external_data,
                &INPUT_TREE,
                &OUTPUT_TREE,
                too_many.iter(),
            ),
            Err(HasherError::InvalidInputLength(
                MAX_EXTERNAL_DATA_HASH_SLICES,
                MAX_EXTERNAL_DATA_HASH_SLICES + 1,
            ))
        );
    }

    #[test]
    fn external_data_hash_binds_the_instruction_discriminator() {
        let base = external_data(
            vec![output([1u8; 32], OwnerTag::Inline([2u8; 32]), None)],
            vec![],
        );
        let bytes = base.serialize().expect("serialize instruction");
        let (_, external_data) =
            TransactIxDataRef::parse_with_external_data_prefix(&bytes).expect("parse instruction");
        let hash = |discriminator, input_tree, output_tree| {
            hash_external_data(
                discriminator,
                external_data,
                input_tree,
                output_tree,
                [].iter(),
            )
            .unwrap()
        };
        let baseline = hash(crate::instruction::tag::TRANSACT, &INPUT_TREE, &OUTPUT_TREE);
        assert_ne!(
            baseline,
            hash(
                crate::instruction::tag::RING_TRANSACT,
                &INPUT_TREE,
                &OUTPUT_TREE
            )
        );
        assert_ne!(
            baseline,
            hash(crate::instruction::tag::TRANSACT, &OUTPUT_TREE, &INPUT_TREE),
            "swapping the tree keys must change the digest"
        );
    }
}
