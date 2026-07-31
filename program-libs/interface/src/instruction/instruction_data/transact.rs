use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
pub use zolana_event::{is_confidential_encrypted_output, MessageData, OutputUtxo};
use zolana_hasher::{sha256::Sha256BE, Hasher, HasherError};

pub use crate::verifying_keys::{Bsb22Commitment, CircuitId, ZoneP256ProofData};
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
/// (recipient signing pubkey, zone HKDF tag, dummy tag); `Account` indexes the
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
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactIxData {
    pub expiry_unix_ts: u64,
    pub private_tx_hash: [u8; 32],
    pub circuit: CircuitId,
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
    pub proof: TransactProof,
    #[wincode(with = "containers::Vec<InputUtxo, FixIntLen<u8>>")]
    pub inputs: Vec<InputUtxo>,
    #[wincode(with = "containers::Vec<InterfaceTransfer, FixIntLen<u8>>")]
    pub interface_transfers: Vec<InterfaceTransfer>,
    /// Optional transaction-level application- and zone-specific external data
    /// digests folded into `external_data_hash`; `None` (`[0; 32]`) for a
    /// default-zone `transact`. Distinct from the per-UTXO `data_hash` /
    /// `zone_data_hash` in the UTXO body.
    pub data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>, // TODO: check whether we use this at all.
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

/// Zero-copy view of [`TransactIxData`]. The large payloads (`proof` and the
/// output ciphertexts) alias the instruction buffer; only the small element
/// vectors are read owned.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct TransactIxDataRef<'a> {
    /// Expire proof for transactions with relayer.
    pub expiry_unix_ts: u64,
    pub private_tx_hash: &'a [u8; 32],
    pub circuit: CircuitId,
    pub tx_viewing_pk: &'a [u8; 33],
    pub salt: &'a [u8; 16],
    pub proof: TransactProof,
    #[wincode(with = "containers::Vec<InputUtxo, FixIntLen<u8>>")]
    pub inputs: Vec<InputUtxo>,
    #[wincode(with = "containers::Vec<InterfaceTransfer, FixIntLen<u8>>")]
    pub interface_transfers: Vec<InterfaceTransfer>,
    pub data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
    #[wincode(with = "containers::Vec<TransactOutputRef<'a>, FixIntLen<u8>>")]
    pub outputs: Vec<TransactOutputRef<'a>>,
    #[wincode(with = "containers::Vec<OutputDataRef<'a>, FixIntLen<u8>>")]
    pub messages: Vec<OutputDataRef<'a>>,
}

impl<'a> TransactIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
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

/// An output whose owner tag has been resolved to concrete bytes: the only form
/// [`ExternalDataHash`] accepts, so the hash covers the resolved tag rather than
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
/// borrowed [`OutputDataRef`], so [`ExternalDataHash`] hashes either message
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

pub struct ExternalDataHash<'a, M: OutputDataBytes> {
    pub spp_instruction_discriminator: u8,
    pub expiry_unix_ts: u64,
    pub interface_transfers: &'a [ResolvedInterfaceTransfer],
    /// Zk programs can commit their data to the external data hash. The option
    /// presence is bound separately from the value.
    pub data_hash: Option<[u8; 32]>,
    /// Zone programs can commit their data to the external data hash. The
    /// option presence is bound separately from the value.
    pub zone_data_hash: Option<[u8; 32]>,
    /// Shared transaction viewing key used to derive every output's encryption
    /// key. Binding it prevents an intermediary from making otherwise-valid
    /// ciphertexts undecryptable.
    pub tx_viewing_pk: &'a [u8; 33],
    /// Shared per-transaction encryption salt. Binding it prevents an
    /// intermediary from changing the key/nonce derivation context.
    pub salt: &'a [u8; 16],
    pub outputs: &'a [ResolvedOutput<'a>],
    pub messages: &'a [M],
}

impl<M: OutputDataBytes> ExternalDataHash<'_, M> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        if self.interface_transfers.len() > MAX_INTERFACE_TRANSFERS {
            return Err(HasherError::IntegerOverflow);
        }
        let mut preimage = Vec::new();
        preimage.push(self.spp_instruction_discriminator);
        preimage.extend_from_slice(&self.expiry_unix_ts.to_be_bytes());
        preimage.push(
            u8::try_from(self.interface_transfers.len())
                .map_err(|_| HasherError::IntegerOverflow)?,
        );
        for transfer in self.interface_transfers {
            match transfer {
                ResolvedInterfaceTransfer::SolDeposit { amount, recipient } => {
                    preimage.push(0);
                    preimage.push(1);
                    preimage.extend_from_slice(&amount.to_be_bytes());
                    preimage.extend_from_slice(recipient);
                }
                ResolvedInterfaceTransfer::SolWithdrawal { amount, recipient } => {
                    preimage.push(0);
                    preimage.push(0);
                    preimage.extend_from_slice(&amount.to_be_bytes());
                    preimage.extend_from_slice(recipient);
                }
                ResolvedInterfaceTransfer::SplDeposit {
                    amount,
                    user_token_account,
                    spl_interface,
                } => {
                    preimage.push(1);
                    preimage.push(1);
                    preimage.extend_from_slice(&amount.to_be_bytes());
                    preimage.extend_from_slice(user_token_account);
                    preimage.extend_from_slice(spl_interface);
                }
                ResolvedInterfaceTransfer::SplWithdrawal {
                    amount,
                    user_token_account,
                    spl_interface,
                } => {
                    preimage.push(1);
                    preimage.push(0);
                    preimage.extend_from_slice(&amount.to_be_bytes());
                    preimage.extend_from_slice(user_token_account);
                    preimage.extend_from_slice(spl_interface);
                }
            }
        }
        preimage.push(u8::from(self.data_hash.is_some()));
        preimage.extend_from_slice(&self.data_hash.unwrap_or([0u8; 32]));
        preimage.push(u8::from(self.zone_data_hash.is_some()));
        preimage.extend_from_slice(&self.zone_data_hash.unwrap_or([0u8; 32]));
        preimage.extend_from_slice(self.tx_viewing_pk);
        preimage.extend_from_slice(self.salt);
        preimage.extend_from_slice(&(self.outputs.len() as u16).to_be_bytes());
        for output in self.outputs {
            preimage.extend_from_slice(output.utxo_hash);
            preimage.extend_from_slice(&output.owner_tag);
            match output.data {
                None => preimage.push(0),
                Some(data) => {
                    preimage.push(1);
                    preimage.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    preimage.extend_from_slice(data);
                }
            }
        }
        preimage.extend_from_slice(&(self.messages.len() as u16).to_be_bytes());
        for message in self.messages {
            preimage.extend_from_slice(message.view_tag());
            preimage.extend_from_slice(&(message.data().len() as u16).to_be_bytes());
            preimage.extend_from_slice(message.data());
        }
        Sha256BE::hash(&preimage)
    }
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
            CircuitId::ZoneEddsa(2, 3, 3),
            CircuitId::ZoneAuthority(4, 4, 3),
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
        let proof_data = crate::verifying_keys::ZoneP256ProofData {
            bsb22_commitment: commitment,
            default_owner_tag: None,
        };
        let p256 = CircuitId::ZoneP256(2, 3, 3, proof_data);
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

        let tagged = CircuitId::ZoneP256(
            2,
            3,
            3,
            ZoneP256ProofData {
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
            proof,
            expiry_unix_ts: 7,
            private_tx_hash: [9u8; 32],
            circuit: CircuitId::ConfidentialEddsa(1, 3, 3),
            inputs: vec![InputUtxo {
                nullifier_hash: [1u8; 32],
                nullifier_tree_root_index: 2,
                utxo_tree_root_index: 3,
            }],
            interface_transfers: vec![
                InterfaceTransfer::SolWithdrawal { amount: 5 },
                InterfaceTransfer::SplDeposit {
                    amount: 7,
                    spl_interface_bump: 42,
                },
            ],
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk: [4u8; 33],
            salt: [6u8; 16],
            outputs: mixed_outputs(),
            messages: vec![MessageData {
                view_tag: [30u8; 32],
                data: vec![8, 9],
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
        assert_eq!(view.proof, owned.proof);
        assert_eq!(view.inputs, owned.inputs);
        assert_eq!(view.interface_transfers, owned.interface_transfers);
        assert_eq!(view.data_hash, owned.data_hash);
        assert_eq!(view.zone_data_hash, owned.zone_data_hash);
        assert_eq!(view.outputs.len(), owned.outputs.len());
        for (got, want) in view.outputs.iter().zip(owned.outputs.iter()) {
            assert_eq!(got.utxo_hash, &want.utxo_hash);
            assert_eq!(got.owner_tag, want.owner_tag);
            assert_eq!(got.data, want.data.as_deref());
        }
        assert_eq!(view.messages.len(), owned.messages.len());
        for (got, want) in view.messages.iter().zip(owned.messages.iter()) {
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

    #[test]
    fn interface_transfer_count_rejects_protocol_overflow_during_serialization_and_hashing() {
        let mut data = ix_data(proof());
        data.interface_transfers =
            vec![InterfaceTransfer::SolDeposit { amount: 1 }; MAX_INTERFACE_TRANSFERS + 1];
        assert!(data.serialize().is_err());

        let resolved = vec![
            ResolvedInterfaceTransfer::SolDeposit {
                amount: 1,
                recipient: [1u8; 32],
            };
            MAX_INTERFACE_TRANSFERS + 1
        ];
        let result = ExternalDataHash::<MessageData> {
            spp_instruction_discriminator: 2,
            expiry_unix_ts: 3,
            interface_transfers: &resolved,
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk: &[0u8; 33],
            salt: &[0u8; 16],
            outputs: &[],
            messages: &[],
        }
        .hash();
        assert_eq!(result, Err(HasherError::IntegerOverflow));
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

    fn hash_of(outputs: &[ResolvedOutput], messages: &[MessageData]) -> [u8; 32] {
        ExternalDataHash {
            spp_instruction_discriminator: 0,
            expiry_unix_ts: 0,
            interface_transfers: &[],
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk: &[0u8; 33],
            salt: &[0u8; 16],
            outputs,
            messages,
        }
        .hash()
        .unwrap()
    }

    fn hash_with_transfers(interface_transfers: &[ResolvedInterfaceTransfer]) -> [u8; 32] {
        ExternalDataHash::<MessageData> {
            spp_instruction_discriminator: 2,
            expiry_unix_ts: 3,
            interface_transfers,
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk: &[0u8; 33],
            salt: &[0u8; 16],
            outputs: &[],
            messages: &[],
        }
        .hash()
        .unwrap()
    }

    fn hash_with_encryption_context(
        data_hash: Option<[u8; 32]>,
        zone_data_hash: Option<[u8; 32]>,
        tx_viewing_pk: &[u8; 33],
        salt: &[u8; 16],
    ) -> [u8; 32] {
        ExternalDataHash::<MessageData> {
            spp_instruction_discriminator: 0,
            expiry_unix_ts: 0,
            interface_transfers: &[],
            data_hash,
            zone_data_hash,
            tx_viewing_pk,
            salt,
            outputs: &[],
            messages: &[],
        }
        .hash()
        .unwrap()
    }

    #[test]
    fn external_data_hash_binds_encryption_context_and_optional_hash_presence() {
        let tx_viewing_pk = [1u8; 33];
        let salt = [2u8; 16];
        let base = hash_with_encryption_context(None, None, &tx_viewing_pk, &salt);

        let mut different_pk = tx_viewing_pk;
        different_pk[0] ^= 1;
        assert_ne!(
            base,
            hash_with_encryption_context(None, None, &different_pk, &salt)
        );

        let mut different_salt = salt;
        different_salt[0] ^= 1;
        assert_ne!(
            base,
            hash_with_encryption_context(None, None, &tx_viewing_pk, &different_salt)
        );

        assert_ne!(
            base,
            hash_with_encryption_context(Some([0u8; 32]), None, &tx_viewing_pk, &salt)
        );
        assert_ne!(
            base,
            hash_with_encryption_context(None, Some([0u8; 32]), &tx_viewing_pk, &salt)
        );
    }

    #[test]
    fn external_data_hash_binds_transfer_count_order_tags_and_accounts() {
        let sol = ResolvedInterfaceTransfer::SolWithdrawal {
            amount: u64::MAX,
            recipient: [1u8; 32],
        };
        let spl = ResolvedInterfaceTransfer::SplWithdrawal {
            amount: u64::MAX,
            user_token_account: [1u8; 32],
            spl_interface: [2u8; 32],
        };
        assert_ne!(
            hash_with_transfers(&[sol]),
            hash_with_transfers(&[sol, sol])
        );
        assert_ne!(
            hash_with_transfers(&[sol, spl]),
            hash_with_transfers(&[spl, sol])
        );
        assert_ne!(hash_with_transfers(&[sol]), hash_with_transfers(&[spl]));

        let other_recipient = ResolvedInterfaceTransfer::SolWithdrawal {
            amount: u64::MAX,
            recipient: [3u8; 32],
        };
        let other_vault = ResolvedInterfaceTransfer::SplWithdrawal {
            amount: u64::MAX,
            user_token_account: [1u8; 32],
            spl_interface: [3u8; 32],
        };
        let opposite_direction = ResolvedInterfaceTransfer::SolDeposit {
            amount: u64::MAX,
            recipient: [1u8; 32],
        };
        assert_ne!(
            hash_with_transfers(&[sol]),
            hash_with_transfers(&[other_recipient])
        );
        assert_ne!(
            hash_with_transfers(&[spl]),
            hash_with_transfers(&[other_vault])
        );
        assert_ne!(
            hash_with_transfers(&[sol]),
            hash_with_transfers(&[opposite_direction])
        );
    }

    #[test]
    fn external_data_hash_transfer_fields_have_fixed_boundaries() {
        let first = ResolvedInterfaceTransfer::SplDeposit {
            amount: 1,
            user_token_account: [2u8; 32],
            spl_interface: [3u8; 32],
        };
        let second = ResolvedInterfaceTransfer::SplDeposit {
            amount: 2,
            user_token_account: [1u8; 32],
            spl_interface: [3u8; 32],
        };
        assert_ne!(
            hash_with_transfers(&[first]),
            hash_with_transfers(&[second])
        );
    }

    #[test]
    fn external_data_hash_matches_go_harness_vector() {
        let sender_tag = core::array::from_fn(|i| i as u8);
        let sol_recipient = core::array::from_fn(|i| 0x20 + i as u8);
        let spl_user = core::array::from_fn(|i| 0x40 + i as u8);
        let spl_vault = core::array::from_fn(|i| 0x60 + i as u8);
        let mut first_hash = [0u8; 32];
        *first_hash.last_mut().unwrap() = 1;
        let mut second_hash = [0u8; 32];
        *second_hash.last_mut().unwrap() = 2;
        let encrypted = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let tx_viewing_pk = core::array::from_fn(|i| 0x90 + i as u8);
        let salt = core::array::from_fn(|i| 0xf0 + i as u8);
        let outputs = [
            ResolvedOutput {
                utxo_hash: &first_hash,
                owner_tag: sender_tag,
                data: Some(&encrypted),
            },
            ResolvedOutput {
                utxo_hash: &second_hash,
                owner_tag: sender_tag,
                data: None,
            },
        ];
        let transfers = [
            ResolvedInterfaceTransfer::SolWithdrawal {
                amount: 1_234_567_890,
                recipient: sol_recipient,
            },
            ResolvedInterfaceTransfer::SplDeposit {
                amount: 987_654_321,
                user_token_account: spl_user,
                spl_interface: spl_vault,
            },
        ];
        let got = ExternalDataHash::<MessageData> {
            spp_instruction_discriminator: 0,
            expiry_unix_ts: 1_234_567_890,
            interface_transfers: &transfers,
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk: &tx_viewing_pk,
            salt: &salt,
            outputs: &outputs,
            messages: &[],
        }
        .hash()
        .unwrap();
        assert_eq!(
            got,
            [
                0, 158, 89, 123, 76, 124, 227, 205, 127, 129, 50, 165, 18, 138, 42, 21, 181, 125,
                204, 170, 184, 141, 92, 9, 24, 208, 134, 151, 150, 45, 223, 100,
            ]
        );
    }

    /// A length-prefixed message vector means a 32-byte value cannot shift from a
    /// resolved output's `data` into a message to forge the same preimage.
    #[test]
    fn external_data_hash_is_injective_across_output_message_boundary() {
        let hash32 = [1u8; 32];
        let tag = [2u8; 32];
        let value = [3u8; 32];

        let value_in_output = hash_of(
            &[ResolvedOutput {
                utxo_hash: &hash32,
                owner_tag: tag,
                data: Some(&value),
            }],
            &[],
        );
        let value_in_message = hash_of(
            &[ResolvedOutput {
                utxo_hash: &hash32,
                owner_tag: tag,
                data: None,
            }],
            &[MessageData {
                view_tag: tag,
                data: value.to_vec(),
            }],
        );
        assert_ne!(value_in_output, value_in_message);
    }

    /// The strict {0,1} presence byte keeps `Some(&[])` distinct from `None`.
    #[test]
    fn external_data_hash_distinguishes_empty_data_from_none() {
        let hash32 = [1u8; 32];
        let tag = [2u8; 32];
        let some_empty = hash_of(
            &[ResolvedOutput {
                utxo_hash: &hash32,
                owner_tag: tag,
                data: Some(&[]),
            }],
            &[],
        );
        let none = hash_of(
            &[ResolvedOutput {
                utxo_hash: &hash32,
                owner_tag: tag,
                data: None,
            }],
            &[],
        );
        assert_ne!(some_empty, none);
    }

    /// The owner tag is a fixed 32-byte field and `data` is length-prefixed, so a
    /// 32-byte value cannot shift between the resolved owner tag and `data`.
    #[test]
    fn external_data_hash_is_injective_across_owner_tag_data_boundary() {
        let hash32 = [1u8; 32];
        let value = [3u8; 32];
        let value_in_tag = hash_of(
            &[ResolvedOutput {
                utxo_hash: &hash32,
                owner_tag: value,
                data: None,
            }],
            &[],
        );
        let value_in_data = hash_of(
            &[ResolvedOutput {
                utxo_hash: &hash32,
                owner_tag: [0u8; 32],
                data: Some(&value),
            }],
            &[],
        );
        assert_ne!(value_in_tag, value_in_data);
    }
}
