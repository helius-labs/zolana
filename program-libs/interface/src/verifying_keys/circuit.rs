use core::mem::MaybeUninit;
use wincode::{
    config::ConfigCore,
    io::{Reader, Writer},
    ReadError, ReadResult, SchemaRead, SchemaWrite, TypeMeta, WriteResult,
};

const CURRENT_PUBLIC_ASSET_SLOTS: u8 = crate::N_PUBLIC_SLOTS as u8;

/// The compressed BSB22 commitment carried by a committed Groth16 proof.
///
/// This lives in [`CircuitId::ZoneP256`] so the existing `TransactProof` and
/// `TransactIxData` layouts need no additional proof-specific fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Bsb22Commitment {
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

/// Proof-specific payload carried by [`CircuitId::ZoneP256`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ZoneP256ProofData {
    pub bsb22_commitment: Bsb22Commitment,
    /// The P256 public key x-coordinate when a real default-zone P256 input or
    /// address is present. `None` keeps zone-only P256 ownership private.
    #[wincode(with = "FixedOptionOwnerTag")]
    pub default_owner_tag: Option<[u8; 32]>,
}

/// Fixed-width wire adapter for the optional owner tag. Keeping the circuit
/// selector statically sized preserves allocation-free borrowed instruction
/// decoding even when a non-P256 selector is used.
struct FixedOptionOwnerTag;

unsafe impl<'de, C: ConfigCore> SchemaRead<'de, C> for FixedOptionOwnerTag {
    type Dst = Option<[u8; 32]>;

    const TYPE_META: TypeMeta = TypeMeta::Static {
        size: 33,
        zero_copy: false,
    };

    fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<Self::Dst>) -> ReadResult<()> {
        let present = <u8 as SchemaRead<'de, C>>::get(reader.by_ref())?;
        let tag = <[u8; 32] as SchemaRead<'de, C>>::get(reader)?;
        match present {
            0 => {
                if tag != [0u8; 32] {
                    return Err(ReadError::InvalidValue(
                        "absent P256 owner tag must be zero",
                    ));
                }
                dst.write(None);
            }
            1 => {
                dst.write(Some(tag));
            }
            _ => return Err(ReadError::InvalidBoolEncoding(present)),
        }
        Ok(())
    }
}

unsafe impl<C: ConfigCore> SchemaWrite<C> for FixedOptionOwnerTag {
    type Src = Option<[u8; 32]>;

    const TYPE_META: TypeMeta = TypeMeta::Static {
        size: 33,
        zero_copy: false,
    };

    fn size_of(_: &Self::Src) -> WriteResult<usize> {
        Ok(33)
    }

    fn write(mut writer: impl Writer, src: &Self::Src) -> WriteResult<()> {
        let (present, tag) = match src {
            Some(tag) => (1u8, *tag),
            None => (0u8, [0u8; 32]),
        };
        <u8 as SchemaWrite<C>>::write(writer.by_ref(), &present)?;
        <[u8; 32] as SchemaWrite<C>>::write(writer, &tag)
    }
}

/// How the program derives the fixed-width output-owner hash vector committed
/// into a circuit's public input hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputOwnerMode {
    None,
    All,
    ConfidentialMarked,
}

/// A supported `transact` circuit instantiation.
///
/// The tuple fields are `(number of inputs, number of outputs, number of
/// public asset slots)`. The selector is not a circuit public input: it selects
/// the verifying key and is validated against the dispatched instruction and
/// the instruction data before verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u16")]
pub enum CircuitId {
    /// NumInputs, NumOutputs, NumPublicAssets
    ConfidentialEddsa(u8, u8, u8),
    ZoneEddsa(u8, u8, u8),
    ZoneAuthority(u8, u8, u8),
    ZoneP256(u8, u8, u8, ZoneP256ProofData),
}

impl CircuitId {
    pub const fn num_inputs(self) -> u8 {
        match self {
            Self::ConfidentialEddsa(n, _, _)
            | Self::ZoneEddsa(n, _, _)
            | Self::ZoneAuthority(n, _, _)
            | Self::ZoneP256(n, _, _, _) => n,
        }
    }

    pub const fn num_outputs(self) -> u8 {
        match self {
            Self::ConfidentialEddsa(_, n, _)
            | Self::ZoneEddsa(_, n, _)
            | Self::ZoneAuthority(_, n, _)
            | Self::ZoneP256(_, n, _, _) => n,
        }
    }

    pub const fn num_public_asset_slots(self) -> u8 {
        match self {
            Self::ConfidentialEddsa(_, _, n)
            | Self::ZoneEddsa(_, _, n)
            | Self::ZoneAuthority(_, _, n)
            | Self::ZoneP256(_, _, n, _) => n,
        }
    }

    pub const fn shape(self) -> (u8, u8, u8) {
        (
            self.num_inputs(),
            self.num_outputs(),
            self.num_public_asset_slots(),
        )
    }

    pub const fn is_confidential(self) -> bool {
        matches!(
            self,
            Self::ConfidentialEddsa(..) | Self::ZoneEddsa(..) | Self::ZoneP256(..)
        )
    }

    pub const fn is_zone(self) -> bool {
        matches!(
            self,
            Self::ZoneEddsa(..) | Self::ZoneAuthority(..) | Self::ZoneP256(..)
        )
    }

    pub const fn is_authority(self) -> bool {
        matches!(self, Self::ZoneAuthority(..))
    }

    pub const fn is_p256(self) -> bool {
        matches!(self, Self::ZoneP256(..))
    }

    pub const fn bsb22_commitment(&self) -> Option<&Bsb22Commitment> {
        match self {
            Self::ZoneP256(_, _, _, proof_data) => Some(&proof_data.bsb22_commitment),
            _ => None,
        }
    }

    pub const fn default_p256_owner_tag(&self) -> Option<&[u8; 32]> {
        match self {
            Self::ZoneP256(_, _, _, proof_data) => proof_data.default_owner_tag.as_ref(),
            _ => None,
        }
    }

    pub const fn requires_input_signatures(self) -> bool {
        !self.is_authority()
    }

    pub const fn output_owner_mode(self) -> OutputOwnerMode {
        match self {
            Self::ConfidentialEddsa(..) => OutputOwnerMode::All,
            Self::ZoneEddsa(..) | Self::ZoneP256(..) => OutputOwnerMode::ConfidentialMarked,
            Self::ZoneAuthority(..) => OutputOwnerMode::None,
        }
    }

    /// Whether this selector names a verifying key generated into this crate.
    pub const fn is_supported(self) -> bool {
        let (n_inputs, n_outputs, n_public_asset_slots) = self.shape();
        if n_public_asset_slots != CURRENT_PUBLIC_ASSET_SLOTS {
            return false;
        }
        match self {
            Self::ConfidentialEddsa(..) | Self::ZoneEddsa(..) | Self::ZoneP256(..) => matches!(
                (n_inputs, n_outputs),
                (1, 1)
                    | (1, 2)
                    | (1, 8)
                    | (2, 2)
                    | (2, 3)
                    | (3, 3)
                    | (4, 3)
                    | (4, 4)
                    | (5, 3)
                    | (5, 4)
            ),
            Self::ZoneAuthority(..) => {
                matches!((n_inputs, n_outputs), (1, 1) | (2, 2) | (3, 3) | (4, 4))
            }
        }
    }

    #[cfg(feature = "verifying-keys")]
    pub fn verifying_key(
        self,
    ) -> Option<&'static groth16_solana::groth16::Groth16Verifyingkey<'static>> {
        use super::*;

        let key = match self {
            Self::ConfidentialEddsa(1, 1, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_1_1::VERIFYINGKEY
            }
            Self::ConfidentialEddsa(1, 2, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_1_2::VERIFYINGKEY
            }
            Self::ConfidentialEddsa(1, 8, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_1_8::VERIFYINGKEY
            }
            Self::ConfidentialEddsa(2, 2, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_2_2::VERIFYINGKEY
            }
            Self::ConfidentialEddsa(2, 3, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_2_3::VERIFYINGKEY
            }
            Self::ConfidentialEddsa(3, 3, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_3_3::VERIFYINGKEY
            }
            Self::ConfidentialEddsa(4, 3, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_4_3::VERIFYINGKEY
            }
            Self::ConfidentialEddsa(4, 4, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_4_4::VERIFYINGKEY
            }
            Self::ConfidentialEddsa(5, 3, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_5_3::VERIFYINGKEY
            }
            Self::ConfidentialEddsa(5, 4, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_5_4::VERIFYINGKEY
            }
            Self::ZoneEddsa(1, 1, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_zone_1_1::VERIFYINGKEY,
            Self::ZoneEddsa(1, 2, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_zone_1_2::VERIFYINGKEY,
            Self::ZoneEddsa(1, 8, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_zone_1_8::VERIFYINGKEY,
            Self::ZoneEddsa(2, 2, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_zone_2_2::VERIFYINGKEY,
            Self::ZoneEddsa(2, 3, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_zone_2_3::VERIFYINGKEY,
            Self::ZoneEddsa(3, 3, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_zone_3_3::VERIFYINGKEY,
            Self::ZoneEddsa(4, 3, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_zone_4_3::VERIFYINGKEY,
            Self::ZoneEddsa(4, 4, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_zone_4_4::VERIFYINGKEY,
            Self::ZoneEddsa(5, 3, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_zone_5_3::VERIFYINGKEY,
            Self::ZoneEddsa(5, 4, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_zone_5_4::VERIFYINGKEY,
            Self::ZoneP256(1, 1, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_zone_1_1::VERIFYINGKEY
            }
            Self::ZoneP256(1, 2, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_zone_1_2::VERIFYINGKEY
            }
            Self::ZoneP256(1, 8, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_zone_1_8::VERIFYINGKEY
            }
            Self::ZoneP256(2, 2, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_zone_2_2::VERIFYINGKEY
            }
            Self::ZoneP256(2, 3, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_zone_2_3::VERIFYINGKEY
            }
            Self::ZoneP256(3, 3, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_zone_3_3::VERIFYINGKEY
            }
            Self::ZoneP256(4, 3, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_zone_4_3::VERIFYINGKEY
            }
            Self::ZoneP256(4, 4, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_zone_4_4::VERIFYINGKEY
            }
            Self::ZoneP256(5, 3, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_zone_5_3::VERIFYINGKEY
            }
            Self::ZoneP256(5, 4, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_zone_5_4::VERIFYINGKEY
            }
            Self::ZoneAuthority(1, 1, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_zone_authority_1_1::VERIFYINGKEY
            }
            Self::ZoneAuthority(2, 2, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_zone_authority_2_2::VERIFYINGKEY
            }
            Self::ZoneAuthority(3, 3, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_zone_authority_3_3::VERIFYINGKEY
            }
            Self::ZoneAuthority(4, 4, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_zone_authority_4_4::VERIFYINGKEY
            }
            _ => return None,
        };
        Some(key)
    }
}
