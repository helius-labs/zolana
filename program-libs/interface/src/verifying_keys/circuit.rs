use core::mem::MaybeUninit;
use wincode::{
    config::ConfigCore,
    io::{Reader, Writer},
    ReadError, ReadResult, SchemaRead, SchemaWrite, TypeMeta, WriteResult,
};

use crate::state::cache::CACHE_CAPACITY;

const CURRENT_PUBLIC_ASSET_SLOTS: u8 = crate::N_PUBLIC_SLOTS as u8;

/// The compressed BSB22 commitment carried by a committed Groth16 proof.
///
/// This lives in [`CircuitId::RingP256`] so the existing `TransactProof` and
/// `TransactIxData` layouts need no additional proof-specific fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Bsb22Commitment {
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

/// Proof-specific payload carried by [`CircuitId::RingP256`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct RingP256ProofData {
    pub bsb22_commitment: Bsb22Commitment,
    /// The P256 public key x-coordinate when a default-ring P256 UTXO is spent;
    /// address slots do not count. `None` keeps ring-only P256 ownership private.
    #[wincode(with = "FixedOptionOwnerTag")]
    pub default_owner_tag: Option<[u8; 32]>,
}

/// Carried by a cached circuit selector; input i selects cache slot i.
/// The cache is the final account.
///
/// A cached selector names no circuit of its own: every owner-signed rail binds
/// this selection into its public input hash whether or not a cache is used, so
/// a cached spend verifies against its rail's ordinary key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CachedInputs {
    pub input_bitmap: u64,
}

impl CachedInputs {
    pub fn valid_bitmap(self, input_count: usize) -> bool {
        (1..=CACHE_CAPACITY).contains(&input_count)
            && self.input_bitmap != 0
            && self.input_bitmap >> input_count == 0
    }

    pub fn selects(self, input_index: usize) -> bool {
        self.input_bitmap
            .checked_shr(input_index as u32)
            .unwrap_or(0)
            & 1
            != 0
    }
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
/// The first three tuple fields are `(number of inputs, number of outputs,
/// number of public asset slots)`, followed by any variant-specific payload.
/// The enum tag selects the verifying key and is validated against the dispatched
/// instruction and its data. The tag is not a circuit public input; payload fields
/// such as `CachedInputs::input_bitmap` contribute to the proof's public input hash.
///
/// Each owner-signed rail has a cached twin carrying the same payload plus a
/// [`CachedInputs`]. The twin is the same circuit and the same verifying key; it
/// only declares that a cache account follows and which inputs it covers, so
/// every rail accessor resolves it through [`CircuitId::uncached`]. Ring
/// authority has no twin: its circuit binds no cache selection. The twins are
/// appended last so no existing tag encoding moves, and a transact that uses no
/// cache is byte-identical to one built before caches existed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u16")]
pub enum CircuitId {
    /// NumInputs, NumOutputs, NumPublicAssets
    ConfidentialEddsa(u8, u8, u8),
    RingEddsa(u8, u8, u8),
    RingAuthority(u8, u8, u8),
    RingP256(u8, u8, u8, RingP256ProofData),
    ConfidentialEddsaCached(u8, u8, u8, CachedInputs),
    RingEddsaCached(u8, u8, u8, CachedInputs),
    RingP256Cached(u8, u8, u8, RingP256ProofData, CachedInputs),
}

impl CircuitId {
    pub const fn cached_inputs(self) -> Option<CachedInputs> {
        match self {
            Self::ConfidentialEddsaCached(_, _, _, selection)
            | Self::RingEddsaCached(_, _, _, selection)
            | Self::RingP256Cached(_, _, _, _, selection) => Some(selection),
            _ => None,
        }
    }

    /// The rail this selector names, with any cache selection dropped. A cached
    /// selector differs from its rail only in the cache it declares, so every
    /// shape, rail and key accessor answers through this.
    pub const fn uncached(self) -> Self {
        match self {
            Self::ConfidentialEddsaCached(n_in, n_out, slots, _) => {
                Self::ConfidentialEddsa(n_in, n_out, slots)
            }
            Self::RingEddsaCached(n_in, n_out, slots, _) => Self::RingEddsa(n_in, n_out, slots),
            Self::RingP256Cached(n_in, n_out, slots, proof_data, _) => {
                Self::RingP256(n_in, n_out, slots, proof_data)
            }
            other => other,
        }
    }

    pub const fn num_inputs(self) -> u8 {
        match self {
            Self::ConfidentialEddsa(n, _, _)
            | Self::RingEddsa(n, _, _)
            | Self::RingAuthority(n, _, _)
            | Self::RingP256(n, _, _, _)
            | Self::ConfidentialEddsaCached(n, _, _, _)
            | Self::RingEddsaCached(n, _, _, _)
            | Self::RingP256Cached(n, _, _, _, _) => n,
        }
    }

    pub const fn num_outputs(self) -> u8 {
        match self {
            Self::ConfidentialEddsa(_, n, _)
            | Self::RingEddsa(_, n, _)
            | Self::RingAuthority(_, n, _)
            | Self::RingP256(_, n, _, _)
            | Self::ConfidentialEddsaCached(_, n, _, _)
            | Self::RingEddsaCached(_, n, _, _)
            | Self::RingP256Cached(_, n, _, _, _) => n,
        }
    }

    pub const fn num_public_asset_slots(self) -> u8 {
        match self {
            Self::ConfidentialEddsa(_, _, n)
            | Self::RingEddsa(_, _, n)
            | Self::RingAuthority(_, _, n)
            | Self::RingP256(_, _, n, _)
            | Self::ConfidentialEddsaCached(_, _, n, _)
            | Self::RingEddsaCached(_, _, n, _)
            | Self::RingP256Cached(_, _, n, _, _) => n,
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
            self.uncached(),
            Self::ConfidentialEddsa(..) | Self::RingEddsa(..) | Self::RingP256(..)
        )
    }

    pub const fn is_ring(self) -> bool {
        matches!(
            self.uncached(),
            Self::RingEddsa(..) | Self::RingAuthority(..) | Self::RingP256(..)
        )
    }

    pub const fn is_authority(self) -> bool {
        matches!(self, Self::RingAuthority(..))
    }

    pub const fn is_p256(self) -> bool {
        matches!(self.uncached(), Self::RingP256(..))
    }

    pub const fn bsb22_commitment(&self) -> Option<&Bsb22Commitment> {
        match self {
            Self::RingP256(_, _, _, proof_data) | Self::RingP256Cached(_, _, _, proof_data, _) => {
                Some(&proof_data.bsb22_commitment)
            }
            _ => None,
        }
    }

    pub const fn default_p256_owner_tag(&self) -> Option<&[u8; 32]> {
        match self {
            Self::RingP256(_, _, _, proof_data) | Self::RingP256Cached(_, _, _, proof_data, _) => {
                proof_data.default_owner_tag.as_ref()
            }
            _ => None,
        }
    }

    pub const fn requires_input_signatures(self) -> bool {
        !self.is_authority()
    }

    pub const fn output_owner_mode(self) -> OutputOwnerMode {
        match self {
            Self::ConfidentialEddsa(..) | Self::ConfidentialEddsaCached(..) => OutputOwnerMode::All,
            Self::RingEddsa(..)
            | Self::RingP256(..)
            | Self::RingEddsaCached(..)
            | Self::RingP256Cached(..) => OutputOwnerMode::ConfidentialMarked,
            Self::RingAuthority(..) => OutputOwnerMode::None,
        }
    }

    /// Whether this selector names a verifying key generated into this crate.
    pub const fn is_supported(self) -> bool {
        let (n_inputs, n_outputs, n_public_asset_slots) = self.shape();
        if n_public_asset_slots != CURRENT_PUBLIC_ASSET_SLOTS {
            return false;
        }
        match self {
            Self::ConfidentialEddsa(..)
            | Self::RingEddsa(..)
            | Self::RingP256(..)
            | Self::ConfidentialEddsaCached(..)
            | Self::RingEddsaCached(..)
            | Self::RingP256Cached(..) => matches!(
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
                    | (36, 2)
            ),
            Self::RingAuthority(..) => {
                matches!((n_inputs, n_outputs), (1, 1) | (2, 2) | (3, 3) | (4, 4))
            }
        }
    }

    #[cfg(feature = "verifying-keys")]
    pub fn verifying_key(
        self,
    ) -> Option<&'static groth16_solana::groth16::Groth16Verifyingkey<'static>> {
        use super::*;

        // A cached spend proves on its rail's own key: the cache adds published
        // values, not a circuit.
        let key = match self.uncached() {
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
            Self::ConfidentialEddsa(36, 2, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_36_2::VERIFYINGKEY
            }
            Self::RingEddsa(1, 1, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_1_1::VERIFYINGKEY,
            Self::RingEddsa(1, 2, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_1_2::VERIFYINGKEY,
            Self::RingEddsa(1, 8, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_1_8::VERIFYINGKEY,
            Self::RingEddsa(2, 2, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_2_2::VERIFYINGKEY,
            Self::RingEddsa(2, 3, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_2_3::VERIFYINGKEY,
            Self::RingEddsa(3, 3, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_3_3::VERIFYINGKEY,
            Self::RingEddsa(4, 3, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_4_3::VERIFYINGKEY,
            Self::RingEddsa(4, 4, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_4_4::VERIFYINGKEY,
            Self::RingEddsa(5, 3, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_5_3::VERIFYINGKEY,
            Self::RingEddsa(5, 4, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_5_4::VERIFYINGKEY,
            Self::RingEddsa(36, 2, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_36_2::VERIFYINGKEY,
            Self::RingP256(1, 1, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_1_1::VERIFYINGKEY
            }
            Self::RingP256(1, 2, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_1_2::VERIFYINGKEY
            }
            Self::RingP256(1, 8, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_1_8::VERIFYINGKEY
            }
            Self::RingP256(2, 2, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_2_2::VERIFYINGKEY
            }
            Self::RingP256(2, 3, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_2_3::VERIFYINGKEY
            }
            Self::RingP256(3, 3, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_3_3::VERIFYINGKEY
            }
            Self::RingP256(4, 3, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_4_3::VERIFYINGKEY
            }
            Self::RingP256(4, 4, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_4_4::VERIFYINGKEY
            }
            Self::RingP256(5, 3, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_5_3::VERIFYINGKEY
            }
            Self::RingP256(5, 4, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_5_4::VERIFYINGKEY
            }
            Self::RingP256(36, 2, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_36_2::VERIFYINGKEY
            }
            Self::RingAuthority(1, 1, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_ring_authority_1_1::VERIFYINGKEY
            }
            Self::RingAuthority(2, 2, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_ring_authority_2_2::VERIFYINGKEY
            }
            Self::RingAuthority(3, 3, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_ring_authority_3_3::VERIFYINGKEY
            }
            Self::RingAuthority(4, 4, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_ring_authority_4_4::VERIFYINGKEY
            }
            _ => return None,
        };
        Some(key)
    }
}
