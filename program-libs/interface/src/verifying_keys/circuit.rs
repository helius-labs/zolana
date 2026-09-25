use core::mem::MaybeUninit;
use wincode::{
    config::ConfigCore,
    io::{Reader, Writer},
    ReadError, ReadResult, SchemaRead, SchemaWrite, TypeMeta, WriteResult,
};

use crate::state::cache::CACHE_CAPACITY;

const CURRENT_PUBLIC_ASSET_SLOTS: u8 = crate::N_PUBLIC_SLOTS as u8;

/// Selects `$item` from the verifying key module a [`CircuitId`] names, or
/// returns `None` from the enclosing function. One table serves both the
/// verifying key and the proving-key sha256 generated next to it.
#[cfg(feature = "verifying-keys")]
macro_rules! circuit_key_item {
    ($circuit:expr, $item:ident) => {{
        use super::*;

        match $circuit {
            CircuitId::ConfidentialEddsa(1, 1, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_1_1::$item
            }
            CircuitId::ConfidentialEddsa(1, 2, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_1_2::$item
            }
            CircuitId::ConfidentialEddsa(1, 8, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_1_8::$item
            }
            CircuitId::ConfidentialEddsa(2, 2, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_2_2::$item
            }
            CircuitId::ConfidentialEddsa(2, 3, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_2_3::$item
            }
            CircuitId::ConfidentialEddsa(3, 3, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_3_3::$item
            }
            CircuitId::ConfidentialEddsa(4, 3, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_4_3::$item
            }
            CircuitId::ConfidentialEddsa(4, 4, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_4_4::$item
            }
            CircuitId::ConfidentialEddsa(5, 3, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_5_3::$item
            }
            CircuitId::ConfidentialEddsa(5, 4, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_5_4::$item
            }
            CircuitId::ConfidentialEddsa(36, 2, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_confidential_36_2::$item
            }
            CircuitId::RingEddsa(1, 1, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_1_1::$item,
            CircuitId::RingEddsa(1, 2, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_1_2::$item,
            CircuitId::RingEddsa(1, 8, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_1_8::$item,
            CircuitId::RingEddsa(2, 2, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_2_2::$item,
            CircuitId::RingEddsa(2, 3, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_2_3::$item,
            CircuitId::RingEddsa(3, 3, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_3_3::$item,
            CircuitId::RingEddsa(4, 3, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_4_3::$item,
            CircuitId::RingEddsa(4, 4, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_4_4::$item,
            CircuitId::RingEddsa(5, 3, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_5_3::$item,
            CircuitId::RingEddsa(5, 4, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_5_4::$item,
            CircuitId::RingEddsa(36, 2, CURRENT_PUBLIC_ASSET_SLOTS) => &transfer_ring_36_2::$item,
            CircuitId::RingP256(1, 1, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_1_1::$item
            }
            CircuitId::RingP256(1, 2, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_1_2::$item
            }
            CircuitId::RingP256(1, 8, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_1_8::$item
            }
            CircuitId::RingP256(2, 2, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_2_2::$item
            }
            CircuitId::RingP256(2, 3, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_2_3::$item
            }
            CircuitId::RingP256(3, 3, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_3_3::$item
            }
            CircuitId::RingP256(4, 3, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_4_3::$item
            }
            CircuitId::RingP256(4, 4, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_4_4::$item
            }
            CircuitId::RingP256(5, 3, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_5_3::$item
            }
            CircuitId::RingP256(5, 4, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_5_4::$item
            }
            CircuitId::RingP256(36, 2, CURRENT_PUBLIC_ASSET_SLOTS, _) => {
                &transfer_p256_ring_36_2::$item
            }
            CircuitId::RingAuthority(1, 1, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_ring_authority_1_1::$item
            }
            CircuitId::RingAuthority(2, 2, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_ring_authority_2_2::$item
            }
            CircuitId::RingAuthority(3, 3, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_ring_authority_3_3::$item
            }
            CircuitId::RingAuthority(4, 4, CURRENT_PUBLIC_ASSET_SLOTS) => {
                &transfer_ring_authority_4_4::$item
            }
            _ => return None,
        }
    }};
}

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

/// One cache shared by reads and writes.
/// The cache follows settlement accounts; writes append its authority signer.
///
/// A cached selector names no circuit of its own: every owner-signed rail binds
/// this selection into its public input hash whether or not a cache is used, so
/// a cached spend verifies against its rail's ordinary key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CacheAccess {
    pub read_bitmap: u64,
    pub write_slots: [CacheWrite; MAX_CACHE_WRITES],
}

pub const MAX_CACHE_WRITES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CacheWrite {
    pub output: u8,
    pub slot: u8,
}

impl CacheWrite {
    pub const NONE: Self = Self {
        output: u8::MAX,
        slot: u8::MAX,
    };
}

impl CacheAccess {
    pub const NO_WRITES: [CacheWrite; MAX_CACHE_WRITES] = [CacheWrite::NONE; MAX_CACHE_WRITES];

    pub fn valid(self, input_count: usize, output_count: usize) -> bool {
        self.read_bitmap >> CACHE_CAPACITY == 0
            && self.read_bitmap.count_ones() as usize <= input_count
            && (self.read_bitmap != 0 || self.writes_cache())
            && valid_cache_writes(&self.write_slots, output_count)
    }

    pub fn writes(&self) -> impl Iterator<Item = CacheWrite> + '_ {
        self.write_slots
            .iter()
            .copied()
            .take_while(|entry| *entry != CacheWrite::NONE)
    }

    pub fn writes_cache(self) -> bool {
        self.write_slots
            .first()
            .is_some_and(|entry| *entry != CacheWrite::NONE)
    }
}

pub fn valid_cache_writes(
    write_slots: &[CacheWrite; MAX_CACHE_WRITES],
    output_count: usize,
) -> bool {
    let used = write_slots
        .iter()
        .take_while(|entry| **entry != CacheWrite::NONE)
        .count();
    let (Some(writes), Some(unused)) = (write_slots.get(..used), write_slots.get(used..)) else {
        return false;
    };
    unused.iter().all(|entry| *entry == CacheWrite::NONE)
        && writes.iter().all(|entry| {
            usize::from(entry.output) < output_count && usize::from(entry.slot) < CACHE_CAPACITY
        })
        && writes.iter().enumerate().all(|(index, entry)| {
            writes
                .iter()
                .skip(index + 1)
                .all(|later| later.slot != entry.slot && later.output != entry.output)
        })
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
/// such as `CacheAccess::read_bitmap` contribute to the proof's public input hash.
///
/// Each owner-signed rail has a cached twin carrying the same payload plus a
/// [`CacheAccess`]. The twin is the same circuit and the same verifying key; it
/// declares cache reads and writes; the write destination is bound through
/// external data and the input selection through the public input hash, so
/// rail and key accessors resolve it through [`CircuitId::uncached`]. Ring
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
    ConfidentialEddsaCached(u8, u8, u8, CacheAccess),
    RingEddsaCached(u8, u8, u8, CacheAccess),
    RingP256Cached(u8, u8, u8, RingP256ProofData, CacheAccess),
}

impl CircuitId {
    pub const fn cache_access(self) -> Option<CacheAccess> {
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
        Some(circuit_key_item!(self.uncached(), VERIFYINGKEY))
    }

    /// SHA-256 of the proving key file this circuit's verifying key was
    /// generated from. A prover reports the same digest with every proof.
    #[cfg(feature = "verifying-keys")]
    pub fn proving_key_sha256(self) -> Option<&'static [u8; 32]> {
        Some(circuit_key_item!(
            self.uncached(),
            VERIFYINGKEY_PROVING_KEY_SHA256
        ))
    }
}
