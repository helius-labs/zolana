use wincode::{SchemaRead, SchemaWrite};

use crate::{shape::Shape, state::cache::CACHE_CAPACITY};

const CURRENT_PUBLIC_ASSET_SLOTS: u8 = crate::N_PUBLIC_SLOTS as u8;

/// Selects `$item` from the verifying key module a [`CircuitId`] names, or
/// returns `None` from the enclosing function. One table serves both the
/// verifying key and the proving-key sha256 generated next to it.
#[cfg(feature = "verifying-keys")]
macro_rules! circuit_key_item {
    ($circuit:expr, $item:ident) => {
        circuit_key_item!(@select $circuit, $item;
            transact {
                (1, 2) => transfer_confidential_1_2, transfer_ring_1_2;
                (1, 4) => transfer_confidential_1_4, transfer_ring_1_4;
                (1, 8) => transfer_confidential_1_8, transfer_ring_1_8;
                (2, 2) => transfer_confidential_2_2, transfer_ring_2_2;
                (2, 4) => transfer_confidential_2_4, transfer_ring_2_4;
                (1, 16) => transfer_confidential_1_16, transfer_ring_1_16;
                (2, 8) => transfer_confidential_2_8, transfer_ring_2_8;
                (3, 2) => transfer_confidential_3_2, transfer_ring_3_2;
                (3, 4) => transfer_confidential_3_4, transfer_ring_3_4;
                (2, 16) => transfer_confidential_2_16, transfer_ring_2_16;
                (3, 8) => transfer_confidential_3_8, transfer_ring_3_8;
                (4, 2) => transfer_confidential_4_2, transfer_ring_4_2;
                (4, 4) => transfer_confidential_4_4, transfer_ring_4_4;
                (4, 8) => transfer_confidential_4_8, transfer_ring_4_8;
                (5, 2) => transfer_confidential_5_2, transfer_ring_5_2;
                (5, 4) => transfer_confidential_5_4, transfer_ring_5_4;
                (4, 16) => transfer_confidential_4_16, transfer_ring_4_16;
                (5, 8) => transfer_confidential_5_8, transfer_ring_5_8;
                (6, 2) => transfer_confidential_6_2, transfer_ring_6_2;
                (6, 4) => transfer_confidential_6_4, transfer_ring_6_4;
                (5, 16) => transfer_confidential_5_16, transfer_ring_5_16;
                (6, 8) => transfer_confidential_6_8, transfer_ring_6_8;
                (8, 2) => transfer_confidential_8_2, transfer_ring_8_2;
                (8, 4) => transfer_confidential_8_4, transfer_ring_8_4;
                (8, 8) => transfer_confidential_8_8, transfer_ring_8_8;
                (8, 16) => transfer_confidential_8_16, transfer_ring_8_16;
                (12, 2) => transfer_confidential_12_2, transfer_ring_12_2;
                (12, 4) => transfer_confidential_12_4, transfer_ring_12_4;
                (12, 8) => transfer_confidential_12_8, transfer_ring_12_8;
                (16, 2) => transfer_confidential_16_2, transfer_ring_16_2;
                (16, 4) => transfer_confidential_16_4, transfer_ring_16_4;
                (16, 8) => transfer_confidential_16_8, transfer_ring_16_8;
                (24, 2) => transfer_confidential_24_2, transfer_ring_24_2;
                (24, 4) => transfer_confidential_24_4, transfer_ring_24_4;
                (32, 2) => transfer_confidential_32_2, transfer_ring_32_2;
                (40, 2) => transfer_confidential_40_2, transfer_ring_40_2;
                (48, 2) => transfer_confidential_48_2, transfer_ring_48_2;
                (49, 2) => transfer_confidential_49_2, transfer_ring_49_2;
            }
            authority {
                (2, 2) => transfer_ring_authority_2_2;
                (4, 4) => transfer_ring_authority_4_4;
            }
            anonymous_ring_ed25519 {
                (2, 2) => transfer_ed25519_ring_2_2;
                (2, 4) => transfer_ed25519_ring_2_4;
                (3, 4) => transfer_ed25519_ring_3_4;
                (4, 2) => transfer_ed25519_ring_4_2;
            }
        )
    };
    (@select $circuit:expr, $item:ident;
        transact { $(($i:literal, $o:literal) => $confidential:ident, $ring:ident;)* }
        authority { $(($ai:literal, $ao:literal) => $authority:ident;)* }
        anonymous_ring_ed25519 { $(($ei:literal, $eo:literal) => $ed25519:ident;)* }
    ) => {{
        use super::*;

        match $circuit {
            $(
                CircuitId::ConfidentialEd25519($i, $o, CURRENT_PUBLIC_ASSET_SLOTS) => {
                    &$confidential::$item
                }
                CircuitId::ConfidentialRingEd25519($i, $o, CURRENT_PUBLIC_ASSET_SLOTS) => &$ring::$item,
            )*
            $(
                CircuitId::RingAuthority($ai, $ao, CURRENT_PUBLIC_ASSET_SLOTS) => &$authority::$item,
            )*
            $(
                CircuitId::AnonymousRingEd25519($ei, $eo, CURRENT_PUBLIC_ASSET_SLOTS, _) => &$ed25519::$item,
            )*
            _ => return None,
        }
    }};
}

/// The compressed BSB22 commitment carried by a committed Groth16 proof.
///
/// This lives in [`CircuitId::AnonymousRingEd25519`] so the existing `TransactProof` and
/// `TransactIxData` layouts need no additional proof-specific fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Bsb22Commitment {
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
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

pub const MAX_CACHE_WRITES: usize = 16;

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
/// The tag selects the verifying key. Explicit tags preserve the wire layout
/// and leave retired selectors 3 and 6 invalid. Cache variants use their
/// uncached circuit and bind reads and writes through its public input hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u16")]
pub enum CircuitId {
    /// Confidential default-ring transfers: private amounts and assets,
    /// with ownership authorized by public Solana signers.
    #[wincode(tag = 0)]
    ConfidentialEd25519(u8, u8, u8),
    /// Confidential custom-ring transfers, authorized by public Solana signers.
    #[wincode(tag = 1)]
    ConfidentialRingEd25519(u8, u8, u8),
    #[wincode(tag = 2)]
    RingAuthority(u8, u8, u8),
    #[wincode(tag = 4)]
    ConfidentialEd25519Cached(u8, u8, u8, CacheAccess),
    #[wincode(tag = 5)]
    ConfidentialRingEd25519Cached(u8, u8, u8, CacheAccess),
    /// Anonymous custom-ring transfers additionally hide sender and recipient
    /// identities. The circuit verifies the private owner's Ed25519 signature
    /// and forbids cache reads, so this variant has no cached twin.
    #[wincode(tag = 7)]
    AnonymousRingEd25519(u8, u8, u8, Bsb22Commitment),
}

impl CircuitId {
    pub const fn cache_access(self) -> Option<CacheAccess> {
        match self {
            Self::ConfidentialEd25519Cached(_, _, _, selection)
            | Self::ConfidentialRingEd25519Cached(_, _, _, selection) => Some(selection),
            _ => None,
        }
    }

    /// The rail this selector names, with any cache selection dropped. A cached
    /// selector differs from its rail only in the cache it declares, so every
    /// shape, rail and key accessor answers through this.
    pub const fn uncached(self) -> Self {
        match self {
            Self::ConfidentialEd25519Cached(n_in, n_out, slots, _) => {
                Self::ConfidentialEd25519(n_in, n_out, slots)
            }
            Self::ConfidentialRingEd25519Cached(n_in, n_out, slots, _) => {
                Self::ConfidentialRingEd25519(n_in, n_out, slots)
            }
            other => other,
        }
    }

    pub const fn num_inputs(self) -> u8 {
        match self {
            Self::ConfidentialEd25519(n, _, _)
            | Self::ConfidentialRingEd25519(n, _, _)
            | Self::RingAuthority(n, _, _)
            | Self::ConfidentialEd25519Cached(n, _, _, _)
            | Self::ConfidentialRingEd25519Cached(n, _, _, _)
            | Self::AnonymousRingEd25519(n, _, _, _) => n,
        }
    }

    pub const fn num_outputs(self) -> u8 {
        match self {
            Self::ConfidentialEd25519(_, n, _)
            | Self::ConfidentialRingEd25519(_, n, _)
            | Self::RingAuthority(_, n, _)
            | Self::ConfidentialEd25519Cached(_, n, _, _)
            | Self::ConfidentialRingEd25519Cached(_, n, _, _)
            | Self::AnonymousRingEd25519(_, n, _, _) => n,
        }
    }

    pub const fn num_public_asset_slots(self) -> u8 {
        match self {
            Self::ConfidentialEd25519(_, _, n)
            | Self::ConfidentialRingEd25519(_, _, n)
            | Self::RingAuthority(_, _, n)
            | Self::ConfidentialEd25519Cached(_, _, n, _)
            | Self::ConfidentialRingEd25519Cached(_, _, n, _)
            | Self::AnonymousRingEd25519(_, _, n, _) => n,
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
            Self::ConfidentialEd25519(..)
                | Self::ConfidentialRingEd25519(..)
                | Self::AnonymousRingEd25519(..)
        )
    }

    pub const fn is_ring(self) -> bool {
        matches!(
            self.uncached(),
            Self::ConfidentialRingEd25519(..)
                | Self::RingAuthority(..)
                | Self::AnonymousRingEd25519(..)
        )
    }

    pub const fn is_authority(self) -> bool {
        matches!(self, Self::RingAuthority(..))
    }

    /// Whether the circuit verifies an owner signature over
    /// `sha256(private_tx_hash || external_data_hash)`.
    pub const fn signs_message_digest(self) -> bool {
        matches!(self.uncached(), Self::AnonymousRingEd25519(..))
    }

    pub const fn bsb22_commitment(&self) -> Option<&Bsb22Commitment> {
        match self {
            Self::AnonymousRingEd25519(_, _, _, commitment) => Some(commitment),
            _ => None,
        }
    }

    pub const fn requires_input_signatures(self) -> bool {
        !self.is_authority()
    }

    pub const fn output_owner_mode(self) -> OutputOwnerMode {
        match self {
            Self::ConfidentialEd25519(..) | Self::ConfidentialEd25519Cached(..) => {
                OutputOwnerMode::All
            }
            Self::ConfidentialRingEd25519(..)
            | Self::ConfidentialRingEd25519Cached(..)
            | Self::AnonymousRingEd25519(..) => OutputOwnerMode::ConfidentialMarked,
            Self::RingAuthority(..) => OutputOwnerMode::None,
        }
    }

    /// Whether this selector names a verifying key generated into this crate.
    pub const fn is_supported(self) -> bool {
        let (n_inputs, n_outputs, n_public_asset_slots) = self.shape();
        if n_public_asset_slots != CURRENT_PUBLIC_ASSET_SLOTS {
            return false;
        }
        let shape = Shape::new(n_inputs as usize, n_outputs as usize);
        match self {
            Self::ConfidentialEd25519(..)
            | Self::ConfidentialRingEd25519(..)
            | Self::ConfidentialEd25519Cached(..)
            | Self::ConfidentialRingEd25519Cached(..) => shape.is_supported(),
            Self::RingAuthority(..) => shape.is_ring_authority(),
            Self::AnonymousRingEd25519(..) => shape.is_anonymous_ring_ed25519(),
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
