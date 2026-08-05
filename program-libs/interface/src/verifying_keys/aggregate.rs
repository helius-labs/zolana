use wincode::{SchemaRead, SchemaWrite};

use super::circuit::CircuitId;

const CURRENT_PUBLIC_ASSET_SLOTS: u8 = crate::N_PUBLIC_SLOTS as u8;

/// One outer verification costs more than one inner one, so a batch of one is
/// a loss.
pub const MIN_AGGREGATE_BATCH: u8 = 2;

/// The `leg_hashes` buffer bound, not the catalogue. A batch above 3 has no
/// registered key, so `is_supported` rejects it.
pub const MAX_AGGREGATE_BATCH: u8 = 5;

/// Which transact rail a batch proves. Carries no per-proof data, because the
/// inner BSB22 commitments stay inside the outer proof's witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u16")]
pub enum InnerCircuitKind {
    ConfidentialEddsa,
    RingEddsa,
    RingAuthority,
    RingP256,
}

impl InnerCircuitKind {
    /// Every rail. A variant missing here escapes the exhaustive tests that
    /// iterate this list.
    pub const ALL: [Self; 4] = [
        Self::ConfidentialEddsa,
        Self::RingEddsa,
        Self::RingAuthority,
        Self::RingP256,
    ];

    /// A leg keeps this discriminator in `external_data_hash`, so one proof is
    /// valid both on its own and inside a batch.
    pub const fn solo_tag(self) -> u8 {
        match self {
            Self::ConfidentialEddsa => zolana_event::tag::TRANSACT,
            Self::RingEddsa | Self::RingP256 => zolana_event::tag::RING_TRANSACT,
            Self::RingAuthority => zolana_event::tag::RING_AUTHORITY_TRANSACT,
        }
    }

    pub const fn is_ring(self) -> bool {
        matches!(self, Self::RingEddsa | Self::RingAuthority | Self::RingP256)
    }

    pub const fn is_p256(self) -> bool {
        matches!(self, Self::RingP256)
    }
}

// Exhaustive over the rails, so a new variant must claim its slot in `ALL`
// before this compiles.
const _: () = {
    let mut i = 0;
    while i < InnerCircuitKind::ALL.len() {
        let expected = match InnerCircuitKind::ALL[i] {
            InnerCircuitKind::ConfidentialEddsa => 0,
            InnerCircuitKind::RingEddsa => 1,
            InnerCircuitKind::RingAuthority => 2,
            InnerCircuitKind::RingP256 => 3,
        };
        assert!(expected == i);
        i += 1;
    }
};

/// A supported `aggregate_transact` instantiation.
///
/// The batched verifying key is compiled into the outer circuit, so this
/// selector names one outer verifying key. A batch cannot claim to have proved
/// one circuit while the outer proof verified another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct AggregateCircuitId {
    pub kind: InnerCircuitKind,
    /// Number of inputs, outputs, and public asset slots of each leg.
    pub num_inputs: u8,
    pub num_outputs: u8,
    pub num_public_asset_slots: u8,
    /// Number of legs in the batch.
    pub batch: u8,
}

impl AggregateCircuitId {
    /// Every leg of a batch shares the rail and shape.
    pub const fn leg_shape(self) -> (u8, u8, u8) {
        (
            self.num_inputs,
            self.num_outputs,
            self.num_public_asset_slots,
        )
    }

    /// Fail closed. An unlisted selector has no key and is rejected before any
    /// pairing runs.
    pub const fn is_supported(self) -> bool {
        if self.num_public_asset_slots != CURRENT_PUBLIC_ASSET_SLOTS {
            return false;
        }
        if self.batch < MIN_AGGREGATE_BATCH || self.batch > MAX_AGGREGATE_BATCH {
            return false;
        }
        match self.kind {
            InnerCircuitKind::ConfidentialEddsa => {
                self.num_inputs == 2
                    && (self.num_outputs == 2 || self.num_outputs == 3)
                    && self.batch <= 3
            }
            InnerCircuitKind::RingEddsa | InnerCircuitKind::RingP256 => {
                self.num_inputs == 2 && self.num_outputs == 3 && self.batch <= 3
            }
            InnerCircuitKind::RingAuthority => false,
        }
    }

    /// The outer verifying key for this selector, or `None` when the selector
    /// names no generated key.
    #[cfg(feature = "verifying-keys")]
    pub const fn verifying_key(
        self,
    ) -> Option<&'static groth16_solana::groth16::Groth16Verifyingkey<'static>> {
        if !self.is_supported() {
            return None;
        }
        match (self.kind, self.num_inputs, self.num_outputs, self.batch) {
            (InnerCircuitKind::RingP256, 2, 3, 2) => {
                Some(&super::aggregate_transfer_p256_ring_2_3_b2::VERIFYINGKEY)
            }
            (InnerCircuitKind::RingP256, 2, 3, 3) => {
                Some(&super::aggregate_transfer_p256_ring_2_3_b3::VERIFYINGKEY)
            }
            (InnerCircuitKind::RingEddsa, 2, 3, 2) => {
                Some(&super::aggregate_transfer_ring_2_3_b2::VERIFYINGKEY)
            }
            (InnerCircuitKind::RingEddsa, 2, 3, 3) => {
                Some(&super::aggregate_transfer_ring_2_3_b3::VERIFYINGKEY)
            }
            (InnerCircuitKind::ConfidentialEddsa, 2, 2, 2) => {
                Some(&super::aggregate_transfer_confidential_2_2_b2::VERIFYINGKEY)
            }
            (InnerCircuitKind::ConfidentialEddsa, 2, 2, 3) => {
                Some(&super::aggregate_transfer_confidential_2_2_b3::VERIFYINGKEY)
            }
            (InnerCircuitKind::ConfidentialEddsa, 2, 3, 2) => {
                Some(&super::aggregate_transfer_confidential_2_3_b2::VERIFYINGKEY)
            }
            (InnerCircuitKind::ConfidentialEddsa, 2, 3, 3) => {
                Some(&super::aggregate_transfer_confidential_2_3_b3::VERIFYINGKEY)
            }
            _ => None,
        }
    }

    /// A leg's rail and shape must be the ones the outer key was built for.
    pub const fn accepts_leg(self, leg: CircuitId) -> bool {
        // A new rail variant on either enum must fail compilation here.
        let kind_matches = match self.kind {
            InnerCircuitKind::ConfidentialEddsa => match leg {
                CircuitId::ConfidentialEddsa(..) => true,
                CircuitId::RingEddsa(..)
                | CircuitId::RingAuthority(..)
                | CircuitId::RingP256(..) => false,
            },
            InnerCircuitKind::RingEddsa => match leg {
                CircuitId::RingEddsa(..) => true,
                CircuitId::ConfidentialEddsa(..)
                | CircuitId::RingAuthority(..)
                | CircuitId::RingP256(..) => false,
            },
            InnerCircuitKind::RingAuthority => match leg {
                CircuitId::RingAuthority(..) => true,
                CircuitId::ConfidentialEddsa(..)
                | CircuitId::RingEddsa(..)
                | CircuitId::RingP256(..) => false,
            },
            InnerCircuitKind::RingP256 => match leg {
                CircuitId::RingP256(..) => true,
                CircuitId::ConfidentialEddsa(..)
                | CircuitId::RingEddsa(..)
                | CircuitId::RingAuthority(..) => false,
            },
        };
        if !kind_matches {
            return false;
        }
        let (n_in, n_out, n_slots) = leg.shape();
        n_in == self.num_inputs
            && n_out == self.num_outputs
            && n_slots == self.num_public_asset_slots
    }
}
