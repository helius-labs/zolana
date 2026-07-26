use wincode::{SchemaRead, SchemaWrite};

const CURRENT_PUBLIC_ASSET_SLOTS: u8 = crate::N_PUBLIC_SLOTS as u8;

/// A supported `transact` circuit instantiation.
///
/// The tuple fields are `(number of inputs, number of outputs, number of
/// public asset slots)`. The selector is not a circuit public input: it selects
/// the verifying key and is validated against the dispatched instruction and
/// the instruction data before verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u16")]
pub enum CircuitId {
    ConfidentialEddsa(u8, u8, u8),
    ZoneEddsa(u8, u8, u8),
    ZoneAuthority(u8, u8, u8),
}

impl CircuitId {
    pub const fn num_inputs(self) -> u8 {
        match self {
            Self::ConfidentialEddsa(n, _, _)
            | Self::ZoneEddsa(n, _, _)
            | Self::ZoneAuthority(n, _, _) => n,
        }
    }

    pub const fn num_outputs(self) -> u8 {
        match self {
            Self::ConfidentialEddsa(_, n, _)
            | Self::ZoneEddsa(_, n, _)
            | Self::ZoneAuthority(_, n, _) => n,
        }
    }

    pub const fn num_public_asset_slots(self) -> u8 {
        match self {
            Self::ConfidentialEddsa(_, _, n)
            | Self::ZoneEddsa(_, _, n)
            | Self::ZoneAuthority(_, _, n) => n,
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
        matches!(self, Self::ConfidentialEddsa(..))
    }

    pub const fn is_zone(self) -> bool {
        matches!(self, Self::ZoneEddsa(..) | Self::ZoneAuthority(..))
    }

    pub const fn is_authority(self) -> bool {
        matches!(self, Self::ZoneAuthority(..))
    }

    pub const fn requires_input_signatures(self) -> bool {
        !self.is_authority()
    }

    pub const fn binds_output_owners(self) -> bool {
        self.is_confidential()
    }

    /// Whether this selector names a verifying key generated into this crate.
    pub const fn is_supported(self) -> bool {
        let (n_inputs, n_outputs, n_public_asset_slots) = self.shape();
        if n_public_asset_slots != CURRENT_PUBLIC_ASSET_SLOTS {
            return false;
        }
        match self {
            Self::ConfidentialEddsa(..) | Self::ZoneEddsa(..) => matches!(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_behavior_match_variants() {
        let confidential = CircuitId::ConfidentialEddsa(2, 3, 3);
        assert_eq!(confidential.shape(), (2, 3, 3));
        assert!(confidential.is_confidential());
        assert!(!confidential.is_zone());
        assert!(confidential.requires_input_signatures());
        assert!(confidential.binds_output_owners());

        let zone = CircuitId::ZoneEddsa(1, 8, 3);
        assert!(zone.is_zone());
        assert!(!zone.is_authority());
        assert!(zone.requires_input_signatures());
        assert!(!zone.binds_output_owners());

        let authority = CircuitId::ZoneAuthority(4, 4, 3);
        assert!(authority.is_zone());
        assert!(authority.is_authority());
        assert!(!authority.requires_input_signatures());
        assert!(!authority.binds_output_owners());
    }

    #[test]
    fn supported_shapes_are_fail_closed() {
        assert!(CircuitId::ConfidentialEddsa(2, 3, 3).is_supported());
        assert!(CircuitId::ZoneEddsa(1, 8, 3).is_supported());
        assert!(CircuitId::ZoneAuthority(4, 4, 3).is_supported());
        assert!(!CircuitId::ConfidentialEddsa(6, 6, 3).is_supported());
        assert!(!CircuitId::ZoneEddsa(2, 3, 2).is_supported());
        assert!(!CircuitId::ZoneAuthority(2, 3, 3).is_supported());
    }

    #[cfg(feature = "verifying-keys")]
    #[test]
    fn every_supported_shape_resolves_exactly_one_key() {
        let transfer_shapes = [
            (1, 1),
            (1, 2),
            (1, 8),
            (2, 2),
            (2, 3),
            (3, 3),
            (4, 3),
            (4, 4),
            (5, 3),
            (5, 4),
        ];
        for (n_inputs, n_outputs) in transfer_shapes {
            for circuit in [
                CircuitId::ConfidentialEddsa(n_inputs, n_outputs, CURRENT_PUBLIC_ASSET_SLOTS),
                CircuitId::ZoneEddsa(n_inputs, n_outputs, CURRENT_PUBLIC_ASSET_SLOTS),
            ] {
                assert!(circuit.is_supported());
                assert!(circuit.verifying_key().is_some());
            }
        }
        for n in 1..=4 {
            let circuit = CircuitId::ZoneAuthority(n, n, CURRENT_PUBLIC_ASSET_SLOTS);
            assert!(circuit.is_supported());
            assert!(circuit.verifying_key().is_some());
        }
        assert!(
            CircuitId::ConfidentialEddsa(2, 3, CURRENT_PUBLIC_ASSET_SLOTS - 1)
                .verifying_key()
                .is_none()
        );
    }
}
