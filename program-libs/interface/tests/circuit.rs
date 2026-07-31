use zolana_interface::{
    verifying_keys::{Bsb22Commitment, CircuitId, OutputOwnerMode, ZoneP256ProofData},
    N_PUBLIC_SLOTS,
};

const PUBLIC_ASSET_SLOTS: u8 = N_PUBLIC_SLOTS as u8;
const COMMITMENT: Bsb22Commitment = Bsb22Commitment {
    commitment: [4u8; 32],
    commitment_pok: [5u8; 32],
};
const P256_PROOF_DATA: ZoneP256ProofData = ZoneP256ProofData {
    bsb22_commitment: COMMITMENT,
    default_owner_tag: None,
};

#[test]
fn accessors_and_behavior_match_variants() {
    let confidential = CircuitId::ConfidentialEddsa(2, 3, 3);
    assert_eq!(confidential.shape(), (2, 3, 3));
    assert!(confidential.is_confidential());
    assert!(!confidential.is_zone());
    assert!(confidential.requires_input_signatures());
    assert_eq!(confidential.output_owner_mode(), OutputOwnerMode::All);

    let zone = CircuitId::ZoneEddsa(1, 8, 3);
    assert!(zone.is_zone());
    assert!(zone.is_confidential());
    assert!(!zone.is_authority());
    assert!(zone.requires_input_signatures());
    assert_eq!(
        zone.output_owner_mode(),
        OutputOwnerMode::ConfidentialMarked
    );

    let authority = CircuitId::ZoneAuthority(4, 4, 3);
    assert!(authority.is_zone());
    assert!(authority.is_authority());
    assert!(!authority.requires_input_signatures());
    assert_eq!(authority.output_owner_mode(), OutputOwnerMode::None);

    let p256 = CircuitId::ZoneP256(2, 3, 3, P256_PROOF_DATA);
    assert_eq!(p256.shape(), (2, 3, 3));
    assert!(p256.is_zone());
    assert!(p256.is_confidential());
    assert!(p256.is_p256());
    assert!(p256.requires_input_signatures());
    assert_eq!(
        p256.output_owner_mode(),
        OutputOwnerMode::ConfidentialMarked
    );
    assert_eq!(p256.bsb22_commitment(), Some(&COMMITMENT));
    assert_eq!(p256.default_p256_owner_tag(), None);
}

#[test]
fn supported_shapes_are_fail_closed() {
    assert!(CircuitId::ConfidentialEddsa(2, 3, 3).is_supported());
    assert!(CircuitId::ZoneEddsa(1, 8, 3).is_supported());
    assert!(CircuitId::ZoneP256(2, 3, 3, P256_PROOF_DATA).is_supported());
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
            CircuitId::ConfidentialEddsa(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS),
            CircuitId::ZoneEddsa(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS),
            CircuitId::ZoneP256(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS, P256_PROOF_DATA),
        ] {
            assert!(circuit.is_supported());
            assert!(circuit.verifying_key().is_some());
        }
    }
    for n in 1..=4 {
        let circuit = CircuitId::ZoneAuthority(n, n, PUBLIC_ASSET_SLOTS);
        assert!(circuit.is_supported());
        assert!(circuit.verifying_key().is_some());
    }
    assert!(CircuitId::ConfidentialEddsa(2, 3, PUBLIC_ASSET_SLOTS - 1)
        .verifying_key()
        .is_none());
}
