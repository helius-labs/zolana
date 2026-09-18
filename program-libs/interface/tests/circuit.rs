use zolana_interface::{
    verifying_keys::{
        Bsb22Commitment, CachedInputs, CircuitId, OutputOwnerMode, RingP256ProofData,
    },
    N_PUBLIC_SLOTS,
};

const CACHE: CachedInputs = CachedInputs { input_bitmap: 1 };

const PUBLIC_ASSET_SLOTS: u8 = N_PUBLIC_SLOTS as u8;
const COMMITMENT: Bsb22Commitment = Bsb22Commitment {
    commitment: [4u8; 32],
    commitment_pok: [5u8; 32],
};
const P256_PROOF_DATA: RingP256ProofData = RingP256ProofData {
    bsb22_commitment: COMMITMENT,
    default_owner_tag: None,
};

#[test]
fn accessors_and_behavior_match_variants() {
    let cached = CircuitId::ConfidentialEddsaCached(2, 3, 3, CACHE);
    assert_eq!(cached.shape(), (2, 3, 3));
    assert!(cached.is_confidential());
    assert!(!cached.is_ring());
    assert!(cached.requires_input_signatures());
    assert_eq!(cached.output_owner_mode(), OutputOwnerMode::All);
    assert_eq!(cached.cached_inputs(), Some(CACHE));

    let ring_cached = CircuitId::RingEddsaCached(2, 3, 3, CACHE);
    assert!(ring_cached.is_ring());
    assert!(!ring_cached.is_p256());
    assert_eq!(ring_cached.cached_inputs(), Some(CACHE));
    assert_eq!(
        ring_cached.output_owner_mode(),
        OutputOwnerMode::ConfidentialMarked
    );

    let p256_cached = CircuitId::RingP256Cached(2, 3, 3, P256_PROOF_DATA, CACHE);
    assert!(p256_cached.is_ring());
    assert!(p256_cached.is_p256());
    assert_eq!(p256_cached.cached_inputs(), Some(CACHE));
    assert_eq!(p256_cached.bsb22_commitment(), Some(&COMMITMENT));
    assert_eq!(
        p256_cached.output_owner_mode(),
        OutputOwnerMode::ConfidentialMarked
    );

    // A cached selector is its rail plus a selection, and nothing else.
    for (rail, twin) in [
        (
            CircuitId::ConfidentialEddsa(2, 3, 3),
            CircuitId::ConfidentialEddsaCached(2, 3, 3, CACHE),
        ),
        (
            CircuitId::RingEddsa(2, 3, 3),
            CircuitId::RingEddsaCached(2, 3, 3, CACHE),
        ),
        (
            CircuitId::RingP256(2, 3, 3, P256_PROOF_DATA),
            CircuitId::RingP256Cached(2, 3, 3, P256_PROOF_DATA, CACHE),
        ),
    ] {
        assert_eq!(twin.uncached(), rail);
        assert_eq!(twin.shape(), rail.shape());
        assert_eq!(twin.output_owner_mode(), rail.output_owner_mode());
        assert_eq!(twin.is_supported(), rail.is_supported());
        assert_eq!(twin.is_ring(), rail.is_ring());
        assert_eq!(twin.is_p256(), rail.is_p256());
        assert_eq!(twin.is_confidential(), rail.is_confidential());
        assert!(rail.cached_inputs().is_none());
    }
    assert!(CircuitId::RingAuthority(2, 2, 3).cached_inputs().is_none());
    let confidential = CircuitId::ConfidentialEddsa(2, 3, 3);
    assert_eq!(confidential.shape(), (2, 3, 3));
    assert!(confidential.is_confidential());
    assert!(!confidential.is_ring());
    assert!(confidential.requires_input_signatures());
    assert_eq!(confidential.output_owner_mode(), OutputOwnerMode::All);

    let ring = CircuitId::RingEddsa(1, 8, 3);
    assert!(ring.is_ring());
    assert!(ring.is_confidential());
    assert!(!ring.is_authority());
    assert!(ring.requires_input_signatures());
    assert_eq!(
        ring.output_owner_mode(),
        OutputOwnerMode::ConfidentialMarked
    );

    let authority = CircuitId::RingAuthority(4, 4, 3);
    assert!(authority.is_ring());
    assert!(authority.is_authority());
    assert!(!authority.requires_input_signatures());
    assert_eq!(authority.output_owner_mode(), OutputOwnerMode::None);

    let p256 = CircuitId::RingP256(2, 3, 3, P256_PROOF_DATA);
    assert_eq!(p256.shape(), (2, 3, 3));
    assert!(p256.is_ring());
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
    assert!(CircuitId::RingEddsa(1, 8, 3).is_supported());
    assert!(CircuitId::RingP256(2, 3, 3, P256_PROOF_DATA).is_supported());
    assert!(CircuitId::RingAuthority(4, 4, 3).is_supported());
    assert!(CircuitId::ConfidentialEddsa(36, 2, 3).is_supported());
    assert!(CircuitId::RingEddsa(36, 2, 3).is_supported());
    assert!(CircuitId::RingP256(36, 2, 3, P256_PROOF_DATA).is_supported());
    assert!(!CircuitId::RingAuthority(36, 2, 3).is_supported());
    assert!(!CircuitId::ConfidentialEddsa(36, 3, 3).is_supported());
    assert!(!CircuitId::ConfidentialEddsa(6, 6, 3).is_supported());
    assert!(!CircuitId::RingEddsa(2, 3, 2).is_supported());
    assert!(!CircuitId::RingAuthority(2, 3, 3).is_supported());
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
        (36, 2),
    ];
    for (n_inputs, n_outputs) in transfer_shapes {
        for circuit in [
            CircuitId::ConfidentialEddsa(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS),
            CircuitId::ConfidentialEddsaCached(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS, CACHE),
            CircuitId::RingEddsa(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS),
            CircuitId::RingEddsaCached(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS, CACHE),
            CircuitId::RingP256(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS, P256_PROOF_DATA),
            CircuitId::RingP256Cached(
                n_inputs,
                n_outputs,
                PUBLIC_ASSET_SLOTS,
                P256_PROOF_DATA,
                CACHE,
            ),
        ] {
            assert!(circuit.is_supported());
            assert!(circuit.verifying_key().is_some());
            // The cache publishes values, not a circuit: a cached spend resolves
            // its rail's own key, so no cached key is generated into this crate.
            let rail = circuit.uncached();
            assert!(core::ptr::eq(
                circuit.verifying_key().expect("cached key"),
                rail.verifying_key().expect("rail key"),
            ));
        }
    }
    for n in 1..=4 {
        let circuit = CircuitId::RingAuthority(n, n, PUBLIC_ASSET_SLOTS);
        assert!(circuit.is_supported());
        assert!(circuit.verifying_key().is_some());
    }
    assert!(CircuitId::ConfidentialEddsa(2, 3, PUBLIC_ASSET_SLOTS - 1)
        .verifying_key()
        .is_none());
    assert!(CircuitId::RingAuthority(36, 2, PUBLIC_ASSET_SLOTS)
        .verifying_key()
        .is_none());
}
