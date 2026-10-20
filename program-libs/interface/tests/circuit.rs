use zolana_interface::{
    shape::{RING_AUTHORITY_WIDTHS, SPP_SUPPORTED_SHAPES},
    verifying_keys::{
        AnonymousRingEddsaProofData, Bsb22Commitment, CacheAccess, CircuitId, OutputOwnerMode,
    },
    N_PUBLIC_SLOTS,
};

const CACHE: CacheAccess = CacheAccess {
    read_bitmap: 1,
    write_slots: CacheAccess::NO_WRITES,
};

const PUBLIC_ASSET_SLOTS: u8 = N_PUBLIC_SLOTS as u8;
const COMMITMENT: Bsb22Commitment = Bsb22Commitment {
    commitment: [4u8; 32],
    commitment_pok: [5u8; 32],
};
const PROOF_DATA: AnonymousRingEddsaProofData = AnonymousRingEddsaProofData {
    bsb22_commitment: COMMITMENT,
    default_owner_tag: None,
};

#[test]
fn accessors_and_behavior_match_variants() {
    let cached = CircuitId::ConfidentialSignerCached(2, 3, 3, CACHE);
    assert_eq!(cached.shape(), (2, 3, 3));
    assert!(cached.is_confidential());
    assert!(!cached.is_ring());
    assert!(cached.requires_input_signatures());
    assert_eq!(cached.output_owner_mode(), OutputOwnerMode::All);
    assert_eq!(cached.cache_access(), Some(CACHE));

    let ring_cached = CircuitId::ConfidentialRingEddsaCached(2, 3, 3, CACHE);
    assert!(ring_cached.is_ring());
    assert!(!ring_cached.is_anonymous());
    assert_eq!(ring_cached.cache_access(), Some(CACHE));
    assert_eq!(
        ring_cached.output_owner_mode(),
        OutputOwnerMode::ConfidentialMarked
    );

    let anonymous_cached = CircuitId::AnonymousRingEddsaCached(2, 3, 3, PROOF_DATA, CACHE);
    assert!(anonymous_cached.is_ring());
    assert!(anonymous_cached.is_anonymous());
    assert_eq!(anonymous_cached.cache_access(), Some(CACHE));
    assert_eq!(anonymous_cached.bsb22_commitment(), Some(&COMMITMENT));
    assert_eq!(
        anonymous_cached.output_owner_mode(),
        OutputOwnerMode::ConfidentialMarked
    );

    // A cached selector is its rail plus a selection, and nothing else.
    for (rail, twin) in [
        (
            CircuitId::ConfidentialSigner(2, 3, 3),
            CircuitId::ConfidentialSignerCached(2, 3, 3, CACHE),
        ),
        (
            CircuitId::ConfidentialRingEddsa(2, 3, 3),
            CircuitId::ConfidentialRingEddsaCached(2, 3, 3, CACHE),
        ),
        (
            CircuitId::AnonymousRingEddsa(2, 3, 3, PROOF_DATA),
            CircuitId::AnonymousRingEddsaCached(2, 3, 3, PROOF_DATA, CACHE),
        ),
    ] {
        assert_eq!(twin.uncached(), rail);
        assert_eq!(twin.shape(), rail.shape());
        assert_eq!(twin.output_owner_mode(), rail.output_owner_mode());
        assert_eq!(twin.is_supported(), rail.is_supported());
        assert_eq!(twin.is_ring(), rail.is_ring());
        assert_eq!(twin.is_anonymous(), rail.is_anonymous());
        assert_eq!(twin.is_confidential(), rail.is_confidential());
        assert!(rail.cache_access().is_none());
    }
    assert!(CircuitId::RingAuthority(2, 2, 3).cache_access().is_none());
    let confidential = CircuitId::ConfidentialSigner(2, 3, 3);
    assert_eq!(confidential.shape(), (2, 3, 3));
    assert!(confidential.is_confidential());
    assert!(!confidential.is_ring());
    assert!(confidential.requires_input_signatures());
    assert_eq!(confidential.output_owner_mode(), OutputOwnerMode::All);

    let ring = CircuitId::ConfidentialRingEddsa(1, 8, 3);
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

    let anonymous = CircuitId::AnonymousRingEddsa(2, 3, 3, PROOF_DATA);
    assert_eq!(anonymous.shape(), (2, 3, 3));
    assert!(anonymous.is_ring());
    assert!(anonymous.is_confidential());
    assert!(anonymous.is_anonymous());
    assert!(anonymous.requires_input_signatures());
    assert_eq!(
        anonymous.output_owner_mode(),
        OutputOwnerMode::ConfidentialMarked
    );
    assert_eq!(anonymous.bsb22_commitment(), Some(&COMMITMENT));
    assert_eq!(anonymous.default_owner_tag(), None);
}

#[test]
fn supported_shapes_are_fail_closed() {
    assert!(CircuitId::ConfidentialSigner(2, 4, 3).is_supported());
    assert!(CircuitId::ConfidentialRingEddsa(1, 8, 3).is_supported());
    assert!(CircuitId::AnonymousRingEddsa(2, 4, 3, PROOF_DATA).is_supported());
    assert!(CircuitId::RingAuthority(4, 4, 3).is_supported());
    assert!(CircuitId::ConfidentialSigner(49, 2, 3).is_supported());
    assert!(CircuitId::ConfidentialRingEddsa(49, 2, 3).is_supported());
    assert!(CircuitId::AnonymousRingEddsa(49, 2, 3, PROOF_DATA).is_supported());
    assert!(CircuitId::ConfidentialSigner(8, 16, 3).is_supported());
    assert!(!CircuitId::RingAuthority(49, 2, 3).is_supported());
    assert!(!CircuitId::ConfidentialSigner(49, 4, 3).is_supported());
    assert!(!CircuitId::ConfidentialSigner(51, 2, 3).is_supported());
    assert!(!CircuitId::ConfidentialSigner(6, 6, 3).is_supported());
    assert!(!CircuitId::ConfidentialRingEddsa(2, 4, 2).is_supported());
    assert!(!CircuitId::RingAuthority(2, 4, 3).is_supported());
    for (n_inputs, n_outputs) in [(1, 1), (2, 3), (3, 3), (4, 3), (5, 3), (36, 2)] {
        assert!(
            !CircuitId::ConfidentialSigner(n_inputs, n_outputs, 3).is_supported(),
            "{n_inputs}x{n_outputs} was removed"
        );
    }
    for n in [1, 3] {
        assert!(!CircuitId::RingAuthority(n, n, 3).is_supported(), "{n}x{n}");
    }
}

#[test]
fn every_supported_shape_is_supported_on_every_owner_signed_rail() {
    for shape in SPP_SUPPORTED_SHAPES {
        let n_inputs = u8::try_from(shape.n_inputs()).expect("fits u8");
        let n_outputs = u8::try_from(shape.n_outputs()).expect("fits u8");
        for circuit in [
            CircuitId::ConfidentialSigner(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS),
            CircuitId::ConfidentialSignerCached(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS, CACHE),
            CircuitId::ConfidentialRingEddsa(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS),
            CircuitId::AnonymousRingEddsa(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS, PROOF_DATA),
        ] {
            assert!(circuit.is_supported(), "{circuit:?}");
        }
    }
}

#[cfg(feature = "verifying-keys")]
#[test]
fn every_supported_shape_resolves_exactly_one_key() {
    for shape in SPP_SUPPORTED_SHAPES {
        let n_inputs = u8::try_from(shape.n_inputs()).expect("fits u8");
        let n_outputs = u8::try_from(shape.n_outputs()).expect("fits u8");
        for circuit in [
            CircuitId::ConfidentialSigner(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS),
            CircuitId::ConfidentialSignerCached(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS, CACHE),
            CircuitId::ConfidentialRingEddsa(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS),
            CircuitId::ConfidentialRingEddsaCached(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS, CACHE),
            CircuitId::AnonymousRingEddsa(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS, PROOF_DATA),
            CircuitId::AnonymousRingEddsaCached(
                n_inputs,
                n_outputs,
                PUBLIC_ASSET_SLOTS,
                PROOF_DATA,
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
    for width in RING_AUTHORITY_WIDTHS {
        let n = u8::try_from(width).expect("fits u8");
        let circuit = CircuitId::RingAuthority(n, n, PUBLIC_ASSET_SLOTS);
        assert!(circuit.is_supported());
        assert!(circuit.verifying_key().is_some());
    }
    assert!(CircuitId::ConfidentialSigner(2, 3, PUBLIC_ASSET_SLOTS - 1)
        .verifying_key()
        .is_none());
    assert!(CircuitId::RingAuthority(49, 2, PUBLIC_ASSET_SLOTS)
        .verifying_key()
        .is_none());
}
