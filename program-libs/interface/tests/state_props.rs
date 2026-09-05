//! Property tests for the interface state kernels: the safe account-bytes cast
//! (`SplAssetRegistry::from_account_bytes`) and the asset-id allocator state
//! machine (`SplAssetCounter::allocate_id`).

use proptest::prelude::*;
use solana_address::Address;
use zolana_interface::{
    error::InterfaceError,
    state::{discriminator, ProtocolConfig, RingConfig, SplAssetCounter, SplAssetRegistry},
};

/// 8-aligned byte buffer so the positive-path `bytemuck` cast in
/// `from_account_bytes` is exercised deterministically (a mis-aligned slice
/// fails the cast cleanly, which the negative property also covers).
#[repr(align(8))]
struct Aligned([u8; 64]);

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// Arbitrary bytes never panic the registry cast: any length other than
    /// exactly `SIZE` is `InvalidAccountData`, and a wrong first byte on a
    /// well-formed record is `InvalidDiscriminator`.
    #[test]
    fn registry_cast_rejects_arbitrary_bytes_cleanly(
        bytes in prop::collection::vec(any::<u8>(), 0..96),
    ) {
        let mut aligned = Aligned([0u8; 64]);
        let len = bytes.len().min(64);
        for (slot, byte) in aligned.0.iter_mut().zip(bytes.iter()) {
            *slot = *byte;
        }
        let view = aligned.0.get(..len).unwrap_or_default();
        match SplAssetRegistry::from_account_bytes(view) {
            Ok(registry) => {
                prop_assert_eq!(len, SplAssetRegistry::SIZE);
                registry.check_discriminator().expect("cast validated discriminator");
            }
            Err(InterfaceError::InvalidAccountData) => {
                // Length mismatch (or unaligned cast) is the only source.
            }
            Err(InterfaceError::InvalidDiscriminator) => {
                prop_assert_eq!(len, SplAssetRegistry::SIZE);
            }
            Err(other) => prop_assert!(false, "unexpected registry cast error: {other:?}"),
        }
    }

    /// The registry's manual encode (`account_bytes`) always round-trips through
    /// its own validated cast to the exact expected record (discriminator,
    /// reserved padding, mint, and asset id).
    #[test]
    fn registry_encode_parses_through_the_validated_cast(
        mint in any::<[u8; 32]>(),
        asset_id in any::<u64>(),
    ) {
        let mut aligned = Aligned([0u8; 64]);
        let encoded = SplAssetRegistry::account_bytes(Address::new_from_array(mint), asset_id);
        for (slot, byte) in aligned.0.iter_mut().zip(encoded.iter()) {
            *slot = *byte;
        }
        let view = aligned.0.get(..SplAssetRegistry::SIZE).unwrap_or_default();
        let registry = SplAssetRegistry::from_account_bytes(view).expect("validated cast");

        // Expected record built through the same public `set` the encoder uses,
        // so the assertion covers the whole struct (incl. discriminator and the
        // reserved padding), not just the two data fields.
        let mut expected = SplAssetRegistry {
            discriminator: 0,
            reserved: [0u8; 7],
            mint: Address::new_from_array([0u8; 32]),
            asset_id: 0,
        };
        expected.set(Address::new_from_array(mint), asset_id);
        prop_assert_eq!(registry, &expected, "registry round-trips to the expected record");
    }

    /// `allocate_id` hands out ids strictly monotonically from any live
    /// counter state, rejects a corrupt below-floor counter, and refuses to
    /// wrap at `u64::MAX`.
    #[test]
    fn counter_allocation_is_monotonic_and_bounded(
        // Arbitrary states plus the boundary values random sampling never hits
        // (floor - 1, the floor itself, and the u64::MAX overflow edge).
        next_id in prop_oneof![
            any::<u64>(),
            (0u64..=SplAssetCounter::FIRST_ASSET_ID + 1),
            Just(u64::MAX - 1),
            Just(u64::MAX),
        ],
    ) {
        let mut counter = SplAssetCounter {
            discriminator: 0,
            reserved: [0u8; 7],
            next_id: 0,
        };
        counter.init().expect("first init on a zeroed counter");
        prop_assert_eq!(counter.next_id, SplAssetCounter::FIRST_ASSET_ID);
        // A freshly initialized counter hands out exactly the floor id.
        prop_assert_eq!(counter.allocate_id(), Ok(SplAssetCounter::FIRST_ASSET_ID));

        counter.next_id = next_id;
        let result = counter.allocate_id();
        if next_id < SplAssetCounter::FIRST_ASSET_ID || next_id == u64::MAX {
            // Below the floor (corrupt) or exhausted id space; allocate_id
            // reports both as InvalidDiscriminator.
            prop_assert_eq!(result, Err(InterfaceError::InvalidDiscriminator));
            prop_assert_eq!(counter.next_id, next_id, "failed allocation must not advance");
        } else {
            prop_assert_eq!(result, Ok(next_id));
            prop_assert_eq!(counter.next_id, next_id + 1);
            // A second allocation continues the sequence without gaps.
            if next_id + 1 != u64::MAX {
                prop_assert_eq!(counter.allocate_id(), Ok(next_id + 1));
                prop_assert_eq!(counter.next_id, next_id + 2);
            }
        }
    }
}

/// Account-layout ABI pin in the style of `error_codes_are_stable`: state
/// struct sizes and discriminator constants are observable by clients and
/// indexers, so any drift must be an explicit, reviewed change.
#[test]
fn state_sizes_and_discriminators_are_stable() {
    let sizes = [
        (ProtocolConfig::SIZE, 166),
        (RingConfig::SIZE, 69),
        (SplAssetCounter::SIZE, 16),
        (SplAssetRegistry::SIZE, 48),
    ];
    for (got, want) in sizes {
        assert_eq!(got, want, "state struct size drifted");
    }

    let discriminators = [
        (discriminator::TREE_ACCOUNT_DISCRIMINATOR, 1),
        (discriminator::PROTOCOL_CONFIG, 3),
        (discriminator::RING_CONFIG, 4),
        (discriminator::SPL_ASSET_REGISTRY, 5),
        (discriminator::SPL_ASSET_COUNTER, 6),
    ];
    for (got, want) in discriminators {
        assert_eq!(got, want, "discriminator drifted");
    }
}

/// `init` refuses to re-initialize a stamped counter, so a second `init` cannot
/// reset the id sequence back to the floor (which would let already-issued ids
/// be handed out a second time).
#[test]
fn init_rejects_reinitialization() {
    let mut counter = SplAssetCounter {
        discriminator: 0,
        reserved: [0u8; 7],
        next_id: 0,
    };
    counter.init().expect("first init on a zeroed counter");
    // Hand out ids so the counter has advanced past the floor.
    assert_eq!(counter.allocate_id(), Ok(SplAssetCounter::FIRST_ASSET_ID));
    let advanced = counter.next_id;
    assert_eq!(advanced, SplAssetCounter::FIRST_ASSET_ID + 1);

    // A second init must be rejected and must NOT reset the sequence.
    assert_eq!(counter.init(), Err(InterfaceError::AlreadyInitialized));
    assert_eq!(
        counter.next_id, advanced,
        "rejected re-init must not reset the counter"
    );
}
