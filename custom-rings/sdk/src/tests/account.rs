use custom_ring_interface::{stream::EPOCH_SLOTS, RingMode};

use super::support::{account, keypair, program, ring, Chain, Registry, RingSettings};
use crate::{PinnedPolicy, RingError};

#[tokio::test]
async fn the_status_carries_the_pinned_registry_and_the_creation_epoch() {
    let member = keypair(1);
    let client = Chain::ring(RingSettings {
        has_policy: true,
        created_slot: 7 * EPOCH_SLOTS + 3,
        ..RingSettings::new(RingMode::Registry)
    })
    .with_registry(Registry::new(&[(&member, 1)]), &super::pipeline_rules())
    .client();
    let status = ring().status(&client).await.unwrap();
    assert_eq!(status.config.creation_epoch(), 7);
    let pinned = PinnedPolicy::of(status.registry.unwrap().account()).unwrap();
    assert_eq!(pinned.table, super::pipeline_rules());
}

#[tokio::test]
async fn a_config_with_an_unknown_mode_byte_is_an_invalid_account() {
    let settings = RingSettings::new(RingMode::Off);
    let mut config = settings.config();
    config.mode = 7;
    let chain = Chain::ring(settings).with(ring().config_pda(), account(program(), &config));
    assert!(matches!(
        ring().config(&chain).await,
        Err(RingError::InvalidAccount { address }) if address == ring().config_pda()
    ));
}
