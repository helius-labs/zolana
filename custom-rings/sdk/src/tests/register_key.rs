use custom_ring_interface::{CustomRingError, QueueEntry, RingMode, MEMBER_QUEUE_LIMIT};
use zolana_ring_policy::Member;

use super::support::{keypair, owner_identity, payer, ring, Chain, Registry, RingSettings, SLOT};
use crate::{EscrowedRecipients, MemberRecords, RegisterKey, RingError};

fn escrowed() -> RingSettings {
    RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Registry)
    }
}

#[tokio::test]
async fn a_key_registers_once_for_the_member_it_derives_on_a_confidential_ring() {
    let member = keypair(1);
    let registered = keypair(2);
    let register = |chain: Chain, authority: &zolana_keypair::ShieldedKeypair| {
        let address = member.shielded_address().unwrap();
        let client = chain.client();
        let authority = authority.nullifier_key.clone();
        async move {
            RegisterKey {
                ring: ring(),
                member: address,
                payer: payer(),
                authority: &authority,
            }
            .prove(&client)
            .await
        }
    };
    assert!(matches!(
        register(Chain::ring(RingSettings::new(RingMode::Anonymous)), &member).await,
        Err(RingError::Program(CustomRingError::AnonymousRingRefused))
    ));
    assert!(matches!(
        register(Chain::ring(escrowed()), &registered).await,
        Err(RingError::NullifierKeyMismatch)
    ));
    let chain = Chain::ring(escrowed())
        .with_registry(Registry::new(&[(&member, 1)]), &super::pipeline_rules())
        .with_queue(&[], SLOT, 0);
    assert!(matches!(
        register(chain, &member).await,
        Err(RingError::KeyAlreadyRegistered { member: refused }) if refused == owner_identity(&member)
    ));
}

/// The program refuses a registration past the member share of the queue, the SDK before proving.
#[tokio::test]
async fn a_full_member_queue_refuses_a_key_before_proving() {
    let member = keypair(1);
    let pending: Vec<QueueEntry> = (1..=MEMBER_QUEUE_LIMIT as u8)
        .map(|byte| QueueEntry {
            member: *Member::owner_tag(&[byte; 32]).unwrap().as_bytes(),
            mask: 1,
            value: 1,
            escrow_key: [0; 32],
        })
        .collect();
    let client = Chain::ring(escrowed())
        .with_registry(Registry::new(&[]), &super::pipeline_rules())
        .with_queue(&pending, SLOT, 0)
        .client();
    assert!(matches!(
        RegisterKey {
            ring: ring(),
            member: member.shielded_address().unwrap(),
            payer: payer(),
            authority: &member.nullifier_key,
        }
        .prove(&client)
        .await,
        Err(RingError::Program(CustomRingError::QueueFull))
    ));
}

#[tokio::test]
async fn member_records_come_back_in_member_order_with_the_escrowed_key() {
    let registered = keypair(1);
    let stranger = keypair(2);
    let client = Chain::ring(escrowed())
        .with_registry(Registry::new(&[(&registered, 1)]), &super::pipeline_rules())
        .client();
    let reads = MemberRecords {
        ring: ring(),
        members: &[owner_identity(&stranger), owner_identity(&registered)],
    }
    .read(&client)
    .await
    .unwrap();
    assert!(reads[0].record().is_none());
    let registered = registered.shielded_address().unwrap();
    assert!(reads[1]
        .escrowed(&registered.nullifier_pubkey)
        .unwrap()
        .is_some());
    assert!(reads[1]
        .escrowed(&stranger.shielded_address().unwrap().nullifier_pubkey)
        .unwrap()
        .is_none());
}

/// A recipient without an escrowed key is refused on a key escrow ring alone.
#[tokio::test]
async fn a_recipient_without_an_escrowed_key_is_refused_before_any_proof() {
    let registered = keypair(1);
    let stranger = keypair(2);
    let recipients = [
        registered.shielded_address().unwrap(),
        stranger.shielded_address().unwrap(),
    ];
    let escrowing = Chain::ring(escrowed())
        .with_registry(Registry::new(&[(&registered, 1)]), &super::pipeline_rules())
        .client();
    assert!(EscrowedRecipients {
        ring: ring(),
        recipients: &recipients[..1],
    }
    .check(&escrowing)
    .await
    .is_ok());
    assert!(matches!(
        EscrowedRecipients {
            ring: ring(),
            recipients: &recipients,
        }
        .check(&escrowing)
        .await,
        Err(RingError::UnregisteredOutputKey { owner }) if owner == owner_identity(&stranger)
    ));
    let confidential = Chain::ring(RingSettings::new(RingMode::Off)).client();
    assert!(EscrowedRecipients {
        ring: ring(),
        recipients: &recipients,
    }
    .check(&confidential)
    .await
    .is_ok());
}
