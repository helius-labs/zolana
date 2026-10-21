use custom_ring_interface::{CustomRingError, QueueEntry, RingMode, APPLY_DELAY_SLOTS};
use solana_address::Address;
use zolana_client::ClientError;
use zolana_ring_policy::{ListId, ListSet, ListWrite, Member, Writer};

use super::support::{authority, ring, Chain, Registry, RingSettings, SLOT};
use crate::{AuthorityListWrite, RecordApplication, RingError};

fn member(byte: u8) -> Member {
    Member::owner_tag(&[byte; 32]).unwrap()
}

fn allow() -> ListWrite {
    ListWrite::new(ListSet::single(ListId::Allow), ListSet::EMPTY).unwrap()
}

fn writes(count: u8) -> AuthorityListWrite {
    (1..=count).fold(
        AuthorityListWrite::new(ring(), authority()),
        |write, byte| write.with_write(member(byte), allow()).unwrap(),
    )
}

fn entry(byte: u8) -> QueueEntry {
    QueueEntry {
        member: *member(byte).as_bytes(),
        mask: 1,
        value: 1,
        escrow_key: [0; 32],
    }
}

fn escrowed() -> Chain {
    Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Registry)
    })
    .with_registry(Registry::new(&[]), &super::pipeline_rules())
}

#[test]
fn authority_writes_split_into_batches_beside_the_pending_member_writes() {
    let sizes = |pending| -> Vec<usize> {
        writes(20)
            .batches(pending)
            .iter()
            .map(|batch| batch.writes().len())
            .collect()
    };
    assert_eq!(sizes(0), [16, 4]);
    assert_eq!(sizes(10), [6, 14]);
    assert_eq!(sizes(16), [16, 4]);
    let batches = writes(20).batches(10);
    let members: Vec<Member> = batches
        .iter()
        .flat_map(|batch| batch.writes().iter().map(|(member, _)| *member))
        .collect();
    assert_eq!(members, (1..=20).map(member).collect::<Vec<_>>());
}

#[test]
fn an_authority_write_names_each_member_once_and_only_authority_lists() {
    assert!(matches!(
        writes(2).with_write(member(1), allow()),
        Err(RingError::DuplicateListWrite { member: repeated }) if repeated == member(1)
    ));
    let recovery = ListWrite::new(ListSet::single(ListId::Recovery), ListSet::EMPTY).unwrap();
    assert!(matches!(
        AuthorityListWrite::new(ring(), authority()).with_write(member(1), recovery),
        Err(RingError::ListNotWritable {
            list: ListId::Recovery,
            writer: Writer::Authority
        })
    ));
}

#[tokio::test]
async fn an_authority_batch_is_refused_before_proving_when_it_cannot_be_applied() {
    let client = escrowed().client();
    assert!(matches!(
        AuthorityListWrite::new(ring(), authority())
            .prove(&client)
            .await,
        Err(RingError::EmptyListWrite)
    ));
    let stranger = AuthorityListWrite::new(ring(), Address::new_from_array([0x47; 32]))
        .with_write(member(1), allow())
        .unwrap();
    assert!(matches!(
        stranger.prove(&client).await,
        Err(RingError::Program(CustomRingError::UnauthorizedAuthority))
    ));
    let pending: Vec<QueueEntry> = (30..40).map(entry).collect();
    let client = escrowed().with_queue(&pending, SLOT, 0).client();
    assert!(matches!(
        writes(7).prove(&client).await,
        Err(RingError::AuthorityBatchSplit {
            writes: 7,
            pending: 10,
            batches: 2
        })
    ));
}

/// A due queue reaches the indexer for its proof inputs, any other returns `None`.
#[tokio::test]
async fn a_permissionless_application_waits_for_a_full_or_aged_queue_and_its_window() {
    let application =
        |chain: Chain| async move { RecordApplication::new(ring()).prove(&chain.client()).await };
    assert!(matches!(
        application(escrowed().with_queue(&[], SLOT, 0)).await,
        Ok(None)
    ));
    let fresh = SLOT - APPLY_DELAY_SLOTS + 1;
    assert!(matches!(
        application(escrowed().with_queue(&[entry(1)], fresh, 0)).await,
        Ok(None)
    ));
    let aged = SLOT - APPLY_DELAY_SLOTS;
    assert!(matches!(
        application(escrowed().with_queue(&[entry(1)], aged, SLOT + 1)).await,
        Ok(None)
    ));
    let full: Vec<QueueEntry> = (1..=8).map(entry).collect();
    for chain in [
        escrowed().with_queue(&[entry(1)], aged, SLOT),
        escrowed().with_queue(&full, SLOT, 0),
    ] {
        assert!(matches!(
            application(chain).await,
            Err(RingError::Client(ClientError::UnsupportedRpcMethod(
                "get_ring_apply_proof_inputs"
            )))
        ));
    }
}
