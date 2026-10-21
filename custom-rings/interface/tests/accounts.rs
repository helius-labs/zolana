use bytemuck::Zeroable;
use custom_ring_interface::{
    queue_chain, ApplyRecordsIxData, CustomRingError, MemberRegistry, PendingApplication,
    QueueEntry, RecordQueue, RingAccount, RingProgramConfig, SourceSlot, WriteRecordsIxData,
    APPLY_DELAY_SLOTS, AUTHORITY_RESERVED_LEAVES, GRACE_SLOTS, MAX_CO_SIGNER_THRESHOLDS,
    MEMBER_QUEUE_LIMIT, MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_EMPTY_ROOT, N_SOURCE_SLOTS,
    QUEUE_CAPACITY, RING_PROGRAM_CONFIG,
};
use solana_address::Address;
use zolana_hasher::primitives::right_align;
use zolana_ring_policy::{ListId, ListSet, ListWrite, Rule, RuleTable, Subject, Writer};

const PROGRAM: Address = Address::new_from_array([7; 32]);

fn config() -> RingProgramConfig {
    let mut config: RingProgramConfig = Zeroable::zeroed();
    config.discriminator = RING_PROGRAM_CONFIG;
    config.authority = Address::new_from_array([1; 32]);
    config.auditor_pubkey = [4; 33];
    config.bump = 255;
    config.has_policy = 1;
    config
}

fn entry(byte: u8) -> QueueEntry {
    let recovery = ListWrite::new(ListSet::single(ListId::Recovery), ListSet::EMPTY).unwrap();
    WriteRecordsIxData::new(recovery)
        .entry(right_align(&[byte]), Writer::Member)
        .unwrap()
}

struct Floors {
    applied: u64,
    floor: u64,
    prior_floor: u64,
    floor_slot: u64,
}

impl Floors {
    /// The newest root, at history slot 1, applied `applied`.
    fn registry(self) -> MemberRegistry {
        let mut registry = MemberRegistry::new(254, 0);
        registry.push_root([9; 32], self.applied, 10);
        registry.floor = self.floor.to_le_bytes();
        registry.prior_floor = self.prior_floor.to_le_bytes();
        registry.floor_slot = self.floor_slot.to_le_bytes();
        registry
    }
}

fn queue_with(pending: u64, slot: u64) -> RecordQueue {
    let mut queue = RecordQueue::new(253);
    for byte in 0..pending {
        queue.push(&entry(byte as u8 + 1), slot).unwrap();
    }
    queue
}

#[test]
fn decode_needs_the_owner_the_length_and_the_discriminator() {
    let bytes = bytemuck::bytes_of(&config()).to_vec();
    assert_eq!(
        RingProgramConfig::decode(&PROGRAM, &PROGRAM, &bytes),
        Some(config())
    );
    let other = Address::new_from_array([8; 32]);
    assert_eq!(RingProgramConfig::decode(&other, &PROGRAM, &bytes), None);
    assert_eq!(
        RingProgramConfig::decode(&PROGRAM, &PROGRAM, &bytes[1..]),
        None
    );
    let mut retired = bytes.clone();
    retired[0] = 1;
    assert_eq!(
        RingProgramConfig::decode(&PROGRAM, &PROGRAM, &retired),
        None
    );
    assert_eq!(MemberRegistry::decode(&PROGRAM, &PROGRAM, &bytes), None);
}

#[test]
fn decode_refuses_values_no_setter_writes() {
    let decodes = |config: &RingProgramConfig| {
        RingProgramConfig::decode(&PROGRAM, &PROGRAM, bytemuck::bytes_of(config)).is_some()
    };
    let mut thresholds = config();
    thresholds.threshold_count = MAX_CO_SIGNER_THRESHOLDS as u8;
    assert!(decodes(&thresholds));
    thresholds.threshold_count += 1;
    assert!(!decodes(&thresholds));
    let mut mode = config();
    mode.mode = 3;
    assert!(!decodes(&mode));
    assert_eq!(mode.mode(), Err(CustomRingError::InvalidRingMode));
    let mut policy = config();
    policy.has_policy = 2;
    assert!(!decodes(&policy));

    let mut registry = MemberRegistry::new(254, 0);
    registry.history_cursor = 32;
    assert_eq!(
        MemberRegistry::decode(&PROGRAM, &PROGRAM, bytemuck::bytes_of(&registry)),
        None
    );
    let mut queue = RecordQueue::new(253);
    queue.head = 1u64.to_le_bytes();
    assert_eq!(
        RecordQueue::decode(&PROGRAM, &PROGRAM, bytemuck::bytes_of(&queue)),
        None
    );
    queue.head = [0; 8];
    queue.tail = (QUEUE_CAPACITY as u64 + 1).to_le_bytes();
    assert_eq!(
        RecordQueue::decode(&PROGRAM, &PROGRAM, bytemuck::bytes_of(&queue)),
        None
    );
}

#[test]
fn a_fresh_registry_binds_the_sentinel_root_at_slot_zero() {
    let registry = MemberRegistry::new(254, 77);
    assert_eq!(registry.own_root(0), Ok(MEMBER_REGISTRY_EMPTY_ROOT));
    assert_eq!(registry.current_root(), MEMBER_REGISTRY_EMPTY_ROOT);
    assert_eq!(registry.next_index(), 1);
    assert_eq!(registry.own_root(1), Err(CustomRingError::RootIndexEmpty));
    assert_eq!(registry.own_root(32), Err(CustomRingError::RootIndexEmpty));
    assert_eq!(registry.policy_hash(), Err(CustomRingError::PolicyNotSet));
}

#[test]
fn an_own_root_one_write_below_the_floor_is_refused() {
    let at_floor = |applied| Floors {
        applied,
        floor: 5,
        prior_floor: 0,
        floor_slot: 0,
    };
    assert_eq!(at_floor(5).registry().own_root(1), Ok([9; 32]));
    assert_eq!(
        at_floor(4).registry().own_root(1),
        Err(CustomRingError::RootBelowFloor)
    );
}

#[test]
fn a_curator_root_below_the_floor_lives_only_through_the_grace_window() {
    let raised_at = 1_000;
    let below = Floors {
        applied: 4,
        floor: 5,
        prior_floor: 3,
        floor_slot: raised_at,
    }
    .registry();
    assert_eq!(
        below.curator_root(1, raised_at + GRACE_SLOTS - 1),
        Ok([9; 32])
    );
    assert_eq!(
        below.curator_root(1, raised_at + GRACE_SLOTS),
        Err(CustomRingError::CuratorRootStale)
    );
    // A second raise inside the window refuses roots below the first raise.
    let raised_twice = Floors {
        applied: 4,
        floor: 6,
        prior_floor: 5,
        floor_slot: raised_at,
    }
    .registry();
    assert_eq!(
        raised_twice.curator_root(1, raised_at),
        Err(CustomRingError::CuratorRootStale)
    );
    let at_the_second_floor = Floors {
        applied: 6,
        floor: 6,
        prior_floor: 5,
        floor_slot: raised_at,
    }
    .registry();
    assert_eq!(at_the_second_floor.curator_root(1, u64::MAX), Ok([9; 32]));
}

#[test]
fn members_hold_at_most_half_a_batch_and_the_authority_the_rest() {
    let registry = MemberRegistry::new(254, 0);
    let full = queue_with(MEMBER_QUEUE_LIMIT, 0);
    assert_eq!(
        queue_with(MEMBER_QUEUE_LIMIT - 1, 0).admit_member_write(&registry),
        Ok(())
    );
    assert_eq!(
        full.admit_member_write(&registry),
        Err(CustomRingError::QueueFull)
    );
    assert_eq!(
        full.admit_authority_writes(QUEUE_CAPACITY as u64 - MEMBER_QUEUE_LIMIT),
        Ok(())
    );
    assert_eq!(
        full.admit_authority_writes(QUEUE_CAPACITY as u64 - MEMBER_QUEUE_LIMIT + 1),
        Err(CustomRingError::AuthorityBatchTooLarge)
    );
}

#[test]
fn every_pending_write_reserves_a_leaf() {
    let mut registry = MemberRegistry::new(254, 0);
    let member_leaves = MEMBER_REGISTRY_CAPACITY - AUTHORITY_RESERVED_LEAVES;
    registry.next_index = ((member_leaves - 2) as u32).to_le_bytes();
    assert_eq!(queue_with(1, 0).admit_member_write(&registry), Ok(()));
    assert_eq!(
        queue_with(2, 0).admit_member_write(&registry),
        Err(CustomRingError::AuthorityLeafReserve)
    );
}

#[test]
fn anyone_applies_a_full_or_aged_member_queue_only() {
    let queued_at = 500;
    assert_eq!(
        RecordQueue::new(253).apply_due(u64::MAX),
        Err(CustomRingError::ApplyNotDue)
    );
    let partial = queue_with(MEMBER_QUEUE_LIMIT - 1, queued_at);
    assert_eq!(
        partial.apply_due(queued_at + APPLY_DELAY_SLOTS - 1),
        Err(CustomRingError::ApplyNotDue)
    );
    assert_eq!(partial.apply_due(queued_at + APPLY_DELAY_SLOTS), Ok(()));
    assert_eq!(
        queue_with(MEMBER_QUEUE_LIMIT, queued_at).apply_due(queued_at),
        Ok(())
    );
}

#[test]
fn only_a_permissionless_application_delays_the_next() {
    let mut registry = MemberRegistry::new(254, 0);
    let mut queue = queue_with(MEMBER_QUEUE_LIMIT, 0);
    let data = ApplyRecordsIxData {
        proof: Zeroable::zeroed(),
        new_root: [1; 32],
        new_next_index: 2u32.to_le_bytes(),
    };
    assert_eq!(queue.apply_due(0), Ok(()));
    let applied_at = 1_000;
    PendingApplication {
        registry: &mut registry,
        queue: &mut queue,
    }
    .settle_permissionless(&data, applied_at);
    for byte in 0..MEMBER_QUEUE_LIMIT as u8 {
        queue.push(&entry(byte + 1), applied_at).unwrap();
    }
    let next = applied_at + APPLY_DELAY_SLOTS;
    assert_eq!(
        queue.apply_due(next - 1),
        Err(CustomRingError::ApplyTooSoon)
    );
    assert_eq!(queue.apply_due(next), Ok(()));
    PendingApplication {
        registry: &mut registry,
        queue: &mut queue,
    }
    .settle_authority(&data, next - 1);
    for byte in 0..MEMBER_QUEUE_LIMIT as u8 {
        queue.push(&entry(byte + 1), next - 1).unwrap();
    }
    assert_eq!(queue.apply_due(next), Ok(()));
}

#[test]
fn an_application_moves_the_head_past_every_pending_write() {
    let mut registry = MemberRegistry::new(254, 0);
    let mut queue = RecordQueue::new(253);
    let mut chain = [0u8; 32];
    // Three rounds of 12 writes wrap the 16 checkpoints of the ring buffer.
    for round in 0..3u8 {
        for byte in 0..12u8 {
            let write = entry(round * 12 + byte + 1);
            chain = queue_chain(&chain, &write).unwrap();
            queue.push(&write, 9).unwrap();
        }
        assert_eq!(queue.chain_tail(), chain);
        let data = ApplyRecordsIxData {
            proof: Zeroable::zeroed(),
            new_root: [round + 1; 32],
            new_next_index: (2 + u32::from(round)).to_le_bytes(),
        };
        let old_root = registry.current_root();
        let application = PendingApplication {
            registry: &mut registry,
            queue: &mut queue,
        };
        let statement = application.statement(&data);
        assert_eq!(statement.count, 12);
        assert_eq!(statement.chain_end, chain);
        assert_eq!(statement.old_root, old_root);
        application.settle_permissionless(&data, 40);
        assert_eq!(queue.head(), 12 * (u64::from(round) + 1));
        assert_eq!((queue.pending(), queue.chain_head), (0, chain));
        assert_eq!(registry.own_root(round + 1), Ok([round + 1; 32]));
        assert_eq!(registry.current_root(), [round + 1; 32]);
    }
}

#[test]
fn a_policy_write_validates_and_repins_the_table() {
    let mut registry = MemberRegistry::new(254, 0);
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    let table = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .build()
        .encode();
    assert_eq!(
        registry.set_policy(sources, table, 3),
        Err(CustomRingError::InvalidSource)
    );
    sources[ListId::Allow.slot()].list_id = ListId::Allow as u8;
    registry.set_policy(sources, table, 3).unwrap();
    let hash = *registry.policy_hash().unwrap();
    assert_eq!(hash, table.hash(&registry.source_map().unwrap()).unwrap());
    assert_eq!((registry.generation(), registry.generation_slot()), (1, 3));
    let mut padded = table;
    padded.rules[1][0] = 1;
    assert_eq!(
        registry.set_policy(sources, padded, 4),
        Err(CustomRingError::InvalidPolicyRules)
    );
    assert_eq!(registry.policy_hash(), Ok(&hash));
}
