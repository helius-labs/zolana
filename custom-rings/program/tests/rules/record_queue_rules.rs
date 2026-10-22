//! Every record write refusal that precedes the apply or envelope proof.

use bytemuck::Zeroable;
use custom_ring_interface::{
    queue_chain, tag, ApplyRecordsIxData, CustomRingError, MemberRegistry, MemberWriteIxData,
    RecordQueue, RecordWriteData, RegisterKeyIxData, SetInsertFeeIxData, WriteRecordsIxData,
    APPLY_DELAY_SLOTS, AUTHORITY_RESERVED_LEAVES, DEFAULT_INSERT_FEE, FIELD_MAX,
    MEMBER_QUEUE_LIMIT, MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_EMPTY_ROOT,
};
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use zolana_account_checks::AccountError;
use zolana_hasher::primitives::{right_align, solana_owner_identity};
use zolana_ring_policy::{ListChange, ListId, ListSet, Writer};

use crate::common::{
    apply_records, authority_write_records, config_write, create_member_registry, key_registration,
    member_write, off_curve_g1, queue_pda, reaches_verification, refused, refused_with,
    register_key, registry_pda, write_records, Fee, Ring, Sent, Setup,
};

fn lists(mask: u64, value: u64) -> WriteRecordsIxData {
    WriteRecordsIxData {
        mask: mask.to_le_bytes(),
        value: value.to_le_bytes(),
    }
}

fn recovery() -> WriteRecordsIxData {
    WriteRecordsIxData::new(
        ListChange {
            set: ListSet::single(ListId::Recovery),
            clear: ListSet::EMPTY,
        }
        .check()
        .unwrap(),
    )
}

fn allow(member: [u8; 32]) -> RecordWriteData {
    RecordWriteData {
        member,
        lists: lists(ListId::Allow.record_bit(), ListId::Allow.record_bit()),
    }
}

fn member(byte: u8) -> [u8; 32] {
    right_align(&[byte])
}

fn apply_data() -> ApplyRecordsIxData {
    ApplyRecordsIxData {
        proof: Zeroable::zeroed(),
        new_root: [3; 32],
        new_next_index: 2u32.to_le_bytes(),
    }
}

fn queue_member_writes(ring: &mut Ring, count: u64) {
    for _ in 0..count {
        let member = Keypair::new();
        let fee = ring.fee();
        ring.send(
            write_records(&member.pubkey(), recovery(), Some(fee)),
            &[&member],
        )
        .expect("a paid member write");
    }
}

/// `next_index` set as if the registry held `leaves` leaves.
fn fill_registry(ring: &mut Ring, leaves: u64) {
    let mut registry: MemberRegistry = ring.read(&registry_pda());
    registry.next_index = u32::try_from(leaves).unwrap().to_le_bytes();
    ring.write(&registry_pda(), &registry);
}

fn insert_fee_write(ring: &mut Ring, fee: u64) -> Sent {
    let authority = ring.authority.insecure_clone();
    ring.send(
        config_write(
            tag::SET_INSERT_FEE,
            &authority.pubkey(),
            &[],
            bytemuck::bytes_of(&SetInsertFeeIxData {
                fee: fee.to_le_bytes(),
            }),
        ),
        &[&authority],
    )
}

fn set_insert_fee(ring: &mut Ring, fee: u64) {
    insert_fee_write(ring, fee).expect("set the insert fee");
}

#[test]
fn create_member_registry_starts_from_the_sentinel_once() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let registry: MemberRegistry = ring.read(&registry_pda());
    assert_eq!(registry.own_root(0), Ok(MEMBER_REGISTRY_EMPTY_ROOT));
    assert_eq!(registry.next_index(), 1);
    assert_eq!(ring.read::<RecordQueue>(&queue_pda()).pending(), 0);
    let (payer, authority) = (ring.payer.pubkey(), ring.authority.insecure_clone());
    refused(
        ring.send(
            create_member_registry(&payer, &authority.pubkey()),
            &[&authority],
        ),
        CustomRingError::MemberRegistryAlreadyExists,
    );
}

#[test]
fn a_new_ring_charges_member_writes_the_default_fee() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let authority = ring.authority.pubkey();
    ring.drain(&authority);
    let member = Keypair::new();
    let fee = ring.fee();
    ring.send(
        write_records(&member.pubkey(), recovery(), Some(fee)),
        &[&member],
    )
    .expect("the default fee opens an empty authority account");
    assert_eq!(ring.lamports(&authority), DEFAULT_INSERT_FEE);
}

#[test]
fn a_free_member_write_queues_its_chained_entry() {
    let mut ring = Ring::new(Setup::AuditOnly);
    set_insert_fee(&mut ring, 0);
    let member = Keypair::new();
    ring.send(
        write_records(&member.pubkey(), recovery(), None),
        &[&member],
    )
    .expect("a free member write takes no fee accounts");
    let identity = solana_owner_identity(member.pubkey().as_array()).unwrap();
    let entry = recovery().entry(identity, Writer::Member).unwrap();
    let queue: RecordQueue = ring.read(&queue_pda());
    assert_eq!(queue.pending(), 1);
    assert_eq!(queue.chain_tail(), queue_chain(&[0; 32], &entry).unwrap());
}

#[test]
fn a_member_writes_only_its_own_lists() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let member = Keypair::new();
    let allow = ListId::Allow.record_bit();
    let escrow = ListId::Escrow.record_bit();
    for mask in [allow, escrow, 1 << 8] {
        refused(
            ring.send(
                write_records(&member.pubkey(), lists(mask, 0), None),
                &[&member],
            ),
            CustomRingError::ListBitNotWritable,
        );
    }
}

#[test]
fn a_member_write_stays_inside_a_nonzero_mask() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let member = Keypair::new();
    let recovery = ListId::Recovery.record_bit();
    let viewing = ListId::RingViewing.record_bit();
    for (mask, value) in [(recovery, recovery | viewing), (0, 0)] {
        refused(
            ring.send(
                write_records(&member.pubkey(), lists(mask, value), None),
                &[&member],
            ),
            CustomRingError::ValueOutsideMask,
        );
    }
}

#[test]
fn the_ninth_pending_member_write_is_refused() {
    let mut ring = Ring::new(Setup::AuditOnly);
    queue_member_writes(&mut ring, MEMBER_QUEUE_LIMIT);
    let member = Keypair::new();
    refused(
        ring.send(
            write_records(&member.pubkey(), recovery(), None),
            &[&member],
        ),
        CustomRingError::QueueFull,
    );
}

#[test]
fn member_writes_stop_at_the_authority_reserve() {
    let mut ring = Ring::new(Setup::AuditOnly);
    fill_registry(
        &mut ring,
        MEMBER_REGISTRY_CAPACITY - AUTHORITY_RESERVED_LEAVES - 1,
    );
    queue_member_writes(&mut ring, 1);
    let writer = Keypair::new();
    let fee = ring.fee();
    refused(
        ring.send(
            write_records(&writer.pubkey(), recovery(), Some(fee)),
            &[&writer],
        ),
        CustomRingError::AuthorityLeafReserve,
    );
    refused(
        ring.send(
            register_key(&writer.pubkey(), &key_registration(), Some(fee)),
            &[&writer],
        ),
        CustomRingError::AuthorityLeafReserve,
    );
    let authority = ring.authority.insecure_clone();
    reaches_verification(ring.send(
        authority_write_records(&authority.pubkey(), &[allow(member(5))], &apply_data()),
        &[&authority],
    ));
}

#[test]
fn a_full_registry_still_takes_an_authority_block_write() {
    let mut ring = Ring::new(Setup::AuditOnly);
    fill_registry(&mut ring, MEMBER_REGISTRY_CAPACITY);
    let authority = ring.authority.insecure_clone();
    let block = RecordWriteData {
        member: member(5),
        lists: lists(ListId::Block.record_bit(), ListId::Block.record_bit()),
    };
    reaches_verification(ring.send(
        authority_write_records(&authority.pubkey(), &[block], &apply_data()),
        &[&authority],
    ));
}

#[test]
fn the_insert_fee_goes_to_the_config_authority_only() {
    let fee = 2 * DEFAULT_INSERT_FEE;
    let mut ring = Ring::new(Setup::AuditOnly);
    set_insert_fee(&mut ring, fee);
    let member = Keypair::new();
    let payer = Keypair::new();
    ring.fund(&payer.pubkey());
    let authority = ring.authority.pubkey();
    let elsewhere = Keypair::new().pubkey();
    refused(
        ring.send(
            write_records(
                &member.pubkey(),
                recovery(),
                Some(Fee {
                    payer: payer.pubkey(),
                    recipient: elsewhere,
                }),
            ),
            &[&member, &payer],
        ),
        CustomRingError::FeeRecipient,
    );
    refused(
        ring.send(
            register_key(
                &member.pubkey(),
                &key_registration(),
                Some(Fee {
                    payer: payer.pubkey(),
                    recipient: elsewhere,
                }),
            ),
            &[&member, &payer],
        ),
        CustomRingError::FeeRecipient,
    );
    let before = ring.lamports(&authority);
    ring.send(
        write_records(
            &member.pubkey(),
            recovery(),
            Some(Fee {
                payer: payer.pubkey(),
                recipient: authority,
            }),
        ),
        &[&member, &payer],
    )
    .expect("a paid member write");
    assert_eq!(ring.lamports(&authority), before + fee);
}

#[test]
fn the_config_authority_writes_its_own_record_free() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let authority = ring.authority.insecure_clone();
    ring.send(
        write_records(&authority.pubkey(), recovery(), None),
        &[&authority],
    )
    .expect("the authority owes no insert fee");
    let member = Keypair::new();
    let missing_fee_payer = InstructionError::Custom(u32::from(AccountError::NotEnoughAccountKeys));
    refused_with(
        ring.send(
            write_records(&member.pubkey(), recovery(), None),
            &[&member],
        ),
        missing_fee_payer,
    );
}

#[test]
fn a_nonzero_insert_fee_funds_an_empty_authority() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let rent = ring.rent_exempt_minimum(0);
    refused(
        insert_fee_write(&mut ring, rent - 1),
        CustomRingError::InsertFeeBelowRent,
    );
    insert_fee_write(&mut ring, rent).expect("a fee at the rent minimum");
    insert_fee_write(&mut ring, 0).expect("a free ring");
}

#[test]
fn a_fee_raised_past_the_writers_maximum_refuses_the_write() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let member = Keypair::new();
    let fee = ring.fee();
    let write = MemberWriteIxData {
        lists: recovery(),
        max_fee: DEFAULT_INSERT_FEE.to_le_bytes(),
    };
    let registration = RegisterKeyIxData {
        max_fee: DEFAULT_INSERT_FEE.to_le_bytes(),
        ..key_registration()
    };
    set_insert_fee(&mut ring, DEFAULT_INSERT_FEE + 1);
    refused(
        ring.send(
            member_write(&member.pubkey(), &write, Some(fee)),
            &[&member],
        ),
        CustomRingError::InsertFeeAboveMax,
    );
    refused(
        ring.send(
            register_key(&member.pubkey(), &registration, Some(fee)),
            &[&member],
        ),
        CustomRingError::InsertFeeAboveMax,
    );
    let authority = ring.authority.insecure_clone();
    let free = MemberWriteIxData {
        max_fee: [0; 8],
        ..write
    };
    ring.send(
        member_write(&authority.pubkey(), &free, None),
        &[&authority],
    )
    .expect("the authority owes no fee whatever its maximum");

    set_insert_fee(&mut ring, DEFAULT_INSERT_FEE);
    ring.send(
        member_write(&member.pubkey(), &write, Some(fee)),
        &[&member],
    )
    .expect("a fee at the maximum");
    reaches_verification(ring.send(
        register_key(&member.pubkey(), &registration, Some(fee)),
        &[&member],
    ));
}

#[test]
fn only_the_config_authority_sets_the_insert_fee() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let stranger = Keypair::new();
    refused(
        ring.send(
            config_write(
                tag::SET_INSERT_FEE,
                &stranger.pubkey(),
                &[],
                &7u64.to_le_bytes(),
            ),
            &[&stranger],
        ),
        CustomRingError::UnauthorizedAuthority,
    );
}

#[test]
fn the_authority_writes_only_authority_lists_of_members_in_range() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let authority = ring.authority.insecure_clone();
    let mut write = |writes: &[RecordWriteData]| {
        ring.send(
            authority_write_records(&authority.pubkey(), writes, &apply_data()),
            &[&authority],
        )
    };
    let viewing = ListId::RingViewing.record_bit();
    refused(
        write(&[RecordWriteData {
            member: member(5),
            lists: lists(viewing, viewing),
        }]),
        CustomRingError::ListBitNotWritable,
    );
    for outside in [[0; 32], FIELD_MAX] {
        refused(write(&[allow(outside)]), CustomRingError::MemberOutOfRange);
    }
    let stranger = Keypair::new();
    refused(
        ring.send(
            authority_write_records(&stranger.pubkey(), &[allow(member(5))], &apply_data()),
            &[&stranger],
        ),
        CustomRingError::UnauthorizedAuthority,
    );
}

#[test]
fn an_authority_batch_fits_beside_the_pending_member_writes() {
    let mut ring = Ring::new(Setup::AuditOnly);
    queue_member_writes(&mut ring, MEMBER_QUEUE_LIMIT);
    let authority = ring.authority.insecure_clone();
    let writes: Vec<RecordWriteData> = (1..=9).map(member).map(allow).collect();
    reaches_verification(ring.send(
        authority_write_records(&authority.pubkey(), &writes[..8], &apply_data()),
        &[&authority],
    ));
    refused(
        ring.send(
            authority_write_records(&authority.pubkey(), &writes, &apply_data()),
            &[&authority],
        ),
        CustomRingError::AuthorityBatchTooLarge,
    );
}

#[test]
fn an_authority_write_past_one_batch_is_refused_as_data() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let authority = ring.authority.insecure_clone();
    let mut instruction =
        authority_write_records(&authority.pubkey(), &[allow(member(1))], &apply_data());
    let writes: Vec<RecordWriteData> = (1..=17).map(member).map(allow).collect();
    instruction.data = [
        &[tag::AUTHORITY_WRITE_RECORDS, 17][..],
        bytemuck::cast_slice(&writes),
        bytemuck::bytes_of(&apply_data()),
    ]
    .concat();
    refused(
        ring.send(instruction, &[&authority]),
        CustomRingError::AuthorityBatchTooLarge,
    );
}

#[test]
fn a_permissionless_application_waits_for_a_full_or_aged_queue() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let queued_at = 1_000;
    ring.warp(queued_at);
    refused(
        ring.send(apply_records(&apply_data()), &[]),
        CustomRingError::ApplyNotDue,
    );
    queue_member_writes(&mut ring, MEMBER_QUEUE_LIMIT - 1);
    ring.warp(queued_at + APPLY_DELAY_SLOTS - 1);
    refused(
        ring.send(apply_records(&apply_data()), &[]),
        CustomRingError::ApplyNotDue,
    );
    ring.warp(queued_at + APPLY_DELAY_SLOTS);
    reaches_verification(ring.send(apply_records(&apply_data()), &[]));

    let mut full = Ring::new(Setup::AuditOnly);
    full.warp(queued_at);
    queue_member_writes(&mut full, MEMBER_QUEUE_LIMIT);
    reaches_verification(full.send(apply_records(&apply_data()), &[]));
}

#[test]
fn a_permissionless_application_waits_one_delay_after_the_last() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let applied_at = 1_000;
    ring.warp(applied_at);
    queue_member_writes(&mut ring, MEMBER_QUEUE_LIMIT);
    let mut queue: RecordQueue = ring.read(&queue_pda());
    queue.next_apply_slot = (applied_at + APPLY_DELAY_SLOTS).to_le_bytes();
    ring.write(&queue_pda(), &queue);
    ring.warp(applied_at + APPLY_DELAY_SLOTS - 1);
    refused(
        ring.send(apply_records(&apply_data()), &[]),
        CustomRingError::ApplyTooSoon,
    );
    let authority = ring.authority.insecure_clone();
    reaches_verification(ring.send(
        authority_write_records(&authority.pubkey(), &[allow(member(5))], &apply_data()),
        &[&authority],
    ));
    ring.warp(applied_at + APPLY_DELAY_SLOTS);
    reaches_verification(ring.send(apply_records(&apply_data()), &[]));
}

#[test]
fn an_anonymous_ring_registers_no_key() {
    let mut ring = Ring::new(Setup::Anonymous);
    let member = Keypair::new();
    refused(
        ring.send(
            register_key(&member.pubkey(), &key_registration(), None),
            &[&member],
        ),
        CustomRingError::AnonymousRingRefused,
    );
}

#[test]
fn a_key_registration_obeys_the_member_queue_limit() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let member = Keypair::new();
    let fee = ring.fee();
    reaches_verification(ring.send(
        register_key(&member.pubkey(), &key_registration(), Some(fee)),
        &[&member],
    ));
    queue_member_writes(&mut ring, MEMBER_QUEUE_LIMIT);
    refused(
        ring.send(
            register_key(&member.pubkey(), &key_registration(), Some(fee)),
            &[&member],
        ),
        CustomRingError::QueueFull,
    );
}

#[test]
fn record_accounts_must_be_the_rings_own() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let member = Keypair::new();
    let mut instruction = write_records(&member.pubkey(), recovery(), None);
    instruction.accounts[3] = AccountMeta::new(registry_pda(), false);
    refused(
        ring.send(instruction, &[&member]),
        CustomRingError::InvalidRecordQueue,
    );
}

#[test]
fn a_record_write_needs_its_writer_signature() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let unsigned = |mut instruction: Instruction| {
        instruction.accounts[0].is_signer = false;
        instruction
    };
    let writer = Keypair::new().pubkey();
    let authority = ring.authority.pubkey();
    for instruction in [
        write_records(&writer, recovery(), None),
        authority_write_records(&authority, &[allow(member(5))], &apply_data()),
    ] {
        refused_with(
            ring.send(unsigned(instruction), &[]),
            InstructionError::Custom(u32::from(AccountError::InvalidSigner)),
        );
    }
}

#[test]
fn an_undecodable_ring_proof_point_has_its_own_code() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let member = Keypair::new();
    let fee = ring.fee();
    let mut registration = key_registration();
    registration.proof.groth16.proof_c = off_curve_g1();
    refused(
        ring.send(
            register_key(&member.pubkey(), &registration, Some(fee)),
            &[&member],
        ),
        CustomRingError::InvalidRingProofPoint,
    );
    refused(
        ring.send(
            register_key(&member.pubkey(), &key_registration(), Some(fee)),
            &[&member],
        ),
        CustomRingError::ProofVerificationFailed,
    );
}
