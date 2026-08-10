//! Squads ring key-material events.
//!
//! A key rotation overwrites a viewing key account in place and a close zeroes
//! it, while the UTXO ciphertexts those keys decrypt stay on chain. The event
//! log is the only record of the destroyed keys, so a recovery or auditor key
//! holder that was offline across the write depends on this parser.

use super::event_site::{find_event_sites, to_instruction_groups};
use super::state_update::{SquadsKeyEventUpdate, StateUpdate};
use crate::ingester::{error::IngesterError, typedefs::block_info::TransactionInfo};
use log::warn;
use solana_pubkey::Pubkey;
use zolana_event::ParsedInstruction as SquadsInstruction;
use zolana_squads_interface::{
    event::{KeyRotationEvent, SquadsEventKind, ViewingKeyAccountClosedEvent},
    instruction::tag,
    state::viewing_key_account::ViewingKeyAccount,
    SQUADS_RING_PROGRAM_ID,
};

/// A record this build decoded in full.
const SQUADS_PARSE_VERSION: i16 = 1;

/// A record this build cannot decode. Only the transaction coordinates,
/// `event_kind`, and `raw_event` carry meaning, and the key material stays
/// readable by a client that knows the encoding.
const SQUADS_RAW_PARSE_VERSION: i16 = 0;

/// A record that carries no kind byte. No real kind byte can collide with it.
const MISSING_EVENT_KIND: i16 = -1;

pub fn parse_squads_events(
    tx: &TransactionInfo,
    slot: u64,
) -> Result<Option<StateUpdate>, IngesterError> {
    let squads_program_id = squads_ring_program_id();
    let groups = to_instruction_groups(&tx.instruction_groups);
    let event_sites = find_event_sites(&groups, squads_program_id, is_emit_event, is_event_source)?;

    if event_sites.is_empty() {
        return Ok(None);
    }

    let mut state_update = StateUpdate::new();

    for (event_index, event_site) in event_sites.into_iter().enumerate() {
        let event_index = i16::try_from(event_index).map_err(|_| {
            IngesterError::ParserError(format!("Event index {} does not fit in i16", event_index))
        })?;
        // Bytes after the `EMIT_EVENT` tag, `[SquadsEventKind,
        // wincode(payload)]`. The destroyed key material lives here and nowhere
        // else, so a record this build cannot read is stored whole rather than
        // dropped, and a ring that adds a kind or a field does not stop a
        // deployed indexer.
        let raw_event = event_site.data.get(1..).unwrap_or_default().to_vec();
        let (event_kind, decoded) = match raw_event.split_first() {
            Some((kind_byte, payload)) => {
                (i16::from(*kind_byte), decode_event(*kind_byte, payload))
            }
            None => (MISSING_EVENT_KIND, None),
        };
        if decoded.is_none() {
            warn!(
                "Storing Squads event {} index {} of kind {} raw: this build cannot decode it",
                tx.signature, event_index, event_kind
            );
        }

        let mut update = SquadsKeyEventUpdate {
            signature: tx.signature,
            event_index,
            slot,
            squads_program_id: squads_program_id.to_bytes(),
            source_instruction_tag: event_site.source_instruction_tag as i16,
            event_kind,
            account: [0; 32],
            owner: [0; 32],
            key_nonce: 0,
            new_key_nonce: None,
            old_state_hash: None,
            raw_event,
            parse_version: SQUADS_RAW_PARSE_VERSION,
        };
        if let Some(event) = decoded {
            // Accepted events are Squads EMIT_EVENT inner instructions under a
            // Squads source instruction, so the body is the program-authored
            // account state and is not re-derived from accounts.
            update.account = event.account;
            update.owner = event.state.owner.to_bytes();
            update.key_nonce = event.state.key_nonce;
            update.new_key_nonce = event.new_key_nonce;
            update.old_state_hash = event.old_state_hash;
            update.parse_version = SQUADS_PARSE_VERSION;
        }
        state_update.squads_key_events.push(update);
    }

    Ok(Some(state_update))
}

/// The viewing key account as it stood before the emitting instruction wrote
/// over it, plus the fields only a rotation carries.
struct DecodedEvent {
    account: [u8; 32],
    state: ViewingKeyAccount,
    new_key_nonce: Option<u64>,
    old_state_hash: Option<[u8; 32]>,
}

/// `None` when the kind byte names no event this build knows, or when the
/// payload carries an encoding it cannot read.
fn decode_event(kind_byte: u8, payload: &[u8]) -> Option<DecodedEvent> {
    match SquadsEventKind::from_byte(kind_byte)? {
        SquadsEventKind::KeyRotation => {
            let event = KeyRotationEvent::deserialize(payload).ok()?;
            Some(DecodedEvent {
                account: event.account.to_bytes(),
                state: event.old_state,
                new_key_nonce: Some(event.new_key_nonce),
                old_state_hash: Some(event.old_state_hash),
            })
        }
        SquadsEventKind::ViewingKeyAccountClosed => {
            let event = ViewingKeyAccountClosedEvent::deserialize(payload).ok()?;
            Some(DecodedEvent {
                account: event.account.to_bytes(),
                state: event.state,
                new_key_nonce: None,
                old_state_hash: None,
            })
        }
    }
}

fn squads_ring_program_id() -> Pubkey {
    Pubkey::new_from_array(SQUADS_RING_PROGRAM_ID)
}

fn is_event_source(squads_program_id: Pubkey, instruction: &SquadsInstruction) -> bool {
    // Keep in sync with the squads-ring processors that call an emit helper in
    // `shared/event.rs`. A tag missing here silently drops those transactions
    // from the index, and the key material they carry is unrecoverable.
    // `every_instruction_tag_is_classified` fails until a new tag is classified.
    instruction.program_id == squads_program_id
        && matches!(
            instruction.data.first().copied(),
            Some(tag::EXECUTE_KEY_UPDATE | tag::CLOSE_VIEWING_KEY_ACCOUNT)
        )
}

fn is_emit_event(squads_program_id: Pubkey, instruction: &SquadsInstruction) -> bool {
    instruction.program_id == squads_program_id
        && instruction.data.first() == Some(&tag::EMIT_EVENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::parser::rings_event_parser::parse_rings_events;
    use crate::ingester::typedefs::block_info::{Instruction, InstructionGroup, TransactionInfo};
    use solana_signature::Signature;
    use zolana_squads_interface::{
        event::{encode_event_instruction, split_event_instruction},
        instruction::tag::InstructionTag,
        state::discriminator as squads_discriminator,
    };

    fn squads() -> Pubkey {
        squads_ring_program_id()
    }

    /// Stand-in for any foreign program (attacker contract, another ring).
    fn foreign() -> Pubkey {
        Pubkey::new_from_array([9; 32])
    }

    fn ix(program_id: Pubkey, data: Vec<u8>, stack_height: u32) -> Instruction {
        Instruction {
            program_id,
            data,
            accounts: Vec::new(),
            stack_height: Some(stack_height),
        }
    }

    fn tx(groups: Vec<InstructionGroup>) -> TransactionInfo {
        TransactionInfo {
            instruction_groups: groups,
            signature: Signature::from([7; 64]),
            error: None,
        }
    }

    fn viewing_key_account() -> ViewingKeyAccount {
        ViewingKeyAccount {
            discriminator: squads_discriminator::VIEWING_KEY_ACCOUNT,
            owner: zolana_squads_interface::types::Address::new_from_array([1; 32]),
            state: 1,
            encryption_scheme: 0,
            owner_kind: 1,
            shared_viewing_key: [2; 33],
            shared_viewing_key_commitment: [3; 32],
            key_nonce: 4,
            nullifier_pubkey: [5; 32],
            key_ciphertext_ephemeral: [6; 33],
            encrypted_nullifier_secret: [7; 31],
            recovery_keys: vec![[8; 33]],
            recovery_key_ciphertexts: vec![[9; 32]],
            auditor_keys: vec![[10; 33]],
            auditor_key_ciphertexts: vec![[11; 32]],
        }
    }

    fn key_rotation_event() -> KeyRotationEvent {
        KeyRotationEvent {
            account: zolana_squads_interface::types::Address::new_from_array([12; 32]),
            old_state_hash: [13; 32],
            new_key_nonce: 5,
            old_state: viewing_key_account(),
        }
    }

    fn key_rotation_instruction() -> Vec<u8> {
        encode_event_instruction(SquadsEventKind::KeyRotation, &key_rotation_event()).unwrap()
    }

    fn rotation_transaction() -> TransactionInfo {
        tx(vec![InstructionGroup {
            outer_instruction: ix(squads(), vec![tag::EXECUTE_KEY_UPDATE], 1),
            inner_instructions: vec![ix(squads(), key_rotation_instruction(), 2)],
        }])
    }

    #[test]
    fn accepts_key_rotation_under_a_squads_parent() {
        let state_update = parse_squads_events(&rotation_transaction(), 42)
            .unwrap()
            .unwrap();

        assert_eq!(state_update.squads_key_events.len(), 1);
        let event = &state_update.squads_key_events[0];
        assert_eq!(event.slot, 42);
        assert_eq!(event.source_instruction_tag, tag::EXECUTE_KEY_UPDATE as i16);
        assert_eq!(event.event_kind, SquadsEventKind::KeyRotation as i16);
        assert_eq!(event.account, [12; 32]);
        assert_eq!(event.old_state_hash, Some([13; 32]));
    }

    #[test]
    fn accepts_close_under_a_squads_parent() {
        let closed = ViewingKeyAccountClosedEvent {
            account: zolana_squads_interface::types::Address::new_from_array([12; 32]),
            state: viewing_key_account(),
        };
        let data =
            encode_event_instruction(SquadsEventKind::ViewingKeyAccountClosed, &closed).unwrap();
        let transaction = tx(vec![InstructionGroup {
            outer_instruction: ix(squads(), vec![tag::CLOSE_VIEWING_KEY_ACCOUNT], 1),
            inner_instructions: vec![ix(squads(), data, 2)],
        }]);

        let state_update = parse_squads_events(&transaction, 1).unwrap().unwrap();

        assert_eq!(state_update.squads_key_events.len(), 1);
        let event = &state_update.squads_key_events[0];
        assert_eq!(
            event.event_kind,
            SquadsEventKind::ViewingKeyAccountClosed as i16
        );
        // A close carries no rotation commitment and no successor nonce.
        assert_eq!(event.old_state_hash, None);
        assert_eq!(event.new_key_nonce, None);
    }

    /// The stored payload must be the pre-rotation account, not the state the
    /// rotation wrote, and `key_nonce` must be the pre-rotation nonce.
    #[test]
    fn key_rotation_payload_decodes_to_the_pre_rotation_account_state() {
        let state_update = parse_squads_events(&rotation_transaction(), 1)
            .unwrap()
            .unwrap();
        let event = &state_update.squads_key_events[0];

        let instruction = key_rotation_instruction();
        let (kind, payload) = split_event_instruction(&instruction).unwrap();
        assert_eq!(kind as i16, event.event_kind);
        assert_eq!(&event.raw_event[1..], payload);

        let decoded = KeyRotationEvent::deserialize(&event.raw_event[1..]).unwrap();
        assert_eq!(decoded.old_state, viewing_key_account());
        assert_eq!(event.key_nonce, viewing_key_account().key_nonce);
        assert_eq!(event.new_key_nonce, Some(5));
        assert_ne!(event.key_nonce, decoded.new_key_nonce);
        assert_eq!(event.owner, viewing_key_account().owner.to_bytes());
    }

    /// A ring upgrade that adds a kind reaches a Photon built before it. The
    /// record is the only copy of the destroyed key material, so it is stored
    /// whole, and the events beside it keep their decoded columns.
    #[test]
    fn stores_an_unknown_kind_and_keeps_ingesting() {
        let unknown_kind = 3;
        let unknown = vec![tag::EMIT_EVENT, unknown_kind, 1, 2, 3];
        let transaction = tx(vec![InstructionGroup {
            outer_instruction: ix(squads(), vec![tag::EXECUTE_KEY_UPDATE], 1),
            inner_instructions: vec![
                ix(squads(), unknown.clone(), 2),
                ix(squads(), key_rotation_instruction(), 2),
            ],
        }]);

        let state_update = parse_squads_events(&transaction, 1).unwrap().unwrap();

        assert_eq!(state_update.squads_key_events.len(), 2);
        let stored_raw = &state_update.squads_key_events[0];
        assert_eq!(stored_raw.event_kind, i16::from(unknown_kind));
        assert_eq!(stored_raw.raw_event, unknown[1..]);
        assert_eq!(stored_raw.parse_version, SQUADS_RAW_PARSE_VERSION);
        assert_eq!(stored_raw.account, [0; 32]);
        assert_eq!(state_update.squads_key_events[1].account, [12; 32]);
        assert_eq!(
            state_update.squads_key_events[1].parse_version,
            SQUADS_PARSE_VERSION
        );
    }

    /// A field appended to a known payload is the same hazard as a new kind.
    #[test]
    fn stores_a_payload_this_build_cannot_read() {
        let mut data = key_rotation_instruction();
        data.push(0);
        let transaction = tx(vec![InstructionGroup {
            outer_instruction: ix(squads(), vec![tag::EXECUTE_KEY_UPDATE], 1),
            inner_instructions: vec![ix(squads(), data.clone(), 2)],
        }]);

        let state_update = parse_squads_events(&transaction, 1).unwrap().unwrap();

        let event = &state_update.squads_key_events[0];
        assert_eq!(event.event_kind, SquadsEventKind::KeyRotation as i16);
        assert_eq!(event.raw_event, data[1..]);
        assert_eq!(event.parse_version, SQUADS_RAW_PARSE_VERSION);
    }

    /// A record with no kind byte carries no key material, and halting on it
    /// would stop the indexer just as an unknown kind would.
    #[test]
    fn stores_a_record_with_no_kind_byte() {
        let transaction = tx(vec![InstructionGroup {
            outer_instruction: ix(squads(), vec![tag::EXECUTE_KEY_UPDATE], 1),
            inner_instructions: vec![ix(squads(), vec![tag::EMIT_EVENT], 2)],
        }]);

        let state_update = parse_squads_events(&transaction, 1).unwrap().unwrap();

        let event = &state_update.squads_key_events[0];
        assert_eq!(event.event_kind, MISSING_EVENT_KIND);
        assert!(event.raw_event.is_empty());
        assert_eq!(event.parse_version, SQUADS_RAW_PARSE_VERSION);
    }

    #[test]
    fn drops_event_forged_by_direct_foreign_cpi() {
        let transaction = tx(vec![InstructionGroup {
            outer_instruction: ix(foreign(), vec![0], 1),
            inner_instructions: vec![ix(squads(), key_rotation_instruction(), 2)],
        }]);

        assert!(parse_squads_events(&transaction, 1).unwrap().is_none());
    }

    #[test]
    fn drops_event_parented_to_a_silent_squads_instruction() {
        let transaction = tx(vec![InstructionGroup {
            outer_instruction: ix(squads(), vec![tag::CREATE_VIEWING_KEY_ACCOUNT], 1),
            inner_instructions: vec![ix(squads(), key_rotation_instruction(), 2)],
        }]);

        assert!(parse_squads_events(&transaction, 1).unwrap().is_none());
    }

    /// The two logs share the `EMIT_EVENT` shape and differ only by program id.
    /// Reading one as the other would decode foreign bytes into key material.
    #[test]
    fn a_rings_event_is_not_read_as_a_squads_one() {
        let rings_program_id = zolana_interface::pda::shielded_pool_program_id();
        let transaction = tx(vec![InstructionGroup {
            outer_instruction: ix(rings_program_id, vec![zolana_event::tag::TRANSACT], 1),
            inner_instructions: vec![ix(
                rings_program_id,
                vec![zolana_event::tag::EMIT_EVENT, 2],
                2,
            )],
        }]);

        assert!(parse_squads_events(&transaction, 1).unwrap().is_none());
    }

    #[test]
    fn a_squads_event_is_not_read_as_a_rings_one() {
        let transaction = rotation_transaction();

        assert!(parse_squads_events(&transaction, 1).unwrap().is_some());
        assert!(parse_rings_events(&transaction, 1).unwrap().is_none());
    }

    /// Every implemented instruction tag is either an event source or listed
    /// here as silent. A new tag matches neither and fails, which is the only
    /// thing standing between an emitting instruction and being dropped from
    /// the index.
    #[test]
    fn every_instruction_tag_is_classified() {
        // Settlement, configuration, the proposal flow, and the event carrier
        // itself call no emit helper in `shared/event.rs`.
        const SILENT: [u8; 17] = [
            tag::TRANSACT,
            tag::DEPOSIT,
            tag::MERGE_TRANSACT,
            tag::CREATE_RING_CONFIG,
            tag::UPDATE_RING_CONFIG,
            tag::CREATE_VIEWING_KEY_ACCOUNT,
            tag::UPDATE_VIEWING_KEY_ACCOUNT,
            tag::FILL_KEY_UPDATE,
            tag::TOGGLE_VIEWING_KEY_ACCOUNT,
            tag::FULL_WITHDRAWAL,
            tag::CREATE_PROPOSAL,
            tag::CANCEL_PROPOSAL,
            tag::EXECUTE_PROPOSAL,
            tag::CANCEL_KEY_UPDATE,
            tag::INIT_SPP_RING_CONFIG,
            tag::FOLD_TRANSACT,
            tag::EMIT_EVENT,
        ];

        for byte in 0..=u8::MAX {
            if InstructionTag::try_from(byte).is_err() {
                continue;
            }
            let source = is_event_source(
                squads(),
                &SquadsInstruction::new(squads(), Vec::new(), vec![byte], Some(1)),
            );
            assert_ne!(
                source,
                SILENT.contains(&byte),
                "tag {byte} is neither an event source nor listed as silent"
            );
        }
    }
}
