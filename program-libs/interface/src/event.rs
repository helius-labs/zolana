use borsh::{BorshDeserialize, BorshSerialize};
use solana_pubkey::Pubkey;

use crate::instruction::tag;

pub mod kind {
    pub const PROOFLESS_SHIELD: u8 = 1;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    ProoflessShield = kind::PROOFLESS_SHIELD,
}

impl TryFrom<u8> for EventKind {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            kind::PROOFLESS_SHIELD => Ok(Self::ProoflessShield),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShieldedPoolEvent {
    ProoflessShield(ProoflessShieldEvent),
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct ProoflessShieldEvent {
    pub view_tag: [u8; 32],
    pub utxo_hash: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
    pub zone_program_id: Option<[u8; 32]>,
    pub policy_data_hash: Option<[u8; 32]>,
    pub owner_utxo_hash: [u8; 32],
    pub salt: [u8; 16],
    pub program_data_hash: Option<[u8; 32]>,
    pub program_data: Option<Vec<u8>>,
    pub zone_data: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedInstruction {
    pub program_id: Pubkey,
    pub accounts: Vec<Pubkey>,
    pub data: Vec<u8>,
    pub stack_height: Option<u32>,
}

impl ParsedInstruction {
    pub fn new(
        program_id: Pubkey,
        accounts: Vec<Pubkey>,
        data: Vec<u8>,
        stack_height: Option<u32>,
    ) -> Self {
        Self {
            program_id,
            accounts,
            data,
            stack_height,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstructionGroup {
    pub outer: ParsedInstruction,
    pub inner: Vec<ParsedInstruction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedEvent {
    pub tag: u8,
    pub payload: Vec<u8>,
    pub decoded: Result<ShieldedPoolEvent, EventDecodeError>,
}

impl ShieldedPoolEvent {
    pub fn kind(&self) -> EventKind {
        match self {
            Self::ProoflessShield(_) => EventKind::ProoflessShield,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventDecodeError {
    MissingInstructionTag,
    InvalidInstructionTag(u8),
    MissingEventKind,
    UnknownEventKind(u8),
    InvalidPayload,
}

pub fn encode_event_instruction(event: &ShieldedPoolEvent) -> Vec<u8> {
    let mut data = vec![tag::EMIT_EVENT];
    encode_event_payload_into(event, &mut data);
    data
}

pub fn encode_event_payload(event: &ShieldedPoolEvent) -> Vec<u8> {
    let mut data = Vec::new();
    encode_event_payload_into(event, &mut data);
    data
}

pub fn decode_event_instruction(data: &[u8]) -> Result<ShieldedPoolEvent, EventDecodeError> {
    let (&instruction_tag, payload) = data
        .split_first()
        .ok_or(EventDecodeError::MissingInstructionTag)?;
    if instruction_tag != tag::EMIT_EVENT {
        return Err(EventDecodeError::InvalidInstructionTag(instruction_tag));
    }
    decode_event_payload(payload)
}

pub fn decode_event_payload(payload: &[u8]) -> Result<ShieldedPoolEvent, EventDecodeError> {
    let (&kind, payload) = payload
        .split_first()
        .ok_or(EventDecodeError::MissingEventKind)?;
    match EventKind::try_from(kind).map_err(|_| EventDecodeError::UnknownEventKind(kind))? {
        EventKind::ProoflessShield => ProoflessShieldEvent::try_from_slice(payload)
            .map(ShieldedPoolEvent::ProoflessShield)
            .map_err(|_| EventDecodeError::InvalidPayload),
    }
}

fn encode_event_payload_into(event: &ShieldedPoolEvent, data: &mut Vec<u8>) {
    data.push(event.kind() as u8);
    match event {
        ShieldedPoolEvent::ProoflessShield(event) => event
            .serialize(data)
            .expect("shielded-pool event serialization is infallible"),
    }
}

pub fn indexed_events_from_instruction_groups<'a>(
    shielded_pool_program_id: Pubkey,
    groups: impl IntoIterator<Item = &'a InstructionGroup>,
) -> Vec<IndexedEvent> {
    let mut events = Vec::new();
    for group in groups {
        for (index, instruction) in group.inner.iter().enumerate() {
            if is_emit_event(shielded_pool_program_id, instruction)
                && parent_is_event_source(shielded_pool_program_id, group, index)
            {
                events.push(indexed_event(&instruction.data));
            }
        }
    }
    events
}

pub fn instruction_may_emit_events(
    shielded_pool_program_id: Pubkey,
    instruction: &ParsedInstruction,
) -> bool {
    is_event_source(shielded_pool_program_id, instruction)
        || (instruction.data.first() == Some(&tag::ZONE_PROOFLESS_SHIELD)
            && instruction.accounts.contains(&shielded_pool_program_id))
}

fn indexed_event(data: &[u8]) -> IndexedEvent {
    IndexedEvent {
        tag: tag::EMIT_EVENT,
        payload: data.get(1..).unwrap_or_default().to_vec(),
        decoded: decode_event_instruction(data),
    }
}

fn parent_is_event_source(
    shielded_pool_program_id: Pubkey,
    group: &InstructionGroup,
    event_index: usize,
) -> bool {
    let Some(event_height) = group.inner[event_index].stack_height else {
        return false;
    };
    let Some(parent_height) = event_height.checked_sub(1) else {
        return false;
    };

    let parent = group.inner[..event_index]
        .iter()
        .rev()
        .find(|instruction| instruction.stack_height == Some(parent_height))
        .or_else(|| (group.outer.stack_height == Some(parent_height)).then_some(&group.outer));

    parent.is_some_and(|instruction| is_event_source(shielded_pool_program_id, instruction))
}

fn is_event_source(shielded_pool_program_id: Pubkey, instruction: &ParsedInstruction) -> bool {
    instruction.program_id == shielded_pool_program_id
        && matches!(
            instruction.data.first().copied(),
            Some(tag::PROOFLESS_SHIELD | tag::ZONE_PROOFLESS_SHIELD)
        )
}

fn is_emit_event(shielded_pool_program_id: Pubkey, instruction: &ParsedInstruction) -> bool {
    instruction.program_id == shielded_pool_program_id
        && instruction.data.first() == Some(&tag::EMIT_EVENT)
}
