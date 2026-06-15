use borsh::{BorshDeserialize, BorshSerialize};

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
