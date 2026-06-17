use borsh::{BorshDeserialize, BorshSerialize};
use solana_pubkey::Pubkey;

use crate::instruction::{tag, OutputUtxo};

/// `GeneralEvent`, emitted via the `emit_event` self-CPI by state-changing
/// instructions (spec: General Event). It records the queue sequence numbers and
/// leaf indices assigned at execution, which are absent from instruction data,
/// so an indexer can reconstruct nullifier insertions and UTXO appends.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct GeneralEvent {
    pub inputs: Vec<Input>,
    pub outputs: Vec<OutputUtxo>,
    /// SEC1-compressed P256 viewing key shared by every output ciphertext, so an
    /// indexer can decrypt without parsing the opaque payloads. Zeroed for
    /// proofless deposits, which carry no shared viewing key.
    pub tx_viewing_pk: [u8; 33],
    /// Leaf index of `outputs[0]`; later outputs append sequentially.
    pub first_output_leaf_index: u64,
    pub output_tree: [u8; 32],
    pub relay_fee: Option<u64>,
    /// `Some` for shield/unshield, `None` for shielded transfer.
    pub deposit_withdraw: Option<DepositWithdraw>,
}

/// One spent input. Inputs may originate from different trees.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct Input {
    pub tree: [u8; 32],
    pub input_queue_seq: u64,
    pub nullifier: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct DepositWithdraw {
    pub is_deposit: bool,
    pub amount: u64,
    pub asset: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum OutputData {
    Unknown(Vec<u8>),
    Proofless(ProoflessOutput),
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct ProoflessOutput {
    pub owner_utxo_hash: [u8; 32],
    pub salt: [u8; 16],
    pub program_data_hash: Option<[u8; 32]>,
    pub program_data: Option<Vec<u8>>,
    pub zone_program_id: Option<[u8; 32]>,
    pub policy_data_hash: Option<[u8; 32]>,
    pub zone_data: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositView {
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
    pub output_tree: [u8; 32],
    pub leaf_index: u64,
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
    pub decoded: Result<GeneralEvent, EventDecodeError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventDecodeError {
    MissingInstructionTag,
    InvalidInstructionTag(u8),
    InvalidPayload,
    InvalidEventKind(u8),
    InvalidOutputData,
    MissingOutput,
    MissingDepositWithdraw,
}

/// First payload byte after `EMIT_EVENT`: names the emitting instruction so an
/// indexer can dispatch (and version) the borsh body without trial-parsing.
/// Every kind currently carries a [`GeneralEvent`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    Deposit = 1,
    Transact = 2,
}

impl EventKind {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Deposit),
            2 => Some(Self::Transact),
            _ => None,
        }
    }
}

pub fn encode_event_instruction(kind: EventKind, event: GeneralEvent) -> Vec<u8> {
    let mut data = vec![tag::EMIT_EVENT, kind as u8];
    event
        .serialize(&mut data)
        .expect("shielded-pool event serialization is infallible");
    data
}

pub fn encode_event_payload(kind: EventKind, event: &GeneralEvent) -> Vec<u8> {
    let mut data = vec![kind as u8];
    event
        .serialize(&mut data)
        .expect("shielded-pool event serialization is infallible");
    data
}

pub fn decode_event_instruction(data: &[u8]) -> Result<GeneralEvent, EventDecodeError> {
    let (&instruction_tag, payload) = data
        .split_first()
        .ok_or(EventDecodeError::MissingInstructionTag)?;
    if instruction_tag != tag::EMIT_EVENT {
        return Err(EventDecodeError::InvalidInstructionTag(instruction_tag));
    }
    decode_event_payload(payload)
}

pub fn decode_event_payload(payload: &[u8]) -> Result<GeneralEvent, EventDecodeError> {
    let (&kind_byte, event_bytes) = payload
        .split_first()
        .ok_or(EventDecodeError::InvalidPayload)?;
    // Validate the kind envelope up front; every known kind currently decodes to
    // a `GeneralEvent`, so dispatch is a single arm until a kind needs its own
    // payload struct.
    EventKind::from_byte(kind_byte).ok_or(EventDecodeError::InvalidEventKind(kind_byte))?;
    GeneralEvent::try_from_slice(event_bytes).map_err(|_| EventDecodeError::InvalidPayload)
}

pub fn encode_output_data(data: &OutputData) -> Vec<u8> {
    let mut bytes = Vec::new();
    data.serialize(&mut bytes)
        .expect("shielded-pool output data serialization is infallible");
    bytes
}

pub fn decode_output_data(data: &[u8]) -> Result<OutputData, EventDecodeError> {
    OutputData::try_from_slice(data).map_err(|_| EventDecodeError::InvalidOutputData)
}

pub fn proofless_output(event: &GeneralEvent) -> Result<DepositView, EventDecodeError> {
    let output = event
        .outputs
        .first()
        .ok_or(EventDecodeError::MissingOutput)?;
    let OutputData::Proofless(proofless) = decode_output_data(&output.data)? else {
        return Err(EventDecodeError::InvalidOutputData);
    };
    let deposit_withdraw = event
        .deposit_withdraw
        .as_ref()
        .ok_or(EventDecodeError::MissingDepositWithdraw)?;
    if !deposit_withdraw.is_deposit {
        return Err(EventDecodeError::MissingDepositWithdraw);
    }

    Ok(DepositView {
        view_tag: output.view_tag,
        utxo_hash: output.utxo_hash,
        asset: deposit_withdraw.asset.unwrap_or([0u8; 32]),
        amount: deposit_withdraw.amount,
        zone_program_id: proofless.zone_program_id,
        policy_data_hash: proofless.policy_data_hash,
        owner_utxo_hash: proofless.owner_utxo_hash,
        salt: proofless.salt,
        program_data_hash: proofless.program_data_hash,
        program_data: proofless.program_data,
        zone_data: proofless.zone_data,
        output_tree: event.output_tree,
        leaf_index: event.first_output_leaf_index,
    })
}

pub fn indexed_events_from_instruction_groups(
    shielded_pool_program_id: Pubkey,
    groups: &[InstructionGroup],
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
        || (instruction.data.first() == Some(&tag::ZONE_DEPOSIT)
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
            Some(tag::DEPOSIT | tag::ZONE_DEPOSIT)
        )
}

fn is_emit_event(shielded_pool_program_id: Pubkey, instruction: &ParsedInstruction) -> bool {
    instruction.program_id == shielded_pool_program_id
        && instruction.data.first() == Some(&tag::EMIT_EVENT)
}
