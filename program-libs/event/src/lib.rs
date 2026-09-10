pub mod output_data;
pub mod output_utxo;
pub mod proofless;
pub mod tag;

use borsh::{BorshDeserialize, BorshSerialize};
pub use output_data::MessageData;
pub use output_utxo::OutputUtxo;
pub use proofless::{
    confidential_encrypted_output_body, decode_encrypted_ring_deposit_output_data,
    decode_output_data, encode_encrypted_ring_deposit_output,
    encode_encrypted_ring_deposit_output_ref, encode_output_data, encode_output_data_ref,
    encode_verifiably_encrypted, is_confidential_encrypted_output,
    ring_confidential_encrypted_output_body, EncryptedRingDepositData, EncryptedRingDepositDataRef,
    EncryptedRingDepositOutput, EncryptedRingDepositOutputRef, OutputDataEncoding, ProoflessOutput,
    ProoflessOutputRef, CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, ENCRYPTED_RING_DEPOSIT_SCHEME,
    PLAINTEXT_OUTPUT_FIXED_LEN, RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
};

/// The indexer-facing view of one state-changing instruction (spec: General
/// Event). `deposit` emits it verbatim via the `emit_event` self-CPI; `transact`
/// and `merge` emit only [`TransactEvent`] / [`MergeEvent`] and an indexer
/// rebuilds this view from that body plus the emitting instruction's data and
/// account list (`zolana-event-parser`).
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct GeneralEvent {
    pub inputs: Vec<Input>,
    pub outputs: Vec<OutputUtxo>,
    /// Published data slots bound to no output position, republished from
    /// `TransactIxData::messages`.
    pub messages: Vec<MessageData>,
    /// SEC1-compressed P256 viewing key shared by every output ciphertext, so an
    /// indexer can decrypt without parsing the per-output `data`. Zeroed for
    /// proofless deposits, which have no shared viewing key.
    pub tx_viewing_pk: [u8; 33],
    /// Per-transaction encryption salt shared by every output ciphertext, so a
    /// wallet can derive the AES key/nonce without parsing the per-output `data`.
    /// Zeroed for proofless deposits, which have no shared salt.
    pub salt: [u8; 16],
    /// Leaf index of `outputs[0]`; later outputs append sequentially.
    pub first_output_leaf_index: u64,
    pub output_tree: [u8; 32],
    /// Per-asset public SPL transfers: empty for a shielded transfer, one entry per
    /// settled interface transfer. A batched `deposit` carries one entry per deposited
    /// asset.
    pub spl_transfers: Vec<SplTransfer>,
}

/// One spent input. Inputs may originate from different trees.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct Input {
    pub tree: [u8; 32],
    pub input_queue_seq: u64,
    pub nullifier: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct SplTransfer {
    pub is_deposit: bool,
    pub amount: u64,
    pub asset: Option<[u8; 32]>,
}

/// One input tree spent by a `transact`/`merge`: the tree and the queue sequence
/// number assigned to its first spent input. Every later input of that tree takes
/// `first_input_queue_seq + position`: queue inserts are sequential within one
/// instruction. SPP spends from a single `input_tree` today, so the emitting
/// instruction writes one entry; the `Vec` keeps the layout stable if inputs
/// later span several trees.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct InputTreeSequence {
    pub tree: [u8; 32],
    pub first_input_queue_seq: u64,
}

/// Body of [`EventKind::Transact`]: only the values assigned at execution or
/// read from accounts. Nullifiers, output commitments, owner tags, ciphertexts,
/// messages, `tx_viewing_pk` and `salt` are not repeated; an indexer reads them
/// from the `transact` instruction data and account list when it rebuilds the
/// [`GeneralEvent`].
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct TransactEvent {
    pub input_trees: Vec<InputTreeSequence>,
    pub output_tree: [u8; 32],
    /// Leaf index of `outputs[0]`; later outputs append sequentially.
    pub first_output_leaf_index: u64,
    /// One entry per interface transfer, in leg order. `asset` is the mint
    /// account, which only the settlement accounts know.
    pub spl_transfers: Vec<SplTransfer>,
}

/// Body of [`EventKind::Merge`]. The output commitment, the nullifiers and a
/// ring merge's output `ring_data_hash` come from the instruction data.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct MergeEvent {
    pub input_trees: Vec<InputTreeSequence>,
    pub output_tree: [u8; 32],
    pub output_leaf_index: u64,
    /// Owner-indexing tag of the merged output: the registered signing view tag
    /// (user-record state) for `merge_transact`, the first nullifier for
    /// `merge_ring`.
    pub output_view_tag: [u8; 32],
}

/// Why an emitted event or output payload could not be decoded or rebuilt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventDecodeError {
    MissingInstructionTag,
    InvalidInstructionTag(u8),
    InvalidPayload,
    InvalidEventKind(u8),
    InvalidOutputData,
    MissingOutput,
    MissingDepositSplTransfer,
    /// The emitting instruction's data did not parse as the instruction the
    /// event kind belongs to.
    InvalidSourceInstructionData,
    /// The emitting instruction's tag cannot produce this event kind.
    UnsupportedSourceInstruction(u8),
    /// An output's `OwnerTag::Account` index points past the emitting
    /// instruction's account list.
    OutputOwnerAccountMissing(u8),
    /// The event names more input trees than the instruction data can assign
    /// inputs to.
    UnsupportedInputTreeCount(usize),
    /// `spl_transfers` and the instruction's interface transfers differ in length.
    SplTransferCountMismatch,
    /// The event kind carries no [`GeneralEvent`] view (nullifier-tree updates).
    NotAGeneralEvent,
    /// Queue sequence or leaf index arithmetic overflowed.
    IndexOverflow,
}

/// A cascade of `num_update` nullifier-tree zkp batch updates applied in one
/// instruction. `new_root` is the final root; the intermediate roots live in
/// the tree's `root_history` at indices `first_root_index .. first_root_index +
/// num_update` (mod `root_history_capacity`). The per-batch values for the
/// `i`-th applied batch (`0 <= i < num_update`) are:
/// - `old_next_index`  = `old_next_index + i * zkp_batch_size`
/// - `new_next_index`  = `old_next_index + (i + 1) * zkp_batch_size`
/// - `sequence_number` = `start_sequence_number + i`
/// - `root_index`      = `(first_root_index + i) % root_history_capacity`
///
/// An indexer must reconstruct all `num_update * zkp_batch_size` appended
/// values before comparing against `new_root`: only the final root is reported,
/// so checking after a single batch mismatches whenever a cascade occurs.
#[repr(C)]
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Clone, Eq)]
pub struct NullifierTreeUpdateEvent {
    pub merkle_tree_pubkey: [u8; 32],
    pub zkp_batch_size: u16,
    pub old_next_index: u64,
    pub start_sequence_number: u64,
    pub first_root_index: u32,
    pub num_update: u32,
    pub first_zkp_batch_index: u32,
    pub new_root: [u8; 32],
}

/// First payload byte after `EMIT_EVENT`: names the emitting instruction so an
/// indexer can dispatch (and version) the borsh body without trial-parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    /// Body is a full [`GeneralEvent`].
    Deposit = 1,
    /// Body is a [`TransactEvent`].
    Transact = 2,
    /// Body is a [`MergeEvent`].
    Merge = 3,
    /// Nullifier-tree batch update. Body is a
    /// [`NullifierTreeUpdateEvent`] (one cascade event per update), not a
    /// [`GeneralEvent`].
    NullifierTreeUpdate = 4,
}

impl EventKind {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Deposit),
            2 => Some(Self::Transact),
            3 => Some(Self::Merge),
            4 => Some(Self::NullifierTreeUpdate),
            _ => None,
        }
    }
}

pub fn encode_event_instruction(kind: EventKind, event: GeneralEvent) -> Vec<u8> {
    encode_event_instruction_with(kind, &event)
}

/// Encode an `EMIT_EVENT` instruction for an event whose body is not a
/// [`GeneralEvent`] (e.g. a batch append event). Layout mirrors
/// [`encode_event_instruction`]: `[EMIT_EVENT, kind, borsh(payload)]`.
pub fn encode_event_instruction_with<T: BorshSerialize>(kind: EventKind, payload: &T) -> Vec<u8> {
    let mut data = vec![tag::EMIT_EVENT, kind as u8];
    payload
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
