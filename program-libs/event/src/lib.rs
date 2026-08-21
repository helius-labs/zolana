pub mod output_data;
pub mod output_utxo;
pub mod proofless;
pub mod tag;

use borsh::{BorshDeserialize, BorshSerialize};
pub use output_data::MessageData;
pub use output_utxo::OutputUtxo;
pub use proofless::{
    confidential_encrypted_output_body, encode_encrypted_ring_deposit_output,
    encode_encrypted_ring_deposit_output_ref, encode_output_data, encode_output_data_ref,
    encode_verifiably_encrypted, is_confidential_encrypted_output,
    ring_confidential_encrypted_output_body, EncryptedRingDepositData, EncryptedRingDepositDataRef,
    EncryptedRingDepositOutput, EncryptedRingDepositOutputRef, OutputDataEncoding, ProoflessOutput,
    ProoflessOutputRef, CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, ENCRYPTED_RING_DEPOSIT_SCHEME,
    PLAINTEXT_OUTPUT_FIXED_LEN, RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
};

/// `GeneralEvent`, emitted via the `emit_event` self-CPI by state-changing
/// instructions (spec: General Event). It records the queue sequence numbers and
/// leaf indices assigned at execution, which are absent from instruction data,
/// so an indexer can reconstruct nullifier insertions and UTXO appends.
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

/// A cascade of `num_update` address-append zkp batches applied in one
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
pub struct BatchAddressAppendEvent {
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
    Deposit = 1,
    Transact = 2,
    Merge = 3,
    /// Address/nullifier-tree batch append. Body is a
    /// [`BatchAddressAppendEvent`] (one cascade event per update), not a
    /// [`GeneralEvent`].
    BatchAddressAppend = 4,
}

impl EventKind {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Deposit),
            2 => Some(Self::Transact),
            3 => Some(Self::Merge),
            4 => Some(Self::BatchAddressAppend),
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

// Decode and indexer-reconstruction helpers used by indexers (the in-repo
// `program-test` harness and Photon) and by wallet deposit discovery, but never
// by the on-chain program, which only emits events.
#[cfg(feature = "program-test")]
pub mod program_test;

#[cfg(feature = "program-test")]
pub use program_test::*;
