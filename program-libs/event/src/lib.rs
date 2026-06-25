pub mod output_utxo;
pub mod proofless;
pub mod tag;

pub use output_utxo::OutputUtxo;
pub use proofless::{encode_output_data, encode_verifiably_encrypted, OutputData, ProoflessOutput};

use borsh::{BorshDeserialize, BorshSerialize};

/// `GeneralEvent`, emitted via the `emit_event` self-CPI by state-changing
/// instructions (spec: General Event). It records the queue sequence numbers and
/// leaf indices assigned at execution, which are absent from instruction data,
/// so an indexer can reconstruct nullifier insertions and UTXO appends.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct GeneralEvent {
    pub inputs: Vec<Input>,
    pub outputs: Vec<OutputUtxo>,
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

/// First payload byte after `EMIT_EVENT`: names the emitting instruction so an
/// indexer can dispatch (and version) the borsh body without trial-parsing.
/// Every kind currently carries a [`GeneralEvent`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    Deposit = 1,
    Transact = 2,
    Merge = 3,
}

impl EventKind {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Deposit),
            2 => Some(Self::Transact),
            3 => Some(Self::Merge),
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

// Decode and indexer-reconstruction helpers used by indexers (the in-repo
// `program-test` harness and Photon) and by wallet deposit discovery, but never
// by the on-chain program, which only emits events.
#[cfg(feature = "program-test")]
pub mod program_test;

#[cfg(feature = "program-test")]
pub use program_test::*;
