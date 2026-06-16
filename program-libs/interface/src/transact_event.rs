//! `GeneralEvent`, the event emitted via `emit_event` self-CPI by
//! state-changing instructions (spec: General Event). It records the queue
//! sequence numbers and leaf indices assigned at execution, which are absent
//! from instruction data, so an indexer can reconstruct nullifier insertions
//! and UTXO appends.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::instruction::OutputUtxo;

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct GeneralEvent {
    pub inputs: Vec<Input>,
    pub outputs: Vec<OutputUtxo>,
    /// SEC1-compressed P256 viewing key shared by every output ciphertext, so
    /// an indexer can decrypt without parsing the opaque payloads.
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

/// Output payload. SPP does not parse it except for proofless shield.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum Data {
    Unknown(Vec<u8>),
    Proofless(ProoflessOutput),
    /// Serialized `TransferEncryptedUtxos`; the client decodes the payload.
    Transfer(Vec<u8>),
    /// Serialized `TransferPlaintextUtxos`; the client decodes the payload.
    PublicTransfer(Vec<u8>),
}

/// Proofless-shield output. Carries `owner_utxo_hash` instead of `owner` and
/// `blinding`, which never reach the program, so the recipient stays hidden.
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

/// Public token movement accompanying the transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct DepositWithdraw {
    pub is_deposit: bool,
    pub amount: u64,
    /// `None` = native SOL, `Some` = SPL mint.
    pub asset: Option<[u8; 32]>,
}
