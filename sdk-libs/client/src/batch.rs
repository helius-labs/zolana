//! Size-aware planning for `BatchTransact` (same-vk RLC over N pure-shielded
//! transacts). Batching saves compute only when the combined transaction fits a
//! packet, so [`plan_batch_transact`] probes the serialized size and falls back
//! to solo `Transact` instructions when the batch would not fit: callers are
//! never worse off than N solo submissions.

use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{BatchTransact, Transact, TransactIxData},
    MAX_BATCH_TRANSACT,
};

use crate::error::ClientError;

/// IPv6 MTU minus UDP/fragment headers: the serialized-transaction ceiling a
/// cluster accepts today (SIMD-0296 may raise it).
pub const PACKET_DATA_SIZE: usize = 1232;

/// Compute-unit ceiling requested for a batch submission. Measured N=2 uses
/// ~266k; the probe budgets generously since unused budget is not charged.
pub const BATCH_TRANSACT_CU_LIMIT: u32 = 1_400_000;

/// How to submit N pure-shielded transacts: one `BatchTransact` when the
/// combined transaction fits a packet, otherwise N solo `Transact`s.
pub enum BatchTransactPlan {
    Batched {
        instruction: Instruction,
        /// Serialized size of the probe transaction (compute-budget ix + batch ix).
        tx_bytes: usize,
    },
    Solo {
        instructions: Vec<Instruction>,
        /// Size the rejected batch would have had; callers can log why.
        batched_tx_bytes: usize,
    },
}

impl BatchTransactPlan {
    pub fn is_batched(&self) -> bool {
        matches!(self, Self::Batched { .. })
    }

    /// The instructions to submit: one element when batched, N when solo.
    pub fn into_instructions(self) -> Vec<Instruction> {
        match self {
            Self::Batched { instruction, .. } => vec![instruction],
            Self::Solo { instructions, .. } => instructions,
        }
    }
}

/// The accounts every entry shares. Extra eddsa signers beyond the fee payer go
/// into `signers` (entry `eddsa_signer_index` resolves into the instruction's
/// account list).
pub struct BatchTransactAccounts {
    pub payer: Pubkey,
    pub input_tree: Pubkey,
    pub output_tree: Pubkey,
    pub signers: Vec<Pubkey>,
}

/// Validate `entries` for the batch rail and decide batched vs solo by probing
/// the serialized transaction size against [`PACKET_DATA_SIZE`].
///
/// Program-enforced constraints checked here so callers fail fast:
/// `1..=MAX_BATCH_TRANSACT` entries, one circuit shape across all entries, and
/// no interface transfers (the batch rail is pure shielded).
pub fn plan_batch_transact(
    accounts: BatchTransactAccounts,
    entries: Vec<TransactIxData>,
) -> Result<BatchTransactPlan, ClientError> {
    if entries.is_empty() {
        return Err(ClientError::BatchEmpty);
    }
    if entries.len() > MAX_BATCH_TRANSACT {
        return Err(ClientError::BatchTooManyEntries {
            got: entries.len(),
            max: MAX_BATCH_TRANSACT,
        });
    }
    let circuit = entries[0].circuit;
    for (index, entry) in entries.iter().enumerate() {
        if entry.circuit != circuit {
            return Err(ClientError::BatchMixedCircuits { index });
        }
        if !entry.interface_transfers.is_empty() {
            return Err(ClientError::BatchNotPureShielded { index });
        }
    }

    let batch = BatchTransact {
        payer: accounts.payer,
        input_tree: accounts.input_tree,
        output_tree: accounts.output_tree,
        signers: accounts.signers,
        entries,
    };
    let batch_ix = batch.instruction();
    let tx_bytes = probe_tx_size(&accounts.payer, batch_ix.clone());
    if tx_bytes <= PACKET_DATA_SIZE {
        return Ok(BatchTransactPlan::Batched {
            instruction: batch_ix,
            tx_bytes,
        });
    }

    let instructions = batch
        .entries
        .into_iter()
        .map(|data| {
            Transact {
                payer: accounts.payer,
                input_tree: accounts.input_tree,
                output_tree: accounts.output_tree,
                interface_transfer_accounts: Vec::new(),
                data,
            }
            .instruction()
        })
        .collect();
    Ok(BatchTransactPlan::Solo {
        instructions,
        batched_tx_bytes: tx_bytes,
    })
}

/// Serialized size of an unsigned legacy transaction carrying a compute-budget
/// instruction plus `ix`: shortvec signature count (1 byte for < 128 signers),
/// 64 bytes per required signature, then the message bytes.
fn probe_tx_size(payer: &Pubkey, ix: Instruction) -> usize {
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(BATCH_TRANSACT_CU_LIMIT);
    let message = Message::new(&[compute, ix], Some(payer));
    let signatures = usize::from(message.header.num_required_signatures);
    1 + 64 * signatures + message.serialize().len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_interface::instruction::{instruction_data::transact::CircuitId, TransactProof};

    fn entry(circuit: CircuitId) -> TransactIxData {
        TransactIxData {
            proof: TransactProof::zeroed(),
            expiry_unix_ts: u64::MAX,
            private_tx_hash: [1u8; 32],
            circuit,
            inputs: vec![],
            interface_transfers: vec![],
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk: [2u8; 33],
            salt: [3u8; 16],
            outputs: vec![],
            messages: vec![],
        }
    }

    fn accounts() -> BatchTransactAccounts {
        BatchTransactAccounts {
            payer: Pubkey::new_unique(),
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            signers: vec![],
        }
    }

    fn shape() -> CircuitId {
        CircuitId::ConfidentialEddsa(1, 1, 3)
    }

    #[test]
    fn empty_batch_rejected() {
        assert!(matches!(
            plan_batch_transact(accounts(), vec![]),
            Err(ClientError::BatchEmpty)
        ));
    }

    #[test]
    fn too_many_entries_rejected() {
        let entries = vec![entry(shape()); MAX_BATCH_TRANSACT + 1];
        assert!(matches!(
            plan_batch_transact(accounts(), entries),
            Err(ClientError::BatchTooManyEntries { .. })
        ));
    }

    #[test]
    fn mixed_circuits_rejected() {
        let entries = vec![entry(shape()), entry(CircuitId::ConfidentialEddsa(2, 3, 3))];
        assert!(matches!(
            plan_batch_transact(accounts(), entries),
            Err(ClientError::BatchMixedCircuits { index: 1 })
        ));
    }

    #[test]
    fn compact_entries_batch() {
        let plan = plan_batch_transact(accounts(), vec![entry(shape()); 2]).expect("plan");
        match plan {
            BatchTransactPlan::Batched { tx_bytes, .. } => {
                assert!(tx_bytes <= PACKET_DATA_SIZE, "probe {tx_bytes}")
            }
            BatchTransactPlan::Solo { .. } => panic!("empty bodies must fit a packet"),
        }
    }

    #[test]
    fn oversized_batch_falls_back_to_solo() {
        use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
        // A ciphertext-sized output payload per entry pushes the pair past the
        // packet limit, mirroring wallet transfer bodies.
        let mut big = entry(shape());
        big.outputs = vec![TransactOutput {
            utxo_hash: [5u8; 32],
            owner_tag: OwnerTag::Inline([6u8; 32]),
            data: Some(vec![7u8; 400]),
        }];
        match plan_batch_transact(accounts(), vec![big.clone(), big]).expect("plan") {
            BatchTransactPlan::Solo {
                instructions,
                batched_tx_bytes,
            } => {
                assert_eq!(instructions.len(), 2);
                assert!(batched_tx_bytes > PACKET_DATA_SIZE);
            }
            BatchTransactPlan::Batched { tx_bytes, .. } => {
                panic!("two 400-byte payload entries must not fit: {tx_bytes}")
            }
        }
    }
}
