//! The table body `CREATE_POLICY` and `SET_POLICY_RULES` share, and the packet
//! bound both builders enforce.

use custom_ring_interface::{PolicyTableIxData, SourceSpec};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_packet::PACKET_DATA_SIZE;
use solana_transaction::Transaction;
use zolana_ring_policy::{ListId, Rule, RuleTable};

use crate::{instructions::entry::EntryError, CustomRing};

pub(crate) struct PolicyTable<'a> {
    pub rules: &'a RuleTable,
    /// Referenced lists reading a curator ring's entries, every other
    /// referenced list reads the ring's own.
    pub shared_sources: &'a [(ListId, CustomRing)],
}

/// The body and the curator policy configs its specs index, in first-use order.
pub(crate) struct PolicyTableBody {
    pub data: PolicyTableIxData,
    pub curators: Vec<CustomRing>,
}

impl PolicyTable<'_> {
    pub(crate) fn body(self) -> Result<PolicyTableBody, EntryError> {
        let referenced = self.rules.referenced();
        if let Some((list_id, _)) = self
            .shared_sources
            .iter()
            .find(|(list_id, _)| !referenced.contains(*list_id))
        {
            return Err(EntryError::UnreferencedList(*list_id));
        }
        let mut curators: Vec<CustomRing> = Vec::new();
        let sources = referenced
            .iter()
            .map(|list_id| {
                let curator = self
                    .shared_sources
                    .iter()
                    .find(|(shared, _)| *shared == list_id)
                    .map(|(_, curator)| *curator);
                let source = match curator {
                    None => 0,
                    Some(curator) => {
                        let index = curators
                            .iter()
                            .position(|known| *known == curator)
                            .unwrap_or_else(|| {
                                curators.push(curator);
                                curators.len() - 1
                            });
                        1 + index as u8
                    }
                };
                SourceSpec {
                    list_id: list_id as u8,
                    source,
                }
            })
            .collect();
        Ok(PolicyTableBody {
            data: PolicyTableIxData {
                sources,
                rules: self.rules.rules().iter().map(Rule::encoded).collect(),
                inline_assets: self.rules.inline_assets().to_vec(),
                inline_limits: self.rules.inline_limits().to_vec(),
            },
            curators,
        })
    }
}

impl PolicyTableBody {
    pub(crate) fn instruction_data(&self, tag: u8) -> Result<Vec<u8>, EntryError> {
        let mut data = vec![tag];
        data.extend_from_slice(&wincode::serialize(&self.data)?);
        Ok(data)
    }

    pub(crate) fn curator_accounts(&self) -> impl Iterator<Item = AccountMeta> + '_ {
        self.curators
            .iter()
            .map(|curator| AccountMeta::new_readonly(curator.policy_config_pda(), false))
    }
}

/// The legacy transaction the instruction rides in, one compute budget
/// instruction ahead of it.
pub(crate) struct LegacyPacket {
    pub payer: Address,
    pub compute_unit_limit: u32,
    pub instruction: Instruction,
}

impl LegacyPacket {
    /// Signatures included, the bound the runtime applies to the whole packet.
    pub(crate) fn fit(self) -> Result<Instruction, EntryError> {
        let instructions = [
            ComputeBudgetInstruction::set_compute_unit_limit(self.compute_unit_limit),
            self.instruction,
        ];
        let message = Message::new(&instructions, Some(&self.payer));
        let bytes = wincode::serialize(&Transaction::new_unsigned(message))?.len();
        if bytes > PACKET_DATA_SIZE {
            return Err(EntryError::TransactionTooLarge {
                bytes,
                limit: PACKET_DATA_SIZE,
            });
        }
        let [_, instruction] = instructions;
        Ok(instruction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(data_len: usize) -> LegacyPacket {
        let payer = Address::new_from_array([1u8; 32]);
        LegacyPacket {
            payer,
            compute_unit_limit: 1,
            instruction: Instruction {
                program_id: Address::new_from_array([2u8; 32]),
                accounts: vec![AccountMeta::new(payer, true)],
                data: vec![7u8; data_len],
            },
        }
    }

    #[test]
    fn the_bound_counts_the_whole_signed_transaction() {
        let instruction = packet(1000).fit().expect("fits");
        assert_eq!(instruction.data.len(), 1000);
        assert!(matches!(
            packet(1100).fit(),
            Err(EntryError::TransactionTooLarge { bytes, limit })
                if bytes > limit && limit == PACKET_DATA_SIZE
        ));
    }
}
