//! The table body `CREATE_POLICY` and `SET_POLICY_RULES` share, and the
//! transaction bound both builders enforce.

use custom_ring_interface::{PolicyTableIxData, SourceSpec};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::v1::MAX_TRANSACTION_SIZE;
use zolana_client::v1_transaction_size;
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

/// The transaction **v1** message the instruction rides in, alone: v1 states
/// its compute ceilings in the message header, so no compute-budget
/// instruction takes up room beside it.
pub(crate) struct V1Transaction {
    pub payer: Address,
    pub instruction: Instruction,
}

impl V1Transaction {
    /// Signatures included, the bound the runtime applies to the whole
    /// transaction.
    ///
    /// Only the byte ceiling can bind here: v1 also caps a transaction at 64
    /// addresses, and a policy table names seven fixed accounts plus one
    /// curator per referenced list, which cannot reach that.
    pub(crate) fn fit(self) -> Result<Instruction, EntryError> {
        let signatures = signature_count(&self.payer, &self.instruction);
        let size = v1_transaction_size(
            &self.payer,
            core::slice::from_ref(&self.instruction),
            signatures,
        )
        .map_err(|error| EntryError::TransactionCompile(Box::new(error)))?;
        if size.bytes > MAX_TRANSACTION_SIZE {
            return Err(EntryError::TransactionTooLarge {
                bytes: size.bytes,
                limit: MAX_TRANSACTION_SIZE,
            });
        }
        Ok(self.instruction)
    }
}

/// The fee payer plus every distinct signer the instruction names.
///
/// The measurement takes the signature count as an input because an unsigned
/// message cannot tell it, and each signature the builder forgets under-reports
/// the transaction by 64 bytes.
fn signature_count(payer: &Address, instruction: &Instruction) -> usize {
    let mut signers = vec![*payer];
    for signer in instruction
        .accounts
        .iter()
        .filter(|meta| meta.is_signer)
        .map(|meta| meta.pubkey)
    {
        if !signers.contains(&signer) {
            signers.push(signer);
        }
    }
    signers.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction(data_len: usize) -> V1Transaction {
        let payer = Address::new_from_array([1u8; 32]);
        V1Transaction {
            payer,
            instruction: Instruction {
                program_id: Address::new_from_array([2u8; 32]),
                accounts: vec![AccountMeta::new(payer, true)],
                data: vec![7u8; data_len],
            },
        }
    }

    /// The bound is the v1 ceiling, not the 1232-byte legacy packet: an
    /// instruction between the two is sendable and must not be refused.
    #[test]
    fn the_bound_counts_the_whole_signed_transaction() {
        let instruction = transaction(3900).fit().expect("fits");
        assert_eq!(instruction.data.len(), 3900);
        assert!(matches!(
            transaction(4100).fit(),
            Err(EntryError::TransactionTooLarge { bytes, limit })
                if bytes > limit && limit == MAX_TRANSACTION_SIZE
        ));
    }
}
