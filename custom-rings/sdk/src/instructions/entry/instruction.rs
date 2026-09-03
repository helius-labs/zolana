use custom_ring_interface::{
    tag, CreateEntryIxData, UpdateEntryIxData, CREATE_POLICY_COMPUTE_UNIT_LIMIT,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use thiserror::Error;
use zolana_client::{ProverClient, Rpc};
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;
use zolana_ring_policy::{EntryState, ListEntry, ListId, ListNamespace, Member, RuleTable};

use crate::{
    instructions::{
        entry::proof::{EntryProof, EntryProofError, EntryWitness},
        policy_table::{LegacyPacket, PolicyTable},
    },
    CustomRing,
};

/// A mutation build failed before any instruction was produced.
#[derive(Debug, Error)]
pub enum EntryError {
    #[error(transparent)]
    Proof(#[from] EntryProofError),
    #[error("namespace owner hashing failed")]
    Hashing,
    #[error("entry version overflows")]
    VersionOverflow,
    #[error("the table does not reference the list")]
    UnreferencedList(ListId),
    #[error("no content of the list recovers the commitment")]
    InvalidContent(ListId),
    #[error("the transaction takes {bytes} bytes, a legacy packet carries {limit}")]
    TransactionTooLarge { bytes: usize, limit: usize },
    #[error(transparent)]
    Encoding(#[from] wincode::WriteError),
}

/// Pins the table and its source map, signed by the upgrade authority.
#[must_use]
pub struct CreatePolicy<'a> {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub entries_tree: Address,
    pub rules: &'a RuleTable,
    /// Referenced lists reading a curator ring's entries, every other
    /// referenced list defaults to the ring's own entries.
    pub shared_sources: Vec<(ListId, CustomRing)>,
}

impl CreatePolicy<'_> {
    pub fn instruction(self) -> Result<Instruction, EntryError> {
        let Self {
            ring,
            payer,
            authority,
            entries_tree,
            rules,
            shared_sources,
        } = self;
        let body = PolicyTable {
            rules,
            shared_sources: &shared_sources,
        }
        .body()?;
        let mut accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(ring.policy_config_pda(), false),
            AccountMeta::new_readonly(entries_tree, false),
            AccountMeta::new_readonly(Address::default(), false),
            AccountMeta::new_readonly(ring.program_id(), false),
            AccountMeta::new_readonly(ring.program_data_pda(), false),
        ];
        accounts.extend(body.curator_accounts());
        LegacyPacket {
            payer,
            compute_unit_limit: CREATE_POLICY_COMPUTE_UNIT_LIMIT,
            instruction: Instruction {
                program_id: ring.program_id(),
                accounts,
                data: body.instruction_data(tag::CREATE_POLICY)?,
            },
        }
        .fit()
    }
}

/// Claims the pair's address at version zero.
#[must_use]
pub struct CreateEntry {
    pub ring: CustomRing,
    pub payer: Address,
    pub entries_tree: Address,
    pub list_id: ListId,
    pub member: Member,
    pub state: EntryState,
    pub content_hash: [u8; 32],
}

impl CreateEntry {
    pub fn prove<I: Rpc, R: Rpc>(
        self,
        environment: EntryProofEnvironment<'_, I, R>,
    ) -> Result<ProvenEntry, EntryError> {
        if !self.list_id.admits_content(self.content_hash) {
            return Err(EntryError::InvalidContent(self.list_id));
        }
        let namespace = self.ring.namespace_pda();
        let owner = ListNamespace::new(namespace.as_array()).map_err(|_| EntryError::Hashing)?;
        let entry = ListEntry {
            list_id: self.list_id,
            member: self.member,
            state: self.state,
            version: 0,
            content_hash: self.content_hash,
        };
        let proof = EntryWitness {
            owner: &owner,
            namespace,
            entries_tree: self.entries_tree,
            payer: self.payer,
            entry,
            spent: None,
        }
        .prove(environment.indexer, environment.rpc, environment.prover)?;
        Ok(ProvenEntry {
            ring: self.ring,
            payer: self.payer,
            entries_tree: self.entries_tree,
            entry,
            spent: None,
            proof,
        })
    }
}

/// Spends the live version and writes its successor at the same address.
#[must_use]
pub struct UpdateEntry {
    pub ring: CustomRing,
    pub payer: Address,
    pub entries_tree: Address,
    pub spent: ListEntry,
    pub state: EntryState,
    pub content_hash: [u8; 32],
}

impl UpdateEntry {
    pub fn prove<I: Rpc, R: Rpc>(
        self,
        environment: EntryProofEnvironment<'_, I, R>,
    ) -> Result<ProvenEntry, EntryError> {
        if !self.spent.list_id.admits_content(self.content_hash) {
            return Err(EntryError::InvalidContent(self.spent.list_id));
        }
        let namespace = self.ring.namespace_pda();
        let owner = ListNamespace::new(namespace.as_array()).map_err(|_| EntryError::Hashing)?;
        let entry = ListEntry {
            list_id: self.spent.list_id,
            member: self.spent.member,
            state: self.state,
            version: self
                .spent
                .version
                .checked_add(1)
                .ok_or(EntryError::VersionOverflow)?,
            content_hash: self.content_hash,
        };
        let proof = EntryWitness {
            owner: &owner,
            namespace,
            entries_tree: self.entries_tree,
            payer: self.payer,
            entry,
            spent: Some(self.spent),
        }
        .prove(environment.indexer, environment.rpc, environment.prover)?;
        Ok(ProvenEntry {
            ring: self.ring,
            payer: self.payer,
            entries_tree: self.entries_tree,
            entry,
            spent: Some(self.spent),
            proof,
        })
    }
}

/// The connections one mutation proof needs.
pub struct EntryProofEnvironment<'a, I: Rpc, R: Rpc> {
    pub indexer: &'a I,
    pub rpc: &'a R,
    pub prover: &'a ProverClient,
}

/// A proven mutation, ready to become one instruction.
#[must_use]
pub struct ProvenEntry {
    ring: CustomRing,
    payer: Address,
    entries_tree: Address,
    entry: ListEntry,
    spent: Option<ListEntry>,
    proof: EntryProof,
}

impl ProvenEntry {
    pub const fn entry(&self) -> ListEntry {
        self.entry
    }

    pub fn instruction(self) -> Result<Instruction, EntryError> {
        let Self {
            ring,
            payer,
            entries_tree,
            entry,
            spent,
            proof,
        } = self;
        let data = match spent {
            None => {
                let mut data = vec![tag::CREATE_ENTRY];
                data.extend_from_slice(&wincode::serialize(&CreateEntryIxData {
                    list_id: entry.list_id as u8,
                    member: *entry.member.as_bytes(),
                    state: entry.state as u8,
                    content_hash: entry.content_hash,
                    nullifier_tree_root_index: proof.nullifier_tree_root_index,
                    utxo_tree_root_index: proof.utxo_tree_root_index,
                    proof: proof.proof,
                })?);
                data
            }
            Some(spent) => {
                let mut data = vec![tag::UPDATE_ENTRY];
                data.extend_from_slice(&wincode::serialize(&UpdateEntryIxData {
                    list_id: entry.list_id as u8,
                    member: *entry.member.as_bytes(),
                    spent_state: spent.state as u8,
                    spent_content_hash: spent.content_hash,
                    spent_version: spent.version,
                    state: entry.state as u8,
                    content_hash: entry.content_hash,
                    nullifier_tree_root_index: proof.nullifier_tree_root_index,
                    utxo_tree_root_index: proof.utxo_tree_root_index,
                    proof: proof.proof,
                })?);
                data
            }
        };
        Ok(Instruction {
            program_id: ring.program_id(),
            // Everything after the two config accounts is forwarded to SPP
            // position for position.
            accounts: vec![
                AccountMeta::new_readonly(ring.config_pda(), false),
                AccountMeta::new_readonly(ring.policy_config_pda(), false),
                AccountMeta::new(payer, true),
                AccountMeta::new(entries_tree, false),
                AccountMeta::new(entries_tree, false),
                AccountMeta::new_readonly(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
                AccountMeta::new_readonly(Address::default(), false),
                AccountMeta::new_readonly(ring.namespace_pda(), false),
            ],
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `Rpc` method has a default that fails, a reached call is an error.
    struct NoRpc;
    impl Rpc for NoRpc {}

    #[test]
    fn a_commitment_no_list_content_recovers_is_refused_before_any_call() {
        let refused = CreateEntry {
            ring: CustomRing::new(Address::new_from_array([42u8; 32])),
            payer: Address::new_from_array([1u8; 32]),
            entries_tree: Address::new_from_array([2u8; 32]),
            list_id: ListId::Allow,
            member: Member::owner_tag(&[3u8; 32]).expect("member"),
            state: EntryState::Active,
            content_hash: [1u8; 32],
        }
        .prove(EntryProofEnvironment {
            indexer: &NoRpc,
            rpc: &NoRpc,
            prover: &ProverClient::new(String::new()),
        });
        assert!(matches!(
            refused,
            Err(EntryError::InvalidContent(ListId::Allow))
        ));
    }
}
