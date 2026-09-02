use custom_ring_interface::{
    tag, CreateEntryIxData, CreatePolicyIxData, SourceSpec, UpdateEntryIxData,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use thiserror::Error;
use zolana_client::{ProverClient, Rpc};
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;
use zolana_ring_policy::{EntryState, ListEntry, ListId, ListNamespace, Member};

use crate::{
    instructions::entry::proof::{EntryProof, EntryProofError, EntryWitness},
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
    #[error("the compiled table does not reference the list")]
    UnreferencedList(ListId),
    #[error(transparent)]
    Encoding(#[from] wincode::WriteError),
}

/// Pins the compiled table and the source map, signed by the upgrade authority.
#[must_use]
pub struct CreatePolicy {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub entries_tree: Address,
    /// Referenced lists reading a curator ring's entries, every other
    /// referenced list defaults to the ring's own entries.
    pub shared_sources: Vec<(ListId, CustomRing)>,
}

impl CreatePolicy {
    pub fn instruction(self) -> Result<Instruction, EntryError> {
        let Self {
            ring,
            payer,
            authority,
            entries_tree,
            shared_sources,
        } = self;
        let referenced: Vec<ListId> = custom_ring_interface::RULES
            .rules()
            .iter()
            .flat_map(|rule| rule.referenced_lists())
            .collect();
        for (list_id, _) in &shared_sources {
            if !referenced.contains(list_id) {
                return Err(EntryError::UnreferencedList(*list_id));
            }
        }
        let mut curators: Vec<CustomRing> = Vec::new();
        let mut specs: Vec<SourceSpec> = Vec::new();
        for list_id in 1u8..=custom_ring_interface::N_SOURCE_SLOTS as u8 {
            let Ok(list_id) = ListId::try_from(list_id) else {
                continue;
            };
            if !referenced.contains(&list_id) {
                continue;
            }
            let source = match shared_sources.iter().find(|(shared, _)| *shared == list_id) {
                None => 0,
                Some((_, curator)) => {
                    let index = curators
                        .iter()
                        .position(|known| known == curator)
                        .unwrap_or_else(|| {
                            curators.push(*curator);
                            curators.len() - 1
                        });
                    1 + index as u8
                }
            };
            specs.push(SourceSpec {
                list_id: list_id as u8,
                source,
            });
        }
        let mut instruction_data = vec![tag::CREATE_POLICY];
        instruction_data
            .extend_from_slice(&wincode::serialize(&CreatePolicyIxData { sources: specs })?);
        let mut accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(ring.policy_config_pda(), false),
            AccountMeta::new_readonly(entries_tree, false),
            AccountMeta::new_readonly(Address::default(), false),
            AccountMeta::new_readonly(ring.program_id(), false),
            AccountMeta::new_readonly(ring.program_data_pda(), false),
        ];
        for curator in &curators {
            accounts.push(AccountMeta::new_readonly(
                curator.policy_config_pda(),
                false,
            ));
        }
        Ok(Instruction {
            program_id: ring.program_id(),
            accounts,
            data: instruction_data,
        })
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
