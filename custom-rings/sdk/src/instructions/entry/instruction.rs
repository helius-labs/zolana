use custom_ring_interface::{tag, CreateEntryIxData, UpdateEntryIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use thiserror::Error;
use zolana_client::{ClientError, ComputeBudgetConfig, ProverClient, Rpc};
use zolana_interface::{pda, SHIELDED_POOL_PROGRAM_ID};
use zolana_ring_policy::{EntryState, ListEntry, ListId, ListNamespace, Member, RuleTable};

use crate::{
    instructions::{
        entry::{
            proof::{EntryDraft, EntryProofError, EntryWitness, WrittenEntry},
            LiveEntry,
        },
        policy_table::{PolicyTable, SizedTransaction},
    },
    CustomRing, PoolTree,
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
    #[error("the transaction takes {bytes} bytes, a v1 transaction carries {limit}")]
    TransactionTooLarge { bytes: usize, limit: usize },
    /// The instruction does not compile into a v1 message at all, so its size
    /// cannot be measured.
    #[error("the transaction message does not compile")]
    TransactionCompile(#[source] Box<ClientError>),
    #[error(transparent)]
    Encoding(#[from] wincode::WriteError),
    #[error(transparent)]
    HeadProof(#[from] crate::CustomRingProofError),
    #[error(transparent)]
    AccountRead(#[from] crate::AccountReadError),
    #[error(transparent)]
    PolicyMatch(#[from] crate::PolicyMatchError),
    #[error("the ring has no policy config")]
    MissingPolicyConfig,
    #[error("the ring has no velocity window")]
    VelocityDisabled,
    #[error("the member already registered a spend record")]
    SpendRecordExists,
}

impl From<ClientError> for EntryError {
    fn from(error: ClientError) -> Self {
        Self::Proof(EntryProofError::Client(Box::new(error)))
    }
}

/// Pins the table and its source map, signed by the upgrade authority.
#[must_use]
pub struct CreatePolicy<'a> {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    /// Every entry and spend record address is claimed here.
    pub address_tree: Address,
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
            address_tree,
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
            AccountMeta::new_readonly(ring.config_pda(), false),
            AccountMeta::new(ring.policy_config_pda(), false),
            AccountMeta::new_readonly(address_tree, false),
            AccountMeta::new_readonly(Address::default(), false),
            AccountMeta::new_readonly(ring.program_id(), false),
            AccountMeta::new_readonly(ring.program_data_pda(), false),
        ];
        accounts.extend(body.curator_accounts());
        SizedTransaction {
            payer,
            compute_budget: ComputeBudgetConfig::new(
                custom_ring_interface::CREATE_POLICY_COMPUTE_UNIT_LIMIT,
            ),
            instruction: Instruction {
                program_id: ring.program_id(),
                accounts,
                data: body.instruction_data(tag::CREATE_POLICY)?,
            },
        }
        .fit()
    }
}

/// Claims the pair's address at version zero, the address tree is the SPP input.
#[must_use]
pub struct CreateEntry {
    pub ring: CustomRing,
    pub payer: Address,
    pub address_tree: PoolTree,
    pub output_tree: PoolTree,
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
        let written = EntryWitness {
            owner: &owner,
            namespace,
            address_tree: self.address_tree,
            output_tree: self.output_tree,
            payer: self.payer,
            draft: EntryDraft {
                list_id: self.list_id,
                member: self.member,
                state: self.state,
                version: 0,
                content_hash: self.content_hash,
            },
            spent: None,
        }
        .prove(environment.indexer, environment.rpc, environment.prover)?;
        Ok(ProvenEntry {
            ring: self.ring,
            payer: self.payer,
            output_tree: self.output_tree.address,
            written,
            spent: None,
        })
    }
}

/// Spends the live version in its tree and writes its successor at the same address.
#[must_use]
pub struct UpdateEntry {
    pub ring: CustomRing,
    pub payer: Address,
    pub address_tree: PoolTree,
    pub output_tree: PoolTree,
    pub spent: LiveEntry,
    pub state: EntryState,
    pub content_hash: [u8; 32],
}

impl UpdateEntry {
    pub fn prove<I: Rpc, R: Rpc>(
        self,
        environment: EntryProofEnvironment<'_, I, R>,
    ) -> Result<ProvenEntry, EntryError> {
        let spent = self.spent.entry;
        if !spent.list_id.admits_content(self.content_hash) {
            return Err(EntryError::InvalidContent(spent.list_id));
        }
        let namespace = self.ring.namespace_pda();
        let owner = ListNamespace::new(namespace.as_array()).map_err(|_| EntryError::Hashing)?;
        let written = EntryWitness {
            owner: &owner,
            namespace,
            address_tree: self.address_tree,
            output_tree: self.output_tree,
            payer: self.payer,
            draft: EntryDraft {
                list_id: spent.list_id,
                member: spent.member,
                state: self.state,
                version: spent
                    .version
                    .checked_add(1)
                    .ok_or(EntryError::VersionOverflow)?,
                content_hash: self.content_hash,
            },
            spent: Some(self.spent),
        }
        .prove(environment.indexer, environment.rpc, environment.prover)?;
        Ok(ProvenEntry {
            ring: self.ring,
            payer: self.payer,
            output_tree: self.output_tree.address,
            written,
            spent: Some(spent),
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
    output_tree: Address,
    written: WrittenEntry,
    spent: Option<ListEntry>,
}

impl ProvenEntry {
    pub const fn entry(&self) -> ListEntry {
        self.written.entry
    }

    pub fn instruction(self) -> Result<Instruction, EntryError> {
        let Self {
            ring,
            payer,
            output_tree,
            written:
                WrittenEntry {
                    entry,
                    input_tree,
                    proof,
                },
            spent,
        } = self;
        let data = match spent {
            None => {
                let mut data = vec![tag::CREATE_ENTRY];
                data.extend_from_slice(&wincode::serialize(&CreateEntryIxData {
                    list_id: entry.list_id as u8,
                    member: *entry.member.as_bytes(),
                    state: entry.state as u8,
                    content_hash: entry.content_hash,
                    blinding: entry.blinding,
                    private_tx_blinding: proof.private_tx_blinding,
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
                    spent_blinding: spent.blinding,
                    state: entry.state as u8,
                    content_hash: entry.content_hash,
                    blinding: entry.blinding,
                    private_tx_blinding: proof.private_tx_blinding,
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
            accounts: NamespaceWriteAccounts {
                ring,
                payer,
                input_tree,
                output_tree,
                nullifier: proof.nullifier,
            }
            .metas(),
            data,
        })
    }
}

pub(crate) struct NamespaceWriteAccounts {
    pub ring: CustomRing,
    pub payer: Address,
    pub input_tree: Address,
    pub output_tree: Address,
    pub nullifier: [u8; 32],
}

impl NamespaceWriteAccounts {
    pub(crate) fn metas(self) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(self.ring.config_pda(), false),
            AccountMeta::new_readonly(self.ring.policy_config_pda(), false),
            AccountMeta::new(self.payer, true),
            AccountMeta::new(self.output_tree, false),
            AccountMeta::new_readonly(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            AccountMeta::new_readonly(Address::default(), false),
            AccountMeta::new(self.input_tree, false),
            AccountMeta::new(
                pda::nullifier_pda(&self.input_tree, &self.nullifier).0,
                false,
            ),
            AccountMeta::new_readonly(self.ring.namespace_pda(), false),
        ]
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
            address_tree: PoolTree::from_id(0),
            output_tree: PoolTree::from_id(0),
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

    #[test]
    fn a_mutation_spends_from_its_input_tree_and_writes_to_its_output_tree() {
        let ring = CustomRing::new(Address::new_from_array([42u8; 32]));
        let input_tree = Address::new_from_array([2u8; 32]);
        let output_tree = Address::new_from_array([4u8; 32]);
        let nullifier = [9u8; 32];
        let metas = NamespaceWriteAccounts {
            ring,
            payer: Address::new_from_array([1u8; 32]),
            input_tree,
            output_tree,
            nullifier,
        }
        .metas();

        assert_eq!(metas[3].pubkey, output_tree);
        assert!(metas[3].is_writable);
        assert_eq!(metas[6].pubkey, input_tree);
        assert!(metas[6].is_writable);
        assert_eq!(
            metas[7].pubkey,
            pda::nullifier_pda(&input_tree, &nullifier).0
        );
        assert!(metas[7].is_writable);
        assert_eq!(metas[8].pubkey, ring.namespace_pda());
    }
}
