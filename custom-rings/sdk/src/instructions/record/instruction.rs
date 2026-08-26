use custom_ring_interface::{tag, CreateRecordIxData, UpdateRecordIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use thiserror::Error;
use zolana_client::{ProverClient, Rpc};
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;
use zolana_ring_policy::{Member, Record, RecordKind, RecordState, RecordsOwner};

use crate::{
    instructions::record::proof::{RecordProof, RecordProofError, RecordWitness},
    CustomRing,
};

#[derive(Debug, Error)]
pub enum RecordError {
    #[error(transparent)]
    Proof(#[from] RecordProofError),
    #[error("records owner hashing failed")]
    Hashing,
    #[error("record version overflows")]
    VersionOverflow,
    #[error(transparent)]
    Encoding(#[from] wincode::WriteError),
}

#[must_use]
pub struct CreatePolicy {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub records_tree: Address,
}

impl CreatePolicy {
    pub fn instruction(self) -> Instruction {
        let Self {
            ring,
            payer,
            authority,
            records_tree,
        } = self;
        Instruction {
            program_id: ring.program_id(),
            accounts: vec![
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new(ring.policy_config_pda(), false),
                AccountMeta::new_readonly(records_tree, false),
                AccountMeta::new_readonly(Address::default(), false),
                AccountMeta::new_readonly(ring.program_id(), false),
                AccountMeta::new_readonly(ring.program_data_pda(), false),
            ],
            data: vec![tag::CREATE_POLICY],
        }
    }
}

#[must_use]
pub struct CreateRecord {
    pub ring: CustomRing,
    pub payer: Address,
    pub records_tree: Address,
    pub kind: RecordKind,
    pub member: Member,
    pub state: RecordState,
    pub payload_hash: [u8; 32],
}

impl CreateRecord {
    pub fn prove<I: Rpc, R: Rpc>(
        self,
        environment: RecordProofEnvironment<'_, I, R>,
    ) -> Result<ProvenRecord, RecordError> {
        let records = self.ring.records_pda();
        let owner = RecordsOwner::new(records.as_array()).map_err(|_| RecordError::Hashing)?;
        let record = Record {
            kind: self.kind,
            member: self.member,
            state: self.state,
            version: 0,
            payload_hash: self.payload_hash,
        };
        let proof = RecordWitness {
            owner: &owner,
            records,
            records_tree: self.records_tree,
            payer: self.payer,
            record,
            spent: None,
        }
        .prove(environment.indexer, environment.rpc, environment.prover)?;
        Ok(ProvenRecord {
            ring: self.ring,
            payer: self.payer,
            records_tree: self.records_tree,
            record,
            spent: None,
            proof,
        })
    }
}

#[must_use]
pub struct UpdateRecord {
    pub ring: CustomRing,
    pub payer: Address,
    pub records_tree: Address,
    pub spent: Record,
    pub state: RecordState,
    pub payload_hash: [u8; 32],
}

impl UpdateRecord {
    pub fn prove<I: Rpc, R: Rpc>(
        self,
        environment: RecordProofEnvironment<'_, I, R>,
    ) -> Result<ProvenRecord, RecordError> {
        let records = self.ring.records_pda();
        let owner = RecordsOwner::new(records.as_array()).map_err(|_| RecordError::Hashing)?;
        let record = Record {
            kind: self.spent.kind,
            member: self.spent.member,
            state: self.state,
            version: self
                .spent
                .version
                .checked_add(1)
                .ok_or(RecordError::VersionOverflow)?,
            payload_hash: self.payload_hash,
        };
        let proof = RecordWitness {
            owner: &owner,
            records,
            records_tree: self.records_tree,
            payer: self.payer,
            record,
            spent: Some(self.spent),
        }
        .prove(environment.indexer, environment.rpc, environment.prover)?;
        Ok(ProvenRecord {
            ring: self.ring,
            payer: self.payer,
            records_tree: self.records_tree,
            record,
            spent: Some(self.spent),
            proof,
        })
    }
}

pub struct RecordProofEnvironment<'a, I: Rpc, R: Rpc> {
    pub indexer: &'a I,
    pub rpc: &'a R,
    pub prover: &'a ProverClient,
}

#[must_use]
pub struct ProvenRecord {
    ring: CustomRing,
    payer: Address,
    records_tree: Address,
    record: Record,
    spent: Option<Record>,
    proof: RecordProof,
}

impl ProvenRecord {
    pub const fn record(&self) -> Record {
        self.record
    }

    pub fn instruction(self) -> Result<Instruction, RecordError> {
        let Self {
            ring,
            payer,
            records_tree,
            record,
            spent,
            proof,
        } = self;
        let data = match spent {
            None => {
                let mut data = vec![tag::CREATE_RECORD];
                data.extend_from_slice(&wincode::serialize(&CreateRecordIxData {
                    kind: record.kind as u8,
                    member: *record.member.as_bytes(),
                    state: record.state as u8,
                    payload_hash: record.payload_hash,
                    nullifier_tree_root_index: proof.nullifier_tree_root_index,
                    utxo_tree_root_index: proof.utxo_tree_root_index,
                    proof: proof.proof,
                })?);
                data
            }
            Some(spent) => {
                let mut data = vec![tag::UPDATE_RECORD];
                data.extend_from_slice(&wincode::serialize(&UpdateRecordIxData {
                    kind: record.kind as u8,
                    member: *record.member.as_bytes(),
                    spent_state: spent.state as u8,
                    spent_payload_hash: spent.payload_hash,
                    spent_version: spent.version,
                    state: record.state as u8,
                    payload_hash: record.payload_hash,
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
                AccountMeta::new(records_tree, false),
                AccountMeta::new(records_tree, false),
                AccountMeta::new_readonly(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
                AccountMeta::new_readonly(Address::default(), false),
                AccountMeta::new_readonly(ring.records_pda(), false),
            ],
            data,
        })
    }
}
