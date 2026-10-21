use custom_ring_interface::{
    instruction::{accounts, tag},
    ApplyRecordsIxData, AuthorityWriteRecordsIxData, CustomRingError, EscrowKey, MemberRegistry,
    QueueEntry, RecordQueue, RecordWriteData, RegisterKeyIxData, WriteRecordsIxData,
};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use thiserror::Error;
use zolana_ring_policy::{Member, MemberError, Writer};

use crate::InstructionView;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordCall {
    Create(RegistryAccounts),
    Change(Box<RecordChange>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordChange {
    pub accounts: RegistryAccounts,
    pub action: RecordAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordAction {
    Queue(QueuedWrite),
    /// The writes queue behind the pending ones, then the whole queue applies.
    AuthorityWrite {
        writes: Vec<QueueEntry>,
        apply: ApplyRecordsIxData,
    },
    Apply(ApplyRecordsIxData),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueuedWrite {
    pub entry: QueueEntry,
    pub seal: Option<SealedKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedKey {
    /// The RegisterKey signer, its owner identity is the record's member.
    pub owner_pubkey: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub eph_u: [u8; 32],
    pub ciphertext: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryAccounts {
    pub registry: Address,
    pub queue: Address,
}

pub struct CanonicalAccounts {
    pub accounts: RegistryAccounts,
    pub registry_bump: u8,
    pub queue_bump: u8,
}

impl CanonicalAccounts {
    pub fn of(program: &Address) -> Self {
        let (registry, registry_bump) =
            Address::find_program_address(&[MemberRegistry::SEED], program);
        let (queue, queue_bump) = Address::find_program_address(&[RecordQueue::SEED], program);
        Self {
            accounts: RegistryAccounts { registry, queue },
            registry_bump,
            queue_bump,
        }
    }
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error(transparent)]
    Ring(#[from] CustomRingError),
    #[error("record instruction has no account {0}")]
    MissingAccount(usize),
    #[error("member derivation failed ({0})")]
    Member(#[from] MemberError),
}

/// `None` for an instruction that touches no record.
pub fn decode(instruction: InstructionView<'_>) -> Result<Option<RecordCall>, DecodeError> {
    let Some((&tag, data)) = instruction.data.split_first() else {
        return Ok(None);
    };
    let named = |[registry, queue]: [usize; 2]| -> Result<RegistryAccounts, DecodeError> {
        Ok(RegistryAccounts {
            registry: account(&instruction, registry)?,
            queue: account(&instruction, queue)?,
        })
    };
    let written = [
        accounts::RECORD_WRITE_REGISTRY,
        accounts::RECORD_WRITE_QUEUE,
    ];
    let (accounts, action) = match tag {
        tag::CREATE_MEMBER_REGISTRY => {
            let created = [
                accounts::CREATE_MEMBER_REGISTRY_REGISTRY,
                accounts::CREATE_MEMBER_REGISTRY_QUEUE,
            ];
            return Ok(Some(RecordCall::Create(named(created)?)));
        }
        tag::WRITE_RECORDS => {
            let data = WriteRecordsIxData::parse(data)?;
            let member = member_of(&account(&instruction, accounts::RECORD_WRITE_SIGNER)?)?;
            let entry = data.entry(member, Writer::Member)?;
            let write = QueuedWrite { entry, seal: None };
            (named(written)?, RecordAction::Queue(write))
        }
        tag::REGISTER_KEY => {
            let data = RegisterKeyIxData::parse(data)?;
            let signer = account(&instruction, accounts::RECORD_WRITE_SIGNER)?;
            let key = EscrowKey {
                nullifier_pk: &data.nullifier_pk,
                ciphertext: &data.ciphertext,
            };
            let write = QueuedWrite {
                entry: QueueEntry::escrow(member_of(&signer)?, &key)?,
                seal: Some(SealedKey {
                    owner_pubkey: signer.to_bytes(),
                    nullifier_pk: data.nullifier_pk,
                    eph_u: data.eph_u,
                    ciphertext: data.ciphertext,
                }),
            };
            (named(written)?, RecordAction::Queue(write))
        }
        tag::AUTHORITY_WRITE_RECORDS => {
            let data = AuthorityWriteRecordsIxData::parse(data)?;
            let writes = data
                .writes
                .iter()
                .map(RecordWriteData::entry)
                .collect::<Result<_, _>>()?;
            let apply = *data.apply;
            (
                named(written)?,
                RecordAction::AuthorityWrite { writes, apply },
            )
        }
        tag::APPLY_RECORDS => {
            let apply = *ApplyRecordsIxData::parse(data)?;
            let applied = [
                accounts::APPLY_RECORDS_REGISTRY,
                accounts::APPLY_RECORDS_QUEUE,
            ];
            (named(applied)?, RecordAction::Apply(apply))
        }
        _ => return Ok(None),
    };
    let change = RecordChange { accounts, action };
    Ok(Some(RecordCall::Change(Box::new(change))))
}

fn account(instruction: &InstructionView<'_>, slot: usize) -> Result<Address, DecodeError> {
    instruction
        .accounts
        .get(slot)
        .copied()
        .ok_or(DecodeError::MissingAccount(slot))
}

fn member_of(signer: &Address) -> Result<[u8; 32], MemberError> {
    Ok(*Member::owner_tag(signer.as_array())?.as_bytes())
}
