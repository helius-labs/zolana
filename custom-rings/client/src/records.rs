//! Member record views as record tree types, every opening checked against its root.

use custom_ring_interface::{
    EscrowKey, QueueEntry, AUDIT_CIPHERTEXT_LEN, QUAD_ARITY, QUAD_HEIGHT, TAGGED_X25519_KEY_LEN,
};
use solana_address::Address;
use zolana_hasher::{primitives::hash_bytes, HasherError};
use zolana_indexer_api::{
    GetRingApplyProofInputsResponse, GetRingMemberRecordsResponse, RingMemberOpening,
    RingMemberRecordView, RingRecordPathView, RingRecordWriteView, MAX_RING_MEMBER_PAGE_LIMIT,
};
use zolana_keypair::X25519Pubkey;
use zolana_ring_member_registry::{
    ApplyProofInputs, MemberRecord, QuadPath, RecordOpening, RecordWriteProofInput,
};
use zolana_ring_policy::ListId;

use crate::{AuditError, SealedNullifierKey};

/// A member's record, or the low record bracketing its absence, read under one root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberOpeningRead {
    pub opening: RecordOpening,
    /// The nullifier secret a registered member sealed to the auditor.
    pub sealed: Option<SealedNullifierKey>,
    /// The `RegisterKey` signer whose owner identity is the member.
    pub owner_pubkey: Option<Address>,
    /// The key the escrow key binds beside the sealed secret.
    pub nullifier_pk: Option<[u8; 32]>,
}

/// The chain-pinned newest registry root every record page is read under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryTip {
    pub root: [u8; 32],
    pub root_index: u8,
    pub next_index: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EscrowedRecord<'a> {
    pub record: &'a MemberRecord,
    pub path: &'a QuadPath,
    pub sealed: &'a SealedNullifierKey,
}

impl EscrowedRecord<'_> {
    /// What the escrow key binds beside the nullifier key.
    pub fn ct_hash(&self) -> Result<[u8; 32], HasherError> {
        hash_bytes(&self.sealed.ciphertext)
    }
}

impl MemberOpeningRead {
    /// `member`'s opening under `root`, refused unless the path reaches the root.
    pub fn verify(
        view: &RingMemberOpening,
        root: &[u8; 32],
        member: &[u8; 32],
    ) -> Result<Self, AuditError> {
        let record = member_record(&view.record);
        let path = quad_path(&view.path)?;
        let opening = match view.present {
            true => RecordOpening::Present { record, path },
            false => RecordOpening::Absent { low: record, path },
        };
        opening
            .verify(root, member)
            .map_err(|_| AuditError::InvalidMemberRegistry)?;
        // An absent member's opening carries the low record, its keys belong to another member.
        let registered = view.present.then_some(&view.record);
        Ok(Self {
            opening,
            sealed: registered.map(sealed_key).transpose()?.flatten(),
            owner_pubkey: registered
                .and_then(|record| record.owner_pubkey.as_ref())
                .map(|owner| owner.0),
            nullifier_pk: registered
                .and_then(|record| record.nullifier_pk.as_ref())
                .map(|key| key.0),
        })
    }

    /// The member's record, `None` for an absent member.
    pub fn record(&self) -> Option<&MemberRecord> {
        match &self.opening {
            RecordOpening::Present { record, .. } => Some(record),
            RecordOpening::Absent { .. } => None,
        }
    }

    pub fn listed(&self, list: ListId) -> bool {
        self.record()
            .is_some_and(|record| record.lists & list.record_bit() != 0)
    }

    /// `None` unless the record's escrow key binds `nullifier_pk` to the sealed secret.
    pub fn escrowed(
        &self,
        nullifier_pk: &[u8; 32],
    ) -> Result<Option<EscrowedRecord<'_>>, AuditError> {
        let (RecordOpening::Present { record, path }, Some(sealed)) = (&self.opening, &self.sealed)
        else {
            return Ok(None);
        };
        let escrow_key = EscrowKey {
            nullifier_pk,
            ciphertext: &sealed.ciphertext,
        }
        .hash()?;
        Ok((escrow_key == record.escrow_key).then_some(EscrowedRecord {
            record,
            path,
            sealed,
        }))
    }
}

/// Ten levels of three siblings, leaf level first.
pub fn quad_path(view: &RingRecordPathView) -> Result<QuadPath, AuditError> {
    let levels: [[_; QUAD_ARITY - 1]; QUAD_HEIGHT] = view
        .siblings
        .iter()
        .map(|level| level.clone().map(|sibling| sibling.0))
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| AuditError::InvalidMemberRegistry)?;
    Ok(QuadPath {
        index: view.index,
        siblings: levels,
    })
}

pub fn member_record(view: &RingMemberRecordView) -> MemberRecord {
    MemberRecord {
        member: view.member.0,
        next: view.next.0,
        lists: view.lists,
        escrow_key: view.escrow_key.0,
    }
}

/// The proof inputs of one application, in queue order.
pub fn apply_proof_inputs(
    response: &GetRingApplyProofInputsResponse,
) -> Result<ApplyProofInputs, AuditError> {
    Ok(ApplyProofInputs {
        old_root: response.old_root.0,
        new_root: response.new_root.0,
        old_next_index: response.old_next_index,
        new_next_index: response.new_next_index,
        chain_start: response.chain_start.0,
        chain_end: response.chain_end.0,
        writes: response
            .writes
            .iter()
            .map(record_write)
            .collect::<Result<_, _>>()?,
    })
}

/// A short, oversized or gapped page cannot silently reduce registry coverage.
pub fn complete_member_page(
    response: &GetRingMemberRecordsResponse,
    tip: RegistryTip,
    start_index: u64,
) -> bool {
    if start_index >= tip.next_index {
        return false;
    }
    let end_index = start_index + (tip.next_index - start_index).min(MAX_RING_MEMBER_PAGE_LIMIT);
    response.root.root.0 == tip.root
        && response.root.root_index == tip.root_index
        && response.root.next_index == tip.next_index
        && response.records.len() == (end_index - start_index) as usize
        && response
            .records
            .iter()
            .enumerate()
            .all(|(offset, row)| row.path.index == start_index + offset as u64)
        && response.next_leaf_index == (end_index < tip.next_index).then_some(end_index)
}

/// The sealed nullifier secret a record view carries, refused when only half of it is present.
pub(crate) fn sealed_key(
    view: &RingMemberRecordView,
) -> Result<Option<SealedNullifierKey>, AuditError> {
    let (eph_pk, ciphertext) = match (&view.eph_pk, &view.ciphertext) {
        (Some(eph_pk), Some(ciphertext)) => (eph_pk, ciphertext),
        (None, None) => return Ok(None),
        _ => return Err(AuditError::InvalidMemberRegistry),
    };
    Ok(Some(SealedNullifierKey {
        eph_pk: X25519Pubkey::from_bytes(
            <[u8; TAGGED_X25519_KEY_LEN]>::try_from(eph_pk.0.as_slice())
                .map_err(|_| AuditError::InvalidMemberRegistry)?,
        )?,
        ciphertext: <[u8; AUDIT_CIPHERTEXT_LEN]>::try_from(ciphertext.0.as_slice())
            .map_err(|_| AuditError::InvalidMemberRegistry)?,
    }))
}

fn record_write(view: &RingRecordWriteView) -> Result<RecordWriteProofInput, AuditError> {
    Ok(RecordWriteProofInput {
        entry: QueueEntry {
            member: view.member.0,
            mask: view.mask,
            value: view.value,
            escrow_key: view.escrow_key.0,
        },
        exists: view.exists,
        old_next: view.old_next.0,
        old_lists: view.old_lists,
        old_escrow: view.old_escrow.0,
        slot: quad_path(&view.slot)?,
        low: member_record(&view.low),
        low_path: quad_path(&view.low_path)?,
    })
}
