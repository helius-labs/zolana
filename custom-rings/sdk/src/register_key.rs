//! Seals a member's nullifier key to the ring auditor and sets it as the escrow key of
//! the member's record, inserting the record when the member has none.

use custom_ring_interface::{
    tag, CustomRingProof, EscrowKey, MemberRecord, MemberUpdate, RegisterKeyIxData,
    RegisterKeyPublicInput,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zeroize::Zeroizing;
use zolana_client::{AsyncIndexer, AsyncRpc, AsyncZolanaClient};
use zolana_hasher::primitives::right_align;
use zolana_keypair::{ShieldedKeypair, X25519Pubkey};
use zolana_ring_client::NullifierKeyEnvelope;
use zolana_ring_member_registry::RegistryOverlay;
use zolana_ring_policy::Member;

use crate::{
    member_registry::{ReadMemberRecord, RecordOpening, RegistryTip},
    projection::retry_projection_lag,
    prover::{RingCircuit, RingRequest},
    request::{RecordUpdate, RegisterKeyBody},
    submission::BoundRoot,
    to_instruction_proof, CustomRing, RegistryBinding, RingError,
};

#[must_use]
#[derive(Clone, Copy)]
pub struct RegisterKey<'a> {
    pub ring: CustomRing,
    /// Also the payer, the member identity derives from it.
    pub member: &'a ShieldedKeypair,
}

#[must_use]
pub struct ProvenKeyRegistration {
    ring: CustomRing,
    member: Address,
    old_root: RegistryBinding,
    new_root: [u8; 32],
    item: MemberUpdate,
    envelope: NullifierKeyEnvelope,
    proof: CustomRingProof,
}

impl RegisterKey<'_> {
    /// Proves key disclosure under the current root, it authorizes no transfer.
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<ProvenKeyRegistration, RingError> {
        let auditor = self
            .ring
            .config(client)
            .await?
            .ok_or(RingError::MissingRingConfig)?
            .auditor_pubkey;
        let member = Address::new_from_array(self.member.signing_pubkey().as_ed25519()?);
        let nullifier_key = &self.member.nullifier_key;
        if nullifier_key.pubkey()? != self.member.shielded_address()?.nullifier_pubkey {
            return Err(RingError::NullifierKeyMismatch);
        }
        let owner = Member::owner_tag(member.as_array())?;
        let (envelope, body, item, root) = retry_projection_lag(|| async {
            let tip = RegistryTip::fetch(self.ring, client).await?;
            let read = ReadMemberRecord {
                ring: self.ring,
                member: owner,
            };
            let record = read.read_at(client, tip.root).await?;
            let envelope = NullifierKeyEnvelope::new(nullifier_key, &auditor)?;
            let secret = Zeroizing::new(right_align(&nullifier_key.secret()));
            let (body, item) = register(&envelope, auditor, secret, &tip, &record.opening)?;
            Ok((envelope, body, item, tip.root))
        })
        .await?;
        let proof = client.prove_request(&RingRequest(&body)).await?;
        Ok(ProvenKeyRegistration {
            ring: self.ring,
            member,
            old_root: RegistryBinding::of(root),
            new_root: body.registry_new_root,
            item,
            envelope,
            proof: to_instruction_proof(proof)?,
        })
    }
}

/// The record keeps its lists and gains the escrow key, a registered key is final.
pub(crate) fn register(
    envelope: &NullifierKeyEnvelope,
    auditor: X25519Pubkey,
    secret: Zeroizing<[u8; 32]>,
    tip: &RegistryTip,
    opening: &RecordOpening,
) -> Result<(RegisterKeyBody, MemberUpdate), RingError> {
    let member = envelope_member(opening)?;
    let escrow_key = EscrowKey {
        nullifier_pk: &envelope.nullifier_pk,
        ciphertext: &envelope.sealed.ciphertext,
    }
    .hash()?;
    let tree_error = |_| RingError::InvalidRecordOpening;
    let mut overlay =
        RegistryOverlay::new(tip.root.next_index, tip.append_path.clone()).map_err(tree_error)?;
    let (item, update, new_root) = match opening {
        RecordOpening::Present {
            record,
            index,
            path,
            ..
        } => {
            if record.escrow_key != [0; 32] {
                return Err(RingError::KeyAlreadyRegistered { member });
            }
            let after = MemberRecord {
                escrow_key,
                ..*record
            };
            let new_root = overlay
                .write(*index, after.hash()?, path)
                .map_err(tree_error)?;
            let item = MemberUpdate {
                member: record.member,
                old_lists: record.lists,
                old_escrow_key: [0; 32],
                lists: record.lists,
                escrow_key,
                index: *index,
            };
            (
                item,
                RecordUpdate::rewrite(record.next, *index, path.clone()),
                new_root,
            )
        }
        RecordOpening::Absent {
            low,
            low_index,
            path: low_path,
        } => {
            let index = tip.root.next_index;
            let relinked = MemberRecord {
                next: *member.as_bytes(),
                ..*low
            };
            overlay
                .write(*low_index, relinked.hash()?, low_path)
                .map_err(tree_error)?;
            let path = overlay.path(index, None).map_err(tree_error)?;
            let record = MemberRecord {
                member: *member.as_bytes(),
                next: low.next,
                lists: 0,
                escrow_key,
            };
            let new_root = overlay
                .write(index, record.hash()?, &path)
                .map_err(tree_error)?;
            let item = MemberUpdate {
                member: *member.as_bytes(),
                old_lists: 0,
                old_escrow_key: [0; 32],
                lists: 0,
                escrow_key,
                index,
            };
            (
                item,
                RecordUpdate::insert(low, *low_index, low_path.clone(), index, path),
                new_root,
            )
        }
    };
    let public_input_hash = RegisterKeyPublicInput {
        registry_old_root: &tip.root.root,
        registry_new_root: &new_root,
        member: member.as_bytes(),
        nullifier_pk: &envelope.nullifier_pk,
        auditor_pk: auditor.as_bytes(),
        eph_pk: envelope.sealed.eph_pk.as_bytes(),
        ciphertext: &envelope.sealed.ciphertext,
        index: item.index,
    }
    .hash()?;
    let body = RegisterKeyBody {
        circuit_type: RingCircuit::RegisterKey,
        public_input_hash,
        registry_old_root: tip.root.root,
        registry_new_root: new_root,
        member: *member.as_bytes(),
        lists: item.lists,
        update,
        nullifier_secret: secret,
        eph_sk: envelope.ephemeral_sk.clone(),
        auditor_pk: auditor,
    };
    Ok((body, item))
}

/// The opening was read for one member, which only its record or its low record names.
fn envelope_member(opening: &RecordOpening) -> Result<Member, RingError> {
    match opening {
        RecordOpening::Present { record, .. } => Ok(Member::from_bytes(record.member)?),
        RecordOpening::Absent { .. } => Err(RingError::InvalidRecordOpening),
    }
}

impl ProvenKeyRegistration {
    pub fn item(&self) -> &MemberUpdate {
        &self.item
    }

    pub(crate) fn bound_root(&self) -> Option<BoundRoot> {
        Some(BoundRoot::registry(self.ring, self.old_root))
    }

    pub fn instruction(self) -> Result<Instruction, RingError> {
        let mut data = vec![tag::REGISTER_KEY];
        data.extend(wincode::serialize(&RegisterKeyIxData {
            proof: self.proof,
            old_root_index: self.old_root.root_index,
            new_root: self.new_root,
            item: self.item,
            nullifier_pk: self.envelope.nullifier_pk,
            eph_pk: *self.envelope.sealed.eph_pk.as_bytes(),
            ciphertext: self.envelope.sealed.ciphertext,
        })?);
        Ok(Instruction {
            program_id: self.ring.program_id(),
            accounts: vec![
                AccountMeta::new_readonly(self.member, true),
                AccountMeta::new_readonly(self.ring.config_pda(), false),
                AccountMeta::new(self.ring.member_registry_root_pda(), false),
            ],
            data,
        })
    }
}
