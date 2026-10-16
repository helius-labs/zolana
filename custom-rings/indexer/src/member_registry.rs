use crate::InstructionView;
use anyhow::{bail, Context, Result};
use custom_ring_interface::{
    instruction::{accounts, tag},
    MemberRecord, MemberRegistryRoot, MemberUpdate, RegisterKeyIxData, UpdateMembersIxData,
    AUDIT_CIPHERTEXT_LEN, COMPRESSED_P256_KEY_LEN, FIELD_MAX, MAX_MEMBER_BATCH,
};
use serde::{Deserialize, Serialize};
use zolana_hasher::HasherError;
use zolana_ring_policy::Member;

/// The nullifier secret a member sealed to the auditor at registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedKey {
    #[serde(with = "compressed_key")]
    pub eph_pk: [u8; COMPRESSED_P256_KEY_LEN],
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
}

/// One projected record, the sealed key stays with the record its escrow key hashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRecordRow {
    pub member: [u8; 32],
    pub index: u64,
    pub next: [u8; 32],
    pub lists: u64,
    pub escrow_key: [u8; 32],
    #[serde(default)]
    pub seal: Option<SealedKey>,
}

impl MemberRecordRow {
    pub fn sentinel() -> Self {
        Self {
            member: [0; 32],
            index: 0,
            next: FIELD_MAX,
            lists: 0,
            escrow_key: [0; 32],
            seal: None,
        }
    }

    pub fn record(&self) -> MemberRecord {
        MemberRecord {
            member: self.member,
            next: self.next,
            lists: self.lists,
            escrow_key: self.escrow_key,
        }
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        self.record().hash()
    }
}

/// A proven batch of record writes, items in the order the program applied them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub new_root: [u8; 32],
    pub items: Vec<MemberUpdate>,
    /// Set by `register_key`, the one item's sealed nullifier secret.
    pub seal: Option<SealedKey>,
}

/// The batch a `register_key` or `update_members` instruction wrote, `None` for any other tag.
pub fn batch(instruction: InstructionView<'_>) -> Result<Option<Batch>> {
    let Some((tag, data)) = instruction.data.split_first() else {
        return Ok(None);
    };
    let (root_slot, batch) = match *tag {
        tag::REGISTER_KEY => {
            let ix: RegisterKeyIxData =
                wincode::deserialize_exact(data).context("invalid key registration wire")?;
            let signer = instruction
                .accounts
                .get(accounts::REGISTER_KEY_MEMBER)
                .context("key registration has no member signer")?;
            let member = Member::owner_tag(&signer.to_bytes())
                .context("registration member derivation failed")?;
            if ix.item.member != *member.as_bytes() {
                bail!("key registration item is not the signer's record");
            }
            let batch = Batch {
                new_root: ix.new_root,
                items: vec![ix.item],
                seal: Some(SealedKey {
                    eph_pk: ix.eph_pk,
                    ciphertext: ix.ciphertext,
                }),
            };
            (accounts::REGISTER_KEY_ROOT, batch)
        }
        tag::UPDATE_MEMBERS => {
            let ix: UpdateMembersIxData =
                wincode::deserialize_exact(data).context("invalid member batch wire")?;
            let batch = Batch {
                new_root: ix.new_root,
                items: ix.items,
                seal: None,
            };
            (accounts::UPDATE_MEMBERS_ROOT, batch)
        }
        _ => return Ok(None),
    };
    let root = solana_address::Address::find_program_address(
        &[MemberRegistryRoot::SEED],
        instruction.program_id,
    )
    .0;
    if instruction.accounts.get(root_slot) != Some(&root) {
        bail!("member batch does not name its canonical root");
    }
    if !(1..=MAX_MEMBER_BATCH).contains(&batch.items.len()) {
        bail!("member batch size out of range");
    }
    if batch
        .items
        .windows(2)
        .any(|pair| pair[0].member >= pair[1].member)
    {
        bail!("member batch is not strictly ascending");
    }
    Ok(Some(batch))
}

mod compressed_key {
    use custom_ring_interface::COMPRESSED_P256_KEY_LEN;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        value: &[u8; COMPRESSED_P256_KEY_LEN],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; COMPRESSED_P256_KEY_LEN], D::Error> {
        Vec::<u8>::deserialize(deserializer)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("eph_pk must be 33 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use custom_ring_interface::{CustomRingProof, PlainGroth16Proof};
    use solana_address::Address;

    fn program() -> Address {
        Address::new_from_array([7; 32])
    }

    fn root() -> Address {
        Address::find_program_address(&[MemberRegistryRoot::SEED], &program()).0
    }

    fn proof() -> CustomRingProof {
        CustomRingProof {
            groth16: PlainGroth16Proof {
                proof_a: [1; 32],
                proof_b: [2; 64],
                proof_c: [3; 32],
            },
            commitment: [4; 32],
            commitment_pok: [5; 32],
        }
    }

    fn item(member: [u8; 32], index: u64) -> MemberUpdate {
        MemberUpdate {
            member,
            lists: 1,
            index,
            ..MemberUpdate::default()
        }
    }

    fn update_members(items: Vec<MemberUpdate>) -> Vec<u8> {
        let mut data = vec![tag::UPDATE_MEMBERS];
        data.extend(
            wincode::serialize(&UpdateMembersIxData {
                proof: proof(),
                old_root_index: 0,
                new_root: [9; 32],
                items,
            })
            .unwrap(),
        );
        data
    }

    #[test]
    fn a_batch_names_its_canonical_root_in_member_order() {
        let items = vec![item([1; 32], 1), item([2; 32], 2)];
        let data = update_members(items.clone());
        let accounts = [Address::new_from_array([3; 32]), root()];
        let batch = batch(InstructionView {
            program_id: &program(),
            accounts: &accounts,
            data: &data,
        })
        .unwrap()
        .unwrap();
        assert_eq!(batch.items, items);
        assert_eq!(batch.new_root, [9; 32]);
        assert!(batch.seal.is_none());

        let other = [Address::new_from_array([3; 32]), Address::new_from_array([4; 32])];
        assert!(batch_of(&other, &data).is_err());
        let unordered = update_members(vec![item([2; 32], 1), item([1; 32], 2)]);
        assert!(batch_of(&accounts, &unordered).is_err());
        assert!(batch_of(&accounts, &update_members(Vec::new())).is_err());
        assert_eq!(batch_of(&accounts, &[tag::SET_PAUSED, 1]).unwrap(), None);
    }

    fn batch_of(accounts: &[Address], data: &[u8]) -> Result<Option<Batch>> {
        batch(InstructionView {
            program_id: &program(),
            accounts,
            data,
        })
    }

    #[test]
    fn a_registration_is_the_signers_single_item_with_its_seal() {
        let signer = Address::new_from_array([5; 32]);
        let member = *Member::owner_tag(signer.as_array()).unwrap().as_bytes();
        let registration = |member| {
            let mut data = vec![tag::REGISTER_KEY];
            data.extend(
                wincode::serialize(&RegisterKeyIxData {
                    proof: proof(),
                    old_root_index: 0,
                    new_root: [9; 32],
                    item: MemberUpdate {
                        member,
                        escrow_key: [6; 32],
                        index: 1,
                        ..MemberUpdate::default()
                    },
                    nullifier_pk: [7; 32],
                    eph_pk: [8; 33],
                    ciphertext: [9; 32],
                })
                .unwrap(),
            );
            data
        };
        let accounts = [signer, Address::new_from_array([3; 32]), root()];
        let batch = batch_of(&accounts, &registration(member)).unwrap().unwrap();
        assert_eq!(batch.items.len(), 1);
        assert_eq!(batch.items[0].member, member);
        assert_eq!(
            batch.seal,
            Some(SealedKey {
                eph_pk: [8; 33],
                ciphertext: [9; 32],
            })
        );
        assert!(batch_of(&accounts, &registration([1; 32])).is_err());
    }
}
