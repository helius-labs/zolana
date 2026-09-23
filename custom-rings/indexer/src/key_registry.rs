use crate::{InstructionView, Leaf, OnChainRoot};
use anyhow::{bail, Context, Result};
use custom_ring_interface::{
    instruction::{accounts, tag},
    pda, KeyRegistryLeaf, KeyRegistryRoot, RegisterKeyIxData, RegisteredKey, AUDIT_CIPHERTEXT_LEN,
    COMPRESSED_P256_KEY_LEN,
};
use serde::{Deserialize, Serialize};
use zolana_hasher::HasherError;
use zolana_ring_key_registry::FIELD_MAX;
use zolana_ring_policy::Member;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberKey {
    pub member: [u8; 32],
    pub index: u64,
    pub next: [u8; 32],
    pub key_hash: [u8; 32],
    #[serde(with = "compressed_key")]
    pub eph_pk: [u8; COMPRESSED_P256_KEY_LEN],
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
}

impl Leaf for MemberKey {
    fn sentinel() -> Self {
        Self {
            member: [0; 32],
            index: 0,
            next: FIELD_MAX,
            key_hash: [0; 32],
            eph_pk: [0; COMPRESSED_P256_KEY_LEN],
            ciphertext: [0; AUDIT_CIPHERTEXT_LEN],
        }
    }

    fn member(&self) -> [u8; 32] {
        self.member
    }

    fn index(&self) -> u64 {
        self.index
    }

    fn next(&self) -> [u8; 32] {
        self.next
    }

    fn set_next(&mut self, next: [u8; 32]) {
        self.next = next;
    }

    fn hash(&self) -> Result<[u8; 32], HasherError> {
        KeyRegistryLeaf {
            member: &self.member,
            next: &self.next,
            key: &self.key_hash,
        }
        .hash()
    }
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

impl OnChainRoot for KeyRegistryRoot {
    fn discriminator(&self) -> u8 {
        self.discriminator
    }

    fn root(&self) -> [u8; 32] {
        self.root
    }

    fn next_index(&self) -> u64 {
        KeyRegistryRoot::next_index(self)
    }

    fn bump(&self) -> u8 {
        self.bump
    }
}

#[derive(Debug)]
pub struct Registration {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub next_index: u64,
    pub member: [u8; 32],
    pub key_hash: [u8; 32],
    pub eph_pk: [u8; COMPRESSED_P256_KEY_LEN],
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
}

pub fn registration(instruction: InstructionView<'_>) -> Result<Option<Registration>> {
    if instruction.data.first() != Some(&tag::REGISTER_KEY) {
        return Ok(None);
    }
    let ix: RegisterKeyIxData = wincode::deserialize_exact(&instruction.data[1..])
        .context("invalid key registration wire")?;
    let root = pda::key_registry_root(instruction.program_id).0;
    if instruction.accounts.get(accounts::REGISTER_KEY_ROOT) != Some(&root) {
        bail!("key registration does not name its canonical root");
    }
    let signer = instruction
        .accounts
        .get(accounts::REGISTER_KEY_MEMBER)
        .context("key registration has no member signer")?;
    let member = *Member::owner_tag(&signer.to_bytes())
        .map_err(|error| anyhow::anyhow!("registration member derivation failed ({error:?})"))?
        .as_bytes();
    Ok(Some(Registration {
        old_root: ix.registry_old_root,
        new_root: ix.registry_new_root,
        next_index: ix.registry_next_index,
        member,
        key_hash: RegisteredKey {
            nullifier_pk: &ix.nullifier_pk,
            ciphertext: &ix.ciphertext,
        }
        .hash()?,
        eph_pk: ix.eph_pk,
        ciphertext: ix.ciphertext,
    }))
}
