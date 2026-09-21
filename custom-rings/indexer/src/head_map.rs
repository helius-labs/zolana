use crate::{Append, Leaf, OnChainRoot};
use custom_ring_interface::{HeadMapLeaf, HeadMapRoot};
use parser::Registration;
use serde::{Deserialize, Serialize};
use zolana_hasher::HasherError;
use zolana_indexer_api::RingHeadRecord;
use zolana_ring_head_map::FIELD_MAX;

pub mod parser;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HeadLeaf {
    Sentinel { next: [u8; 32] },
    Member(Box<MemberHead>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberHead {
    pub member: [u8; 32],
    pub index: u64,
    pub next: [u8; 32],
    pub nullifier: [u8; 32],
    pub record: RingHeadRecord,
}

impl HeadLeaf {
    pub fn nullifier(&self) -> [u8; 32] {
        match self {
            Self::Sentinel { .. } => [0; 32],
            Self::Member(head) => head.nullifier,
        }
    }
}

impl Leaf for HeadLeaf {
    fn sentinel() -> Self {
        Self::Sentinel { next: FIELD_MAX }
    }

    fn member(&self) -> [u8; 32] {
        match self {
            Self::Sentinel { .. } => [0; 32],
            Self::Member(head) => head.member,
        }
    }

    fn index(&self) -> u64 {
        match self {
            Self::Sentinel { .. } => 0,
            Self::Member(head) => head.index,
        }
    }

    fn next(&self) -> [u8; 32] {
        match self {
            Self::Sentinel { next } => *next,
            Self::Member(head) => head.next,
        }
    }

    fn set_next(&mut self, next: [u8; 32]) {
        match self {
            Self::Sentinel { next: current } => *current = next,
            Self::Member(head) => head.next = next,
        }
    }

    fn hash(&self) -> Result<[u8; 32], HasherError> {
        let (member, next, nullifier) = (self.member(), self.next(), self.nullifier());
        HeadMapLeaf {
            member: &member,
            next: &next,
            nullifier: &nullifier,
        }
        .hash()
    }
}

impl OnChainRoot for HeadMapRoot {
    fn discriminator(&self) -> u8 {
        self.discriminator
    }

    fn root(&self) -> [u8; 32] {
        self.root
    }

    fn next_index(&self) -> u64 {
        HeadMapRoot::next_index(self)
    }

    fn bump(&self) -> u8 {
        self.bump
    }
}

impl parser::Transfer {
    pub fn replace(self, current: HeadLeaf) -> anyhow::Result<HeadLeaf> {
        let HeadLeaf::Member(mut head) = current else {
            anyhow::bail!("the sentinel cannot transfer");
        };
        if head.member != self.member || !self.nullifiers.contains(&head.nullifier) {
            anyhow::bail!("transfer did not consume the member head");
        }
        head.nullifier = self.nullifier;
        head.record = self.record;
        Ok(HeadLeaf::Member(head))
    }
}

impl Registration {
    pub fn append(self) -> Append<HeadLeaf> {
        let Self {
            old_root,
            new_root,
            next_index,
            member,
            nullifier,
            record,
        } = self;
        Append {
            old_root,
            new_root,
            next_index,
            leaf: HeadLeaf::Member(Box::new(MemberHead {
                member,
                index: next_index,
                next: [0; 32],
                nullifier,
                record,
            })),
        }
    }
}
