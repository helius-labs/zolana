pub(super) mod parser;

use custom_ring_interface::{
    instruction::{accounts, tag},
    pda, HeadMapLeaf, HeadMapRoot, HEAD_MAP_ROOT,
};
use sea_orm::{DatabaseConnection, DatabaseTransaction};
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use zolana_hasher::HasherError;
use zolana_indexer_api::{
    GetRingHeadRegisterProofResponse, GetRingHeadTransferProofResponse, Hash, RingHeadRecord,
    RingMemberProofRequest,
};
use zolana_ring_head_map::FIELD_MAX;

use super::{
    api::{self, Insertion, MemberPath},
    append, fault,
    storage::{LeafWrite, MemberRestore, RingRoot, RingStore, Undo},
    Append, BlockEnv, Invocation, Leaf, OnChainRoot, ProjectError, Projection, ProjectionKind,
    Step,
};
use crate::{api::error::PhotonApiError, rpc::RpcClient};
pub(crate) use parser::{Registration, Transfer, Transition};

pub(crate) struct HeadMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum HeadLeaf {
    Sentinel { next: [u8; 32] },
    Member(Box<MemberHead>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct MemberHead {
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

impl Projection for HeadMap {
    const KIND: ProjectionKind = ProjectionKind::HeadMap;
    const INIT_TAG: u8 = tag::CREATE_HEAD_MAP_ROOT;
    const INIT_ROOT_SLOT: usize = accounts::CREATE_HEAD_MAP_ROOT_ROOT;
    const TRANSITION_TAGS: &'static [u8] = &[tag::REGISTER_SPEND, tag::TRANSACT];
    const ROOT_DISCRIMINATOR: u8 = HEAD_MAP_ROOT;
    type Root = HeadMapRoot;
    type Leaf = HeadLeaf;
    type Transition = Transition;

    fn root_address(program: &Pubkey) -> (Pubkey, u8) {
        pda::head_map_root(program)
    }

    async fn transition(
        invocation: &Invocation<'_>,
        env: &mut BlockEnv<'_>,
    ) -> Result<Option<Transition>, ProjectError> {
        parser::transition(invocation, env).await
    }

    async fn apply(
        store: &RingStore<'_, DatabaseTransaction, Self>,
        step: Step<'_, Transition>,
    ) -> Result<Undo<HeadLeaf>, ProjectError> {
        let Step {
            root,
            transition,
            revision,
        } = step;
        match transition {
            Transition::Register(registration) => {
                append::<Self>(
                    store,
                    Step {
                        root,
                        transition: registration.append(),
                        revision,
                    },
                )
                .await
            }
            Transition::Transfer(transfer) => {
                replace(
                    store,
                    Step {
                        root,
                        transition: transfer,
                        revision,
                    },
                )
                .await
            }
        }
    }
}

impl Registration {
    fn append(self) -> Append<HeadLeaf> {
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

async fn replace(
    store: &RingStore<'_, DatabaseTransaction, HeadMap>,
    step: Step<'_, Transfer>,
) -> Result<Undo<HeadLeaf>, ProjectError> {
    let Step {
        root,
        transition,
        revision,
    } = step;
    let Transfer {
        old_root,
        new_root,
        member,
        nullifiers,
        nullifier,
        record,
    } = transition;
    if old_root != root.root {
        return Err(fault("old root mismatch"));
    }
    let current = store
        .member(&member)
        .await?
        .ok_or_else(|| fault("transfer member is unregistered"))?;
    let HeadLeaf::Member(mut head) = current.clone() else {
        return Err(fault("the sentinel cannot transfer"));
    };
    if !nullifiers.contains(&head.nullifier) {
        return Err(fault("transfer did not consume the member's head"));
    }
    let undo = Undo {
        program: root.program,
        before: Some(root.clone()),
        members: vec![MemberRestore {
            member,
            before: Some(current.clone()),
        }],
        leaves: vec![LeafWrite {
            index: head.index,
            hash: current.hash()?,
        }],
    };
    head.nullifier = nullifier;
    head.record = record;
    let leaf = HeadLeaf::Member(head);
    let computed = store
        .write_leaves(
            &root.address,
            &[LeafWrite {
                index: leaf.index(),
                hash: leaf.hash()?,
            }],
            revision,
        )
        .await?;
    if computed != new_root {
        return Err(fault("new root mismatch"));
    }
    store.save_member(&leaf).await?;
    store
        .save_root(&RingRoot {
            root: new_root,
            ..root.clone()
        })
        .await?;
    Ok(undo)
}

pub(crate) async fn register(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: RingMemberProofRequest,
) -> Result<GetRingHeadRegisterProofResponse, PhotonApiError> {
    let Insertion {
        context,
        root,
        low,
        low_proof,
        new_proof,
    } = api::insertion::<HeadMap>(db, rpc, &request).await?;
    Ok(GetRingHeadRegisterProofResponse {
        context,
        root: Hash(root.root),
        next_index: root.next_index,
        member: request.member,
        low_member: Hash(low.member()),
        low_next: Hash(low.next()),
        low_nullifier: Hash(low.nullifier()),
        low_index: low.index(),
        low_proof: low_proof.into_iter().map(Hash).collect(),
        new_proof: new_proof.into_iter().map(Hash).collect(),
    })
}

pub(crate) async fn transfer(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: RingMemberProofRequest,
) -> Result<GetRingHeadTransferProofResponse, PhotonApiError> {
    let MemberPath {
        context,
        root,
        leaf,
        proof,
    } = api::member_path::<HeadMap>(db, rpc, &request).await?;
    let HeadLeaf::Member(head) = leaf else {
        return Err(PhotonApiError::UnexpectedError(
            "the sentinel was served as a member".into(),
        ));
    };
    let MemberHead {
        next,
        nullifier,
        index,
        record,
        ..
    } = *head;
    Ok(GetRingHeadTransferProofResponse {
        context,
        root: Hash(root.root),
        next_index: root.next_index,
        member: request.member,
        next: Hash(next),
        nullifier: Hash(nullifier),
        index,
        proof: proof.into_iter().map(Hash).collect(),
        record,
    })
}

#[cfg(test)]
mod tests;
