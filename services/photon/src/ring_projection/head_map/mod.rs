pub(super) mod parser;

use custom_ring_interface::{
    instruction::{accounts, tag},
    pda, HeadMapRoot, HEAD_MAP_ROOT,
};
use sea_orm::{DatabaseConnection, DatabaseTransaction};
use solana_pubkey::Pubkey;
use zolana_indexer_api::{
    GetRingHeadRegisterProofResponse, GetRingHeadTransferProofResponse, Hash,
    RingMemberProofRequest,
};

use super::{
    api::{self, Insertion, MemberPath},
    append, fault,
    storage::{LeafWrite, MemberRestore, RingRoot, RingStore, Undo},
    BlockEnv, Invocation, Leaf, ProjectError, Projection, ProjectionKind, Step,
};
use crate::{api::error::PhotonApiError, rpc::RpcClient};
#[cfg(test)]
use parser::Registration;
pub(crate) use parser::{Transfer, Transition};

pub(crate) struct HeadMap;

pub(crate) use zolana_ring_indexer::head_map::{HeadLeaf, MemberHead};

impl Projection for HeadMap {
    const KIND: ProjectionKind = ProjectionKind::HeadMap;
    const INIT_TAG: u8 = tag::CREATE_HEAD_MAP_ROOT;
    const INIT_ROOT_SLOT: usize = accounts::CREATE_HEAD_MAP_ROOT_ROOT;
    const TRANSITION_TAGS: &'static [u8] = &[tag::REGISTER_SPEND, tag::TRANSACT];
    const ROOT_DISCRIMINATOR: u8 = HEAD_MAP_ROOT;
    type Root = HeadMapRoot;
    type Leaf = HeadLeaf;
    type Transition = Transition;

    fn undos(block: &mut super::storage::BlockUndo) -> &mut Vec<Undo<HeadLeaf>> {
        &mut block.head_map
    }

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
        ..
    } = transition;
    if old_root != root.root {
        return Err(fault("old root mismatch"));
    }
    let current = store
        .member(&member)
        .await?
        .ok_or_else(|| fault("transfer member is unregistered"))?;
    let leaf = transition
        .replace(current.clone())
        .map_err(|error| fault(error.to_string()))?;
    let undo = Undo {
        program: root.program,
        before: Some(root.clone()),
        members: vec![MemberRestore {
            member,
            before: Some(current.clone()),
        }],
        leaves: vec![LeafWrite {
            index: current.index(),
            hash: current.hash()?,
        }],
    };
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
