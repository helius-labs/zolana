use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use sea_orm::DatabaseTransaction;
use zolana_hasher::{Hasher, Poseidon};

use crate::{
    common::rings_tree::RingsTreeKind,
    ingester::persist::persisted_state_tree::{get_proof_nodes, zero_hash_for_level},
};

use super::storage::Map;

pub const HEIGHT: usize = custom_ring_interface::HEAD_MAP_HEIGHT;
pub const CAPACITY: u64 = 1 << HEIGHT;

pub fn parent(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32]> {
    Poseidon::hashv(&[left, right])
        .map_err(|error| anyhow::anyhow!("head-map parent hash failed ({error:?})"))
}

pub fn root(mut leaf: [u8; 32], mut index: u64, proof: &[[u8; 32]]) -> Result<[u8; 32]> {
    if index >= CAPACITY || proof.len() != HEIGHT {
        bail!("invalid head-map path");
    }
    for sibling in proof {
        leaf = if index & 1 == 0 {
            parent(&leaf, sibling)?
        } else {
            parent(sibling, &leaf)?
        };
        index >>= 1;
    }
    Ok(leaf)
}

pub async fn path(
    tx: &DatabaseTransaction,
    map: &Map,
    index: u64,
) -> Result<([u8; 32], Vec<[u8; 32]>)> {
    if index >= CAPACITY {
        bail!("head-map index out of range");
    }
    let mut node = i64::try_from(CAPACITY + index)?;
    let values = get_proof_nodes(
        tx,
        vec![(map.address.to_vec(), RingsTreeKind::HeadMap.into(), node)],
        true,
        true,
        HEIGHT as u32 + 1,
    )
    .await?;
    let lookup = |node, level| -> Result<[u8; 32]> {
        match values.get(&(map.address.to_vec(), RingsTreeKind::HeadMap.into(), node)) {
            Some(value) => value
                .hash
                .clone()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid head-map node")),
            None => zero_hash_for_level(level).context("head-map zero level out of range"),
        }
    };
    let leaf = lookup(node, 0)?;
    let mut proof = Vec::with_capacity(HEIGHT);
    for level in 0..HEIGHT {
        proof.push(lookup(node ^ 1, level)?);
        node >>= 1;
    }
    if root(leaf, index, &proof)? != map.root {
        bail!("persisted head-map path does not match its root");
    }
    Ok((leaf, proof))
}

/// The append path binds the intermediate root after the predecessor update.
pub fn after_update(
    index: u64,
    mut leaf: [u8; 32],
    proof: &[[u8; 32]],
    target: u64,
    target_proof: &mut [[u8; 32]],
) -> Result<()> {
    if index >= CAPACITY
        || target >= CAPACITY
        || proof.len() != HEIGHT
        || target_proof.len() != HEIGHT
    {
        bail!("invalid head-map overlay path");
    }
    let mut changed = HashMap::new();
    let mut node = CAPACITY + index;
    changed.insert(node, leaf);
    for sibling in proof {
        leaf = if node & 1 == 0 {
            parent(&leaf, sibling)?
        } else {
            parent(sibling, &leaf)?
        };
        node >>= 1;
        changed.insert(node, leaf);
    }
    let mut target_node = CAPACITY + target;
    for sibling in target_proof {
        if let Some(replacement) = changed.get(&(target_node ^ 1)) {
            *sibling = *replacement;
        }
        target_node >>= 1;
    }
    Ok(())
}
