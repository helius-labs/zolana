pub mod head_map;
pub mod key_registry;
pub mod proof;

use serde::{de::DeserializeOwned, Serialize};
use solana_address::Address;
use std::fmt;
use zolana_hasher::HasherError;

pub struct InstructionView<'a> {
    pub program_id: &'a Address,
    pub accounts: &'a [Address],
    pub data: &'a [u8],
}

pub trait OnChainRoot: bytemuck::Pod {
    fn discriminator(&self) -> u8;
    fn root(&self) -> [u8; 32];
    fn next_index(&self) -> u64;
    fn bump(&self) -> u8;
}

pub trait Leaf: Clone + fmt::Debug + Serialize + DeserializeOwned + Send + Sync + 'static {
    fn sentinel() -> Self;
    fn member(&self) -> [u8; 32];
    fn index(&self) -> u64;
    fn next(&self) -> [u8; 32];
    fn set_next(&mut self, next: [u8; 32]);
    fn hash(&self) -> Result<[u8; 32], HasherError>;
}

/// `leaf.next` is assigned from the predecessor.
pub struct Append<L> {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub next_index: u64,
    pub leaf: L,
}

pub struct Spliced<L> {
    pub predecessor: L,
    pub added: L,
}

impl<L: Leaf> Append<L> {
    pub fn splice(self, mut predecessor: L) -> anyhow::Result<Spliced<L>> {
        let member = self.leaf.member();
        if self.next_index >= custom_ring_interface::HEAD_MAP_CAPACITY
            || self.leaf.index() != self.next_index
            || predecessor.index() >= self.next_index
            || predecessor.member() >= member
            || member >= predecessor.next()
        {
            anyhow::bail!("invalid append position");
        }
        let mut added = self.leaf;
        added.set_next(predecessor.next());
        predecessor.set_next(member);
        Ok(Spliced { predecessor, added })
    }
}
