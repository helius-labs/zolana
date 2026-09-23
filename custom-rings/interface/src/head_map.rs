use zolana_hasher::{primitives::is_canonical_bn254_scalar_be, Hasher, HasherError, Poseidon};

/// Matches the circuit height and the on-chain tree.
pub const HEAD_MAP_HEIGHT: usize = 40;
pub const HEAD_MAP_CAPACITY: u64 = 1 << HEAD_MAP_HEIGHT;

/// Invalid indexed-tree witness or commitment during client verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadMapVerifyError {
    Hashing,
    ProofLength,
    OutOfRange,
    RootMismatch,
    SlotOccupied,
}

impl From<HasherError> for HeadMapVerifyError {
    fn from(_: HasherError) -> Self {
        Self::Hashing
    }
}

/// Ordered member link and the value committed for that member.
pub struct HeadMapLeaf<'a> {
    pub member: &'a [u8; 32],
    pub next: &'a [u8; 32],
    pub nullifier: &'a [u8; 32],
}

impl HeadMapLeaf<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[self.member, self.next, self.nullifier])
    }
}

/// Leaf position and sibling hashes reconstructing an indexed-tree root.
pub struct MerklePath<'a> {
    pub index: u64,
    pub siblings: &'a [[u8; 32]],
}

impl MerklePath<'_> {
    pub fn root_of(&self, leaf: [u8; 32]) -> Result<[u8; 32], HeadMapVerifyError> {
        self.check()?;
        let mut index = self.index;
        let mut node = leaf;
        for sibling in self.siblings {
            node = if index & 1 == 0 {
                Poseidon::hashv(&[&node[..], &sibling[..]])?
            } else {
                Poseidon::hashv(&[&sibling[..], &node[..]])?
            };
            index >>= 1;
        }
        Ok(node)
    }

    fn check(&self) -> Result<(), HeadMapVerifyError> {
        if self.siblings.len() != HEAD_MAP_HEIGHT {
            return Err(HeadMapVerifyError::ProofLength);
        }
        if self.index >= HEAD_MAP_CAPACITY {
            return Err(HeadMapVerifyError::OutOfRange);
        }
        Ok(())
    }
}

/// Non-membership witness followed by predecessor splicing and a genesis leaf
/// append.
pub struct HeadMapInsert<'a> {
    pub root: &'a [u8; 32],
    pub append_index: u64,
    pub member: &'a [u8; 32],
    pub genesis: &'a [u8; 32],
    pub low_member: &'a [u8; 32],
    pub low_next: &'a [u8; 32],
    pub low_nullifier: &'a [u8; 32],
    pub low_index: u64,
    pub low_proof: &'a [[u8; 32]],
    pub new_proof: &'a [[u8; 32]],
}

impl HeadMapInsert<'_> {
    /// `root` is not checked against chain state.
    pub fn verify(&self) -> Result<[u8; 32], HeadMapVerifyError> {
        // 1. Validate positions and canonical field encodings before hashing
        // the witness.
        let low_path = MerklePath {
            index: self.low_index,
            siblings: self.low_proof,
        };
        let new_path = MerklePath {
            index: self.append_index,
            siblings: self.new_proof,
        };
        low_path.check()?;
        new_path.check()?;
        // Slot 0 is the sentinel.
        if self.append_index == 0 {
            return Err(HeadMapVerifyError::OutOfRange);
        }
        if [
            self.root,
            self.member,
            self.genesis,
            self.low_member,
            self.low_next,
            self.low_nullifier,
        ]
        .into_iter()
        .chain(self.low_proof)
        .chain(self.new_proof)
        .any(|field| !is_canonical_bn254_scalar_be(field))
        {
            return Err(HeadMapVerifyError::OutOfRange);
        }
        // 2. Prove the member absent inside an authenticated predecessor
        // interval.
        if !(self.low_member < self.member && self.member < self.low_next) {
            return Err(HeadMapVerifyError::OutOfRange);
        }
        let low_old = HeadMapLeaf {
            member: self.low_member,
            next: self.low_next,
            nullifier: self.low_nullifier,
        }
        .hash()?;
        if &low_path.root_of(low_old)? != self.root {
            return Err(HeadMapVerifyError::RootMismatch);
        }
        // 3. Splice the predecessor link and append only into a proven empty
        // slot.
        let low_new = HeadMapLeaf {
            member: self.low_member,
            next: self.member,
            nullifier: self.low_nullifier,
        }
        .hash()?;
        let spliced = low_path.root_of(low_new)?;
        let empty = Poseidon::zero_bytes()[0];
        if new_path.root_of(empty)? != spliced {
            return Err(HeadMapVerifyError::SlotOccupied);
        }
        let member_leaf = HeadMapLeaf {
            member: self.member,
            next: self.low_next,
            nullifier: self.genesis,
        }
        .hash()?;
        new_path.root_of(member_leaf)
    }
}
