use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice,
    primitives::{is_canonical_bn254_scalar_be, right_align},
    Hasher, HasherError, Poseidon,
};

/// Matches the circuit height and the on-chain tree.
pub const HEAD_MAP_HEIGHT: usize = 40;

/// The register proof's single public input, the program recomputes it from the
/// member and genesis it authorizes and the on-chain append cursor.
pub struct CompressedRegisterPublicInput<'a> {
    pub head_old_root: &'a [u8; 32],
    pub head_new_root: &'a [u8; 32],
    pub member: &'a [u8; 32],
    pub genesis: &'a [u8; 32],
    pub new_index: u64,
}

impl CompressedRegisterPublicInput<'_> {
    /// `HashChain([head_old_root, head_new_root, member, genesis, new_index])`,
    /// mirroring the circuit element for element.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_from_slice(&[
            *self.head_old_root,
            *self.head_new_root,
            *self.member,
            *self.genesis,
            right_align(&self.new_index.to_be_bytes()),
        ])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadMapError {
    Hashing,
    ProofLength,
    OutOfRange,
    RootMismatch,
    SlotOccupied,
}

/// Leaf preimage binding a member to its successor pointer and current nullifier.
pub fn head_map_leaf(
    member: &[u8; 32],
    next: &[u8; 32],
    nullifier: &[u8; 32],
) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[member, next, nullifier])
}

fn root_from_proof(
    leaf: [u8; 32],
    mut index: u64,
    proof: &[[u8; 32]],
) -> Result<[u8; 32], HasherError> {
    let mut node = leaf;
    for sibling in proof {
        node = if index & 1 == 0 {
            Poseidon::hashv(&[&node[..], &sibling[..]])?
        } else {
            Poseidon::hashv(&[&sibling[..], &node[..]])?
        };
        index >>= 1;
    }
    Ok(node)
}

/// Inserts a member off a client-supplied low element and empty append slot.
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
    /// The advanced root, or the first check the witness fails.
    pub fn verify(&self) -> Result<[u8; 32], HeadMapError> {
        if self.low_proof.len() != HEAD_MAP_HEIGHT || self.new_proof.len() != HEAD_MAP_HEIGHT {
            return Err(HeadMapError::ProofLength);
        }
        if self.low_index >= (1u64 << HEAD_MAP_HEIGHT)
            || self.append_index == 0
            || self.append_index >= (1u64 << HEAD_MAP_HEIGHT)
        {
            return Err(HeadMapError::OutOfRange);
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
            return Err(HeadMapError::OutOfRange);
        }
        // Strict order proves the member absent between the low element and its successor.
        if !(self.low_member < self.member && self.member < self.low_next) {
            return Err(HeadMapError::OutOfRange);
        }
        let low_old = self.leaf(self.low_member, self.low_next, self.low_nullifier)?;
        if &self.reduce(low_old, self.low_index, self.low_proof)? != self.root {
            return Err(HeadMapError::RootMismatch);
        }
        let low_new = self.leaf(self.low_member, self.member, self.low_nullifier)?;
        let spliced = self.reduce(low_new, self.low_index, self.low_proof)?;
        // A non-empty append slot would overwrite a live member.
        let empty = Poseidon::zero_bytes()[0];
        if self.reduce(empty, self.append_index, self.new_proof)? != spliced {
            return Err(HeadMapError::SlotOccupied);
        }
        let member_leaf = self.leaf(self.member, self.low_next, self.genesis)?;
        self.reduce(member_leaf, self.append_index, self.new_proof)
    }

    fn leaf(
        &self,
        member: &[u8; 32],
        next: &[u8; 32],
        nullifier: &[u8; 32],
    ) -> Result<[u8; 32], HeadMapError> {
        head_map_leaf(member, next, nullifier).map_err(|_| HeadMapError::Hashing)
    }

    fn reduce(
        &self,
        leaf: [u8; 32],
        index: u64,
        proof: &[[u8; 32]],
    ) -> Result<[u8; 32], HeadMapError> {
        root_from_proof(leaf, index, proof).map_err(|_| HeadMapError::Hashing)
    }
}

/// Advances a member's leaf from `spent` to `successor`, the successor pointer fixed.
pub struct HeadMapTransfer<'a> {
    pub root: &'a [u8; 32],
    pub member: &'a [u8; 32],
    pub next: &'a [u8; 32],
    pub spent: &'a [u8; 32],
    pub successor: &'a [u8; 32],
    pub index: u64,
    pub proof: &'a [[u8; 32]],
}

impl HeadMapTransfer<'_> {
    /// The advanced root, or the first check the witness fails.
    pub fn verify(&self) -> Result<[u8; 32], HeadMapError> {
        if self.proof.len() != HEAD_MAP_HEIGHT {
            return Err(HeadMapError::ProofLength);
        }
        if self.index == 0 || self.index >= (1u64 << HEAD_MAP_HEIGHT) {
            return Err(HeadMapError::OutOfRange);
        }
        if self.member == &[0u8; 32]
            || self.member >= self.next
            || [
                self.root,
                self.member,
                self.next,
                self.spent,
                self.successor,
            ]
            .into_iter()
            .chain(self.proof)
            .any(|field| !is_canonical_bn254_scalar_be(field))
        {
            return Err(HeadMapError::OutOfRange);
        }
        let spent =
            head_map_leaf(self.member, self.next, self.spent).map_err(|_| HeadMapError::Hashing)?;
        if &root_from_proof(spent, self.index, self.proof).map_err(|_| HeadMapError::Hashing)?
            != self.root
        {
            return Err(HeadMapError::RootMismatch);
        }
        let successor = head_map_leaf(self.member, self.next, self.successor)
            .map_err(|_| HeadMapError::Hashing)?;
        root_from_proof(successor, self.index, self.proof).map_err(|_| HeadMapError::Hashing)
    }
}
