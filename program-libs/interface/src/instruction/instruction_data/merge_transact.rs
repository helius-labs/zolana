use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_hasher::{sha256::Sha256BE, Hasher, HasherError};

use super::borrowed::{finish, read, BorrowedList, DecodeError};
use crate::error::ShieldedPoolError;

/// Input counts the merge circuits have verifying keys for, smallest first.
/// Dummy slots publish deterministic nullifiers derived from the owner's
/// nullifier secret and `nullifiers[0]`, so a spender pads up to the next
/// supported count rather than needing an exact-fit shape.
///
/// Merge instruction data carries no circuit selector: the shape is the declared
/// nullifier count, so this set is what the program dispatches its verifying key
/// on. Mirror `SupportedInputCounts` in
/// `prover/server/circuits/spp_merge/shared/transaction.go`,
/// `mergeSupportedInputCounts` in `prover/server/prover/common/lazy_key_manager.go`,
/// and `MERGE_SUPPORTED_INPUT_COUNTS` in `sdk-libs/ts/src/interface/constants.ts`.
///
/// 36 was measured, not guessed: the tightest merge path is `merge_ring` under a
/// custom ring with a second signer, whose transaction v1 ceiling is 42 inputs
/// (`cargo run -p xtask -- max-merge-shape`), so 36 keeps six inputs of headroom
/// and matches the 36-input transact consolidation shape.
pub const MERGE_SUPPORTED_INPUT_COUNTS: [usize; 2] = [8, 36];

/// Largest supported merge input count, for callers sizing a buffer or a plan
/// against the widest shape. It is not the shape: every instruction declares its
/// own by the length of its vectors.
pub const MAX_MERGE_INPUTS: usize = 36;

/// The smallest supported merge shape, and the one the default consolidation
/// path pads up to. Named because builders, tests, and the fee math refer to the
/// 8-in/1-out shape directly.
pub const MERGE_DEFAULT_INPUT_COUNT: usize = 8;

/// The vanilla Groth16 proof carried by the merge instructions: `a || b || c`,
/// 128 bytes on the wire (compressed points, G1 -> 32 bytes, G2 -> 64 bytes).
/// The merge circuit carries no P256 gadget, so there is no BSB22 commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeProof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}

impl MergeProof {
    /// Serialized length: the three points back to back, no tag.
    pub const LEN: usize = 128;

    /// A zeroed proof, used as a placeholder before the real proof is attached
    /// and as a dummy in tests.
    pub const fn zeroed() -> Self {
        Self {
            a: [0u8; 32],
            b: [0u8; 64],
            c: [0u8; 32],
        }
    }
}

/// Zero-copy view of [`MergeProof`]: every point aliases the instruction buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct MergeProofRef<'a> {
    pub a: &'a [u8; 32],
    pub b: &'a [u8; 64],
    pub c: &'a [u8; 32],
}

/// `merge_transact` instruction data (spec: SPP `merge_transact`).
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeTransactIxData {
    pub expiry_unix_ts: u64,
    pub proof: MergeProof,
    pub output_utxo_hash: [u8; 32],
    /// When true the owner identity (`pk_field(user_signing_pk)`) is derived from
    /// the registry account's ed25519 `owner` instead of its P256 `owner_p256`.
    pub eddsa_owner: bool,
    pub private_tx_hash: [u8; 32],
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub nullifiers: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<u16, FixIntLen<u8>>")]
    pub utxo_tree_root_index: Vec<u16>,
    #[wincode(with = "containers::Vec<u16, FixIntLen<u8>>")]
    pub nullifier_tree_root_index: Vec<u16>,
}

impl MergeTransactIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Allocation-free view of [`MergeTransactIxData`]. Proof points and
/// nullifiers alias the instruction buffer; index lists are decoded lazily.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeTransactIxDataRef<'a> {
    pub expiry_unix_ts: u64,
    pub proof: MergeProofRef<'a>,
    pub output_utxo_hash: &'a [u8; 32],
    pub eddsa_owner: bool,
    pub private_tx_hash: &'a [u8; 32],
    pub nullifiers: BorrowedList<'a, &'a [u8; 32]>,
    pub utxo_tree_root_index: BorrowedList<'a, u16>,
    pub nullifier_tree_root_index: BorrowedList<'a, u16>,
}

impl<'a> MergeTransactIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, DecodeError> {
        // Exact: trailing bytes after a merge payload are unbound by any proof
        // input, so they must be rejected rather than ignored.
        let mut cursor = data;
        let parsed = Self::read_from(&mut cursor)?;
        finish(cursor)?;
        parsed.validate_shape()?;
        Ok(parsed)
    }

    pub(crate) fn read_from(cursor: &mut &'a [u8]) -> Result<Self, DecodeError> {
        let shape = ShieldedPoolError::InvalidMergeShape;
        Ok(Self {
            expiry_unix_ts: read::<u64>(cursor)?,
            proof: read::<MergeProofRef<'a>>(cursor)?,
            output_utxo_hash: read::<&[u8; 32]>(cursor)?,
            eddsa_owner: read::<bool>(cursor)?,
            private_tx_hash: read::<&[u8; 32]>(cursor)?,
            nullifiers: BorrowedList::read::<&[u8; 32]>(cursor, MAX_MERGE_INPUTS, shape)?,
            utxo_tree_root_index: BorrowedList::read::<u16>(cursor, MAX_MERGE_INPUTS, shape)?,
            nullifier_tree_root_index: BorrowedList::read::<u16>(cursor, MAX_MERGE_INPUTS, shape)?,
        })
    }

    /// Enforce a supported merge shape. Shared with `merge_ring`, which embeds
    /// a `MergeTransactIxDataRef`.
    ///
    /// The three vectors must agree on a single length, and that length must be
    /// a count the circuits have a key for. Requiring agreement first is what
    /// makes the decode fail-closed: a shape is the instruction's own declared
    /// input count, not a constant the program assumes.
    pub(crate) fn validate_shape(&self) -> Result<(), DecodeError> {
        let input_count = self.nullifiers.len();
        if self.utxo_tree_root_index.len() != input_count
            || self.nullifier_tree_root_index.len() != input_count
            || !MERGE_SUPPORTED_INPUT_COUNTS.contains(&input_count)
        {
            return Err(DecodeError::Limit(ShieldedPoolError::InvalidMergeShape));
        }
        Ok(())
    }
}

/// `external_data_hash` public input for the merge instructions. Domain-separated
/// by the instruction's discriminator (`merge_transact` or `merge_ring`) so a
/// preimage cannot be reused across instructions. Computed identically by the
/// client and the program. For `merge_ring`, the output `ring_data_hash` is
/// bound directly as a public-input-hash element, so it does not enter this
/// preimage.
pub struct MergeExternalDataHash<'a> {
    pub spp_instruction_discriminator: u8,
    pub expiry_unix_ts: u64,
    pub output_utxo_hash: &'a [u8; 32],
}

impl MergeExternalDataHash<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        // Three fixed-width segments hashed in place. `hash(v)` is defined as
        // `hashv(&[v])`, so the digest is unchanged; on-chain this is the same
        // single sha256 syscall without the heap preimage, which matters under
        // a bump allocator that never frees.
        Sha256BE::hashv(&[
            &[self.spp_instruction_discriminator],
            &self.expiry_unix_ts.to_be_bytes(),
            self.output_utxo_hash,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_with(input_count: usize) -> MergeTransactIxData {
        MergeTransactIxData {
            expiry_unix_ts: 42,
            proof: MergeProof {
                a: [1u8; 32],
                b: [2u8; 64],
                c: [3u8; 32],
            },
            output_utxo_hash: [9u8; 32],
            nullifiers: (0..input_count).map(|i| [i as u8; 32]).collect(),
            utxo_tree_root_index: (0..input_count as u16).collect(),
            nullifier_tree_root_index: (10..10 + input_count as u16).collect(),
            private_tx_hash: [3u8; 32],
            eddsa_owner: false,
        }
    }

    fn data() -> MergeTransactIxData {
        data_with(MERGE_DEFAULT_INPUT_COUNT)
    }

    #[test]
    fn round_trips_owned_and_ref() {
        let owned = data();
        let bytes = owned.serialize().unwrap();
        let view = MergeTransactIxDataRef::from_bytes(&bytes).unwrap();
        assert_eq!(view.expiry_unix_ts, owned.expiry_unix_ts);
        assert_eq!(view.proof.a, &owned.proof.a);
        assert_eq!(view.proof.b, &owned.proof.b);
        assert_eq!(view.proof.c, &owned.proof.c);
        assert_eq!(view.output_utxo_hash, &owned.output_utxo_hash);
        assert_eq!(view.nullifiers.len(), owned.nullifiers.len());
        for (got, want) in view.nullifiers.try_iter().zip(&owned.nullifiers) {
            assert_eq!(got.unwrap(), want);
        }
        assert_eq!(
            view.nullifier_tree_root_index
                .try_iter()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            owned.nullifier_tree_root_index,
        );
        assert_eq!(view.private_tx_hash, &owned.private_tx_hash);
        assert_eq!(view.eddsa_owner, owned.eddsa_owner);
    }

    #[test]
    fn every_supported_shape_has_the_contracted_wire_length() {
        // expiry(8) || proof(128) || output_hash(32) || eddsa_owner(1) ||
        // private_tx_hash(32) || 3 vecs with u8 lens, so 204 fixed bytes plus 36
        // per input. The size model in the transaction-size tests and the fee
        // math both read this formula.
        for input_count in MERGE_SUPPORTED_INPUT_COUNTS {
            let bytes = data_with(input_count)
                .serialize()
                .expect("serialize merge instruction");
            assert_eq!(bytes.len(), 204 + 36 * input_count);
            MergeTransactIxDataRef::from_bytes(&bytes).expect("a supported shape must parse back");
        }
    }

    #[test]
    fn max_merge_inputs_is_the_widest_supported_shape() {
        assert_eq!(
            MERGE_SUPPORTED_INPUT_COUNTS.iter().copied().max(),
            Some(MAX_MERGE_INPUTS)
        );
        assert!(MERGE_SUPPORTED_INPUT_COUNTS.contains(&MERGE_DEFAULT_INPUT_COUNT));
    }

    #[test]
    fn rejects_wrong_shape() {
        // One short of a supported count: the three vectors still agree, so only
        // the supported-count check can reject it.
        for input_count in MERGE_SUPPORTED_INPUT_COUNTS {
            let mut owned = data_with(input_count);
            owned.nullifiers.pop();
            owned.utxo_tree_root_index.pop();
            owned.nullifier_tree_root_index.pop();
            let bytes = owned.serialize().unwrap();
            assert!(MergeTransactIxDataRef::from_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn rejects_disagreeing_vector_lengths() {
        let mut owned = data();
        owned.nullifiers.pop();
        let bytes = owned.serialize().unwrap();
        assert!(MergeTransactIxDataRef::from_bytes(&bytes).is_err());
    }

    fn hash_of(discriminator: u8, expiry: u64, output: &[u8; 32]) -> [u8; 32] {
        MergeExternalDataHash {
            spp_instruction_discriminator: discriminator,
            expiry_unix_ts: expiry,
            output_utxo_hash: output,
        }
        .hash()
        .unwrap()
    }

    #[test]
    fn external_data_hash_is_injective() {
        let base = hash_of(crate::instruction::tag::MERGE_TRANSACT, 1, &[1u8; 32]);
        assert_ne!(
            base,
            hash_of(crate::instruction::tag::MERGE_TRANSACT, 2, &[1u8; 32])
        );
        assert_ne!(
            base,
            hash_of(crate::instruction::tag::MERGE_TRANSACT, 1, &[2u8; 32])
        );
        assert_ne!(
            base,
            hash_of(crate::instruction::tag::RING_MERGE_TRANSACT, 1, &[1u8; 32])
        );
    }
}
