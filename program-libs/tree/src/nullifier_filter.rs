//! Negative filter over the nullifiers spent since a checkpoint. Positives
//! require exact spentness checks.
//!
//! The filter never covers the whole history on its own: its header carries a
//! checkpoint `(root, next_index)` of the nullifier tree, and every spend that
//! relies on a filter negative also proves non-inclusion at that root. A
//! checkpoint moves the boundary forward and clears the bits: everything the
//! tree had inserted by then is the root's job, everything still queued is
//! re-recorded, so the filter starts again with only the recent spends.

use thiserror::Error;
use zolana_hasher::{primitives::is_canonical_bn254_scalar_be, Hasher, Keccak};

use crate::{
    nullifier_tree::constants::NULLIFIER_TREE_INIT_ROOT_40,
    pending_nullifiers::PendingNullifierBatch,
};

const HEADER: usize = 128;
const MAGIC: &[u8; 8] = b"ZNFBLOM3";
const HASH_DOMAIN: &[u8] = b"SPP nullifier filter v2";
const SEQUENCE: std::ops::Range<usize> = 48..56;
const CHECKPOINT_ROOT: std::ops::Range<usize> = 64..96;
const CHECKPOINT_INDEX: std::ops::Range<usize> = 96..104;
const REBUILD_CURSOR: std::ops::Range<usize> = 104..112;
const REBUILD_CLOSE_BEFORE: std::ops::Range<usize> = 112..120;
pub const MAX_BATCH: usize = 512;
/// Largest backlog chunk one rebuild step re-records.
pub const MAX_CHECKPOINT_BACKLOG: usize = 1024;
pub const MAX_BIT_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_BIT_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_HASHES: u8 = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NullifierFilterMode {
    Off = 0,
    Active = 1,
    Retired = 2,
}

impl TryFrom<u8> for NullifierFilterMode {
    type Error = crate::TreeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Off),
            1 => Ok(Self::Active),
            2 => Ok(Self::Retired),
            _ => Err(crate::TreeError::Deserialize),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FilterError {
    #[error("invalid nullifier filter layout or domain")]
    InvalidFilter,
    #[error("invalid nullifier batch")]
    InvalidBatch,
    #[error("duplicate nullifier")]
    Duplicate,
    #[error("filter does not cover the complete nullifier history")]
    HistoryGap,
    #[error("filter positive requires exact spentness proof")]
    NeedsProof,
    #[error("nullifier hashing failed")]
    Hash,
}

pub struct NullifierFilter<'a> {
    header: &'a mut [u8],
    bits: &'a mut [u8],
    tree: [u8; 32],
    hashes: u8,
}

impl<'a> NullifierFilter<'a> {
    pub fn account_size(bit_bytes: usize) -> Option<usize> {
        if !bit_bytes.is_power_of_two() || bit_bytes > MAX_BIT_BYTES {
            return None;
        }
        HEADER.checked_add(bit_bytes)
    }

    pub fn init(bytes: &'a mut [u8], tree: &[u8; 32], hashes: u8) -> Result<Self, FilterError> {
        if bytes.iter().any(|byte| *byte != 0) {
            return Err(FilterError::InvalidFilter);
        }
        Self::init_zeroed(bytes, tree, hashes)
    }

    /// Requires fresh program-owned zero-filled data and a never-spent tree
    /// domain: the first checkpoint is the empty nullifier tree.
    pub fn init_zeroed(
        bytes: &'a mut [u8],
        tree: &[u8; 32],
        hashes: u8,
    ) -> Result<Self, FilterError> {
        let bit_bytes = bytes
            .len()
            .checked_sub(HEADER)
            .ok_or(FilterError::InvalidFilter)?;
        if !valid_shape(bit_bytes, hashes) || bytes[..HEADER].iter().any(|byte| *byte != 0) {
            return Err(FilterError::InvalidFilter);
        }
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..40].copy_from_slice(tree);
        bytes[40] = hashes;
        bytes[SEQUENCE].copy_from_slice(&1u64.to_le_bytes());
        bytes[CHECKPOINT_ROOT].copy_from_slice(&NULLIFIER_TREE_INIT_ROOT_40);
        bytes[CHECKPOINT_INDEX].copy_from_slice(&1u64.to_le_bytes());
        Self::from_bytes(bytes, tree)
    }

    pub fn from_bytes(bytes: &'a mut [u8], tree: &[u8; 32]) -> Result<Self, FilterError> {
        validate_header(bytes, tree)?;
        let hashes = bytes[40];
        let (header, bits) = bytes.split_at_mut(HEADER);
        Ok(Self {
            header,
            bits,
            tree: *tree,
            hashes,
        })
    }

    /// `(checkpoint_root, checkpoint_index, settled)` of a filter, read-only.
    pub fn read_checkpoint(
        bytes: &[u8],
        tree: &[u8; 32],
    ) -> Result<([u8; 32], u64, bool), FilterError> {
        validate_header(bytes, tree)?;
        Ok((
            bytes[CHECKPOINT_ROOT].try_into().unwrap(),
            u64::from_le_bytes(bytes[CHECKPOINT_INDEX].try_into().unwrap()),
            u64::from_le_bytes(bytes[REBUILD_CURSOR].try_into().unwrap()) == 0,
        ))
    }

    pub fn next_sequence(&self) -> u64 {
        u64::from_le_bytes(self.header[SEQUENCE].try_into().unwrap())
    }

    /// Nullifier-tree root every filter negative is paired with.
    pub fn checkpoint_root(&self) -> [u8; 32] {
        self.header[CHECKPOINT_ROOT].try_into().unwrap()
    }

    /// Tree `next_index` at the checkpoint: leaves below it are in the
    /// checkpoint root. `1` means the filter still covers the whole history.
    pub fn checkpoint_index(&self) -> u64 {
        u64::from_le_bytes(self.header[CHECKPOINT_INDEX].try_into().unwrap())
    }

    /// Pending-table slot the checkpoint rebuild continues from, plus one;
    /// `0` when no rebuild is in progress.
    pub fn rebuild_cursor(&self) -> u64 {
        u64::from_le_bytes(self.header[REBUILD_CURSOR].try_into().unwrap())
    }

    /// Tree `close_before_index` when the rebuild began; if it moved, the
    /// pending table may have forgotten a backlog entry and the rebuild must
    /// start over.
    pub fn rebuild_close_before(&self) -> u64 {
        u64::from_le_bytes(self.header[REBUILD_CLOSE_BEFORE].try_into().unwrap())
    }

    /// Whether the filter covers the spends since its checkpoint completely;
    /// a filter negative means nothing while a rebuild is in progress.
    pub fn is_settled(&self) -> bool {
        self.rebuild_cursor() == 0
    }

    /// Move the checkpoint to `(root, next_index)` and clear the bits. The
    /// nullifiers queued but not yet in the tree have to be re-recorded from
    /// the pending table with [`Self::record_backlog`] before the filter is
    /// settled again; `close_before` is remembered to detect a table that
    /// forgot entries in between. Recording continuity (`next_sequence`) is
    /// untouched. Fails without writing when the checkpoint would move
    /// backwards.
    pub fn begin_checkpoint(
        &mut self,
        root: [u8; 32],
        next_index: u64,
        close_before: u64,
    ) -> Result<(), FilterError> {
        if next_index < self.checkpoint_index() || root == [0; 32] {
            return Err(FilterError::InvalidFilter);
        }
        self.bits.fill(0);
        self.header[CHECKPOINT_ROOT].copy_from_slice(&root);
        self.header[CHECKPOINT_INDEX].copy_from_slice(&next_index.to_le_bytes());
        self.header[REBUILD_CURSOR].copy_from_slice(&1u64.to_le_bytes());
        self.header[REBUILD_CLOSE_BEFORE].copy_from_slice(&close_before.to_le_bytes());
        Ok(())
    }

    /// Re-record one chunk of the backlog during a rebuild and move the cursor
    /// to `next_slot` (+1), or settle the filter when the scan is complete.
    #[cfg_attr(feature = "profile-program", light_program_profiler::profile)]
    pub fn record_backlog(
        &mut self,
        backlog: &[[u8; 32]],
        next_slot: Option<usize>,
    ) -> Result<(), FilterError> {
        if self.is_settled() {
            return Err(FilterError::InvalidFilter);
        }
        if backlog.len() > MAX_CHECKPOINT_BACKLOG
            || backlog
                .iter()
                .any(|nf| *nf == [0; 32] || !is_canonical_bn254_scalar_be(nf))
        {
            return Err(FilterError::InvalidBatch);
        }
        let hashes = self.batch_hashes(backlog)?;
        let mask = self.bits.len() * 8 - 1;
        for (start, step) in hashes {
            for i in 0..usize::from(self.hashes) {
                let bit = start.wrapping_add(step.wrapping_mul(i)) & mask;
                self.bits[bit / 8] |= 1 << (bit % 8);
            }
        }
        let cursor = match next_slot {
            Some(slot) => u64::try_from(slot)
                .ok()
                .and_then(|slot| slot.checked_add(1))
                .ok_or(FilterError::InvalidBatch)?,
            None => 0,
        };
        self.header[REBUILD_CURSOR].copy_from_slice(&cursor.to_le_bytes());
        Ok(())
    }

    pub fn check_batch(
        &self,
        nullifiers: &[[u8; 32]],
        expected_next: u64,
    ) -> Result<Vec<usize>, FilterError> {
        if self.next_sequence() != expected_next {
            return Err(FilterError::HistoryGap);
        }
        validate_batch(nullifiers)?;
        let hashes = self.batch_hashes(nullifiers)?;
        Ok(hashes
            .iter()
            .enumerate()
            .filter_map(|(i, hash)| self.contains(*hash).then_some(i))
            .collect())
    }

    /// `exact_verified` requires valid historical NIP and current pending-nullifier admission.
    /// The sequence is the tree queue's pre-insertion index, never client-supplied metadata.
    #[cfg_attr(feature = "profile-program", light_program_profiler::profile)]
    pub fn record_batch(
        &mut self,
        nullifiers: &[[u8; 32]],
        first_sequence: u64,
        exact_verified: bool,
    ) -> Result<(), FilterError> {
        validate_batch(nullifiers)?;
        self.record_validated_batch(nullifiers, first_sequence, exact_verified)
    }

    /// Reuses pending admission's canonical-value and duplicate checks.
    /// `exact_verified` still requires a valid historical non-inclusion proof.
    #[cfg_attr(feature = "profile-program", light_program_profiler::profile)]
    pub fn record_pending_batch(
        &mut self,
        batch: PendingNullifierBatch<'_>,
        exact_verified: bool,
    ) -> Result<(), FilterError> {
        let (nullifiers, first_sequence, tree) = batch.into_parts();
        if tree != self.tree {
            return Err(FilterError::InvalidFilter);
        }
        self.record_validated_batch(nullifiers, first_sequence, exact_verified)
    }

    fn record_validated_batch(
        &mut self,
        nullifiers: &[[u8; 32]],
        first_sequence: u64,
        exact_verified: bool,
    ) -> Result<(), FilterError> {
        if self.next_sequence() != first_sequence {
            return Err(FilterError::HistoryGap);
        }
        if nullifiers.len() > MAX_BATCH {
            return Err(FilterError::InvalidBatch);
        }
        let next = first_sequence
            .checked_add(nullifiers.len() as u64)
            .ok_or(FilterError::InvalidBatch)?;
        let hashes = self.batch_hashes(nullifiers)?;
        if !exact_verified && hashes.iter().any(|hash| self.contains(*hash)) {
            return Err(FilterError::NeedsProof);
        }
        let mask = self.bits.len() * 8 - 1;
        for (start, step) in hashes {
            for i in 0..usize::from(self.hashes) {
                let bit = start.wrapping_add(step.wrapping_mul(i)) & mask;
                self.bits[bit / 8] |= 1 << (bit % 8);
            }
        }
        self.header[SEQUENCE].copy_from_slice(&next.to_le_bytes());
        Ok(())
    }

    #[cfg_attr(feature = "profile-program", light_program_profiler::profile)]
    fn batch_hashes(&self, nullifiers: &[[u8; 32]]) -> Result<Vec<(usize, usize)>, FilterError> {
        nullifiers
            .iter()
            .map(|nullifier| {
                let digest = Keccak::hashv(&[HASH_DOMAIN, &self.tree, nullifier])
                    .map_err(|_| FilterError::Hash)?;
                Ok((
                    u64::from_le_bytes(digest[..8].try_into().unwrap()) as usize,
                    u64::from_le_bytes(digest[8..16].try_into().unwrap()) as usize | 1,
                ))
            })
            .collect()
    }

    fn contains(&self, (start, step): (usize, usize)) -> bool {
        let mask = self.bits.len() * 8 - 1;
        (0..usize::from(self.hashes)).all(|i| {
            let bit = start.wrapping_add(step.wrapping_mul(i)) & mask;
            self.bits[bit / 8] & (1 << (bit % 8)) != 0
        })
    }
}

fn validate_header(bytes: &[u8], tree: &[u8; 32]) -> Result<(), FilterError> {
    let bit_bytes = bytes
        .len()
        .checked_sub(HEADER)
        .ok_or(FilterError::InvalidFilter)?;
    if !valid_shape(bit_bytes, bytes[40])
        || bytes[..8] != *MAGIC
        || bytes[8..40] != *tree
        || bytes[41..48]
            .iter()
            .chain(&bytes[56..64])
            .chain(&bytes[120..HEADER])
            .any(|byte| *byte != 0)
        || u64::from_le_bytes(bytes[SEQUENCE].try_into().unwrap()) == 0
        || u64::from_le_bytes(bytes[CHECKPOINT_INDEX].try_into().unwrap()) == 0
    {
        return Err(FilterError::InvalidFilter);
    }
    Ok(())
}

fn valid_shape(bit_bytes: usize, hashes: u8) -> bool {
    NullifierFilter::account_size(bit_bytes).is_some()
        && (1..=32).contains(&hashes)
        && usize::from(hashes) <= bit_bytes * 8
}

#[cfg_attr(feature = "profile-program", light_program_profiler::profile)]
fn validate_batch(nullifiers: &[[u8; 32]]) -> Result<(), FilterError> {
    if nullifiers.len() > MAX_BATCH
        || nullifiers
            .iter()
            .any(|nf| *nf == [0; 32] || !is_canonical_bn254_scalar_be(nf))
    {
        return Err(FilterError::InvalidBatch);
    }
    let mut ordered: Vec<_> = nullifiers.iter().collect();
    ordered.sort_unstable();
    if ordered.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(FilterError::Duplicate);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pending_nullifiers::PendingNullifiers;

    fn nf(value: u64) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    fn init(bit_bytes: usize, hashes: u8) -> Vec<u8> {
        let mut bytes = vec![0; NullifierFilter::account_size(bit_bytes).unwrap()];
        NullifierFilter::init(&mut bytes, &[1; 32], hashes).unwrap();
        bytes
    }

    #[test]
    fn pending_receipt_matches_standalone_recording() {
        let values: Vec<_> = (1..=MAX_BATCH as u64).map(nf).collect();
        let mut expected = init(1024, DEFAULT_HASHES);
        let mut actual = expected.clone();
        NullifierFilter::from_bytes(&mut expected, &[1; 32])
            .unwrap()
            .record_batch(&values, 1, false)
            .unwrap();
        let mut pending = vec![0; PendingNullifiers::account_size(MAX_BATCH as u64).unwrap()];
        let mut table = PendingNullifiers::init(&mut pending, &[1; 32]).unwrap();
        let receipt = table.insert_batch(&values, 1, 1).unwrap();
        NullifierFilter::from_bytes(&mut actual, &[1; 32])
            .unwrap()
            .record_pending_batch(receipt, false)
            .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn receipts_cannot_cross_trees_or_skip_history() {
        let values = [nf(1), nf(2)];
        for (tree, first, error) in [
            ([2; 32], 1, FilterError::InvalidFilter),
            ([1; 32], 2, FilterError::HistoryGap),
        ] {
            let mut bytes = init(1024, DEFAULT_HASHES);
            let before = bytes.clone();
            let mut pending = vec![0; PendingNullifiers::account_size(10).unwrap()];
            let mut table = PendingNullifiers::init(&mut pending, &tree).unwrap();
            let receipt = table.insert_batch(&values, first, 1).unwrap();
            assert_eq!(
                NullifierFilter::from_bytes(&mut bytes, &[1; 32])
                    .unwrap()
                    .record_pending_batch(receipt, false),
                Err(error)
            );
            assert_eq!(bytes, before);
        }
    }

    #[test]
    fn a_pending_receipt_does_not_bypass_filter_positives() {
        let values = [nf(1)];
        let mut bytes = init(1024, DEFAULT_HASHES);
        bytes[HEADER..].fill(255);
        let before = bytes.clone();
        let mut pending = vec![0; PendingNullifiers::account_size(10).unwrap()];
        PendingNullifiers::init(&mut pending, &[1; 32]).unwrap();
        let pending_before = pending.clone();
        {
            let mut table = PendingNullifiers::from_bytes(&mut pending, &[1; 32]).unwrap();
            let receipt = table.insert_batch(&values, 1, 1).unwrap();
            assert_eq!(
                NullifierFilter::from_bytes(&mut bytes, &[1; 32])
                    .unwrap()
                    .record_pending_batch(receipt, false),
                Err(FilterError::NeedsProof)
            );
        }
        assert_eq!(bytes, before);
        pending.copy_from_slice(&pending_before);
        let mut table = PendingNullifiers::from_bytes(&mut pending, &[1; 32]).unwrap();
        let receipt = table.insert_batch(&values, 1, 1).unwrap();
        let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        filter.record_pending_batch(receipt, true).unwrap();
        assert_eq!(filter.next_sequence(), 2);
    }

    #[test]
    fn a_pending_receipt_cannot_exceed_filter_capacity() {
        let values: Vec<_> = (1..=MAX_BATCH as u64 + 1).map(nf).collect();
        let mut bytes = init(1024, DEFAULT_HASHES);
        let before = bytes.clone();
        let mut pending = vec![0; PendingNullifiers::account_size(MAX_BATCH as u64 + 1).unwrap()];
        let mut table = PendingNullifiers::init(&mut pending, &[1; 32]).unwrap();
        let receipt = table.insert_batch(&values, 1, 1).unwrap();
        assert_eq!(
            NullifierFilter::from_bytes(&mut bytes, &[1; 32])
                .unwrap()
                .record_pending_batch(receipt, false),
            Err(FilterError::InvalidBatch)
        );
        assert_eq!(bytes, before);
    }

    #[test]
    fn replays_need_exact_proof_and_queries_do_not_mutate() {
        let mut bytes = init(1024, 7);
        let batch: Vec<_> = (1..=128).map(nf).collect();
        let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        assert!(filter.check_batch(&batch, 1).unwrap().is_empty());
        filter.record_batch(&batch, 1, false).unwrap();
        assert_eq!(filter.next_sequence(), 129);
        let before = bytes.clone();
        let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        assert_eq!(
            filter.check_batch(&batch, 129).unwrap(),
            (0..128).collect::<Vec<_>>()
        );
        assert_eq!(
            filter.record_batch(&batch, 129, false),
            Err(FilterError::NeedsProof)
        );
        assert_eq!(bytes, before);
    }

    #[test]
    fn later_insertions_never_hide_prior_spends() {
        let mut bytes = init(1024, 7);
        let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        let history: Vec<_> = (1..=2048).map(nf).collect();
        for end in (512..=2048).step_by(512) {
            filter
                .record_batch(&history[end - 512..end], (end - 511) as u64, true)
                .unwrap();
            for batch in history[..end].chunks(MAX_BATCH) {
                assert_eq!(
                    filter.check_batch(batch, end as u64 + 1).unwrap().len(),
                    batch.len()
                );
            }
        }
    }

    #[test]
    fn invalid_batches_and_history_gaps_do_not_write() {
        let mut bytes = init(32, 7);
        let before = bytes.clone();
        for (batch, error) in [
            (vec![nf(1), nf(1)], FilterError::Duplicate),
            (vec![nf(1), [0; 32]], FilterError::InvalidBatch),
            (vec![nf(1), [255; 32]], FilterError::InvalidBatch),
            ((1..=513).map(nf).collect(), FilterError::InvalidBatch),
        ] {
            let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
            assert_eq!(filter.check_batch(&batch, 1), Err(error));
            assert!(filter.record_batch(&batch, 1, true).is_err());
            assert_eq!(bytes, before);
        }
        for sequence in [0, 2, u64::MAX] {
            let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
            assert_eq!(
                filter.check_batch(&[nf(1)], sequence),
                Err(FilterError::HistoryGap)
            );
            assert_eq!(
                filter.record_batch(&[nf(1)], sequence, true),
                Err(FilterError::HistoryGap)
            );
            assert_eq!(bytes, before);
        }
    }

    #[test]
    fn domain_configuration_and_layout_are_bound() {
        let bytes = init(32, 7);
        assert!(NullifierFilter::from_bytes(&mut bytes.clone(), &[2; 32]).is_err());
        for index in [0, 8, 40, 41, 56, 120, HEADER - 1] {
            let mut corrupt = bytes.clone();
            corrupt[index] = 255;
            assert!(NullifierFilter::from_bytes(&mut corrupt, &[1; 32]).is_err());
        }
        for range in [SEQUENCE, CHECKPOINT_INDEX] {
            let mut corrupt = bytes.clone();
            corrupt[range].fill(0);
            assert!(NullifierFilter::from_bytes(&mut corrupt, &[1; 32]).is_err());
        }
        assert!(
            NullifierFilter::from_bytes(&mut bytes[..bytes.len() - 1].to_vec(), &[1; 32]).is_err()
        );
        assert!(NullifierFilter::from_bytes(&mut [0; 10], &[1; 32]).is_err());
        assert!(NullifierFilter::init_zeroed(&mut bytes.clone(), &[1; 32], 7).is_err());
        assert_eq!(NullifierFilter::account_size(0), None);
        assert_eq!(NullifierFilter::account_size(3), None);
        assert_eq!(NullifierFilter::account_size(MAX_BIT_BYTES * 2), None);
        let mut other = vec![0; bytes.len()];
        let mut first = bytes.clone();
        NullifierFilter::from_bytes(&mut first, &[1; 32])
            .unwrap()
            .record_batch(&[nf(42)], 1, false)
            .unwrap();
        NullifierFilter::init(&mut other, &[2; 32], 7)
            .unwrap()
            .record_batch(&[nf(42)], 1, false)
            .unwrap();
        assert_ne!(&first[HEADER..], &other[HEADER..]);
    }

    #[test]
    fn saturation_falls_back_without_clearing_history() {
        let mut bytes = init(1, 8);
        let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        filter.record_batch(&[nf(1)], 1, false).unwrap();
        assert_eq!(
            filter.check_batch(&[nf(1), nf(2), nf(3)], 2).unwrap(),
            vec![0, 1, 2]
        );
        assert_eq!(
            filter.record_batch(&[nf(2)], 2, false),
            Err(FilterError::NeedsProof)
        );
        assert_eq!(filter.next_sequence(), 2);
        filter.record_batch(&[nf(2)], 2, true).unwrap();
        assert_eq!(filter.next_sequence(), 3);
        assert_eq!(filter.check_batch(&[nf(1), nf(2)], 3).unwrap(), vec![0, 1]);
    }

    #[test]
    fn batch_checks_use_the_pre_transaction_bits() {
        let mut bytes = init(1, 8);
        let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        filter.record_batch(&[nf(1), nf(2)], 1, false).unwrap();
        assert_eq!(filter.check_batch(&[nf(1), nf(2)], 3).unwrap(), vec![0, 1]);
    }

    #[test]
    fn overflow_and_reinitialization_fail_without_writes() {
        let mut bytes = init(32, 7);
        bytes[SEQUENCE].copy_from_slice(&u64::MAX.to_le_bytes());
        let before = bytes.clone();
        let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        assert_eq!(
            filter.record_batch(&[nf(1)], u64::MAX, true),
            Err(FilterError::InvalidBatch)
        );
        assert_eq!(bytes, before);
        assert!(NullifierFilter::init_zeroed(&mut bytes, &[1; 32], 7).is_err());
        assert_eq!(bytes, before);
    }

    #[test]
    fn checkpoint_clears_bits_and_keeps_the_backlog() {
        let mut bytes = init(1024, 7);
        let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        assert_eq!(filter.checkpoint_root(), NULLIFIER_TREE_INIT_ROOT_40);
        assert_eq!(filter.checkpoint_index(), 1);
        assert!(filter.is_settled());
        let spent: Vec<_> = (1..=300).map(nf).collect();
        filter.record_batch(&spent, 1, false).unwrap();
        assert_eq!(filter.check_batch(&spent, 301).unwrap().len(), 300);

        // The tree inserted the first 200; the last 100 are still queued and
        // come back in two chunks.
        filter.begin_checkpoint([7; 32], 201, 150).unwrap();
        assert!(!filter.is_settled());
        assert_eq!(filter.rebuild_cursor(), 1);
        assert_eq!(filter.rebuild_close_before(), 150);
        assert!(filter.check_batch(&spent, 301).unwrap().is_empty());
        filter.record_backlog(&spent[200..250], Some(4096)).unwrap();
        assert_eq!(filter.rebuild_cursor(), 4097);
        filter.record_backlog(&spent[250..], None).unwrap();
        assert!(filter.is_settled());
        assert_eq!(filter.checkpoint_root(), [7; 32]);
        assert_eq!(filter.checkpoint_index(), 201);
        assert_eq!(filter.next_sequence(), 301, "recording continuity is kept");
        assert_eq!(
            filter.check_batch(&spent, 301).unwrap(),
            (200..300).collect::<Vec<_>>(),
            "only the backlog survives the clear"
        );
        filter.record_batch(&[nf(301)], 301, false).unwrap();
        assert_eq!(filter.check_batch(&[nf(301)], 302).unwrap(), vec![0]);
        assert_eq!(
            filter.record_backlog(&[nf(5)], None),
            Err(FilterError::InvalidFilter),
            "a settled filter takes no backlog"
        );

        let before = bytes.clone();
        let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        assert_eq!(
            filter.begin_checkpoint([8; 32], 200, 0),
            Err(FilterError::InvalidFilter),
            "a checkpoint never moves backwards"
        );
        assert_eq!(
            filter.begin_checkpoint([0; 32], 202, 0),
            Err(FilterError::InvalidFilter)
        );
        assert_eq!(bytes, before);
        let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        filter.begin_checkpoint([8; 32], 202, 0).unwrap();
        let too_many: Vec<_> = (1..=MAX_CHECKPOINT_BACKLOG as u64 + 1).map(nf).collect();
        assert_eq!(
            filter.record_backlog(&too_many, None),
            Err(FilterError::InvalidBatch)
        );
        assert_eq!(
            filter.record_backlog(&[[0; 32]], None),
            Err(FilterError::InvalidBatch)
        );
        assert!(!filter.is_settled());
    }

    #[test]
    fn transaction_snapshot_can_discard_bits_and_coverage() {
        let mut committed = init(1024, 7);
        let mut working = committed.clone();
        NullifierFilter::from_bytes(&mut working, &[1; 32])
            .unwrap()
            .record_batch(&[nf(1)], 1, false)
            .unwrap();
        assert_ne!(working, committed);
        let filter = NullifierFilter::from_bytes(&mut committed, &[1; 32]).unwrap();
        assert_eq!(filter.next_sequence(), 1);
        assert!(filter.check_batch(&[nf(1)], 1).unwrap().is_empty());
    }
}
