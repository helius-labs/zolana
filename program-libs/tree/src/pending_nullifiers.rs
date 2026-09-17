use thiserror::Error;
use zolana_hasher::primitives::is_canonical_bn254_scalar_be;

const HEADER: usize = 40;
const ENTRY: usize = 40;
const MAGIC: [u8; 8] = *b"ZNULLV1\0";
const MAX_PROBES: usize = 64;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PendingNullifierError {
    #[error("invalid pending-nullifier table")]
    InvalidTable,
    #[error("invalid nullifier or queue sequence")]
    InvalidEntry,
    #[error("nullifier was already spent")]
    AlreadySpent,
    #[error("pending-nullifier table has no available probe slot")]
    Full,
}

pub struct PendingNullifiers<'a> {
    entries: &'a mut [[u8; ENTRY]],
    tree: [u8; 32],
}

#[derive(Debug)]
#[must_use]
pub struct PendingNullifierBatch<'a> {
    nullifiers: &'a [[u8; 32]],
    first_sequence: u64,
    tree: [u8; 32],
}

impl<'a> PendingNullifierBatch<'a> {
    pub(crate) fn into_parts(self) -> (&'a [[u8; 32]], u64, [u8; 32]) {
        (self.nullifiers, self.first_sequence, self.tree)
    }
}

impl<'a> PendingNullifiers<'a> {
    pub fn account_size(batch_size: u64) -> Option<usize> {
        if batch_size == 0 {
            return None;
        }
        let slots = usize::try_from(batch_size)
            .ok()?
            .checked_mul(4)?
            .checked_next_power_of_two()?;
        HEADER.checked_add(slots.checked_mul(ENTRY)?)
    }

    pub fn init(bytes: &'a mut [u8], tree: &[u8; 32]) -> Result<Self, PendingNullifierError> {
        if bytes.iter().any(|byte| *byte != 0) {
            return Err(PendingNullifierError::InvalidTable);
        }
        Self::init_zeroed(bytes, tree)
    }

    /// The caller must supply freshly allocated, zero-filled program account data.
    pub fn init_zeroed(
        bytes: &'a mut [u8],
        tree: &[u8; 32],
    ) -> Result<Self, PendingNullifierError> {
        let slots = bytes
            .len()
            .checked_sub(HEADER)
            .ok_or(PendingNullifierError::InvalidTable)?;
        if slots % ENTRY != 0
            || !(slots / ENTRY).is_power_of_two()
            || bytes[..HEADER].iter().any(|byte| *byte != 0)
        {
            return Err(PendingNullifierError::InvalidTable);
        }
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[8..HEADER].copy_from_slice(tree);
        Self::from_bytes(bytes, tree)
    }

    pub fn from_bytes(bytes: &'a mut [u8], tree: &[u8; 32]) -> Result<Self, PendingNullifierError> {
        if bytes.get(..8) != Some(&MAGIC) || bytes.get(8..HEADER) != Some(tree) {
            return Err(PendingNullifierError::InvalidTable);
        }
        let (entries, remainder) = bytes[HEADER..].as_chunks_mut::<ENTRY>();
        if !remainder.is_empty() || !entries.len().is_power_of_two() {
            return Err(PendingNullifierError::InvalidTable);
        }
        Ok(Self {
            entries,
            tree: *tree,
        })
    }

    /// On error, the enclosing transaction must roll back earlier inserts in this batch.
    pub fn insert_batch<'n>(
        &'n mut self,
        nullifiers: &'n [[u8; 32]],
        first_sequence: u64,
        close_before: u64,
    ) -> Result<PendingNullifierBatch<'n>, PendingNullifierError> {
        if first_sequence == 0
            || first_sequence < close_before
            || first_sequence
                .checked_add(nullifiers.len() as u64)
                .is_none()
        {
            return Err(PendingNullifierError::InvalidEntry);
        }
        for (index, nullifier) in nullifiers.iter().enumerate() {
            self.insert(nullifier, first_sequence + index as u64, close_before)?;
        }
        Ok(PendingNullifierBatch {
            nullifiers,
            first_sequence,
            tree: self.tree,
        })
    }

    pub fn insert(
        &mut self,
        nullifier: &[u8; 32],
        sequence: u64,
        close_before: u64,
    ) -> Result<(), PendingNullifierError> {
        if sequence == 0
            || sequence < close_before
            || *nullifier == [0; 32]
            || !is_canonical_bn254_scalar_be(nullifier)
        {
            return Err(PendingNullifierError::InvalidEntry);
        }
        let start = self.bucket(nullifier);
        let mut free = None;
        for offset in 0..MAX_PROBES.min(self.entries.len()) {
            let index = (start + offset) & (self.entries.len() - 1);
            let entry = &self.entries[index];
            let stored_sequence = u64::from_le_bytes(entry[32..].try_into().unwrap());
            if stored_sequence == 0 {
                free.get_or_insert(index);
                break;
            }
            if stored_sequence < close_before {
                free.get_or_insert(index);
            } else if entry[..32] == *nullifier {
                return Err(PendingNullifierError::AlreadySpent);
            }
        }
        let entry = &mut self.entries[free.ok_or(PendingNullifierError::Full)?];
        entry[..32].copy_from_slice(nullifier);
        entry[32..].copy_from_slice(&sequence.to_le_bytes());
        Ok(())
    }

    /// Scan slots `[start, start + limit)` for entries queued at or after
    /// `sequence`: the nullifiers a checkpoint at the tree's `next_index` has
    /// to carry over, since the tree does not hold them yet. Returns them with
    /// the next slot to scan, or `None` once the table is exhausted.
    pub fn queued_since(
        &self,
        sequence: u64,
        start: usize,
        limit: usize,
    ) -> (Vec<[u8; 32]>, Option<usize>) {
        let end = start.saturating_add(limit).min(self.entries.len());
        let backlog = self.entries[start.min(end)..end]
            .iter()
            .filter(|entry| u64::from_le_bytes(entry[32..].try_into().unwrap()) >= sequence.max(1))
            .map(|entry| entry[..32].try_into().unwrap())
            .collect();
        (backlog, (end < self.entries.len()).then_some(end))
    }

    pub fn slots(&self) -> usize {
        self.entries.len()
    }

    fn bucket(&self, nullifier: &[u8; 32]) -> usize {
        let mut value = u64::from_le_bytes(nullifier[..8].try_into().unwrap());
        value ^= u64::from_le_bytes(nullifier[24..].try_into().unwrap());
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
        ((value ^ (value >> 31)) as usize) & (self.entries.len() - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nullifier(n: u64) -> [u8; 32] {
        let mut value = [0; 32];
        value[24..].copy_from_slice(&n.to_be_bytes());
        value
    }

    #[test]
    fn queued_since_lists_the_uninserted_backlog_in_chunks() {
        let mut bytes = vec![0; PendingNullifiers::account_size(10).unwrap()];
        let mut table = PendingNullifiers::init(&mut bytes, &[1; 32]).unwrap();
        for sequence in 1..=5 {
            table.insert(&nullifier(sequence), sequence, 0).unwrap();
        }
        let slots = table.slots();
        let (mut backlog, next) = table.queued_since(4, 0, slots);
        backlog.sort_unstable();
        assert_eq!(backlog, vec![nullifier(4), nullifier(5)]);
        assert_eq!(next, None);
        assert_eq!(table.queued_since(6, 0, slots).0, Vec::<[u8; 32]>::new());
        assert_eq!(
            table.queued_since(0, 0, slots).0.len(),
            5,
            "empty slots are skipped"
        );

        let mut chunked = Vec::new();
        let mut cursor = Some(0);
        while let Some(start) = cursor {
            let (part, next) = table.queued_since(1, start, 3);
            chunked.extend(part);
            cursor = next;
        }
        chunked.sort_unstable();
        assert_eq!(chunked, (1..=5).map(nullifier).collect::<Vec<_>>());
        assert_eq!(table.queued_since(1, slots, 3), (Vec::new(), None));
    }

    #[test]
    fn rejects_replays_until_the_watermark_passes() {
        let mut bytes = vec![0; PendingNullifiers::account_size(10).unwrap()];
        let mut table = PendingNullifiers::init(&mut bytes, &[1; 32]).unwrap();
        table.insert(&nullifier(1), 1, 0).unwrap();
        assert_eq!(
            table.insert(&nullifier(1), 2, 1),
            Err(PendingNullifierError::AlreadySpent)
        );
        table.insert(&nullifier(1), 2, 2).unwrap();
        assert_eq!(
            table.insert(&nullifier(1), 3, 2),
            Err(PendingNullifierError::AlreadySpent)
        );
    }

    #[test]
    fn expired_collision_does_not_hide_a_live_entry() {
        let mut bytes = vec![0; PendingNullifiers::account_size(10).unwrap()];
        let mut table = PendingNullifiers::init(&mut bytes, &[1; 32]).unwrap();
        let first = nullifier(1);
        let second = (2..)
            .map(nullifier)
            .find(|v| table.bucket(v) == table.bucket(&first))
            .unwrap();
        table.insert(&first, 1, 0).unwrap();
        table.insert(&second, 2, 0).unwrap();
        assert_eq!(
            table.insert(&second, 3, 2),
            Err(PendingNullifierError::AlreadySpent)
        );
        table.insert(&nullifier(3), 3, 2).unwrap();
    }

    #[test]
    fn collision_limit_fails_without_overwriting() {
        let mut bytes = vec![0; PendingNullifiers::account_size(32).unwrap()];
        let mut table = PendingNullifiers::init(&mut bytes, &[1; 32]).unwrap();
        let values: Vec<_> = (1..)
            .map(nullifier)
            .filter(|v| table.bucket(v) == 0)
            .take(MAX_PROBES + 1)
            .collect();
        for (i, value) in values[..MAX_PROBES].iter().enumerate() {
            table.insert(value, i as u64 + 1, 0).unwrap();
        }
        assert_eq!(
            table.insert(&values[MAX_PROBES], 100, 0),
            Err(PendingNullifierError::Full)
        );
        assert_eq!(
            table.insert(&values[0], 100, 0),
            Err(PendingNullifierError::AlreadySpent)
        );
    }

    #[test]
    fn validates_tree_and_layout() {
        let mut bytes = vec![0; PendingNullifiers::account_size(10).unwrap()];
        PendingNullifiers::init(&mut bytes, &[1; 32]).unwrap();
        assert!(PendingNullifiers::from_bytes(&mut bytes, &[2; 32]).is_err());
        assert!(PendingNullifiers::init(&mut bytes, &[1; 32]).is_err());
        bytes.pop();
        assert!(PendingNullifiers::from_bytes(&mut bytes, &[1; 32]).is_err());
    }

    #[test]
    fn rejects_invalid_entries() {
        let mut bytes = vec![0; PendingNullifiers::account_size(10).unwrap()];
        let mut table = PendingNullifiers::init(&mut bytes, &[1; 32]).unwrap();
        for (value, sequence, watermark) in [
            ([0; 32], 1, 0),
            ([255; 32], 1, 0),
            (nullifier(1), 0, 0),
            (nullifier(1), 1, 2),
        ] {
            assert_eq!(
                table.insert(&value, sequence, watermark),
                Err(PendingNullifierError::InvalidEntry)
            );
        }
    }

    #[test]
    fn rejects_zero_batch_size() {
        assert_eq!(PendingNullifiers::account_size(0), None);
    }

    #[test]
    fn batch_receipt_binds_the_values_sequence_and_tree() {
        let mut bytes = vec![0; PendingNullifiers::account_size(10).unwrap()];
        let mut table = PendingNullifiers::init(&mut bytes, &[7; 32]).unwrap();
        let values = [nullifier(1), nullifier(2)];
        let receipt = table.insert_batch(&values, 4, 3).unwrap();
        assert_eq!(receipt.into_parts(), (values.as_slice(), 4, [7; 32]));
        assert_eq!(
            table.insert_batch(&values, 6, 3).unwrap_err(),
            PendingNullifierError::AlreadySpent
        );
    }

    #[test]
    fn invalid_or_duplicate_batches_cannot_issue_a_receipt() {
        for (values, first, watermark, error) in [
            (
                vec![nullifier(1), [0; 32]],
                1,
                0,
                PendingNullifierError::InvalidEntry,
            ),
            (
                vec![nullifier(1), [255; 32]],
                1,
                0,
                PendingNullifierError::InvalidEntry,
            ),
            (
                vec![nullifier(1), nullifier(1)],
                1,
                0,
                PendingNullifierError::AlreadySpent,
            ),
            (
                vec![nullifier(1)],
                0,
                0,
                PendingNullifierError::InvalidEntry,
            ),
            (
                vec![nullifier(1)],
                1,
                2,
                PendingNullifierError::InvalidEntry,
            ),
            (
                vec![nullifier(1), nullifier(2)],
                u64::MAX - 1,
                0,
                PendingNullifierError::InvalidEntry,
            ),
        ] {
            let mut bytes = vec![0; PendingNullifiers::account_size(10).unwrap()];
            let mut table = PendingNullifiers::init(&mut bytes, &[1; 32]).unwrap();
            assert_eq!(
                table.insert_batch(&values, first, watermark).unwrap_err(),
                error
            );
        }
    }
}
