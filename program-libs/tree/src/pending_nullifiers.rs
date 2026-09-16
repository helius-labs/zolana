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
        Ok(Self { entries })
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
}
