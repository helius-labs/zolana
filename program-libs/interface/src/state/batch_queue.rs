//! Byte layout of the two-phase operator batch queue (`docs/batching/two-phase.md`).
//!
//! The account is operator-owned and moves through three stages: filling,
//! verified, applied. Each slot stores one pure-shielded transact payload, its
//! fold-ready decompressed proof, and the input owner hashes that the enqueue
//! signer checks produced. Layout helpers live here so the program, builders,
//! and tests agree on offsets without a second definition.

use crate::state::discriminator::BATCH_QUEUE_ACCOUNT_DISCRIMINATOR;

/// Queue capacity for v1. Sixteen matches the fold table and bounds the
/// account near 27 KB.
pub const MAX_QUEUE_ENTRIES: usize = 16;
/// One slot holds any entry that fits a solo transaction packet.
pub const MAX_ENTRY_BYTES: usize = 1232;
/// Decompressed proof: a (64) then b (128) then c (64), fold-ready with `a`
/// un-negated.
pub const ENTRY_PROOF_BYTES: usize = 256;
/// Input owner hash slots per entry, the circuit input maximum.
pub const MAX_ENTRY_SIGNERS: usize = 5;

pub const STAGE_FILLING: u8 = 0;
pub const STAGE_VERIFIED: u8 = 1;
pub const STAGE_APPLIED: u8 = 2;

/// Header layout, in order: discriminator, stage, count, applied cursor,
/// allow-dummy flag captured at verify, circuit (variant, inputs, outputs,
/// public slots), operator address.
pub const HEADER_SIZE: usize = 1 + 1 + 1 + 1 + 1 + 4 + 32;
pub const SLOT_SIZE: usize =
    2 + MAX_ENTRY_BYTES + ENTRY_PROOF_BYTES + MAX_ENTRY_SIGNERS * 32;
pub const QUEUE_ACCOUNT_SIZE: usize = HEADER_SIZE + MAX_QUEUE_ENTRIES * SLOT_SIZE;

const OFFSET_STAGE: usize = 1;
const OFFSET_COUNT: usize = 2;
const OFFSET_APPLIED: usize = 3;
const OFFSET_ALLOW_DUMMY: usize = 4;
const OFFSET_CIRCUIT: usize = 5;
const OFFSET_OPERATOR: usize = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchQueueError;

fn check(data: &[u8]) -> Result<(), BatchQueueError> {
    if data.len() != QUEUE_ACCOUNT_SIZE || data[0] != BATCH_QUEUE_ACCOUNT_DISCRIMINATOR {
        return Err(BatchQueueError);
    }
    Ok(())
}

/// Initialize a zeroed account: discriminator, filling stage, circuit, and
/// operator. The caller must check that the account was zero before.
pub fn init(data: &mut [u8], circuit: [u8; 4], operator: [u8; 32]) -> Result<(), BatchQueueError> {
    if data.len() != QUEUE_ACCOUNT_SIZE {
        return Err(BatchQueueError);
    }
    data[0] = BATCH_QUEUE_ACCOUNT_DISCRIMINATOR;
    data[OFFSET_STAGE] = STAGE_FILLING;
    data[OFFSET_COUNT] = 0;
    data[OFFSET_APPLIED] = 0;
    data[OFFSET_ALLOW_DUMMY] = 0;
    data[OFFSET_CIRCUIT..OFFSET_CIRCUIT + 4].copy_from_slice(&circuit);
    data[OFFSET_OPERATOR..OFFSET_OPERATOR + 32].copy_from_slice(&operator);
    Ok(())
}

pub fn stage(data: &[u8]) -> Result<u8, BatchQueueError> {
    check(data)?;
    Ok(data[OFFSET_STAGE])
}

pub fn set_stage(data: &mut [u8], stage: u8) -> Result<(), BatchQueueError> {
    check(data)?;
    data[OFFSET_STAGE] = stage;
    Ok(())
}

pub fn count(data: &[u8]) -> Result<usize, BatchQueueError> {
    check(data)?;
    Ok(usize::from(data[OFFSET_COUNT]))
}

pub fn applied(data: &[u8]) -> Result<usize, BatchQueueError> {
    check(data)?;
    Ok(usize::from(data[OFFSET_APPLIED]))
}

pub fn set_applied(data: &mut [u8], applied: usize) -> Result<(), BatchQueueError> {
    check(data)?;
    data[OFFSET_APPLIED] = u8::try_from(applied).map_err(|_| BatchQueueError)?;
    Ok(())
}

pub fn allow_dummy(data: &[u8]) -> Result<bool, BatchQueueError> {
    check(data)?;
    Ok(data[OFFSET_ALLOW_DUMMY] == 1)
}

pub fn set_allow_dummy(data: &mut [u8], allow: bool) -> Result<(), BatchQueueError> {
    check(data)?;
    data[OFFSET_ALLOW_DUMMY] = u8::from(allow);
    Ok(())
}

pub fn circuit(data: &[u8]) -> Result<[u8; 4], BatchQueueError> {
    check(data)?;
    let mut out = [0u8; 4];
    out.copy_from_slice(&data[OFFSET_CIRCUIT..OFFSET_CIRCUIT + 4]);
    Ok(out)
}

pub fn operator(data: &[u8]) -> Result<[u8; 32], BatchQueueError> {
    check(data)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[OFFSET_OPERATOR..OFFSET_OPERATOR + 32]);
    Ok(out)
}

fn slot_range(index: usize) -> Result<core::ops::Range<usize>, BatchQueueError> {
    if index >= MAX_QUEUE_ENTRIES {
        return Err(BatchQueueError);
    }
    let start = HEADER_SIZE + index * SLOT_SIZE;
    Ok(start..start + SLOT_SIZE)
}

/// Append one entry: payload bytes, fold-ready proof, and the input owner
/// hashes. Returns the new count.
pub fn push_entry(
    data: &mut [u8],
    payload: &[u8],
    proof: &[u8; ENTRY_PROOF_BYTES],
    input_owner_pk_hashes: &[[u8; 32]],
) -> Result<usize, BatchQueueError> {
    check(data)?;
    if payload.len() > MAX_ENTRY_BYTES || input_owner_pk_hashes.len() > MAX_ENTRY_SIGNERS {
        return Err(BatchQueueError);
    }
    let index = usize::from(data[OFFSET_COUNT]);
    let range = slot_range(index)?;
    let slot = &mut data[range];
    let payload_len = u16::try_from(payload.len()).map_err(|_| BatchQueueError)?;
    slot[..2].copy_from_slice(&payload_len.to_le_bytes());
    slot[2..2 + payload.len()].copy_from_slice(payload);
    let proof_start = 2 + MAX_ENTRY_BYTES;
    slot[proof_start..proof_start + ENTRY_PROOF_BYTES].copy_from_slice(proof);
    let signers_start = proof_start + ENTRY_PROOF_BYTES;
    for (i, hash) in input_owner_pk_hashes.iter().enumerate() {
        let at = signers_start + i * 32;
        slot[at..at + 32].copy_from_slice(hash);
    }
    data[OFFSET_COUNT] = (index + 1) as u8;
    Ok(index + 1)
}

pub struct EntryView<'a> {
    pub payload: &'a [u8],
    pub proof: &'a [u8; ENTRY_PROOF_BYTES],
    pub input_owner_pk_hashes: &'a [u8],
}

impl EntryView<'_> {
    pub fn input_owner_pk_hash(&self, index: usize) -> Result<[u8; 32], BatchQueueError> {
        let start = index.checked_mul(32).ok_or(BatchQueueError)?;
        let bytes = self
            .input_owner_pk_hashes
            .get(start..start + 32)
            .ok_or(BatchQueueError)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    }
}

pub fn entry(data: &[u8], index: usize) -> Result<EntryView<'_>, BatchQueueError> {
    check(data)?;
    if index >= usize::from(data[OFFSET_COUNT]) {
        return Err(BatchQueueError);
    }
    let range = slot_range(index)?;
    let slot = &data[range];
    let payload_len = usize::from(u16::from_le_bytes([slot[0], slot[1]]));
    if payload_len > MAX_ENTRY_BYTES {
        return Err(BatchQueueError);
    }
    let proof_start = 2 + MAX_ENTRY_BYTES;
    let signers_start = proof_start + ENTRY_PROOF_BYTES;
    Ok(EntryView {
        payload: &slot[2..2 + payload_len],
        proof: slot[proof_start..proof_start + ENTRY_PROOF_BYTES]
            .try_into()
            .map_err(|_| BatchQueueError)?,
        input_owner_pk_hashes: &slot[signers_start..signers_start + MAX_ENTRY_SIGNERS * 32],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_round_trip() {
        let mut data = vec![0u8; QUEUE_ACCOUNT_SIZE];
        init(&mut data, [0, 1, 1, 3], [7u8; 32]).expect("init");
        assert_eq!(stage(&data), Ok(STAGE_FILLING));
        assert_eq!(count(&data), Ok(0));
        assert_eq!(circuit(&data), Ok([0, 1, 1, 3]));
        assert_eq!(operator(&data), Ok([7u8; 32]));

        let payload = vec![9u8; 700];
        let proof = [3u8; ENTRY_PROOF_BYTES];
        let signers = [[4u8; 32]];
        assert_eq!(push_entry(&mut data, &payload, &proof, &signers), Ok(1));

        let view = entry(&data, 0).expect("entry");
        assert_eq!(view.payload, payload.as_slice());
        assert_eq!(view.proof, &proof);
        assert_eq!(view.input_owner_pk_hash(0), Ok([4u8; 32]));

        set_stage(&mut data, STAGE_VERIFIED).expect("stage");
        set_allow_dummy(&mut data, true).expect("allow dummy");
        set_applied(&mut data, 1).expect("applied");
        assert_eq!(stage(&data), Ok(STAGE_VERIFIED));
        assert_eq!(allow_dummy(&data), Ok(true));
        assert_eq!(applied(&data), Ok(1));
    }

    #[test]
    fn full_queue_rejects_push() {
        let mut data = vec![0u8; QUEUE_ACCOUNT_SIZE];
        init(&mut data, [0, 1, 1, 3], [7u8; 32]).expect("init");
        let proof = [0u8; ENTRY_PROOF_BYTES];
        for _ in 0..MAX_QUEUE_ENTRIES {
            push_entry(&mut data, &[1], &proof, &[]).expect("push");
        }
        assert_eq!(push_entry(&mut data, &[1], &proof, &[]), Err(BatchQueueError));
    }
}
