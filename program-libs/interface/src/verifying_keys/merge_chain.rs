use crate::instruction::instruction_data::merge_transact::MERGE_INPUT_COUNT;

/// A chain of one leg is a merge, and the outer proof would cost more than the
/// merge it replaced.
pub const MIN_MERGE_CHAIN_LEGS: usize = 2;

/// Bounds the instruction's vectors. The limit is the transaction, not the
/// circuit. Every tree-backed input carries a nullifier and two root indices.
pub const MAX_MERGE_CHAIN_LEGS: usize = 9;

/// Bounds the level vector before any leg count is derived from it.
pub const MAX_MERGE_CHAIN_LEVELS: usize = 8;

/// Legs a level shape totals, or `None` when the shape is not a tree the chain
/// circuit can be built for.
///
/// Level 0 legs spend only tree-backed UTXOs. Every later level consumes the
/// previous level's outputs, up to `MERGE_INPUT_COUNT` per leg, and the top
/// level is one leg whose output is the only one the pool inserts. A level too
/// small to absorb the one below would leave an output nothing spends.
pub fn merge_chain_legs(levels: &[u8]) -> Option<usize> {
    if levels.len() < 2 || levels.len() > MAX_MERGE_CHAIN_LEVELS {
        return None;
    }
    if *levels.last()? != 1 {
        return None;
    }
    let mut legs = 0usize;
    for (level, &count) in levels.iter().enumerate() {
        if count == 0 {
            return None;
        }
        if level > 0 && usize::from(count) * MERGE_INPUT_COUNT < usize::from(levels[level - 1]) {
            return None;
        }
        legs += usize::from(count);
    }
    if !(MIN_MERGE_CHAIN_LEGS..=MAX_MERGE_CHAIN_LEGS).contains(&legs) {
        return None;
    }
    Some(legs)
}

/// UTXOs a chain spends out of the state tree, which is the number of
/// nullifiers the transaction carries. Every leg but the top one fills exactly
/// one slot of the level above.
pub const fn merge_chain_tree_inputs(legs: usize) -> usize {
    (MERGE_INPUT_COUNT - 1) * legs + 1
}

/// Chained slots per leg, in the leg order the circuit verifies. A chained slot
/// spends the output of the level below, so it publishes no nullifier and the
/// transaction drops it from every per-slot vector.
///
/// Mirrors `NewShape` in `prover/server/circuits/spp_merge_chain`. A level
/// consumes the one below in order, up to `MERGE_INPUT_COUNT` per leg, and the
/// chained slots take the high slots of a leg so the tree-backed inputs keep a
/// contiguous low range.
pub fn merge_chain_chained_slots(levels: &[u8]) -> Option<Vec<u8>> {
    let legs = merge_chain_legs(levels)?;
    let mut chained = vec![0u8; legs];
    let mut base = Vec::with_capacity(levels.len());
    let mut total = 0usize;
    for &count in levels {
        base.push(total);
        total += usize::from(count);
    }
    for level in 1..levels.len() {
        let mut source = base[level - 1];
        let end = base[level - 1] + usize::from(levels[level - 1]);
        for slot_count in chained
            .iter_mut()
            .skip(base[level])
            .take(usize::from(levels[level]))
        {
            let count = (end - source).min(MERGE_INPUT_COUNT);
            *slot_count = count as u8;
            source += count;
        }
    }
    Some(chained)
}

/// The outer verifying key for a level shape, or `None` when the shape names
/// no generated key. Fail closed. An unlisted shape is rejected before any
/// pairing runs.
#[cfg(feature = "verifying-keys")]
pub fn merge_chain_verifying_key(
    levels: &[u8],
) -> Option<&'static groth16_solana::groth16::Groth16Verifyingkey<'static>> {
    merge_chain_legs(levels)?;
    match levels {
        [1, 1] => Some(&super::merge_chain_1_1::VERIFYINGKEY),
        [2, 1] => Some(&super::merge_chain_2_1::VERIFYINGKEY),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every leg but the top one fills exactly one slot above it, which is what
    /// makes the tree-backed input count 7*legs+1.
    #[test]
    fn chained_slots_account_for_every_leg_but_the_top() {
        for levels in [vec![1, 1], vec![2, 1], vec![1, 1, 1], vec![8, 1]] {
            let legs = merge_chain_legs(&levels).expect("closed tree");
            let chained = merge_chain_chained_slots(&levels).expect("closed tree");
            let total: usize = chained.iter().map(|&c| usize::from(c)).sum();
            assert_eq!(total, legs - 1, "levels {levels:?}");
            assert_eq!(
                MERGE_INPUT_COUNT * legs - total,
                merge_chain_tree_inputs(legs),
                "levels {levels:?}"
            );
        }
    }

    #[test]
    fn level_zero_legs_spend_only_the_tree() {
        let chained = merge_chain_chained_slots(&[2, 1]).expect("closed tree");
        assert_eq!(chained, vec![0, 0, 2]);
    }
}
