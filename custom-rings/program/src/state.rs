use custom_ring_interface::{
    CustomRingError, MemberRegistryRoot, ReaderKeyBytes, RingAccount, MEMBER_REGISTRY_CAPACITY,
    MEMBER_REGISTRY_EMPTY_ROOT, MEMBER_REGISTRY_ROOT, MEMBER_REGISTRY_ROOT_HISTORY,
    READER_KEY_ED25519, READER_KEY_P256,
};
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use solana_curve25519::{
    edwards::{add_edwards, multiply_edwards, validate_edwards, PodEdwardsPoint},
    scalar::PodScalar,
};

/// Writes `T` into a freshly created account.
pub(crate) struct Init<'a, T>(pub &'a T);

impl<T: RingAccount> Init<'_, T> {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let mut data = account.try_borrow_mut().map_err(|_| T::EXISTS)?;
        if data.len() != T::SIZE {
            return Err(T::ADDRESS.into());
        }
        // A nonzero first byte is a live discriminator, never overwrite it.
        if data[0] != 0 {
            return Err(T::EXISTS.into());
        }
        data.copy_from_slice(bytemuck::bytes_of(self.0));
        Ok(())
    }
}

/// Leaf 0 holds the sentinel, inserts start at index 1.
pub(crate) const fn empty_member_registry_root(bump: u8) -> MemberRegistryRoot {
    let mut history = [[0u8; 32]; MEMBER_REGISTRY_ROOT_HISTORY];
    history[0] = MEMBER_REGISTRY_EMPTY_ROOT;
    MemberRegistryRoot {
        discriminator: MEMBER_REGISTRY_ROOT,
        next_index: 1u64.to_le_bytes(),
        bump,
        history_cursor: 0,
        history,
    }
}

/// Accepts a canonical auditor key only when clamped ECDH can be contributory.
/// Low-order peers yield zero DH for every secret and cannot satisfy the proof.
pub(crate) fn is_x25519_key(key: &[u8; 33]) -> bool {
    const LOW_ORDER_U: [[u8; 32]; 5] = [
        [0; 32],
        {
            let mut u = [0; 32];
            u[0] = 1;
            u
        },
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
        {
            let mut u = [0xff; 32];
            u[0] = 0xec;
            u[31] = 0x7f;
            u
        },
    ];

    key[0] == 4
        && <&[u8; 32]>::try_from(&key[1..]).is_ok_and(|u| {
            zolana_hasher::primitives::is_canonical_x25519_public_key(u) && !LOW_ORDER_U.contains(u)
        })
}

/// Curve membership is the SDK's job, an off-curve key only fails its own ring closed.
pub(crate) fn is_p256_key(key: &[u8; 33]) -> bool {
    matches!(key[0], 0x02 | 0x03) && !zolana_interface::is_reserved_p256_derivation_point(key)
}

pub(crate) fn check_reader_key(key: &ReaderKeyBytes) -> Result<(), CustomRingError> {
    let valid = match key[0] {
        READER_KEY_P256 => <&[u8; 33]>::try_from(&key[1..]).is_ok_and(is_p256_key),
        READER_KEY_ED25519 => {
            key[33] == 0 && <[u8; 32]>::try_from(&key[1..33]).is_ok_and(is_signing_ed25519_key)
        }
        _ => false,
    };
    valid.then_some(()).ok_or(CustomRingError::InvalidReaderKey)
}

fn is_signing_ed25519_key(body: [u8; 32]) -> bool {
    const FIELD_MODULUS: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    const SUBGROUP_ORDER_MINUS_ONE: PodScalar = PodScalar([
        0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ]);
    const IDENTITY: PodEdwardsPoint = PodEdwardsPoint([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);

    let mut y = body;
    y[31] &= 0x7f;
    let point = PodEdwardsPoint(body);
    y.iter().rev().cmp(FIELD_MODULUS.iter().rev()).is_lt()
        && validate_edwards(&point)
        && y != IDENTITY.0
        && multiply_edwards(&SUBGROUP_ORDER_MINUS_ONE, &point)
            .and_then(|multiple| add_edwards(&multiple, &point))
            .is_some_and(|point| point == IDENTITY)
}

/// A proven registry transition, applied only from the root the proof was built on.
#[must_use]
pub(crate) struct RootTransition {
    /// The history slot the proof read, the current cursor or the proof is stale.
    pub old_root_index: u8,
    pub new_root: [u8; 32],
    /// Records appended at the next free indices.
    pub inserts: u64,
}

#[must_use]
pub(crate) struct CheckedRootTransition {
    old_root: [u8; 32],
    new_root: [u8; 32],
    next_index: u64,
}

impl RootTransition {
    pub fn check(self, root: &MemberRegistryRoot) -> Result<CheckedRootTransition, ProgramError> {
        if self.old_root_index != root.history_cursor {
            return Err(CustomRingError::StaleMemberRegistryRoot.into());
        }
        let old_root = root
            .root()
            .ok_or(CustomRingError::InvalidMemberRegistryRoot)?;
        let next_index = root.next_index();
        let advanced = next_index.checked_add(self.inserts);
        if next_index == 0 || advanced.is_none_or(|next| next > MEMBER_REGISTRY_CAPACITY) {
            return Err(CustomRingError::InvalidMemberRegistryCursor.into());
        }
        Ok(CheckedRootTransition {
            old_root,
            new_root: self.new_root,
            next_index: next_index + self.inserts,
        })
    }
}

impl CheckedRootTransition {
    pub fn old_root(&self) -> &[u8; 32] {
        &self.old_root
    }

    pub fn apply(self, root: &mut MemberRegistryRoot) {
        let cursor = (usize::from(root.history_cursor) + 1) % MEMBER_REGISTRY_ROOT_HISTORY;
        root.history[cursor] = self.new_root;
        root.history_cursor = cursor as u8;
        root.next_index = self.next_index.to_le_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(root: [u8; 32], next_index: u64) -> MemberRegistryRoot {
        let mut state = empty_member_registry_root(254);
        state.history[0] = root;
        state.next_index = next_index.to_le_bytes();
        state
    }

    fn advance(state: &mut MemberRegistryRoot, transition: RootTransition) -> ProgramResult {
        transition.check(state)?.apply(state);
        Ok(())
    }

    fn apply(state: &mut MemberRegistryRoot, old_root_index: u8, inserts: u64) -> ProgramResult {
        advance(
            state,
            RootTransition {
                old_root_index,
                new_root: [7u8; 32],
                inserts,
            },
        )
    }

    fn custom(error: CustomRingError) -> ProgramError {
        ProgramError::Custom(error as u32)
    }

    #[test]
    fn a_proof_built_on_an_older_root_is_refused() {
        let mut state = root([1u8; 32], 1);
        assert_eq!(
            apply(&mut state, 1, 0),
            Err(custom(CustomRingError::StaleMemberRegistryRoot))
        );
        assert_eq!(state.root(), Some([1u8; 32]));
    }

    #[test]
    fn a_transition_advances_the_cursor_and_the_append_index_by_its_inserts() {
        let mut state = root([1u8; 32], 5);
        apply(&mut state, 0, 2).expect("advance");
        assert_eq!(state.root(), Some([7u8; 32]));
        assert_eq!(state.next_index(), 7);
        assert_eq!(state.history_cursor, 1);
        apply(&mut state, 1, 0).expect("rewrite only");
        assert_eq!(state.next_index(), 7);
    }

    #[test]
    fn the_sentinel_root_is_the_first_history_entry() {
        let state = empty_member_registry_root(254);
        assert_eq!(state.root(), Some(MEMBER_REGISTRY_EMPTY_ROOT));
        assert_eq!(state.next_index(), 1);
        assert_eq!(state.root_at(1), None);
        assert_eq!(state.root_at(MEMBER_REGISTRY_ROOT_HISTORY as u8), None);
        assert_eq!(state.root_at(u8::MAX), None);
    }

    #[test]
    fn the_history_keeps_every_root_and_wraps_over_the_oldest() {
        let mut state = root([1u8; 32], 1);
        for step in 1..=MEMBER_REGISTRY_ROOT_HISTORY as u8 {
            let old_root_index = state.history_cursor;
            advance(
                &mut state,
                RootTransition {
                    old_root_index,
                    new_root: [step + 1; 32],
                    inserts: 1,
                },
            )
            .expect("advance");
            let slot = usize::from(step) % MEMBER_REGISTRY_ROOT_HISTORY;
            assert_eq!(usize::from(state.history_cursor), slot);
            assert_eq!(state.root_at(slot as u8), Some([step + 1; 32]));
        }
        assert_eq!(
            state.root_at(0),
            Some([MEMBER_REGISTRY_ROOT_HISTORY as u8 + 1; 32])
        );
        assert_eq!(state.root_at(1), Some([2u8; 32]));
        assert!(!state.history.contains(&[1u8; 32]));
    }

    #[test]
    fn inserts_past_the_capacity_or_from_a_zero_cursor_are_refused() {
        let mut state = root([1u8; 32], 0);
        assert_eq!(
            apply(&mut state, 0, 1),
            Err(custom(CustomRingError::InvalidMemberRegistryCursor))
        );
        let mut state = root([1u8; 32], MEMBER_REGISTRY_CAPACITY - 1);
        apply(&mut state, 0, 1).expect("the last leaf");
        assert_eq!(
            apply(&mut state, 1, 1),
            Err(custom(CustomRingError::InvalidMemberRegistryCursor))
        );
        apply(&mut state, 1, 0).expect("a rewrite of a full registry");
    }
}
