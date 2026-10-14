use custom_ring_interface::{
    CustomRingError, KeyRegistryRoot, ReaderKeyBytes, RingAccount, KEY_REGISTRY_CAPACITY,
    KEY_REGISTRY_EMPTY_ROOT, KEY_REGISTRY_ROOT, KEY_REGISTRY_ROOT_HISTORY, READER_KEY_ED25519,
    READER_KEY_P256,
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

/// Leaf 0 holds the sentinel, appends start at index 1.
pub(crate) const fn empty_key_registry_root(bump: u8) -> KeyRegistryRoot {
    let mut history = [[0u8; 32]; KEY_REGISTRY_ROOT_HISTORY];
    history[0] = KEY_REGISTRY_EMPTY_ROOT;
    KeyRegistryRoot {
        discriminator: KEY_REGISTRY_ROOT,
        next_index: 1u64.to_le_bytes(),
        bump,
        history_cursor: 0,
        history,
    }
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

#[must_use]
pub(crate) struct RootTransition<'a> {
    pub expected_root: &'a [u8; 32],
    pub expected_next_index: u64,
    pub new_root: [u8; 32],
}

#[must_use]
pub(crate) struct CheckedRootTransition {
    new_root: [u8; 32],
    next_index: u64,
}

impl RootTransition<'_> {
    pub fn check(self, root: &KeyRegistryRoot) -> Result<CheckedRootTransition, ProgramError> {
        if root.root().as_ref() != Some(self.expected_root) {
            return Err(CustomRingError::StaleKeyRegistryRoot.into());
        }
        let next_index = root.next_index();
        if next_index != self.expected_next_index
            || next_index == 0
            || next_index >= KEY_REGISTRY_CAPACITY
        {
            return Err(CustomRingError::InvalidKeyRegistryCursor.into());
        }
        Ok(CheckedRootTransition {
            new_root: self.new_root,
            next_index,
        })
    }
}

impl CheckedRootTransition {
    pub fn apply(self, root: &mut KeyRegistryRoot) {
        let cursor = (usize::from(root.history_cursor) + 1) % KEY_REGISTRY_ROOT_HISTORY;
        root.history[cursor] = self.new_root;
        root.history_cursor = cursor as u8;
        root.next_index = (self.next_index + 1).to_le_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(root: [u8; 32], next_index: u64) -> KeyRegistryRoot {
        let mut state = empty_key_registry_root(254);
        state.history[0] = root;
        state.next_index = next_index.to_le_bytes();
        state
    }

    fn advance(state: &mut KeyRegistryRoot, transition: RootTransition) -> ProgramResult {
        transition.check(state)?.apply(state);
        Ok(())
    }

    fn apply(state: &mut KeyRegistryRoot, expected_root: &[u8; 32]) -> ProgramResult {
        let expected_next_index = state.next_index();
        advance(
            state,
            RootTransition {
                expected_root,
                expected_next_index,
                new_root: [7u8; 32],
            },
        )
    }

    fn custom(error: CustomRingError) -> ProgramError {
        ProgramError::Custom(error as u32)
    }

    #[test]
    fn a_root_that_is_not_the_current_root_is_refused() {
        let mut state = root([1u8; 32], 1);
        assert_eq!(
            apply(&mut state, &[2u8; 32]),
            Err(custom(CustomRingError::StaleKeyRegistryRoot))
        );
        assert_eq!(state.root(), Some([1u8; 32]));
    }

    #[test]
    fn registration_advances_the_cursor_and_publishes_the_successor_root() {
        let mut state = root([1u8; 32], 5);
        apply(&mut state, &[1u8; 32]).expect("advance");
        assert_eq!(state.root(), Some([7u8; 32]));
        assert_eq!(state.next_index(), 6);
    }

    #[test]
    fn the_sentinel_root_is_the_first_history_entry() {
        let state = empty_key_registry_root(254);
        assert_eq!(state.root(), Some(KEY_REGISTRY_EMPTY_ROOT));
        assert_eq!(state.root_at(1), None);
        assert_eq!(state.root_at(KEY_REGISTRY_ROOT_HISTORY as u8), None);
        assert_eq!(state.root_at(u8::MAX), None);
    }

    #[test]
    fn the_history_keeps_every_root_and_wraps_over_the_oldest() {
        let mut state = root([1u8; 32], 1);
        for step in 1..=KEY_REGISTRY_ROOT_HISTORY as u8 {
            let current = state.root().expect("current root");
            let expected_next_index = state.next_index();
            advance(
                &mut state,
                RootTransition {
                    expected_root: &current,
                    expected_next_index,
                    new_root: [step + 1; 32],
                },
            )
            .expect("advance");
            let slot = usize::from(step) % KEY_REGISTRY_ROOT_HISTORY;
            assert_eq!(usize::from(state.history_cursor), slot);
            assert_eq!(state.root_at(slot as u8), Some([step + 1; 32]));
        }
        assert_eq!(
            state.root_at(0),
            Some([KEY_REGISTRY_ROOT_HISTORY as u8 + 1; 32])
        );
        assert_eq!(state.root_at(1), Some([2u8; 32]));
        assert!(!state.history.contains(&[1u8; 32]));
    }

    #[test]
    fn registration_refuses_an_out_of_bounds_or_moved_cursor() {
        for cursor in [0, KEY_REGISTRY_CAPACITY] {
            let mut state = root([1u8; 32], cursor);
            assert_eq!(
                apply(&mut state, &[1u8; 32]),
                Err(custom(CustomRingError::InvalidKeyRegistryCursor))
            );
        }
        let mut state = root([1u8; 32], 5);
        assert_eq!(
            advance(
                &mut state,
                RootTransition {
                    expected_root: &[1u8; 32],
                    expected_next_index: 4,
                    new_root: [7u8; 32],
                },
            ),
            Err(custom(CustomRingError::InvalidKeyRegistryCursor))
        );
    }
}
