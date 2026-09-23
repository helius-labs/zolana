use bytemuck::{from_bytes_mut, Pod};
use custom_ring_interface::{
    CoSigner, Delegate, KeyRegistryRoot, PolicyConfig, SourceSlot, SpendWindow,
    WithdrawalThresholdRow, CO_SIGNER, DELEGATE, KEY_REGISTRY_CAPACITY, KEY_REGISTRY_EMPTY_ROOT,
    KEY_REGISTRY_ROOT, KEY_REGISTRY_ROOT_HISTORY, MAX_CO_SIGNER_THRESHOLDS, N_SOURCE_SLOTS,
    POLICY_CONFIG, SPEND_WINDOW,
};
use custom_ring_interface::{DepositAudit, DEPOSIT_AUDIT};
use custom_ring_interface::{
    ReadAccessRecord, ReaderKeyBytes, RingProgramConfig, READER_KEY_ED25519, READER_KEY_P256,
    READ_ACCESS_RECORD, RING_PROGRAM_CONFIG,
};
use pinocchio::{AccountView, Address, ProgramResult};
use solana_curve25519::{
    edwards::{add_edwards, multiply_edwards, validate_edwards, PodEdwardsPoint},
    scalar::PodScalar,
};
use zolana_ring_policy::EncodedRuleTable;

use crate::error::CustomRingError;

pub(crate) trait Account: Pod + sealed::Sealed {
    const DISCRIMINATOR: u8;
    const SIZE: usize = core::mem::size_of::<Self>();
    const NOT_INITIALIZED: CustomRingError;
    const ALREADY_INITIALIZED: CustomRingError;
    const WRONG_SIZE: CustomRingError;

    fn discriminator(&self) -> u8;
    fn bump(&self) -> u8;
}

impl Account for DepositAudit {
    const DISCRIMINATOR: u8 = DEPOSIT_AUDIT;
    const NOT_INITIALIZED: CustomRingError = CustomRingError::InvalidDepositAudit;
    const ALREADY_INITIALIZED: CustomRingError = CustomRingError::InvalidDepositAudit;
    const WRONG_SIZE: CustomRingError = CustomRingError::InvalidDepositAudit;

    fn discriminator(&self) -> u8 {
        self.discriminator
    }

    fn bump(&self) -> u8 {
        self.bump
    }
}

/// Initial disclosure requirement stored at the canonical deposit-audit PDA.
pub(crate) struct DepositAuditInit {
    pub required: u8,
    pub bump: u8,
}

impl DepositAuditInit {
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        init_account(
            account,
            DepositAudit {
                discriminator: DEPOSIT_AUDIT,
                required: self.required,
                bump: self.bump,
            },
        )
    }
}

impl Account for RingProgramConfig {
    const DISCRIMINATOR: u8 = RING_PROGRAM_CONFIG;
    const NOT_INITIALIZED: CustomRingError = CustomRingError::ConfigNotInitialized;
    const ALREADY_INITIALIZED: CustomRingError = CustomRingError::ConfigAlreadyInitialized;
    const WRONG_SIZE: CustomRingError = CustomRingError::InvalidConfigPda;

    fn discriminator(&self) -> u8 {
        self.discriminator
    }

    fn bump(&self) -> u8 {
        self.bump
    }
}

/// Values written into a freshly created config account.
pub(crate) struct RingProgramConfigInitParams {
    pub authority: Address,
    pub auditor_pubkey: [u8; 33],
    pub bump: u8,
    pub has_policy: u8,
}

impl RingProgramConfigInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        init_account(
            account,
            RingProgramConfig {
                discriminator: RING_PROGRAM_CONFIG,
                authority: self.authority,
                auditor_pubkey: self.auditor_pubkey,
                bump: self.bump,
                has_policy: self.has_policy,
                key_escrow: 0,
            },
        )
    }
}

/// Curve membership is the sdk's job, an off-curve key only fails its own ring closed.
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

impl Account for ReadAccessRecord {
    const DISCRIMINATOR: u8 = READ_ACCESS_RECORD;
    const NOT_INITIALIZED: CustomRingError = CustomRingError::InvalidReadAccessRecord;
    const ALREADY_INITIALIZED: CustomRingError = CustomRingError::ReadAccessRecordAlreadyExists;
    const WRONG_SIZE: CustomRingError = CustomRingError::InvalidReadAccessRecord;

    fn discriminator(&self) -> u8 {
        self.discriminator
    }

    fn bump(&self) -> u8 {
        self.bump
    }
}

/// Authorizes a reader to query the ring's auditor view.
pub(crate) struct ReadAccessRecordInitParams {
    pub reader: ReaderKeyBytes,
    pub bump: u8,
}

impl ReadAccessRecordInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        init_account(
            account,
            ReadAccessRecord {
                discriminator: READ_ACCESS_RECORD,
                reader: self.reader,
                bump: self.bump,
            },
        )
    }
}

impl Account for PolicyConfig {
    const DISCRIMINATOR: u8 = POLICY_CONFIG;
    const NOT_INITIALIZED: CustomRingError = CustomRingError::PolicyConfigNotInitialized;
    const ALREADY_INITIALIZED: CustomRingError = CustomRingError::PolicyConfigAlreadyInitialized;
    const WRONG_SIZE: CustomRingError = CustomRingError::InvalidPolicyConfigPda;

    fn discriminator(&self) -> u8 {
        self.discriminator
    }

    fn bump(&self) -> u8 {
        self.bump
    }
}

/// Written field by field, a whole `PolicyConfig` exceeds the SBF stack frame.
pub(crate) struct PolicyConfigInit<'a> {
    pub policy_hash: [u8; 32],
    pub address_tree: Address,
    pub address_tree_id: u16,
    pub namespace_bump: u8,
    pub bump: u8,
    pub namespace_owner_hash: [u8; 32],
    pub sources: &'a [SourceSlot; N_SOURCE_SLOTS],
    pub rules: &'a EncodedRuleTable,
    pub generation_slot: u64,
}

impl PolicyConfigInit<'_> {
    pub fn write(self, account: &mut AccountView) -> ProgramResult {
        init_account_with(account, |config: &mut PolicyConfig| {
            config.discriminator = POLICY_CONFIG;
            config.policy_hash = self.policy_hash;
            config.address_tree = self.address_tree;
            config.address_tree_id = self.address_tree_id.to_le_bytes();
            config.namespace_bump = self.namespace_bump;
            config.bump = self.bump;
            config.namespace_owner_hash = self.namespace_owner_hash;
            config.sources = *self.sources;
            config.rules = *self.rules;
            config.generation = 1u32.to_le_bytes();
            config.generation_slot = self.generation_slot.to_le_bytes();
        })
    }
}

impl Account for CoSigner {
    const DISCRIMINATOR: u8 = CO_SIGNER;
    const NOT_INITIALIZED: CustomRingError = CustomRingError::InvalidCoSigner;
    const ALREADY_INITIALIZED: CustomRingError = CustomRingError::InvalidCoSigner;
    const WRONG_SIZE: CustomRingError = CustomRingError::InvalidCoSigner;

    fn discriminator(&self) -> u8 {
        self.discriminator
    }

    fn bump(&self) -> u8 {
        self.bump
    }
}

/// Validated signer and public thresholds for creating or replacing co-signing
/// controls.
pub(crate) struct CoSignerInitParams {
    pub signer: Address,
    pub scope: u8,
    pub thresholds: [WithdrawalThresholdRow; MAX_CO_SIGNER_THRESHOLDS],
    pub threshold_count: u8,
    pub bump: u8,
}

impl CoSignerInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        init_account(account, self.value())
    }

    pub const fn value(self) -> CoSigner {
        CoSigner {
            discriminator: CO_SIGNER,
            signer: self.signer,
            scope: self.scope,
            threshold_count: self.threshold_count,
            thresholds: self.thresholds,
            bump: self.bump,
        }
    }
}

impl Account for Delegate {
    const DISCRIMINATOR: u8 = DELEGATE;
    const NOT_INITIALIZED: CustomRingError = CustomRingError::InvalidDelegate;
    const ALREADY_INITIALIZED: CustomRingError = CustomRingError::DelegateAlreadySet;
    const WRONG_SIZE: CustomRingError = CustomRingError::InvalidDelegate;

    fn discriminator(&self) -> u8 {
        self.discriminator
    }

    fn bump(&self) -> u8 {
        self.bump
    }
}

/// Solana spend authority installed once, independent of the auditor viewing
/// key.
pub(crate) struct DelegateInitParams {
    pub delegate: Address,
    pub bump: u8,
}

impl DelegateInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        init_account(
            account,
            Delegate {
                discriminator: DELEGATE,
                delegate: self.delegate,
                bump: self.bump,
            },
        )
    }
}

impl Account for SpendWindow {
    const DISCRIMINATOR: u8 = SPEND_WINDOW;
    const NOT_INITIALIZED: CustomRingError = CustomRingError::InvalidSpendWindow;
    const ALREADY_INITIALIZED: CustomRingError = CustomRingError::InvalidSpendWindow;
    const WRONG_SIZE: CustomRingError = CustomRingError::InvalidSpendWindow;

    fn discriminator(&self) -> u8 {
        self.discriminator
    }

    fn bump(&self) -> u8 {
        self.bump
    }
}

/// Per-mint public caps initialized with empty counters in the current fixed
/// window.
pub(crate) struct SpendWindowInitParams {
    pub mint: Address,
    pub window_slots: u64,
    pub deposit_cap: u64,
    pub withdrawal_cap: u64,
    pub window_start_slot: u64,
    pub bump: u8,
}

impl SpendWindowInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        init_account(account, self.value())
    }

    pub(crate) const fn value(self) -> SpendWindow {
        SpendWindow {
            discriminator: SPEND_WINDOW,
            mint: self.mint,
            window_slots: self.window_slots.to_le_bytes(),
            deposit_cap: self.deposit_cap.to_le_bytes(),
            withdrawal_cap: self.withdrawal_cap.to_le_bytes(),
            window_start_slot: self.window_start_slot.to_le_bytes(),
            deposited: [0; 8],
            withdrawn: [0; 8],
            bump: self.bump,
        }
    }
}

/// A root over an append-only leaf map, leaf 0 the sentinel, cursor at 1 when fresh.
pub(crate) trait AppendRoot: Account {
    const SEED: &'static [u8];
    const STALE: CustomRingError;
    const CURSOR: CustomRingError;

    fn sentinel(bump: u8) -> Self;
    fn root(&self) -> &[u8; 32];
    fn next_index(&self) -> u64;
    fn advance_to(&mut self, root: [u8; 32], next_index: u64);
}

impl Account for KeyRegistryRoot {
    const DISCRIMINATOR: u8 = KEY_REGISTRY_ROOT;
    const NOT_INITIALIZED: CustomRingError = CustomRingError::InvalidKeyRegistryRoot;
    const ALREADY_INITIALIZED: CustomRingError = CustomRingError::KeyRegistryRootAlreadyExists;
    const WRONG_SIZE: CustomRingError = CustomRingError::InvalidKeyRegistryRoot;

    fn discriminator(&self) -> u8 {
        self.discriminator
    }

    fn bump(&self) -> u8 {
        self.bump
    }
}

impl AppendRoot for KeyRegistryRoot {
    const SEED: &'static [u8] = KeyRegistryRoot::SEED;
    const STALE: CustomRingError = CustomRingError::StaleKeyRegistryRoot;
    const CURSOR: CustomRingError = CustomRingError::InvalidKeyRegistryCursor;

    fn sentinel(bump: u8) -> Self {
        let mut history = [[0u8; 32]; KEY_REGISTRY_ROOT_HISTORY];
        history[0] = KEY_REGISTRY_EMPTY_ROOT;
        Self {
            discriminator: KEY_REGISTRY_ROOT,
            root: KEY_REGISTRY_EMPTY_ROOT,
            next_index: 1u64.to_le_bytes(),
            bump,
            history_cursor: 0,
            history,
        }
    }

    fn root(&self) -> &[u8; 32] {
        &self.root
    }

    fn next_index(&self) -> u64 {
        KeyRegistryRoot::next_index(self)
    }

    fn advance_to(&mut self, root: [u8; 32], next_index: u64) {
        let cursor = (usize::from(self.history_cursor) + 1) % KEY_REGISTRY_ROOT_HISTORY;
        self.history[cursor] = root;
        self.history_cursor = cursor as u8;
        self.root = root;
        self.next_index = next_index.to_le_bytes();
    }
}

/// Initializes an empty indexed registry with its sentinel and first append
/// position.
pub(crate) struct SentinelRootInit {
    pub bump: u8,
}

impl SentinelRootInit {
    #[inline(always)]
    pub fn init<T: AppendRoot>(self, account: &mut AccountView) -> ProgramResult {
        init_account(account, T::sentinel(self.bump))
    }
}

/// The root update and the SPP CPI commit atomically.
#[must_use]
pub(crate) struct RootTransition<'a> {
    pub expected_root: &'a [u8; 32],
    pub new_root: [u8; 32],
}

impl RootTransition<'_> {
    pub fn apply<T: AppendRoot>(self, root: &mut T) -> ProgramResult {
        if root.root() != self.expected_root {
            return Err(T::STALE.into());
        }
        let cursor = root.next_index();
        if cursor == 0 || cursor >= KEY_REGISTRY_CAPACITY {
            return Err(T::CURSOR.into());
        }
        root.advance_to(self.new_root, cursor + 1);
        Ok(())
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::DepositAudit {}
    impl Sealed for super::RingProgramConfig {}
    impl Sealed for super::ReadAccessRecord {}
    impl Sealed for super::PolicyConfig {}
    impl Sealed for super::CoSigner {}
    impl Sealed for super::Delegate {}
    impl Sealed for super::SpendWindow {}
    impl Sealed for super::KeyRegistryRoot {}
}

#[inline(always)]
fn init_account<T: Account>(account: &mut AccountView, value: T) -> ProgramResult {
    init_account_with(account, |slot: &mut T| *slot = value)
}

#[inline(always)]
fn init_account_with<T: Account>(
    account: &mut AccountView,
    write: impl FnOnce(&mut T),
) -> ProgramResult {
    let mut data = account
        .try_borrow_mut()
        .map_err(|_| T::ALREADY_INITIALIZED)?;
    // The account was just allocated with exactly `SIZE` bytes; any other
    // length means this is not the account this program created.
    if data.len() != T::SIZE {
        return Err(T::WRONG_SIZE.into());
    }
    // A nonzero first byte is a live discriminator: never overwrite an
    // existing account.
    if data.first() != Some(&0) {
        return Err(T::ALREADY_INITIALIZED.into());
    }
    // Length is checked above and each account is align 1, so this cannot panic.
    write(from_bytes_mut::<T>(&mut data[..]));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pinocchio::error::ProgramError;

    fn root(root: [u8; 32], next_index: u64) -> KeyRegistryRoot {
        let mut state = KeyRegistryRoot::sentinel(254);
        state.root = root;
        state.history[0] = root;
        state.next_index = next_index.to_le_bytes();
        state
    }

    fn apply(state: &mut KeyRegistryRoot, expected_root: &[u8; 32]) -> ProgramResult {
        RootTransition {
            expected_root,
            new_root: [7u8; 32],
        }
        .apply(state)
    }

    fn custom(error: CustomRingError) -> ProgramError {
        ProgramError::Custom(error as u32)
    }

    #[test]
    fn a_root_that_is_not_the_head_is_refused() {
        let mut state = root([1u8; 32], 1);
        assert_eq!(
            apply(&mut state, &[2u8; 32]),
            Err(custom(CustomRingError::StaleKeyRegistryRoot))
        );
        assert_eq!(state.root, [1u8; 32]);
    }

    #[test]
    fn registration_advances_the_cursor_and_publishes_the_successor_root() {
        let mut state = root([1u8; 32], 5);
        apply(&mut state, &[1u8; 32]).expect("advance");
        assert_eq!(state.root, [7u8; 32]);
        assert_eq!(state.next_index(), 6);
    }

    #[test]
    fn the_sentinel_root_is_the_first_history_entry() {
        let state = KeyRegistryRoot::sentinel(254);
        assert_eq!(state.root_at(0), Some(KEY_REGISTRY_EMPTY_ROOT));
        assert_eq!(state.root_at(1), None);
        assert_eq!(state.root_at(KEY_REGISTRY_ROOT_HISTORY as u8), None);
        assert_eq!(state.root_at(u8::MAX), None);
    }

    #[test]
    fn the_history_keeps_every_root_and_wraps_over_the_oldest() {
        let mut state = root([1u8; 32], 1);
        for step in 1..=KEY_REGISTRY_ROOT_HISTORY as u8 {
            let head = state.root;
            RootTransition {
                expected_root: &head,
                new_root: [step + 1; 32],
            }
            .apply(&mut state)
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
    fn registration_refuses_an_out_of_bounds_cursor() {
        for cursor in [0, KEY_REGISTRY_CAPACITY] {
            let mut state = root([1u8; 32], cursor);
            assert_eq!(
                apply(&mut state, &[1u8; 32]),
                Err(custom(CustomRingError::InvalidKeyRegistryCursor))
            );
        }
    }
}
