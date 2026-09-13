use bytemuck::{from_bytes_mut, Pod};
use custom_ring_interface::{
    CoSigner, Delegate, HeadMapRoot, PolicyConfig, SourceSlot, SpendWindow, WithdrawalThreshold,
    CO_SIGNER, DELEGATE, HEAD_MAP_EMPTY_ROOT, HEAD_MAP_ROOT, MAX_CO_SIGNER_THRESHOLDS,
    N_SOURCE_SLOTS, POLICY_CONFIG, SPEND_WINDOW,
};
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
}

impl Account for RingProgramConfig {
    const DISCRIMINATOR: u8 = RING_PROGRAM_CONFIG;
    const NOT_INITIALIZED: CustomRingError = CustomRingError::ConfigNotInitialized;
    const ALREADY_INITIALIZED: CustomRingError = CustomRingError::ConfigAlreadyInitialized;
    const WRONG_SIZE: CustomRingError = CustomRingError::InvalidConfigPda;

    fn discriminator(&self) -> u8 {
        self.discriminator
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
}

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
}

/// Borrows the bound rules and sources so no full `PolicyConfig` lands on the
/// SBF frame.
pub(crate) struct PolicyConfigInit<'a> {
    pub policy_hash: [u8; 32],
    pub entries_tree: Address,
    pub entries_tree_id: u16,
    pub namespace_bump: u8,
    pub bump: u8,
    pub namespace_owner_hash: [u8; 32],
    pub sources: &'a [SourceSlot; N_SOURCE_SLOTS],
    pub rules: &'a EncodedRuleTable,
    pub generation_slot: u64,
}

impl PolicyConfigInit<'_> {
    pub fn write(self, account: &mut AccountView) -> ProgramResult {
        let mut data = account
            .try_borrow_mut()
            .map_err(|_| CustomRingError::PolicyConfigAlreadyInitialized)?;
        if data.len() != PolicyConfig::SIZE {
            return Err(CustomRingError::InvalidPolicyConfigPda.into());
        }
        if data.first() != Some(&0) {
            return Err(CustomRingError::PolicyConfigAlreadyInitialized.into());
        }
        let config: &mut PolicyConfig = from_bytes_mut(&mut data[..]);
        config.discriminator = POLICY_CONFIG;
        config.policy_hash = self.policy_hash;
        config.entries_tree = self.entries_tree;
        config.entries_tree_id = self.entries_tree_id.to_le_bytes();
        config.namespace_bump = self.namespace_bump;
        config.bump = self.bump;
        config.namespace_owner_hash = self.namespace_owner_hash;
        config.sources = *self.sources;
        config.rules = *self.rules;
        config.generation = 1u32.to_le_bytes();
        config.generation_slot = self.generation_slot.to_le_bytes();
        Ok(())
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
}

pub(crate) struct CoSignerInitParams {
    pub signer: Address,
    pub scope: u8,
    pub thresholds: [WithdrawalThreshold; MAX_CO_SIGNER_THRESHOLDS],
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
}

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
}

impl Account for HeadMapRoot {
    const DISCRIMINATOR: u8 = HEAD_MAP_ROOT;
    const NOT_INITIALIZED: CustomRingError = CustomRingError::InvalidHeadMapRoot;
    const ALREADY_INITIALIZED: CustomRingError = CustomRingError::InvalidHeadMapRoot;
    const WRONG_SIZE: CustomRingError = CustomRingError::InvalidHeadMapRoot;

    fn discriminator(&self) -> u8 {
        self.discriminator
    }
}

pub(crate) struct HeadMapRootInitParams {
    pub bump: u8,
}

/// The root update and SPP CPI commit atomically.
pub(crate) fn advance_head_map_root(
    account: &mut AccountView,
    expected_root: &[u8; 32],
    new_root: [u8; 32],
    register: bool,
) -> ProgramResult {
    let mut data = account.try_borrow_mut()?;
    if data.len() != HeadMapRoot::SIZE {
        return Err(CustomRingError::InvalidHeadMapRoot.into());
    }
    let state = from_bytes_mut::<HeadMapRoot>(&mut data);
    if &state.root != expected_root {
        return Err(CustomRingError::StaleHeadMapRoot.into());
    }
    if register {
        let cursor = state.next_index();
        if cursor == 0 || cursor >= (1u64 << custom_ring_interface::HEAD_MAP_HEIGHT) {
            return Err(CustomRingError::InvalidHeadMapCursor.into());
        }
        state.next_index = (cursor + 1).to_le_bytes();
    }
    state.root = new_root;
    Ok(())
}

impl HeadMapRootInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        // Leaf 0 holds the sentinel, the first registration appends at 1.
        init_account(
            account,
            HeadMapRoot {
                discriminator: HEAD_MAP_ROOT,
                root: HEAD_MAP_EMPTY_ROOT,
                next_index: 1u64.to_le_bytes(),
                bump: self.bump,
            },
        )
    }
}

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

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::RingProgramConfig {}
    impl Sealed for super::ReadAccessRecord {}
    impl Sealed for super::PolicyConfig {}
    impl Sealed for super::CoSigner {}
    impl Sealed for super::Delegate {}
    impl Sealed for super::SpendWindow {}
    impl Sealed for super::HeadMapRoot {}
}

#[inline(always)]
fn init_account<T: Account>(account: &mut AccountView, value: T) -> ProgramResult {
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
    *from_bytes_mut::<T>(&mut data[..]) = value;
    Ok(())
}
