use bytemuck::{from_bytes_mut, Pod};
use pinocchio::{AccountView, Address, ProgramResult};
use solana_curve25519::{
    edwards::{add_edwards, multiply_edwards, validate_edwards, PodEdwardsPoint},
    scalar::PodScalar,
};
use zolana_interface::custom_ring::{
    ReaderKeyBytes, ReaderRecord, RingProgramConfig, READER_KEY_ED25519, READER_KEY_P256,
    READER_RECORD, RING_PROGRAM_CONFIG,
};

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

impl Account for ReaderRecord {
    const DISCRIMINATOR: u8 = READER_RECORD;
    const NOT_INITIALIZED: CustomRingError = CustomRingError::InvalidReaderRecord;
    const ALREADY_INITIALIZED: CustomRingError = CustomRingError::ReaderRecordAlreadyExists;
    const WRONG_SIZE: CustomRingError = CustomRingError::InvalidReaderRecord;

    fn discriminator(&self) -> u8 {
        self.discriminator
    }
}

pub(crate) struct ReaderRecordInitParams {
    pub reader: ReaderKeyBytes,
    pub bump: u8,
}

impl ReaderRecordInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        init_account(
            account,
            ReaderRecord {
                discriminator: READER_RECORD,
                reader: self.reader,
                bump: self.bump,
            },
        )
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::RingProgramConfig {}
    impl Sealed for super::ReaderRecord {}
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
