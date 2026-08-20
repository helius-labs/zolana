use bytemuck::{from_bytes_mut, Pod, Zeroable};
use pinocchio::{AccountView, Address, ProgramResult};

use crate::error::CustomRingError;

/// Discriminator of [`RingProgramConfig`]. Value 0 stays reserved for
/// "uninitialized".
pub const RING_PROGRAM_CONFIG: u8 = 1;
/// Discriminator of [`ReaderRecord`].
pub const READER_RECORD: u8 = 2;

/// The ring's singleton config: who may register the ring with SPP, and the
/// auditor key every `transact` must verifiably encrypt the transaction viewing
/// secret key to.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RingProgramConfig {
    pub discriminator: u8,
    pub authority: Address,
    /// Auditor P256 public key in SEC1 compressed form (`0x02`/`0x03 || x`).
    pub auditor_pubkey: [u8; 33],
    pub bump: u8,
}

impl RingProgramConfig {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const SEED: &'static [u8] = crate::CONFIG_PDA_SEED;

    pub fn has_discriminator(&self) -> bool {
        self.discriminator == RING_PROGRAM_CONFIG
    }
}

// Every field is byte-typed (`Address` is a 32-byte, align-1 newtype), so the
// struct carries no padding: its `Pod` image is exactly its field bytes and
// `SIZE` is the on-chain account length.
const _: () = assert!(RingProgramConfig::SIZE == 67);
const _: () = assert!(core::mem::align_of::<RingProgramConfig>() == 1);

/// Values written into a freshly created config account.
pub struct RingProgramConfigInitParams {
    pub authority: Address,
    pub auditor_pubkey: [u8; 33],
    pub bump: u8,
}

impl RingProgramConfigInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let mut data = account
            .try_borrow_mut()
            .map_err(|_| CustomRingError::ConfigAlreadyInitialized)?;
        // The account was just allocated with exactly `SIZE` bytes; any other
        // length means this is not the account this program created.
        if data.len() != RingProgramConfig::SIZE {
            return Err(CustomRingError::InvalidConfigPda.into());
        }
        // A nonzero first byte is a live discriminator: never overwrite an
        // existing config.
        if data.first() != Some(&0) {
            return Err(CustomRingError::ConfigAlreadyInitialized.into());
        }
        // Length is checked above and the struct is align 1, so this cannot panic.
        let config: &mut RingProgramConfig = from_bytes_mut(&mut data[..]);
        *config = RingProgramConfig {
            discriminator: RING_PROGRAM_CONFIG,
            authority: self.authority,
            auditor_pubkey: self.auditor_pubkey,
            bump: self.bump,
        };
        Ok(())
    }
}

/// A reader the authority delegated ring-scope reads to. The ring RPC accepts
/// an ed25519 attestation from `reader` as if the authority had signed it, for
/// as long as this record exists.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct ReaderRecord {
    pub discriminator: u8,
    pub reader: [u8; 32],
    pub bump: u8,
}

impl ReaderRecord {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const SEED: &'static [u8] = crate::READER_RECORD_PDA_SEED;

    pub fn has_discriminator(&self) -> bool {
        self.discriminator == READER_RECORD
    }
}

const _: () = assert!(ReaderRecord::SIZE == 34);
const _: () = assert!(core::mem::align_of::<ReaderRecord>() == 1);

pub struct ReaderRecordInitParams {
    pub reader: [u8; 32],
    pub bump: u8,
}

impl ReaderRecordInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let mut data = account
            .try_borrow_mut()
            .map_err(|_| CustomRingError::ReaderRecordAlreadyExists)?;
        if data.len() != ReaderRecord::SIZE {
            return Err(CustomRingError::InvalidReaderRecord.into());
        }
        if data.first() != Some(&0) {
            return Err(CustomRingError::ReaderRecordAlreadyExists.into());
        }
        // Length is checked above and the struct is align 1, so this cannot panic.
        let record: &mut ReaderRecord = from_bytes_mut(&mut data[..]);
        *record = ReaderRecord {
            discriminator: READER_RECORD,
            reader: self.reader,
            bump: self.bump,
        };
        Ok(())
    }
}
