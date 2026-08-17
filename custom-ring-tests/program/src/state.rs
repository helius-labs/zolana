use bytemuck::{from_bytes_mut, Pod, Zeroable};
use pinocchio::{AccountView, Address, ProgramResult};

use crate::error::CustomRingError;

/// Discriminator of [`RingProgramConfig`]. The program owns a single account
/// type, so one byte suffices; value 0 stays reserved for "uninitialized".
pub const RING_PROGRAM_CONFIG: u8 = 1;

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
