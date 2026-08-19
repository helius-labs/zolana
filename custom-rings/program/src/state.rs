use bytemuck::{from_bytes_mut, Pod, Zeroable};
use pinocchio::{AccountView, Address, ProgramResult};

use crate::error::CustomRingError;

/// Discriminator of [`RingProgramConfig`]. The program owns a single account
/// type, so one byte suffices; value 0 stays reserved for "uninitialized".
pub const RING_PROGRAM_CONFIG: u8 = 1;

/// Capacity of the asset allowlist. Fixed so the config stays a `Pod` account.
pub const MAX_ALLOWED_ASSETS: usize = 8;

/// `RingProgramConfig::withdrawals`: public withdrawals (SOL or SPL settlement
/// legs out of the pool) are forwarded or refused.
pub const WITHDRAWALS_OPEN: u8 = 0;
pub const WITHDRAWALS_BLOCKED: u8 = 1;

/// `RingProgramConfig::asset_policy`: any asset, or only the listed mints.
pub const ASSETS_ANY: u8 = 0;
pub const ASSETS_ALLOWLIST: u8 = 1;

/// The mint that stands for native SOL in the allowlist and in SPP's registry.
pub const SOL_MINT: [u8; 32] = [0u8; 32];

/// The ring's singleton config: who may register the ring with SPP, the auditor
/// key every `transact` must verifiably encrypt the transaction viewing secret
/// key to, and the policy the ring enforces on what enters and leaves it.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RingProgramConfig {
    pub discriminator: u8,
    pub authority: Address,
    /// Auditor P256 public key in SEC1 compressed form (`0x02`/`0x03 || x`).
    pub auditor_pubkey: [u8; 33],
    pub bump: u8,
    /// [`WITHDRAWALS_OPEN`] or [`WITHDRAWALS_BLOCKED`].
    pub withdrawals: u8,
    /// [`ASSETS_ANY`] or [`ASSETS_ALLOWLIST`].
    pub asset_policy: u8,
    /// Live entries of `allowed_assets`, at most [`MAX_ALLOWED_ASSETS`].
    pub allowed_assets_len: u8,
    /// Mints the ring accepts when `asset_policy` is the allowlist; SOL is
    /// [`SOL_MINT`].
    pub allowed_assets: [[u8; 32]; MAX_ALLOWED_ASSETS],
}

impl RingProgramConfig {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const SEED: &'static [u8] = crate::CONFIG_PDA_SEED;

    pub fn has_discriminator(&self) -> bool {
        self.discriminator == RING_PROGRAM_CONFIG
    }

    pub fn allowed_assets(&self) -> &[[u8; 32]] {
        let len = usize::from(self.allowed_assets_len).min(MAX_ALLOWED_ASSETS);
        &self.allowed_assets[..len]
    }

    pub fn allows_every_asset(&self) -> bool {
        self.asset_policy != ASSETS_ALLOWLIST
    }

    /// Whether `mint` may enter or leave the ring under the asset policy.
    pub fn allows_asset(&self, mint: &[u8; 32]) -> bool {
        self.allows_every_asset() || self.allowed_assets().contains(mint)
    }

    pub fn withdrawals_blocked(&self) -> bool {
        self.withdrawals == WITHDRAWALS_BLOCKED
    }
}

// Every field is byte-typed (`Address` is a 32-byte, align-1 newtype), so the
// struct carries no padding: its `Pod` image is exactly its field bytes and
// `SIZE` is the on-chain account length.
const _: () = assert!(RingProgramConfig::SIZE == 70 + 32 * MAX_ALLOWED_ASSETS);
const _: () = assert!(core::mem::align_of::<RingProgramConfig>() == 1);

/// Values written into a freshly created config account. The policy starts
/// open (any asset, withdrawals allowed) until `set_policy` narrows it.
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
            withdrawals: WITHDRAWALS_OPEN,
            asset_policy: ASSETS_ANY,
            allowed_assets_len: 0,
            allowed_assets: [[0u8; 32]; MAX_ALLOWED_ASSETS],
        };
        Ok(())
    }
}
