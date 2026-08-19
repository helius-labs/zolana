use bytemuck::{from_bytes_mut, Pod, Zeroable};
use pinocchio::{AccountView, Address, ProgramResult};

use crate::error::CustomRingError;

/// Discriminator of [`RingProgramConfig`]. Value 0 stays reserved for
/// "uninitialized".
pub const RING_PROGRAM_CONFIG: u8 = 1;
/// Discriminator of an approval account, see `approve_transact`.
pub const TRANSACT_APPROVAL: u8 = 2;

/// Capacity of the asset table. Fixed so the config stays a `Pod` account.
pub const MAX_ASSETS: usize = 8;

/// A withdrawal rule: what happens to a public settlement leg out of the pool.
pub const WITHDRAWALS_OPEN: u8 = 0;
pub const WITHDRAWALS_BLOCKED: u8 = 1;
/// The transact must carry an approval account the configured approver created
/// for its `private_tx_hash`.
pub const WITHDRAWALS_APPROVAL: u8 = 2;

/// `RingProgramConfig::asset_policy`: any asset, or only the listed mints.
pub const ASSETS_ANY: u8 = 0;
pub const ASSETS_ALLOWLIST: u8 = 1;

/// The mint that stands for native SOL in the asset table and in SPP's registry.
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
    /// Withdrawal rule for assets without an entry in the table.
    pub withdrawals: u8,
    /// [`ASSETS_ANY`] or [`ASSETS_ALLOWLIST`]. Under the allowlist only the
    /// table's mints may enter or leave the ring.
    pub asset_policy: u8,
    /// Live entries of `assets` and `asset_withdrawals`, at most [`MAX_ASSETS`].
    pub assets_len: u8,
    /// The key that may create approval accounts; all zero when no rule needs
    /// approval.
    pub approver: Address,
    /// Mints of the asset table; SOL is [`SOL_MINT`].
    pub assets: [[u8; 32]; MAX_ASSETS],
    /// Withdrawal rule per table entry.
    pub asset_withdrawals: [u8; MAX_ASSETS],
}

impl RingProgramConfig {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const SEED: &'static [u8] = crate::CONFIG_PDA_SEED;

    pub fn has_discriminator(&self) -> bool {
        self.discriminator == RING_PROGRAM_CONFIG
    }

    /// The asset table as `(mint, withdrawal rule)` pairs.
    pub fn assets(&self) -> impl Iterator<Item = (&[u8; 32], u8)> {
        let len = usize::from(self.assets_len).min(MAX_ASSETS);
        self.assets[..len]
            .iter()
            .zip(self.asset_withdrawals[..len].iter().copied())
    }

    pub fn allows_every_asset(&self) -> bool {
        self.asset_policy != ASSETS_ALLOWLIST
    }

    /// Whether `mint` may enter or leave the ring under the asset policy.
    pub fn allows_asset(&self, mint: &[u8; 32]) -> bool {
        self.allows_every_asset() || self.assets().any(|(listed, _)| listed == mint)
    }

    /// The withdrawal rule for `mint`: its table entry, else the default.
    pub fn withdrawal_rule(&self, mint: &[u8; 32]) -> u8 {
        self.assets()
            .find(|(listed, _)| *listed == mint)
            .map_or(self.withdrawals, |(_, rule)| rule)
    }

    pub fn has_approver(&self) -> bool {
        self.approver != Address::default()
    }
}

// Every field is byte-typed (`Address` is a 32-byte, align-1 newtype), so the
// struct carries no padding: its `Pod` image is exactly its field bytes and
// `SIZE` is the on-chain account length.
const _: () = assert!(RingProgramConfig::SIZE == 102 + 33 * MAX_ASSETS);
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
            assets_len: 0,
            approver: Address::default(),
            assets: [[0u8; 32]; MAX_ASSETS],
            asset_withdrawals: [0u8; MAX_ASSETS],
        };
        Ok(())
    }
}
