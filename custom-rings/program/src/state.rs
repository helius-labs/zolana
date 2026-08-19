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

/// The mint that stands for native SOL in the asset table and in SPP's registry.
pub const SOL_MINT: [u8; 32] = [0u8; 32];

/// What happens to a public settlement leg out of the pool. Stored as its `u8`
/// in the config; every byte the program writes came through `try_from`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WithdrawalRule {
    Open = 0,
    Blocked = 1,
    /// The transact must carry an approval account the configured approver
    /// created for its `private_tx_hash`.
    Approval = 2,
}

impl WithdrawalRule {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Blocked => "blocked",
            Self::Approval => "approval",
        }
    }
}

impl TryFrom<u8> for WithdrawalRule {
    type Error = CustomRingError;

    fn try_from(value: u8) -> Result<Self, CustomRingError> {
        match value {
            0 => Ok(Self::Open),
            1 => Ok(Self::Blocked),
            2 => Ok(Self::Approval),
            _ => Err(CustomRingError::InvalidPolicy),
        }
    }
}

impl core::str::FromStr for WithdrawalRule {
    type Err = CustomRingError;

    fn from_str(text: &str) -> Result<Self, CustomRingError> {
        match text {
            "open" => Ok(Self::Open),
            "blocked" => Ok(Self::Blocked),
            "approval" => Ok(Self::Approval),
            _ => Err(CustomRingError::InvalidPolicy),
        }
    }
}

/// Which mints may enter or leave the ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AssetPolicy {
    Any = 0,
    /// Only the mints in the asset table.
    Allowlist = 1,
}

impl TryFrom<u8> for AssetPolicy {
    type Error = CustomRingError;

    fn try_from(value: u8) -> Result<Self, CustomRingError> {
        match value {
            0 => Ok(Self::Any),
            1 => Ok(Self::Allowlist),
            _ => Err(CustomRingError::InvalidPolicy),
        }
    }
}

/// One asset table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetRule {
    pub mint: [u8; 32],
    pub withdrawals: WithdrawalRule,
}

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
    /// [`WithdrawalRule`] for assets without an entry in the table.
    pub withdrawals: u8,
    /// [`AssetPolicy`].
    pub asset_policy: u8,
    /// Live entries of `assets` and `asset_withdrawals`, at most [`MAX_ASSETS`].
    pub assets_len: u8,
    /// The key that may create approval accounts; all zero when no rule needs
    /// approval.
    pub approver: Address,
    /// Mints of the asset table; SOL is [`SOL_MINT`].
    pub assets: [[u8; 32]; MAX_ASSETS],
    /// [`WithdrawalRule`] per table entry.
    pub asset_withdrawals: [u8; MAX_ASSETS],
}

impl RingProgramConfig {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const SEED: &'static [u8] = crate::CONFIG_PDA_SEED;

    pub fn has_discriminator(&self) -> bool {
        self.discriminator == RING_PROGRAM_CONFIG
    }

    /// The asset table. A rule byte the program never wrote reads as
    /// `Blocked`, so corrupted state fails closed.
    pub fn assets(&self) -> impl Iterator<Item = AssetRule> + '_ {
        let len = usize::from(self.assets_len).min(MAX_ASSETS);
        self.assets[..len]
            .iter()
            .zip(&self.asset_withdrawals[..len])
            .map(|(mint, rule)| AssetRule {
                mint: *mint,
                withdrawals: rule_or_blocked(*rule),
            })
    }

    pub fn asset_policy(&self) -> AssetPolicy {
        AssetPolicy::try_from(self.asset_policy).unwrap_or(AssetPolicy::Allowlist)
    }

    /// Whether `mint` may enter or leave the ring under the asset policy.
    pub fn allows_asset(&self, mint: &[u8; 32]) -> bool {
        match self.asset_policy() {
            AssetPolicy::Any => true,
            AssetPolicy::Allowlist => self.assets().any(|asset| asset.mint == *mint),
        }
    }

    /// The withdrawal rule for `mint`: its table entry, else the default.
    pub fn withdrawal_rule(&self, mint: &[u8; 32]) -> WithdrawalRule {
        self.assets().find(|asset| asset.mint == *mint).map_or_else(
            || rule_or_blocked(self.withdrawals),
            |asset| asset.withdrawals,
        )
    }

    pub fn approver(&self) -> Option<&Address> {
        (self.approver != Address::default()).then_some(&self.approver)
    }

    /// Replaces the policy fields; the caller has validated `assets.len()`.
    pub fn set_policy(
        &mut self,
        asset_policy: AssetPolicy,
        withdrawals: WithdrawalRule,
        approver: Address,
        assets: &[AssetRule],
    ) {
        self.asset_policy = asset_policy as u8;
        self.withdrawals = withdrawals as u8;
        self.approver = approver;
        self.assets = [[0u8; 32]; MAX_ASSETS];
        self.asset_withdrawals = [0u8; MAX_ASSETS];
        for (index, asset) in assets.iter().enumerate().take(MAX_ASSETS) {
            self.assets[index] = asset.mint;
            self.asset_withdrawals[index] = asset.withdrawals as u8;
        }
        self.assets_len = assets.len().min(MAX_ASSETS) as u8;
    }
}

fn rule_or_blocked(value: u8) -> WithdrawalRule {
    WithdrawalRule::try_from(value).unwrap_or(WithdrawalRule::Blocked)
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
            withdrawals: WithdrawalRule::Open as u8,
            asset_policy: AssetPolicy::Any as u8,
            assets_len: 0,
            approver: Address::default(),
            assets: [[0u8; 32]; MAX_ASSETS],
            asset_withdrawals: [0u8; MAX_ASSETS],
        };
        Ok(())
    }
}
