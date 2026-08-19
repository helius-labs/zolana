use custom_ring_program::{
    instructions::set_policy::{AssetRule as AssetRuleData, SetPolicyIxData},
    state::{
        RingProgramConfig, ASSETS_ALLOWLIST, ASSETS_ANY, MAX_ASSETS, SOL_MINT,
        WITHDRAWALS_APPROVAL, WITHDRAWALS_BLOCKED, WITHDRAWALS_OPEN,
    },
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::{config_pda, tag, PROGRAM_ID};

/// The address SOL takes in the asset table.
pub const SOL: Address = Address::new_from_array(SOL_MINT);

/// What happens to a public settlement leg out of the pool.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WithdrawalRule {
    #[default]
    Open,
    Blocked,
    /// The transact must carry an approval the ring's approver created for it.
    Approval,
}

impl WithdrawalRule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Blocked => "blocked",
            Self::Approval => "approval",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "open" => Some(Self::Open),
            "blocked" => Some(Self::Blocked),
            "approval" => Some(Self::Approval),
            _ => None,
        }
    }

    fn from_wire(value: u8) -> Self {
        match value {
            WITHDRAWALS_BLOCKED => Self::Blocked,
            WITHDRAWALS_APPROVAL => Self::Approval,
            _ => Self::Open,
        }
    }

    fn to_wire(self) -> u8 {
        match self {
            Self::Open => WITHDRAWALS_OPEN,
            Self::Blocked => WITHDRAWALS_BLOCKED,
            Self::Approval => WITHDRAWALS_APPROVAL,
        }
    }
}

/// One asset table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetRule {
    pub mint: Address,
    pub withdrawals: WithdrawalRule,
}

/// What the ring enforces on the transfers it forwards.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RingPolicy {
    /// Only the table's mints may enter or leave the ring.
    pub allowlist: bool,
    /// The asset table: a withdrawal rule per mint, and under `allowlist` the
    /// mints allowed at all.
    pub assets: Vec<AssetRule>,
    /// Withdrawal rule for mints outside the table.
    pub withdrawals: WithdrawalRule,
    /// Required when any rule is `Approval`.
    pub approver: Option<Address>,
}

impl RingPolicy {
    /// The policy a config account carries.
    pub fn from_config(config: &RingProgramConfig) -> Self {
        Self {
            allowlist: config.asset_policy == ASSETS_ALLOWLIST,
            assets: config
                .assets()
                .map(|(mint, rule)| AssetRule {
                    mint: Address::new_from_array(*mint),
                    withdrawals: WithdrawalRule::from_wire(rule),
                })
                .collect(),
            withdrawals: WithdrawalRule::from_wire(config.withdrawals),
            approver: config.has_approver().then_some(config.approver),
        }
    }

    pub fn withdrawal_rule(&self, mint: &Address) -> WithdrawalRule {
        self.assets
            .iter()
            .find(|asset| asset.mint == *mint)
            .map_or(self.withdrawals, |asset| asset.withdrawals)
    }

    pub fn needs_approver(&self) -> bool {
        self.withdrawals == WithdrawalRule::Approval
            || self
                .assets
                .iter()
                .any(|asset| asset.withdrawals == WithdrawalRule::Approval)
    }

    pub fn ix_data(&self) -> Result<SetPolicyIxData, PolicyError> {
        if self.assets.len() > MAX_ASSETS {
            return Err(PolicyError::TooManyAssets(self.assets.len()));
        }
        if self.needs_approver() && self.approver.is_none() {
            return Err(PolicyError::ApproverRequired);
        }
        Ok(SetPolicyIxData {
            withdrawals: self.withdrawals.to_wire(),
            asset_policy: if self.allowlist {
                ASSETS_ALLOWLIST
            } else {
                ASSETS_ANY
            },
            approver: self.approver.map(|key| key.to_bytes()).unwrap_or_default(),
            assets: self
                .assets
                .iter()
                .map(|asset| AssetRuleData {
                    mint: asset.mint.to_bytes(),
                    withdrawals: asset.withdrawals.to_wire(),
                })
                .collect(),
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("asset table holds {0} entries, the ring stores at most {MAX_ASSETS}")]
    TooManyAssets(usize),
    #[error("a withdrawal rule requires approval but no approver is set")]
    ApproverRequired,
}

/// Replaces the ring's policy; `authority` is the config's authority.
pub struct SetPolicy {
    pub authority: Address,
    pub policy: RingPolicy,
}

impl SetPolicy {
    pub fn instruction(self) -> Result<Instruction, PolicyError> {
        let mut data = vec![tag::SET_POLICY];
        data.extend_from_slice(
            &wincode::serialize(&self.policy.ix_data()?)
                .expect("set_policy instruction data is bounded"),
        );
        Ok(Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new(config_pda(), false),
            ],
            data,
        })
    }
}
