use custom_ring_program::{
    instructions::set_policy::{AssetRuleData, SetPolicyIxData},
    state::{AssetPolicy, RingProgramConfig, WithdrawalRule, MAX_ASSETS, SOL_MINT},
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::{config_pda, tag, PROGRAM_ID};

/// The address SOL takes in the asset table.
pub const SOL: Address = Address::new_from_array(SOL_MINT);

/// One asset table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetRule {
    pub mint: Address,
    pub withdrawals: WithdrawalRule,
}

/// What the ring enforces on the transfers it forwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingPolicy {
    pub asset_policy: AssetPolicy,
    /// The asset table, a withdrawal rule per mint and, under the allowlist,
    /// the mints allowed at all.
    pub assets: Vec<AssetRule>,
    /// Withdrawal rule for mints outside the table.
    pub withdrawals: WithdrawalRule,
    /// Required when any rule is `Approval`.
    pub approver: Option<Address>,
}

impl Default for RingPolicy {
    fn default() -> Self {
        Self {
            asset_policy: AssetPolicy::Any,
            assets: Vec::new(),
            withdrawals: WithdrawalRule::Open,
            approver: None,
        }
    }
}

impl RingPolicy {
    /// The policy a config account carries.
    pub fn from_config(config: &RingProgramConfig) -> Self {
        Self {
            asset_policy: config.asset_policy(),
            assets: config
                .assets()
                .map(|asset| AssetRule {
                    mint: Address::new_from_array(asset.mint),
                    withdrawals: asset.withdrawals,
                })
                .collect(),
            withdrawals: WithdrawalRule::try_from(config.withdrawals)
                .unwrap_or(WithdrawalRule::Blocked),
            approver: config.approver().copied(),
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
        if let Some(duplicate) = self.assets.iter().enumerate().find(|(index, asset)| {
            self.assets[..*index]
                .iter()
                .any(|earlier| earlier.mint == asset.mint)
        }) {
            return Err(PolicyError::DuplicateAsset(duplicate.1.mint));
        }
        if self.needs_approver() && self.approver.is_none() {
            return Err(PolicyError::ApproverRequired);
        }
        Ok(SetPolicyIxData {
            withdrawals: self.withdrawals as u8,
            asset_policy: self.asset_policy as u8,
            approver: self.approver.map(|key| key.to_bytes()).unwrap_or_default(),
            assets: self
                .assets
                .iter()
                .map(|asset| AssetRuleData {
                    mint: asset.mint.to_bytes(),
                    withdrawals: asset.withdrawals as u8,
                })
                .collect(),
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("asset table holds {0} entries, the ring stores at most {MAX_ASSETS}")]
    TooManyAssets(usize),
    #[error("asset {0} is listed twice")]
    DuplicateAsset(Address),
    #[error("a withdrawal rule requires approval but no approver is set")]
    ApproverRequired,
}

/// Replaces the ring's policy. `authority` is the config's authority.
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
