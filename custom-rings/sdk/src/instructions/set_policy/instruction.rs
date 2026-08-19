use custom_ring_program::{
    instructions::set_policy::SetPolicyIxData,
    state::{
        RingProgramConfig, ASSETS_ALLOWLIST, ASSETS_ANY, MAX_ALLOWED_ASSETS, SOL_MINT,
        WITHDRAWALS_BLOCKED, WITHDRAWALS_OPEN,
    },
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::{config_pda, tag, PROGRAM_ID};

/// What the ring enforces on the transfers it forwards.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RingPolicy {
    /// `Some(mints)`: only these assets may enter or leave the ring (SOL is
    /// [`SOL_MINT`]). `None`: any asset.
    pub allowed_assets: Option<Vec<Address>>,
    pub withdrawals_blocked: bool,
}

impl RingPolicy {
    /// The policy a config account carries.
    pub fn from_config(config: &RingProgramConfig) -> Self {
        Self {
            allowed_assets: (config.asset_policy == ASSETS_ALLOWLIST).then(|| {
                config
                    .allowed_assets()
                    .iter()
                    .map(|mint| Address::new_from_array(*mint))
                    .collect()
            }),
            withdrawals_blocked: config.withdrawals_blocked(),
        }
    }

    pub fn ix_data(&self) -> Result<SetPolicyIxData, PolicyError> {
        let allowed_assets = self.allowed_assets.clone().unwrap_or_default();
        if allowed_assets.len() > MAX_ALLOWED_ASSETS {
            return Err(PolicyError::TooManyAssets(allowed_assets.len()));
        }
        Ok(SetPolicyIxData {
            withdrawals: if self.withdrawals_blocked {
                WITHDRAWALS_BLOCKED
            } else {
                WITHDRAWALS_OPEN
            },
            asset_policy: if self.allowed_assets.is_some() {
                ASSETS_ALLOWLIST
            } else {
                ASSETS_ANY
            },
            allowed_assets: allowed_assets.iter().map(Address::to_bytes).collect(),
        })
    }
}

/// The address SOL takes in an allowlist.
pub const SOL: Address = Address::new_from_array(SOL_MINT);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("allowlist holds {0} assets, the ring stores at most {MAX_ALLOWED_ASSETS}")]
    TooManyAssets(usize),
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
