use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::AsyncRpc;
use zolana_interface::pda;
use zolana_keypair::ShieldedAddress;

use kamino_vault_rfq_sdk::{
    kvault::{self, UserAccounts, VaultAccounts, VaultState},
    rebalance::ShieldLanes,
};

use super::{error::MakerError, scheduler::profile::LaneProfile};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultFlow {
    Deposit,
    Withdrawal,
}

#[derive(Clone, Copy, Debug)]
pub struct RebalanceOrder {
    pub vault: VaultAccounts,
    pub flow: VaultFlow,
    pub amount: u64,
}

pub struct RebalanceTail {
    pub before: VaultState,
    pub withdrawal: u64,
    pub instructions: Vec<Instruction>,
}

#[derive(Clone, Copy)]
pub struct MakerAccounts {
    pub owner: Address,
    pub identity: ShieldedAddress,
    pub tree: Address,
}

pub struct ShieldPlan<'a> {
    pub profile: &'a LaneProfile,
    pub lanes: Vec<u64>,
    pub max_lanes: usize,
}

impl ShieldPlan<'_> {
    pub fn amounts(&self, amount: u64) -> Vec<u64> {
        self.profile.parts(amount, &self.lanes, self.max_lanes)
    }
}

impl RebalanceOrder {
    pub fn shielded_asset(&self) -> Address {
        match self.flow {
            VaultFlow::Deposit => self.vault.shares_mint,
            VaultFlow::Withdrawal => self.vault.token_mint,
        }
    }

    pub async fn vault_state(&self, rpc: &dyn AsyncRpc) -> Result<VaultState, MakerError> {
        let account = rpc
            .get_account(self.vault.vault)
            .await
            .map_err(MakerError::Rpc)?
            .ok_or(MakerError::VaultMissing {
                vault: self.vault.vault,
            })?;
        VaultState::from_data(&account.data).map_err(|error| MakerError::VaultState {
            vault: self.vault.vault,
            reason: error.to_string(),
        })
    }

    pub fn tail(
        &self,
        before: VaultState,
        maker: MakerAccounts,
        shield: &ShieldPlan,
        also_shield: Vec<(Address, u64)>,
    ) -> Result<RebalanceTail, MakerError> {
        let vault = &self.vault;
        let user = maker.public_accounts(vault);
        let math = |error: anyhow::Error| MakerError::VaultMath {
            vault: vault.vault,
            reason: error.to_string(),
        };
        let (withdrawal, vault_instruction, shielded) = match self.flow {
            VaultFlow::Deposit => {
                let outcome = before.deposit(self.amount).map_err(math)?;
                let deposit = kvault::Deposit {
                    vault,
                    user: &user,
                    max_amount: outcome.tokens,
                }
                .instruction();
                (outcome.tokens, deposit, outcome.shares)
            }
            VaultFlow::Withdrawal => {
                let outcome = before.withdraw(self.amount).map_err(math)?;
                let withdraw = kvault::WithdrawFromAvailable {
                    vault,
                    user: &user,
                    shares: outcome.shares,
                }
                .instruction();
                (outcome.shares, withdraw, outcome.tokens)
            }
        };
        let shielded_asset = self.shielded_asset();
        let shield = maker.shield(
            shield
                .amounts(shielded)
                .into_iter()
                .map(|amount| (shielded_asset, amount))
                .chain(also_shield)
                .collect(),
        )?;
        Ok(RebalanceTail {
            before,
            withdrawal,
            instructions: vec![vault_instruction, shield],
        })
    }
}

impl MakerAccounts {
    pub fn public_accounts(&self, vault: &VaultAccounts) -> UserAccounts {
        UserAccounts {
            user: self.owner,
            token_account: pda::associated_token_address(&self.owner, &vault.token_mint),
            shares_account: pda::associated_token_address(&self.owner, &vault.shares_mint),
        }
    }

    pub fn shield(&self, lanes: Vec<(Address, u64)>) -> Result<Instruction, MakerError> {
        ShieldLanes {
            tree: self.tree,
            depositor: self.owner,
            recipient: self.identity,
            lanes,
        }
        .instruction()
        .map_err(|error| MakerError::ShieldInstruction(error.to_string()))
    }
}
