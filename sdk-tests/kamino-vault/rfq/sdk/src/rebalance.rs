use anyhow::Result;
use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::ComputeBudgetConfig;
use zolana_interface::pda;
use zolana_keypair::ShieldedAddress;
use zolana_program::instruction::{AssetDeposit, Deposit, DepositAsset, DepositSplAccounts};

pub const REBALANCE_COMPUTE_BUDGET: ComputeBudgetConfig = ComputeBudgetConfig::new(1_400_000);

pub fn lane_amounts(amount: u64, lanes: usize) -> Vec<u64> {
    let count = u64::try_from(lanes.max(1)).unwrap_or(1).min(amount.max(1));
    let part = amount / count;
    (0..count)
        .map(|lane| {
            if lane + 1 == count {
                amount - part * (count - 1)
            } else {
                part
            }
        })
        .collect()
}

pub struct ShieldLanes {
    pub tree: Address,
    pub depositor: Address,
    pub recipient: ShieldedAddress,
    pub mint: Address,
    pub amounts: Vec<u64>,
}

impl ShieldLanes {
    pub fn instruction(&self) -> Result<Instruction> {
        let owner = self.recipient.owner_hash()?;
        let view_tag = self.recipient.viewing_pubkey.x();
        let asset = DepositAsset::Spl(DepositSplAccounts {
            mint: self.mint,
            user_token: pda::associated_token_address(&self.depositor, &self.mint),
            token_program: pda::spl_token_program_id(),
        });
        Ok(Deposit {
            tree: self.tree,
            depositor: self.depositor,
            deposits: self
                .amounts
                .iter()
                .map(|amount| AssetDeposit {
                    asset,
                    view_tag,
                    owner,
                    amount: *amount,
                    memo: None,
                })
                .collect(),
        }
        .instruction()?)
    }
}
