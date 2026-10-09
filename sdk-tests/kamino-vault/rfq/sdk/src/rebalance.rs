use anyhow::Result;
use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::ComputeBudgetConfig;
use zolana_interface::pda;
use zolana_keypair::ShieldedAddress;
use zolana_program::instruction::{AssetDeposit, Deposit, DepositAsset, DepositSplAccounts};

pub const REBALANCE_COMPUTE_BUDGET: ComputeBudgetConfig = ComputeBudgetConfig::new(1_400_000);

pub struct ShieldLanes {
    pub tree: Address,
    pub depositor: Address,
    pub recipient: ShieldedAddress,
    pub lanes: Vec<(Address, u64)>,
}

impl ShieldLanes {
    pub fn instruction(&self) -> Result<Instruction> {
        let owner = self.recipient.owner_hash()?;
        let view_tag = self.recipient.viewing_pubkey.x();
        Ok(Deposit {
            tree: self.tree,
            depositor: self.depositor,
            deposits: self
                .lanes
                .iter()
                .map(|(mint, amount)| AssetDeposit {
                    asset: DepositAsset::Spl(DepositSplAccounts {
                        mint: *mint,
                        user_token: pda::associated_token_address(&self.depositor, mint),
                        token_program: pda::spl_token_program_id(),
                    }),
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
