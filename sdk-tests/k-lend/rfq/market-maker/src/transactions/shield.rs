use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::ComputeBudgetConfig;
use zolana_interface::pda;
use zolana_keypair::ShieldedAddress;
use zolana_program::instruction::{AssetDeposit, Deposit, DepositAsset, DepositSplAccounts};

use crate::{
    config::Settings,
    error::MakerError,
    inventory::balance::{profile::InventoryProfile, reservations::Reservations},
    transactions::Identity,
};

pub const REBALANCE_COMPUTE_BUDGET: ComputeBudgetConfig = ComputeBudgetConfig::new(1_400_000);

pub struct ShieldUtxos {
    pub tree: Address,
    pub depositor: Address,
    pub recipient: ShieldedAddress,
    pub utxos: Vec<(Address, u64)>,
}

impl ShieldUtxos {
    pub fn instruction(&self) -> Result<Instruction, MakerError> {
        let owner = self.recipient.owner_hash()?;
        let view_tag = self.recipient.viewing_pubkey.x();
        Deposit {
            tree: self.tree,
            depositor: self.depositor,
            deposits: self
                .utxos
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
        .instruction()
        .map_err(|error| MakerError::ShieldInstruction(error.to_string()))
    }
}

pub struct ShieldPlan<'a> {
    pub profile: &'a InventoryProfile,
    pub utxos: Vec<u64>,
    pub max_utxos: usize,
}

impl<'a> ShieldPlan<'a> {
    pub fn new(config: &'a Settings, reservations: &Reservations, asset: &Address) -> Self {
        Self {
            profile: config.profile(asset),
            utxos: reservations
                .utxos(asset)
                .into_iter()
                .map(|utxo| utxo.amount)
                .collect(),
            max_utxos: config.max_shield_utxos,
        }
    }

    pub fn amounts(&self, amount: u64) -> Vec<u64> {
        self.profile.parts(amount, &self.utxos, self.max_utxos)
    }
}

impl Identity {
    pub fn shield(&self, utxos: Vec<(Address, u64)>) -> Result<Instruction, MakerError> {
        ShieldUtxos {
            tree: self.tree,
            depositor: self.payer,
            recipient: self.own,
            utxos,
        }
        .instruction()
    }
}
