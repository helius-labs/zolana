use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, DepositAssetKind, DepositEntry, DepositIxData, UtxoData},
    pda, PROGRAM_ID_PUBKEY, SPL_TOKEN_PROGRAM_ID,
};

/// SPL settlement for one deposited mint. The vault and registry are canonical
/// PDAs of `mint`, so callers pass only the mint and the funding token account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositSplAccounts {
    pub mint: Pubkey,
    pub user_token: Pubkey,
}

/// Asset one batch entry deposits. Native SOL settles through the SOL interface
/// PDA; an SPL mint settles through its vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositAsset {
    Sol,
    Spl(DepositSplAccounts),
}

/// One output of a deposit batch, tagged with the asset it deposits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetDeposit {
    pub asset: DepositAsset,
    pub view_tag: [u8; 32],
    pub owner: [u8; 32],
    pub blinding: [u8; 31],
    pub amount: u64,
    pub utxo_data: Option<UtxoData>,
    pub memo: Option<Vec<u8>>,
}

/// Batched public deposit. Entries name their own asset; the builder groups them
/// into settlement account sets and assigns each entry's `asset_index`, so an
/// index can never disagree with the accounts it selects.
pub struct Deposit {
    pub tree: Pubkey,
    pub depositor: Pubkey,
    pub deposits: Vec<AssetDeposit>,
}

impl Deposit {
    pub fn instruction(self) -> Instruction {
        // Group order must match the program's account parse order: the SOL
        // group (when any entry deposits SOL) is asset index 0, then one SPL
        // group per distinct settlement set in first-appearance order.
        let has_sol = self
            .deposits
            .iter()
            .any(|deposit| matches!(deposit.asset, DepositAsset::Sol));
        let mut spl_groups: Vec<DepositSplAccounts> = Vec::new();
        for deposit in &self.deposits {
            if let DepositAsset::Spl(spl) = deposit.asset {
                if !spl_groups.contains(&spl) {
                    spl_groups.push(spl);
                }
            }
        }
        let spl_base = usize::from(has_sol);

        let deposits = self
            .deposits
            .iter()
            .map(|deposit| {
                let asset_index = match deposit.asset {
                    DepositAsset::Sol => 0,
                    DepositAsset::Spl(spl) => {
                        let group = spl_groups
                            .iter()
                            .position(|candidate| *candidate == spl)
                            .expect("spl settlement group collected above");
                        spl_base.saturating_add(group)
                    }
                };
                DepositEntry {
                    asset_index: u8::try_from(asset_index)
                        .expect("deposit asset count is bounded by MAX_DEPOSIT_ASSETS"),
                    view_tag: deposit.view_tag,
                    owner: deposit.owner,
                    blinding: deposit.blinding,
                    amount: deposit.amount,
                    utxo_data: deposit.utxo_data.clone(),
                    memo: deposit.memo.clone(),
                }
            })
            .collect();

        let mut assets = Vec::with_capacity(spl_base.saturating_add(spl_groups.len()));
        if has_sol {
            assets.push(DepositAssetKind::Sol);
        }
        assets.extend(spl_groups.iter().map(|_| DepositAssetKind::Spl));

        let mut data = vec![tag::DEPOSIT];
        data.extend_from_slice(
            &DepositIxData { assets, deposits }
                .serialize()
                .expect("proofless ix data serialization is infallible"),
        );

        let mut accounts = vec![
            AccountMeta::new(self.tree, false),
            AccountMeta::new(self.depositor, true),
        ];
        if has_sol {
            accounts.extend([
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new(pda::sol_interface(), false),
            ]);
        }
        for spl in &spl_groups {
            accounts.extend([
                AccountMeta::new_readonly(Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID), false),
                AccountMeta::new(spl.user_token, false),
                AccountMeta::new(pda::spl_asset_vault(&spl.mint), false),
                AccountMeta::new_readonly(pda::spl_asset_registry(&spl.mint), false),
            ]);
        }
        accounts.push(AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false));

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data,
        }
    }
}
