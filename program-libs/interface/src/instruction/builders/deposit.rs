use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use thiserror::Error;

use crate::{
    instruction::{
        tag, DepositAssetKind, DepositEntry, DepositIxData, UtxoData, MAX_DEPOSIT_ASSETS,
    },
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

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DepositBuildError {
    #[error("deposit batch contains no entries")]
    EmptyBatch,
    #[error("deposit batch has {count} entries; the wire format supports at most {max}")]
    TooManyEntries { count: usize, max: usize },
    #[error("deposit batch has {count} assets; at most {max} are supported")]
    TooManyAssets { count: usize, max: usize },
    #[error(
        "SPL mint {mint} uses conflicting source token accounts {first_user_token} and {conflicting_user_token}"
    )]
    ConflictingSplSources {
        mint: Pubkey,
        first_user_token: Pubkey,
        conflicting_user_token: Pubkey,
    },
    #[error("deposit instruction data could not be serialized")]
    Serialization,
}

pub(super) struct DepositLayout {
    has_sol: bool,
    spl_groups: Vec<DepositSplAccounts>,
}

impl DepositLayout {
    pub(super) fn new(
        entry_count: usize,
        assets: impl IntoIterator<Item = DepositAsset>,
    ) -> Result<Self, DepositBuildError> {
        if entry_count == 0 {
            return Err(DepositBuildError::EmptyBatch);
        }
        let max_entries = usize::from(u8::MAX);
        if entry_count > max_entries {
            return Err(DepositBuildError::TooManyEntries {
                count: entry_count,
                max: max_entries,
            });
        }

        // Group order must match the program's account parse order: the SOL
        // group (when any entry deposits SOL) is asset index 0, then one SPL
        // group per distinct mint in first-appearance order.
        let mut has_sol = false;
        let mut spl_groups: Vec<DepositSplAccounts> = Vec::new();
        for asset in assets {
            match asset {
                DepositAsset::Sol => has_sol = true,
                DepositAsset::Spl(spl) => {
                    match spl_groups
                        .iter()
                        .find(|candidate| candidate.mint == spl.mint)
                    {
                        Some(existing) if existing.user_token != spl.user_token => {
                            return Err(DepositBuildError::ConflictingSplSources {
                                mint: spl.mint,
                                first_user_token: existing.user_token,
                                conflicting_user_token: spl.user_token,
                            });
                        }
                        Some(_) => {}
                        None => spl_groups.push(spl),
                    }
                }
            }
        }
        let spl_base = usize::from(has_sol);
        let asset_count = spl_base + spl_groups.len();
        if asset_count > MAX_DEPOSIT_ASSETS {
            return Err(DepositBuildError::TooManyAssets {
                count: asset_count,
                max: MAX_DEPOSIT_ASSETS,
            });
        }

        Ok(Self {
            has_sol,
            spl_groups,
        })
    }

    pub(super) fn asset_index(
        &self,
        asset: DepositAsset,
    ) -> Result<u8, DepositBuildError> {
        let spl_base = usize::from(self.has_sol);
        let asset_index = match asset {
            DepositAsset::Sol => 0,
            DepositAsset::Spl(spl) => {
                let Some(group) = self
                    .spl_groups
                    .iter()
                    .position(|candidate| candidate.mint == spl.mint)
                else {
                    return Err(DepositBuildError::Serialization);
                };
                spl_base + group
            }
        };
        u8::try_from(asset_index).map_err(|_| DepositBuildError::TooManyAssets {
            count: self.asset_count(),
            max: MAX_DEPOSIT_ASSETS,
        })
    }

    pub(super) fn asset_kinds(&self) -> Vec<DepositAssetKind> {
        let mut assets = Vec::with_capacity(self.asset_count());
        if self.has_sol {
            assets.push(DepositAssetKind::Sol);
        }
        assets.extend(
            self.spl_groups
                .iter()
                .map(|_| DepositAssetKind::Spl),
        );
        assets
    }

    pub(super) fn extend_account_metas(&self, accounts: &mut Vec<AccountMeta>) {
        if self.has_sol {
            accounts.extend([
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new(pda::sol_interface(), false),
            ]);
        }
        for spl in &self.spl_groups {
            accounts.extend([
                AccountMeta::new_readonly(Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID), false),
                AccountMeta::new(spl.user_token, false),
                AccountMeta::new(pda::spl_asset_vault(&spl.mint), false),
                AccountMeta::new_readonly(pda::spl_asset_registry(&spl.mint), false),
            ]);
        }
    }

    fn asset_count(&self) -> usize {
        usize::from(self.has_sol) + self.spl_groups.len()
    }
}

impl AssetDeposit {
    pub(super) fn into_entry(self, asset_index: u8) -> DepositEntry {
        DepositEntry {
            asset_index,
            view_tag: self.view_tag,
            owner: self.owner,
            blinding: self.blinding,
            amount: self.amount,
            utxo_data: self.utxo_data,
            memo: self.memo,
        }
    }
}

impl Deposit {
    pub fn instruction(self) -> Result<Instruction, DepositBuildError> {
        let layout = DepositLayout::new(
            self.deposits.len(),
            self.deposits.iter().map(|deposit| deposit.asset),
        )?;
        let deposits = self
            .deposits
            .into_iter()
            .map(|deposit| {
                let asset_index = layout.asset_index(deposit.asset)?;
                Ok(deposit.into_entry(asset_index))
            })
            .collect::<Result<Vec<_>, DepositBuildError>>()?;

        let mut data = vec![tag::DEPOSIT];
        data.extend_from_slice(
            &DepositIxData {
                assets: layout.asset_kinds(),
                deposits,
            }
                .serialize()
                .map_err(|_| DepositBuildError::Serialization)?,
        );

        let mut accounts = vec![
            AccountMeta::new(self.tree, false),
            AccountMeta::new(self.depositor, true),
        ];
        layout.extend_account_metas(&mut accounts);
        accounts.push(AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false));

        Ok(Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(asset: DepositAsset, seed: u8) -> AssetDeposit {
        AssetDeposit {
            asset,
            view_tag: [seed; 32],
            owner: [seed; 32],
            blinding: [seed; 31],
            amount: u64::from(seed),
            utxo_data: None,
            memo: None,
        }
    }

    fn spl(mint: Pubkey, user_token: Pubkey, seed: u8) -> AssetDeposit {
        entry(
            DepositAsset::Spl(DepositSplAccounts { mint, user_token }),
            seed,
        )
    }

    fn deposit(deposits: Vec<AssetDeposit>) -> Deposit {
        Deposit {
            tree: Pubkey::new_unique(),
            depositor: Pubkey::new_unique(),
            deposits,
        }
    }

    fn decode(ix: &Instruction) -> DepositIxData {
        DepositIxData::deserialize(ix.data.get(1..).expect("instruction tag"))
            .expect("builder emits valid instruction data")
    }

    #[test]
    fn rejects_empty_batch() {
        assert_eq!(
            deposit(Vec::new()).instruction(),
            Err(DepositBuildError::EmptyBatch)
        );
    }

    #[test]
    fn same_mint_and_source_share_one_group() {
        let mint = Pubkey::new_unique();
        let user_token = Pubkey::new_unique();
        let ix = deposit(vec![
            spl(mint, user_token, 1),
            entry(DepositAsset::Sol, 2),
            spl(mint, user_token, 3),
        ])
        .instruction()
        .expect("same mint and source are compatible");
        let data = decode(&ix);

        assert_eq!(
            data.assets,
            vec![DepositAssetKind::Sol, DepositAssetKind::Spl]
        );
        assert_eq!(
            data.deposits
                .iter()
                .map(|entry| entry.asset_index)
                .collect::<Vec<_>>(),
            vec![1, 0, 1]
        );
    }

    #[test]
    fn rejects_conflicting_sources_for_one_mint() {
        let mint = Pubkey::new_unique();
        let first_user_token = Pubkey::new_unique();
        let conflicting_user_token = Pubkey::new_unique();

        assert_eq!(
            deposit(vec![
                spl(mint, first_user_token, 1),
                spl(mint, conflicting_user_token, 2),
            ])
            .instruction(),
            Err(DepositBuildError::ConflictingSplSources {
                mint,
                first_user_token,
                conflicting_user_token,
            })
        );
    }

    #[test]
    fn accepts_exactly_max_assets_and_rejects_one_more() {
        let deposits = (0..MAX_DEPOSIT_ASSETS)
            .map(|index| {
                spl(
                    Pubkey::new_unique(),
                    Pubkey::new_unique(),
                    u8::try_from(index + 1).expect("small test index"),
                )
            })
            .collect::<Vec<_>>();
        let ix = deposit(deposits.clone())
            .instruction()
            .expect("maximum asset count is valid");
        assert_eq!(decode(&ix).assets.len(), MAX_DEPOSIT_ASSETS);

        let mut too_many = deposits;
        too_many.push(spl(Pubkey::new_unique(), Pubkey::new_unique(), 9));
        assert_eq!(
            deposit(too_many).instruction(),
            Err(DepositBuildError::TooManyAssets {
                count: MAX_DEPOSIT_ASSETS + 1,
                max: MAX_DEPOSIT_ASSETS,
            })
        );
    }

    #[test]
    fn rejects_more_entries_than_the_wire_format_can_encode() {
        let entries = (0..=u8::MAX)
            .map(|seed| entry(DepositAsset::Sol, seed))
            .collect();
        assert_eq!(
            deposit(entries).instruction(),
            Err(DepositBuildError::TooManyEntries {
                count: usize::from(u8::MAX) + 1,
                max: usize::from(u8::MAX),
            })
        );
    }
}
