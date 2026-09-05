use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use thiserror::Error;
use zolana_hasher::primitives::is_canonical_bn254_scalar_be;

use crate::{
    instruction::{
        tag, DepositAssetKind, DepositEntry, DepositIxData, UtxoData, MAX_DEPOSIT_ASSETS,
    },
    pda, PROGRAM_ID_PUBKEY,
};

/// SPL settlement for one deposited mint. The SPL interface is the canonical
/// PDA of `mint`, so callers pass only the mint and funding token account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositSplAccounts {
    pub mint: Pubkey,
    pub user_token: Pubkey,
    pub token_program: Pubkey,
}

/// Asset one batch entry deposits. Native SOL settles through the SOL interface
/// PDA; an SPL mint settles through its interface token account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositAsset {
    Sol,
    Spl(DepositSplAccounts),
}

impl DepositAsset {
    /// The settled mint, the zero address for SOL.
    pub fn mint(&self) -> Pubkey {
        match self {
            DepositAsset::Sol => Pubkey::default(),
            DepositAsset::Spl(spl) => spl.mint,
        }
    }
}

/// One output of a deposit batch, tagged with the asset it deposits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetDeposit {
    pub asset: DepositAsset,
    pub view_tag: [u8; 32],
    pub owner: [u8; 32],
    /// Zero is valid: it appends the output but performs no settlement transfer.
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
    #[error(
        "SPL mint {mint} uses conflicting token programs {first_token_program} and {conflicting_token_program}"
    )]
    ConflictingSplTokenPrograms {
        mint: Pubkey,
        first_token_program: Pubkey,
        conflicting_token_program: Pubkey,
    },
    #[error(
        "deposit entry {entry_index} field {field} is not a canonical BN254 scalar field element"
    )]
    NonCanonicalField {
        entry_index: usize,
        field: &'static str,
    },
    #[error("deposit amount total for asset {asset} overflows u64")]
    AmountOverflow { asset: Pubkey },
    #[error("deposit instruction data could not be serialized")]
    Serialization,
}

pub(super) fn validate_canonical_field(
    value: &[u8; 32],
    entry_index: usize,
    field: &'static str,
) -> Result<(), DepositBuildError> {
    if !is_canonical_bn254_scalar_be(value) {
        return Err(DepositBuildError::NonCanonicalField { entry_index, field });
    }
    Ok(())
}

pub(super) fn add_deposit_amount(
    totals: &mut [u64; MAX_DEPOSIT_ASSETS],
    asset_index: u8,
    asset: Pubkey,
    amount: u64,
) -> Result<(), DepositBuildError> {
    let total = totals
        .get_mut(usize::from(asset_index))
        .ok_or(DepositBuildError::Serialization)?;
    *total = total
        .checked_add(amount)
        .ok_or(DepositBuildError::AmountOverflow { asset })?;
    Ok(())
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
                        Some(existing) if existing.token_program != spl.token_program => {
                            return Err(DepositBuildError::ConflictingSplTokenPrograms {
                                mint: spl.mint,
                                first_token_program: existing.token_program,
                                conflicting_token_program: spl.token_program,
                            });
                        }
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

    pub(super) fn asset_index(&self, asset: DepositAsset) -> Result<u8, DepositBuildError> {
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
        assets.extend(self.spl_groups.iter().map(|spl| DepositAssetKind::Spl {
            spl_interface_bump: pda::spl_interface_with_bump(&spl.mint).1,
        }));
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
                AccountMeta::new_readonly(spl.token_program, false),
                AccountMeta::new_readonly(spl.mint, false),
                AccountMeta::new(spl.user_token, false),
                AccountMeta::new(pda::spl_interface(&spl.mint), false),
            ]);
        }
    }

    fn asset_count(&self) -> usize {
        usize::from(self.has_sol) + self.spl_groups.len()
    }
}

impl AssetDeposit {
    fn validate_fields(&self, entry_index: usize) -> Result<(), DepositBuildError> {
        validate_canonical_field(&self.owner, entry_index, "owner")?;
        if let Some(utxo_data) = &self.utxo_data {
            validate_canonical_field(&utxo_data.data_hash, entry_index, "data_hash")?;
        }
        Ok(())
    }

    pub(super) fn into_entry(self, asset_index: u8) -> DepositEntry {
        DepositEntry {
            asset_index,
            view_tag: self.view_tag,
            owner: self.owner,
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
        let mut totals = [0u64; MAX_DEPOSIT_ASSETS];
        let deposits = self
            .deposits
            .into_iter()
            .enumerate()
            .map(|(entry_index, deposit)| {
                deposit.validate_fields(entry_index)?;
                let asset_index = layout.asset_index(deposit.asset)?;
                add_deposit_amount(
                    &mut totals,
                    asset_index,
                    deposit.asset.mint(),
                    deposit.amount,
                )?;
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
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
        ];
        layout.extend_account_metas(&mut accounts);

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
    use zolana_hasher::primitives::BN254_SCALAR_MODULUS_BE;

    fn entry(asset: DepositAsset, seed: u8) -> AssetDeposit {
        AssetDeposit {
            asset,
            view_tag: [seed; 32],
            owner: [seed; 32],
            amount: u64::from(seed),
            utxo_data: None,
            memo: None,
        }
    }

    fn spl(mint: Pubkey, user_token: Pubkey, seed: u8) -> AssetDeposit {
        entry(
            DepositAsset::Spl(DepositSplAccounts {
                mint,
                user_token,
                token_program: pda::spl_token_program_id(),
            }),
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
            vec![
                DepositAssetKind::Sol,
                DepositAssetKind::Spl {
                    spl_interface_bump: pda::spl_interface_with_bump(&mint).1,
                },
            ]
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
    fn spl_layout_places_program_before_four_account_settlement_group() {
        let mint = Pubkey::new_unique();
        let user_token = Pubkey::new_unique();
        let deposit = deposit(vec![spl(mint, user_token, 1)]);
        let tree = deposit.tree;
        let depositor = deposit.depositor;

        let ix = deposit.instruction().unwrap();

        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new(tree, false),
                AccountMeta::new(depositor, true),
                AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
                AccountMeta::new_readonly(pda::spl_token_program_id(), false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new(user_token, false),
                AccountMeta::new(pda::spl_interface(&mint), false),
            ]
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

    #[test]
    fn rejects_every_non_canonical_deposit_field() {
        let mut owner = entry(DepositAsset::Sol, 1);
        owner.owner = BN254_SCALAR_MODULUS_BE;
        assert_eq!(
            deposit(vec![entry(DepositAsset::Sol, 2), owner]).instruction(),
            Err(DepositBuildError::NonCanonicalField {
                entry_index: 1,
                field: "owner",
            })
        );

        let mut data_hash = entry(DepositAsset::Sol, 1);
        data_hash.utxo_data = Some(UtxoData {
            data_hash: BN254_SCALAR_MODULUS_BE,
            data: vec![7],
        });
        assert_eq!(
            deposit(vec![data_hash]).instruction(),
            Err(DepositBuildError::NonCanonicalField {
                entry_index: 0,
                field: "data_hash",
            })
        );
    }

    #[test]
    fn validates_amount_totals_per_asset_and_preserves_zero_amounts() {
        let mut maximum_sol = entry(DepositAsset::Sol, 1);
        maximum_sol.amount = u64::MAX;
        let mut one_more_sol = entry(DepositAsset::Sol, 2);
        one_more_sol.amount = 1;
        assert_eq!(
            deposit(vec![maximum_sol.clone(), one_more_sol]).instruction(),
            Err(DepositBuildError::AmountOverflow {
                asset: Pubkey::default(),
            })
        );

        let mint = Pubkey::new_unique();
        let user_token = Pubkey::new_unique();
        let mut maximum_spl = spl(mint, user_token, 3);
        maximum_spl.amount = u64::MAX;
        let mut one_more_spl = spl(mint, user_token, 4);
        one_more_spl.amount = 1;
        assert_eq!(
            deposit(vec![maximum_spl.clone(), one_more_spl]).instruction(),
            Err(DepositBuildError::AmountOverflow { asset: mint })
        );

        let ix = deposit(vec![maximum_sol, maximum_spl])
            .instruction()
            .expect("independent asset totals may each reach u64::MAX");
        assert_eq!(
            decode(&ix)
                .deposits
                .iter()
                .map(|entry| entry.amount)
                .collect::<Vec<_>>(),
            vec![u64::MAX, u64::MAX]
        );

        let mut zero = entry(DepositAsset::Sol, 5);
        zero.amount = 0;
        let ix = deposit(vec![zero])
            .instruction()
            .expect("zero-value outputs remain valid");
        assert_eq!(
            decode(&ix)
                .deposits
                .iter()
                .map(|entry| entry.amount)
                .collect::<Vec<_>>(),
            vec![0]
        );
    }
}
