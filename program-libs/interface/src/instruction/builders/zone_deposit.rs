use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use super::deposit::{DepositAsset, DepositBuildError, DepositLayout};
use crate::{
    instruction::{tag, EncryptedZoneDepositData, ZoneDepositEntry, ZoneDepositIxData},
    pda, PROGRAM_ID_PUBKEY,
};

/// One owner-hidden output of a zone deposit batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneAssetDeposit {
    pub asset: DepositAsset,
    /// Opaque indexing tag. SPP copies it without validation.
    pub view_tag: [u8; 32],
    pub owner_utxo_hash: [u8; 32],
    pub amount: u64,
    pub data_hash: Option<[u8; 32]>,
    pub zone_data_hash: [u8; 32],
    pub encrypted: EncryptedZoneDepositData,
}

/// Batched policy-zone deposit. The zone program authorizes the whole
/// instruction, while each output carries its own policy data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneDeposit {
    pub tree: Pubkey,
    pub depositor: Pubkey,
    /// Calling zone program's id; its canonical `zone_auth` PDA is the signing
    /// `ZoneConfig` account.
    pub zone_program_id: Pubkey,
    pub deposits: Vec<ZoneAssetDeposit>,
}

impl ZoneDeposit {
    /// Build the outer instruction sent to the zone program. The zone fixture or
    /// production zone forwards it to SPP and signs for `zone_auth`.
    pub fn instruction(self) -> Result<Instruction, DepositBuildError> {
        let program_id = self.zone_program_id;
        self.build_instruction(program_id, false)
    }

    /// Build the CPI into SPP from inside the zone program.
    pub fn cpi_instruction(self) -> Result<Instruction, DepositBuildError> {
        self.build_instruction(PROGRAM_ID_PUBKEY, true)
    }

    fn build_instruction(
        self,
        program_id: Pubkey,
        auth_signer: bool,
    ) -> Result<Instruction, DepositBuildError> {
        let layout = DepositLayout::new(
            self.deposits.len(),
            self.deposits.iter().map(|entry| entry.asset),
        )?;
        let deposits = self
            .deposits
            .into_iter()
            .map(|entry| {
                let asset_index = layout.asset_index(entry.asset)?;
                Ok(ZoneDepositEntry {
                    asset_index,
                    view_tag: entry.view_tag,
                    owner_utxo_hash: entry.owner_utxo_hash,
                    amount: entry.amount,
                    data_hash: entry.data_hash,
                    zone_data_hash: entry.zone_data_hash,
                    encrypted: entry.encrypted,
                })
            })
            .collect::<Result<Vec<_>, DepositBuildError>>()?;

        let ix_data = ZoneDepositIxData {
            assets: layout.asset_kinds(),
            deposits,
        };
        let mut data = vec![tag::ZONE_DEPOSIT];
        data.extend_from_slice(
            &ix_data
                .serialize()
                .map_err(|_| DepositBuildError::Serialization)?,
        );

        // The `ZoneConfig` account is the zone's canonical `zone_auth` PDA: it
        // signs and its stored `program_id` becomes each UTXO's zone program.
        let zone_config = pda::zone_auth(&self.zone_program_id).0;
        let mut accounts = vec![
            AccountMeta::new(self.tree, false),
            AccountMeta::new(self.depositor, true),
            AccountMeta::new_readonly(zone_config, auth_signer),
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
        ];
        layout.extend_account_metas(&mut accounts);

        Ok(Instruction {
            program_id,
            accounts,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::{
        DepositAsset, DepositAssetKind, DepositSplAccounts, MAX_DEPOSIT_ASSETS,
    };

    fn zone_entry(asset: DepositAsset, seed: u8) -> ZoneAssetDeposit {
        ZoneAssetDeposit {
            asset,
            view_tag: [seed; 32],
            owner_utxo_hash: [seed.wrapping_add(1); 32],
            amount: u64::from(seed),
            data_hash: None,
            zone_data_hash: [seed.wrapping_add(10); 32],
            encrypted: EncryptedZoneDepositData {
                tx_viewing_pk: [seed.wrapping_add(2); 33],
                salt: [seed.wrapping_add(3); 16],
                ciphertext: vec![seed],
            },
        }
    }

    fn builder(deposits: Vec<ZoneAssetDeposit>) -> ZoneDeposit {
        ZoneDeposit {
            tree: Pubkey::new_unique(),
            depositor: Pubkey::new_unique(),
            zone_program_id: Pubkey::new_unique(),
            deposits,
        }
    }

    fn decode(ix: &Instruction) -> ZoneDepositIxData {
        ZoneDepositIxData::deserialize(ix.data.get(1..).expect("instruction tag"))
            .expect("builder emits valid instruction data")
    }

    #[test]
    fn builds_mixed_batch_with_per_output_zone_data() {
        let mint = Pubkey::new_unique();
        let user_token = Pubkey::new_unique();
        let spl = DepositAsset::Spl(DepositSplAccounts {
            mint,
            user_token,
            token_program: pda::spl_token_program_id(),
        });
        let expected = vec![
            zone_entry(spl, 1),
            zone_entry(DepositAsset::Sol, 2),
            zone_entry(spl, 3),
        ];

        let ix = builder(expected.clone())
            .instruction()
            .expect("valid zone batch");
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
        assert_eq!(
            data.deposits
                .iter()
                .map(|entry| entry.zone_data_hash)
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|entry| entry.zone_data_hash)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn rejects_conflicting_sources_and_asset_limits() {
        let mint = Pubkey::new_unique();
        let first_user_token = Pubkey::new_unique();
        let conflicting_user_token = Pubkey::new_unique();
        assert_eq!(
            builder(vec![
                zone_entry(
                    DepositAsset::Spl(DepositSplAccounts {
                        mint,
                        user_token: first_user_token,
                        token_program: pda::spl_token_program_id(),
                    }),
                    1,
                ),
                zone_entry(
                    DepositAsset::Spl(DepositSplAccounts {
                        mint,
                        user_token: conflicting_user_token,
                        token_program: pda::spl_token_program_id(),
                    }),
                    2,
                ),
            ])
            .instruction(),
            Err(DepositBuildError::ConflictingSplSources {
                mint,
                first_user_token,
                conflicting_user_token,
            })
        );

        let too_many = (0..=MAX_DEPOSIT_ASSETS)
            .map(|index| {
                zone_entry(
                    DepositAsset::Spl(DepositSplAccounts {
                        mint: Pubkey::new_unique(),
                        user_token: Pubkey::new_unique(),
                        token_program: pda::spl_token_program_id(),
                    }),
                    u8::try_from(index + 1).expect("small test index"),
                )
            })
            .collect();
        assert_eq!(
            builder(too_many).instruction(),
            Err(DepositBuildError::TooManyAssets {
                count: MAX_DEPOSIT_ASSETS + 1,
                max: MAX_DEPOSIT_ASSETS,
            })
        );
    }

    #[test]
    fn direct_and_cpi_modes_target_and_sign_correctly() {
        let direct_builder = builder(vec![zone_entry(DepositAsset::Sol, 1)]);
        let zone_program_id = direct_builder.zone_program_id;
        let cpi_builder = direct_builder.clone();

        let direct = direct_builder.instruction().expect("direct instruction");
        let cpi = cpi_builder.cpi_instruction().expect("CPI instruction");

        assert_eq!(direct.program_id, zone_program_id);
        assert!(!direct.accounts[2].is_signer);
        assert_eq!(cpi.program_id, PROGRAM_ID_PUBKEY);
        assert!(cpi.accounts[2].is_signer);
        assert_eq!(direct.accounts[2].pubkey, cpi.accounts[2].pubkey);
        assert_eq!(&direct.accounts[..2], &cpi.accounts[..2]);
        assert_eq!(&direct.accounts[3..], &cpi.accounts[3..]);
    }

    #[test]
    fn rejects_empty_and_oversized_ciphertext() {
        assert_eq!(
            builder(Vec::new()).instruction(),
            Err(DepositBuildError::EmptyBatch)
        );

        let mut entry = zone_entry(DepositAsset::Sol, 1);
        entry.encrypted.ciphertext = vec![0; usize::from(u16::MAX) + 1];
        assert_eq!(
            builder(vec![entry]).instruction(),
            Err(DepositBuildError::Serialization)
        );
    }
}
