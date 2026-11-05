use alloc::{vec, vec::Vec};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use spr_interface::{
    instruction::{tag, InputUtxo, InterfaceTransfer, TransactIxData},
    pda, MAX_INTERFACE_TRANSFERS, PROGRAM_ID_PUBKEY, SHIELDED_POOL_CPI_AUTHORITY_PUBKEY,
    SOL_INTERFACE_PUBKEY,
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactSolTransferAccounts {
    pub recipient: Pubkey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactSplDepositAccounts {
    pub mint: Pubkey,
    pub spl_interface: Pubkey,
    pub token_authority: Pubkey,
    pub user_token_account: Pubkey,
    pub token_program: Pubkey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactSplWithdrawalAccounts {
    pub mint: Pubkey,
    pub spl_interface: Pubkey,
    pub user_token_account: Pubkey,
    pub token_program: Pubkey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactInterfaceTransferAccounts {
    Sol(TransactSolTransferAccounts),
    SplDeposit(TransactSplDepositAccounts),
    SplWithdrawal(TransactSplWithdrawalAccounts),
}

/// Why a transact-family builder (`transact`, `ring_transact`,
/// `ring_authority_transact`, `merge_transact`, `merge_ring`) rejected its
/// input. Each case is one the program would reject on chain.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TransactBuildError {
    #[error("transaction has {count} interface transfers; at most {max} are supported")]
    TooManyInterfaceTransfers { count: usize, max: usize },
    #[error("interface transfer {index} moves a zero amount")]
    ZeroInterfaceTransferAmount { index: usize },
    #[error("{transfers} interface transfers but {account_groups} settlement account groups")]
    InterfaceTransferAccountCountMismatch {
        transfers: usize,
        account_groups: usize,
    },
    #[error("interface transfer {index} does not match the kind of its settlement account group")]
    InterfaceTransferAccountMismatch { index: usize },
    #[error("input {input} references tree {tree_index}, but only {input_trees} input trees are declared")]
    InputTreeIndexOutOfRange {
        input: usize,
        tree_index: u8,
        input_trees: usize,
    },
    #[error("instruction data could not be serialized")]
    Serialization,
}

/// Builder for the `transact` instruction. The account layout mirrors the
/// program loader (`TransactAccounts::validate_and_parse`): `payer`,
/// `output_tree`, the SPP and System Program accounts, one input tree per
/// declared tree context (in context order), one writable nullifier PDA per input (in
/// `inputs` order), owner signers, then the ordered interface-transfer account
/// groups.
pub struct Transact {
    pub payer: Pubkey,
    /// One tree per `data.tree_contexts` entry, in the same order.
    pub input_trees: Vec<Pubkey>,
    pub output_tree: Pubkey,
    pub owner_signers: Vec<Pubkey>,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub data: TransactIxData,
}

pub(super) fn append_interface_transfer_accounts(
    accounts: &mut Vec<AccountMeta>,
    interface_transfers: &[InterfaceTransfer],
    transfer_accounts: &[TransactInterfaceTransferAccounts],
) -> Result<(), TransactBuildError> {
    if interface_transfers.len() > MAX_INTERFACE_TRANSFERS {
        return Err(TransactBuildError::TooManyInterfaceTransfers {
            count: interface_transfers.len(),
            max: MAX_INTERFACE_TRANSFERS,
        });
    }
    if let Some(index) = interface_transfers
        .iter()
        .position(|transfer| transfer.amount() == 0)
    {
        return Err(TransactBuildError::ZeroInterfaceTransferAmount { index });
    }
    if interface_transfers.len() != transfer_accounts.len() {
        return Err(TransactBuildError::InterfaceTransferAccountCountMismatch {
            transfers: interface_transfers.len(),
            account_groups: transfer_accounts.len(),
        });
    }

    for (index, (transfer, transfer_accounts)) in interface_transfers
        .iter()
        .zip(transfer_accounts)
        .enumerate()
    {
        match (transfer, transfer_accounts) {
            (InterfaceTransfer::SolDeposit { .. }, TransactInterfaceTransferAccounts::Sol(sol)) => {
                accounts.push(AccountMeta::new(SOL_INTERFACE_PUBKEY, false));
                accounts.push(AccountMeta::new(sol.recipient, true));
            }
            (
                InterfaceTransfer::SolWithdrawal { .. },
                TransactInterfaceTransferAccounts::Sol(sol),
            ) => {
                accounts.push(AccountMeta::new(SOL_INTERFACE_PUBKEY, false));
                accounts.push(AccountMeta::new(sol.recipient, false));
            }
            (
                InterfaceTransfer::SplDeposit { .. },
                TransactInterfaceTransferAccounts::SplDeposit(spl),
            ) => {
                accounts.push(AccountMeta::new_readonly(spl.mint, false));
                accounts.push(AccountMeta::new(spl.spl_interface, false));
                accounts.push(AccountMeta::new_readonly(spl.token_authority, true));
                accounts.push(AccountMeta::new(spl.user_token_account, false));
                accounts.push(AccountMeta::new_readonly(spl.token_program, false));
            }
            (
                InterfaceTransfer::SplWithdrawal { .. },
                TransactInterfaceTransferAccounts::SplWithdrawal(spl),
            ) => {
                accounts.push(AccountMeta::new_readonly(
                    SHIELDED_POOL_CPI_AUTHORITY_PUBKEY,
                    false,
                ));
                accounts.push(AccountMeta::new_readonly(spl.mint, false));
                accounts.push(AccountMeta::new(spl.spl_interface, false));
                accounts.push(AccountMeta::new(spl.user_token_account, false));
                accounts.push(AccountMeta::new_readonly(spl.token_program, false));
            }
            _ => return Err(TransactBuildError::InterfaceTransferAccountMismatch { index }),
        }
    }
    Ok(())
}

/// Serialize transact instruction data behind `tag`.
pub(super) fn transact_instruction_data(
    tag: u8,
    data: &TransactIxData,
) -> Result<Vec<u8>, TransactBuildError> {
    let mut instruction_data = vec![tag];
    instruction_data.extend_from_slice(
        &data
            .serialize()
            .map_err(|_| TransactBuildError::Serialization)?,
    );
    Ok(instruction_data)
}

/// One writable nullifier-PDA account per nullifier, all derived under one
/// tree, preserving input order. Single-tree instructions (`merge_transact`,
/// `merge_ring`, `close_nullifier_pdas`) use this directly; a `transact` uses
/// [`transact_nullifier_pda_accounts`], which derives each PDA under its own
/// input's tree.
pub fn nullifier_pda_accounts<'a>(
    input_tree: &Pubkey,
    nullifiers: impl IntoIterator<Item = &'a [u8; 32]>,
) -> Vec<AccountMeta> {
    nullifiers
        .into_iter()
        .map(|nullifier| AccountMeta::new(pda::nullifier_pda(input_tree, nullifier).0, false))
        .collect()
}

/// One writable nullifier-PDA account per input, in input order, each derived
/// under the tree its `tree_index` selects from `input_trees`. An index outside
/// `input_trees`, which the program rejects as `InputTreeIndexOutOfRange`, is
/// an error.
pub fn transact_nullifier_pda_accounts<'a>(
    input_trees: &[Pubkey],
    inputs: impl IntoIterator<Item = &'a InputUtxo>,
) -> Result<Vec<AccountMeta>, TransactBuildError> {
    inputs
        .into_iter()
        .enumerate()
        .map(|(index, input)| {
            let input_tree = input_trees.get(usize::from(input.tree_index)).ok_or(
                TransactBuildError::InputTreeIndexOutOfRange {
                    input: index,
                    tree_index: input.tree_index,
                    input_trees: input_trees.len(),
                },
            )?;
            Ok(AccountMeta::new(
                pda::nullifier_pda(input_tree, &input.nullifier_hash).0,
                false,
            ))
        })
        .collect()
}

impl Transact {
    pub fn instruction(&self) -> Result<Instruction, TransactBuildError> {
        let accounts = self.accounts(&[])?;
        Ok(Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: transact_instruction_data(tag::TRANSACT, &self.data)?,
        })
    }

    pub fn cpi_accounts(
        &self,
        signer_pdas: &[Pubkey],
    ) -> Result<Vec<AccountMeta>, TransactBuildError> {
        self.accounts(signer_pdas)
    }

    fn accounts(&self, signer_pdas: &[Pubkey]) -> Result<Vec<AccountMeta>, TransactBuildError> {
        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new(self.output_tree, false),
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ];
        accounts.extend(
            self.input_trees
                .iter()
                .map(|input_tree| AccountMeta::new(*input_tree, false)),
        );
        accounts.extend(transact_nullifier_pda_accounts(
            &self.input_trees,
            self.data.inputs.iter(),
        )?);
        accounts.extend(
            self.owner_signers
                .iter()
                .copied()
                .map(|signer| AccountMeta::new_readonly(signer, true)),
        );
        accounts.extend(
            signer_pdas
                .iter()
                .copied()
                .map(|pda| AccountMeta::new_readonly(pda, false)),
        );
        append_interface_transfer_accounts(
            &mut accounts,
            &self.data.interface_transfers,
            &self.interface_transfer_accounts,
        )?;
        Ok(accounts)
    }

    pub fn instruction_with_cache_read(
        &self,
        cache: Pubkey,
    ) -> Result<Instruction, TransactBuildError> {
        let mut instruction = self.instruction()?;
        append_cache_accounts(&mut instruction.accounts, Some(cache), None);
        Ok(instruction)
    }

    pub fn instruction_with_cache_write(
        &self,
        cache: Pubkey,
        writer: Pubkey,
    ) -> Result<Instruction, TransactBuildError> {
        let mut instruction = self.instruction()?;
        append_cache_accounts(&mut instruction.accounts, None, Some((cache, writer)));
        Ok(instruction)
    }

    pub fn instruction_with_caches(
        &self,
        read_cache: Pubkey,
        write_cache: Pubkey,
        writer: Pubkey,
    ) -> Result<Instruction, TransactBuildError> {
        let mut instruction = self.instruction()?;
        append_cache_accounts(
            &mut instruction.accounts,
            Some(read_cache),
            Some((write_cache, writer)),
        );
        Ok(instruction)
    }
}

pub(super) fn append_cache_accounts(
    accounts: &mut Vec<AccountMeta>,
    read_cache: Option<Pubkey>,
    write_cache: Option<(Pubkey, Pubkey)>,
) {
    if let Some(read_cache) = read_cache {
        accounts.push(AccountMeta::new_readonly(read_cache, false));
    }
    if let Some((write_cache, writer)) = write_cache {
        accounts.extend([
            AccountMeta::new(write_cache, false),
            AccountMeta::new_readonly(writer, true),
        ]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spr_interface::instruction::instruction_data::transact::{
        CircuitId, InputUtxo, TransactProof, TreeContext,
    };

    fn empty_data(interface_transfers: Vec<InterfaceTransfer>) -> TransactIxData {
        TransactIxData {
            proof: TransactProof::zeroed(),
            expiry_unix_ts: u64::MAX,
            private_tx_hash: [0u8; 32],
            circuit: CircuitId::ConfidentialSigner(0, 0, 3),
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            inputs: Vec::new(),
            interface_transfers,
            data_hash: None,
            ring_data_hash: None,
            outputs: Vec::new(),
            messages: Vec::new(),
            tree_contexts: vec![TreeContext {
                utxo_tree_root_index: 0,
                nullifier_tree_root_index: 0,
            }],
        }
    }

    #[test]
    fn single_sol_withdrawal_preserves_account_indices() {
        let recipient = Pubkey::new_unique();
        let owner_signer = Pubkey::new_unique();
        let input_tree = Pubkey::new_unique();
        let builder = Transact {
            payer: Pubkey::new_unique(),
            input_trees: vec![input_tree],
            output_tree: Pubkey::new_unique(),
            owner_signers: vec![owner_signer],
            interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient },
            )],
            data: empty_data(vec![InterfaceTransfer::SolWithdrawal { amount: 7 }]),
        };

        let ix = builder.instruction().unwrap();
        let keys: Vec<_> = ix.accounts.iter().map(|account| account.pubkey).collect();
        assert_eq!(
            keys,
            vec![
                builder.payer,
                builder.output_tree,
                PROGRAM_ID_PUBKEY,
                Pubkey::default(),
                input_tree,
                owner_signer,
                SOL_INTERFACE_PUBKEY,
                recipient,
            ]
        );
        assert!(ix.accounts[5].is_signer);
        assert!(!ix.accounts[7].is_signer);
    }

    #[test]
    fn single_spl_withdrawal_preserves_account_indices() {
        let input_tree = Pubkey::new_unique();
        let spl = TransactSplWithdrawalAccounts {
            mint: Pubkey::new_unique(),
            spl_interface: Pubkey::new_unique(),
            user_token_account: Pubkey::new_unique(),
            token_program: Pubkey::new_unique(),
        };
        let builder = Transact {
            payer: Pubkey::new_unique(),
            input_trees: vec![input_tree],
            output_tree: Pubkey::new_unique(),
            owner_signers: Vec::new(),
            interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::SplWithdrawal(
                spl,
            )],
            data: empty_data(vec![InterfaceTransfer::SplWithdrawal {
                amount: 7,
                spl_interface_bump: 42,
            }]),
        };

        let ix = builder.instruction().unwrap();
        let keys: Vec<_> = ix.accounts.iter().map(|account| account.pubkey).collect();
        assert_eq!(
            keys,
            vec![
                builder.payer,
                builder.output_tree,
                PROGRAM_ID_PUBKEY,
                Pubkey::default(),
                input_tree,
                SHIELDED_POOL_CPI_AUTHORITY_PUBKEY,
                spl.mint,
                spl.spl_interface,
                spl.user_token_account,
                spl.token_program,
            ]
        );
    }

    #[test]
    fn ordered_mixed_transfers_share_one_system_program() {
        let input_tree = Pubkey::new_unique();
        let sol_depositor = Pubkey::new_unique();
        let spl = TransactSplWithdrawalAccounts {
            mint: Pubkey::new_unique(),
            spl_interface: Pubkey::new_unique(),
            user_token_account: Pubkey::new_unique(),
            token_program: Pubkey::new_unique(),
        };
        let sol_recipient = Pubkey::new_unique();
        let builder = Transact {
            payer: Pubkey::new_unique(),
            input_trees: vec![input_tree],
            output_tree: Pubkey::new_unique(),
            owner_signers: Vec::new(),
            interface_transfer_accounts: vec![
                TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                    recipient: sol_depositor,
                }),
                TransactInterfaceTransferAccounts::SplWithdrawal(spl),
                TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                    recipient: sol_recipient,
                }),
            ],
            data: empty_data(vec![
                InterfaceTransfer::SolDeposit { amount: 3 },
                InterfaceTransfer::SplWithdrawal {
                    amount: 5,
                    spl_interface_bump: 42,
                },
                InterfaceTransfer::SolWithdrawal { amount: 2 },
            ]),
        };

        let ix = builder.instruction().unwrap();
        let keys: Vec<_> = ix.accounts.iter().map(|account| account.pubkey).collect();
        assert_eq!(
            keys,
            vec![
                builder.payer,
                builder.output_tree,
                PROGRAM_ID_PUBKEY,
                Pubkey::default(),
                input_tree,
                SOL_INTERFACE_PUBKEY,
                sol_depositor,
                SHIELDED_POOL_CPI_AUTHORITY_PUBKEY,
                spl.mint,
                spl.spl_interface,
                spl.user_token_account,
                spl.token_program,
                SOL_INTERFACE_PUBKEY,
                sol_recipient,
            ]
        );
        assert!(ix.accounts[6].is_signer);
        assert!(!ix.accounts[10].is_signer);
        assert!(!ix.accounts[13].is_signer);
    }

    #[test]
    fn spl_deposit_omits_cpi_authority_and_marks_depositor_signer() {
        let input_tree = Pubkey::new_unique();
        let spl = TransactSplDepositAccounts {
            mint: Pubkey::new_unique(),
            spl_interface: Pubkey::new_unique(),
            token_authority: Pubkey::new_unique(),
            user_token_account: Pubkey::new_unique(),
            token_program: Pubkey::new_unique(),
        };
        let builder = Transact {
            payer: Pubkey::new_unique(),
            input_trees: vec![input_tree],
            output_tree: Pubkey::new_unique(),
            owner_signers: Vec::new(),
            interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::SplDeposit(spl)],
            data: empty_data(vec![InterfaceTransfer::SplDeposit {
                amount: 7,
                spl_interface_bump: 42,
            }]),
        };

        let ix = builder.instruction().unwrap();
        assert_eq!(ix.accounts[5].pubkey, spl.mint);
        assert_eq!(ix.accounts[6].pubkey, spl.spl_interface);
        assert_eq!(ix.accounts[7].pubkey, spl.token_authority);
        assert!(ix.accounts[7].is_signer);
    }

    #[test]
    fn nullifier_pdas_follow_input_trees_and_precede_owner_signers() {
        let recipient = Pubkey::new_unique();
        let owner_signer = Pubkey::new_unique();
        let input_tree = Pubkey::new_unique();
        let nullifiers = [[11u8; 32], [22u8; 32]];
        let mut data = empty_data(vec![InterfaceTransfer::SolWithdrawal { amount: 7 }]);
        data.inputs = nullifiers
            .iter()
            .map(|nullifier_hash| InputUtxo {
                nullifier_hash: *nullifier_hash,
                tree_index: 0,
            })
            .collect();
        let builder = Transact {
            payer: Pubkey::new_unique(),
            input_trees: vec![input_tree],
            output_tree: Pubkey::new_unique(),
            owner_signers: vec![owner_signer],
            interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient },
            )],
            data,
        };

        let ix = builder.instruction().unwrap();
        let nullifier_pda = |nullifier: &[u8; 32]| pda::nullifier_pda(&input_tree, nullifier).0;
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new(builder.payer, true),
                AccountMeta::new(builder.output_tree, false),
                AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new(input_tree, false),
                AccountMeta::new(nullifier_pda(&nullifiers[0]), false),
                AccountMeta::new(nullifier_pda(&nullifiers[1]), false),
                AccountMeta::new_readonly(owner_signer, true),
                AccountMeta::new(SOL_INTERFACE_PUBKEY, false),
                AccountMeta::new(recipient, false),
            ]
        );
        assert_eq!(ix.accounts.len(), 5 + nullifiers.len() + 1 + 2);
    }

    #[test]
    fn rejects_transfer_account_count_mismatch() {
        let error = Transact {
            payer: Pubkey::new_unique(),
            input_trees: vec![Pubkey::new_unique()],
            output_tree: Pubkey::new_unique(),
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            data: empty_data(vec![InterfaceTransfer::SolWithdrawal { amount: 1 }]),
        }
        .instruction()
        .unwrap_err();
        assert_eq!(
            error,
            TransactBuildError::InterfaceTransferAccountCountMismatch {
                transfers: 1,
                account_groups: 0,
            }
        );
    }

    #[test]
    fn rejects_transfer_account_tag_mismatch() {
        let error = Transact {
            payer: Pubkey::new_unique(),
            input_trees: vec![Pubkey::new_unique()],
            output_tree: Pubkey::new_unique(),
            owner_signers: Vec::new(),
            interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts {
                    recipient: Pubkey::new_unique(),
                },
            )],
            data: empty_data(vec![InterfaceTransfer::SplWithdrawal {
                amount: 1,
                spl_interface_bump: 42,
            }]),
        }
        .instruction()
        .unwrap_err();
        assert_eq!(
            error,
            TransactBuildError::InterfaceTransferAccountMismatch { index: 0 }
        );
    }

    fn sol_withdrawals(amounts: &[u64]) -> Transact {
        Transact {
            payer: Pubkey::new_unique(),
            input_trees: vec![Pubkey::new_unique()],
            output_tree: Pubkey::new_unique(),
            owner_signers: Vec::new(),
            interface_transfer_accounts: amounts
                .iter()
                .map(|_| {
                    TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                        recipient: Pubkey::new_unique(),
                    })
                })
                .collect(),
            data: empty_data(
                amounts
                    .iter()
                    .map(|&amount| InterfaceTransfer::SolWithdrawal { amount })
                    .collect(),
            ),
        }
    }

    /// The instruction serializer rejects more than `MAX_INTERFACE_TRANSFERS`;
    /// the builder returns it as a typed error.
    #[test]
    fn rejects_too_many_interface_transfers() {
        let builder = sol_withdrawals(&[1; MAX_INTERFACE_TRANSFERS + 1]);
        assert_eq!(
            builder.instruction().unwrap_err(),
            TransactBuildError::TooManyInterfaceTransfers {
                count: MAX_INTERFACE_TRANSFERS + 1,
                max: MAX_INTERFACE_TRANSFERS,
            }
        );
        assert!(builder.cpi_accounts(&[]).is_err());
    }

    /// The instruction serializer rejects a zero-amount interface transfer;
    /// the builder returns it as a typed error.
    #[test]
    fn rejects_zero_amount_interface_transfer() {
        assert_eq!(
            sol_withdrawals(&[3, 0]).instruction().unwrap_err(),
            TransactBuildError::ZeroInterfaceTransferAmount { index: 1 }
        );
    }

    #[test]
    fn rejects_input_tree_index_outside_declared_trees() {
        let mut builder = builder_without_transfers();
        builder.data.inputs = vec![InputUtxo {
            nullifier_hash: [9u8; 32],
            tree_index: 1,
        }];
        assert_eq!(
            builder.instruction().unwrap_err(),
            TransactBuildError::InputTreeIndexOutOfRange {
                input: 0,
                tree_index: 1,
                input_trees: 1,
            }
        );
    }

    fn builder_without_transfers() -> Transact {
        Transact {
            payer: Pubkey::new_unique(),
            input_trees: vec![Pubkey::new_unique()],
            output_tree: Pubkey::new_unique(),
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            data: empty_data(Vec::new()),
        }
    }

    #[test]
    fn cache_write_appends_writable_cache_then_signing_writer() {
        let builder = builder_without_transfers();
        let cache = Pubkey::new_unique();
        let writer = Pubkey::new_unique();
        let mut expected = builder.instruction().unwrap().accounts;
        expected.push(AccountMeta::new(cache, false));
        expected.push(AccountMeta::new_readonly(writer, true));
        assert_eq!(
            builder
                .instruction_with_cache_write(cache, writer)
                .unwrap()
                .accounts,
            expected
        );
    }

    #[test]
    fn cache_read_appends_read_only_cache() {
        let builder = builder_without_transfers();
        let cache = Pubkey::new_unique();
        let mut expected = builder.instruction().unwrap().accounts;
        expected.push(AccountMeta::new_readonly(cache, false));
        assert_eq!(
            builder.instruction_with_cache_read(cache).unwrap().accounts,
            expected
        );
    }

    #[test]
    fn caches_append_read_cache_then_write_cache_then_writer() {
        let builder = builder_without_transfers();
        let read_cache = Pubkey::new_unique();
        let write_cache = Pubkey::new_unique();
        let writer = Pubkey::new_unique();
        let mut expected = builder.instruction().unwrap().accounts;
        expected.push(AccountMeta::new_readonly(read_cache, false));
        expected.push(AccountMeta::new(write_cache, false));
        expected.push(AccountMeta::new_readonly(writer, true));
        assert_eq!(
            builder
                .instruction_with_caches(read_cache, write_cache, writer)
                .unwrap()
                .accounts,
            expected
        );
    }
}
