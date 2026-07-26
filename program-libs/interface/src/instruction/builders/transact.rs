use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, InterfaceTransfer, TransactIxData},
    MAX_INTERFACE_TRANSFERS, PROGRAM_ID_PUBKEY, SHIELDED_POOL_CPI_AUTHORITY_PUBKEY,
    SOL_INTERFACE_PUBKEY,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactSolTransferAccounts {
    pub recipient: Pubkey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactSplDepositAccounts {
    pub mint: Pubkey,
    pub vault: Pubkey,
    pub depositor: Pubkey,
    pub user_token_account: Pubkey,
    pub token_program: Pubkey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactSplWithdrawalAccounts {
    pub mint: Pubkey,
    pub vault: Pubkey,
    pub user_token_account: Pubkey,
    pub token_program: Pubkey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactInterfaceTransferAccounts {
    Sol(TransactSolTransferAccounts),
    SplDeposit(TransactSplDepositAccounts),
    SplWithdrawal(TransactSplWithdrawalAccounts),
}

/// Builder for the `transact` instruction. The account layout mirrors the
/// program loader (`TransactAccounts::validate_and_parse`): `payer`,
/// `input_tree`, `output_tree`, the ordered interface-transfer account groups, and the
/// program account last for the `emit_event` self-CPI.
pub struct Transact {
    pub payer: Pubkey,
    pub input_tree: Pubkey,
    pub output_tree: Pubkey,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub data: TransactIxData,
}

pub(super) fn append_interface_transfer_accounts(
    accounts: &mut Vec<AccountMeta>,
    interface_transfers: &[InterfaceTransfer],
    transfer_accounts: &[TransactInterfaceTransferAccounts],
) {
    assert!(
        interface_transfers.len() <= MAX_INTERFACE_TRANSFERS,
        "interface transfer count exceeds the u8 wire encoding"
    );
    assert_eq!(
        interface_transfers.len(),
        transfer_accounts.len(),
        "interface transfers and settlement account groups must have equal lengths"
    );

    for (transfer, transfer_accounts) in interface_transfers.iter().zip(transfer_accounts) {
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
                accounts.push(AccountMeta::new(spl.vault, false));
                accounts.push(AccountMeta::new_readonly(spl.depositor, true));
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
                accounts.push(AccountMeta::new(spl.vault, false));
                accounts.push(AccountMeta::new(spl.user_token_account, false));
                accounts.push(AccountMeta::new_readonly(spl.token_program, false));
            }
            _ => {
                panic!("interface transfer type must match its settlement account group");
            }
        }
    }

    // Required for the forester-fee collection CPI and, when present, native
    // SOL public settlement.
    accounts.push(AccountMeta::new_readonly(Pubkey::default(), false));
}

impl Transact {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::TRANSACT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("shielded-pool instruction serialization is infallible"),
        );

        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new(self.input_tree, false),
            AccountMeta::new(self.output_tree, false),
        ];
        append_interface_transfer_accounts(
            &mut accounts,
            &self.data.interface_transfers,
            &self.interface_transfer_accounts,
        );
        accounts.push(AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false));

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::instruction_data::transact::{CircuitId, TransactProof};

    fn empty_data(interface_transfers: Vec<InterfaceTransfer>) -> TransactIxData {
        TransactIxData {
            proof: TransactProof::zeroed_eddsa(),
            expiry_unix_ts: u64::MAX,
            private_tx_hash: [0u8; 32],
            circuit: CircuitId::ConfidentialEddsa(0, 0, 3),
            p256_signing_pk_x: None,
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            inputs: Vec::new(),
            interface_transfers,
            data_hash: None,
            zone_data_hash: None,
            outputs: Vec::new(),
            messages: Vec::new(),
        }
    }

    #[test]
    fn single_sol_withdrawal_preserves_account_indices() {
        let recipient = Pubkey::new_unique();
        let builder = Transact {
            payer: Pubkey::new_unique(),
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient },
            )],
            data: empty_data(vec![InterfaceTransfer::SolWithdrawal { amount: 7 }]),
        };

        let ix = builder.instruction();
        let keys: Vec<_> = ix.accounts.iter().map(|account| account.pubkey).collect();
        assert_eq!(
            keys,
            vec![
                builder.payer,
                builder.input_tree,
                builder.output_tree,
                SOL_INTERFACE_PUBKEY,
                recipient,
                Pubkey::default(),
                PROGRAM_ID_PUBKEY,
            ]
        );
        assert!(!ix.accounts[4].is_signer);
    }

    #[test]
    fn single_spl_withdrawal_preserves_account_indices() {
        let spl = TransactSplWithdrawalAccounts {
            mint: Pubkey::new_unique(),
            vault: Pubkey::new_unique(),
            user_token_account: Pubkey::new_unique(),
            token_program: Pubkey::new_unique(),
        };
        let builder = Transact {
            payer: Pubkey::new_unique(),
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::SplWithdrawal(
                spl,
            )],
            data: empty_data(vec![InterfaceTransfer::SplWithdrawal {
                amount: 7,
                vault_bump: 42,
            }]),
        };

        let ix = builder.instruction();
        let keys: Vec<_> = ix.accounts.iter().map(|account| account.pubkey).collect();
        assert_eq!(
            keys,
            vec![
                builder.payer,
                builder.input_tree,
                builder.output_tree,
                SHIELDED_POOL_CPI_AUTHORITY_PUBKEY,
                spl.mint,
                spl.vault,
                spl.user_token_account,
                spl.token_program,
                Pubkey::default(),
                PROGRAM_ID_PUBKEY,
            ]
        );
    }

    #[test]
    fn ordered_mixed_transfers_share_one_system_program() {
        let sol_depositor = Pubkey::new_unique();
        let spl = TransactSplWithdrawalAccounts {
            mint: Pubkey::new_unique(),
            vault: Pubkey::new_unique(),
            user_token_account: Pubkey::new_unique(),
            token_program: Pubkey::new_unique(),
        };
        let sol_recipient = Pubkey::new_unique();
        let builder = Transact {
            payer: Pubkey::new_unique(),
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
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
                    vault_bump: 42,
                },
                InterfaceTransfer::SolWithdrawal { amount: 2 },
            ]),
        };

        let ix = builder.instruction();
        let keys: Vec<_> = ix.accounts.iter().map(|account| account.pubkey).collect();
        assert_eq!(
            keys,
            vec![
                builder.payer,
                builder.input_tree,
                builder.output_tree,
                SOL_INTERFACE_PUBKEY,
                sol_depositor,
                SHIELDED_POOL_CPI_AUTHORITY_PUBKEY,
                spl.mint,
                spl.vault,
                spl.user_token_account,
                spl.token_program,
                SOL_INTERFACE_PUBKEY,
                sol_recipient,
                Pubkey::default(),
                PROGRAM_ID_PUBKEY,
            ]
        );
        assert!(ix.accounts[4].is_signer);
        assert!(!ix.accounts[8].is_signer);
        assert!(!ix.accounts[11].is_signer);
    }

    #[test]
    fn spl_deposit_omits_cpi_authority_and_marks_depositor_signer() {
        let spl = TransactSplDepositAccounts {
            mint: Pubkey::new_unique(),
            vault: Pubkey::new_unique(),
            depositor: Pubkey::new_unique(),
            user_token_account: Pubkey::new_unique(),
            token_program: Pubkey::new_unique(),
        };
        let builder = Transact {
            payer: Pubkey::new_unique(),
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::SplDeposit(spl)],
            data: empty_data(vec![InterfaceTransfer::SplDeposit {
                amount: 7,
                vault_bump: 42,
            }]),
        };

        let ix = builder.instruction();
        assert_eq!(ix.accounts[3].pubkey, spl.mint);
        assert_eq!(ix.accounts[4].pubkey, spl.vault);
        assert_eq!(ix.accounts[5].pubkey, spl.depositor);
        assert!(ix.accounts[5].is_signer);
    }

    #[test]
    #[should_panic(expected = "equal lengths")]
    fn rejects_transfer_account_count_mismatch() {
        Transact {
            payer: Pubkey::new_unique(),
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            interface_transfer_accounts: Vec::new(),
            data: empty_data(vec![InterfaceTransfer::SolWithdrawal { amount: 1 }]),
        }
        .instruction();
    }

    #[test]
    #[should_panic(expected = "interface transfer type")]
    fn rejects_transfer_account_tag_mismatch() {
        Transact {
            payer: Pubkey::new_unique(),
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts {
                    recipient: Pubkey::new_unique(),
                },
            )],
            data: empty_data(vec![InterfaceTransfer::SplWithdrawal {
                amount: 1,
                vault_bump: 42,
            }]),
        }
        .instruction();
    }
}
