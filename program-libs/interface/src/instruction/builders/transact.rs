use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, InterfaceTransfer, TransactIxData},
    pda, MAX_INTERFACE_TRANSFERS, PROGRAM_ID_PUBKEY, SHIELDED_POOL_CPI_AUTHORITY_PUBKEY,
    SOL_INTERFACE_PUBKEY,
};

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

/// Builder for the `transact` instruction. The account layout mirrors the
/// program loader (`TransactAccounts::validate_and_parse`): `payer`,
/// `input_tree`, `output_tree`, the SPP and System Program accounts, one
/// writable nullifier PDA per input (in `inputs` order), owner signers, then
/// the ordered interface-transfer account groups.
///
/// # Compute budget
///
/// **No proof-bearing shape fits the 200,000 CU per-instruction default.** The
/// caller must prepend a `ComputeBudgetInstruction::set_compute_unit_limit`;
/// this builder deliberately returns only the transact instruction, so the
/// returned account and instruction list is exactly what the program consumes.
/// The same holds for [`super::merge_transact::MergeTransact`], whose rustdoc
/// carries the per-shape merge figures.
///
/// The Groth16 pairing is shape-independent; everything above it scales with
/// the input count, because each input costs a queue insertion plus a nullifier
/// PDA creation (whose canonical bump search makes the cost a range, not a
/// point). Measured at the wide consolidation shape: `transact` 36x2 consumes
/// about 452,000 CU and serializes to 3,281 transaction v1 bytes (validator,
/// 2026-09).
pub struct Transact {
    pub payer: Pubkey,
    pub input_tree: Pubkey,
    pub output_tree: Pubkey,
    pub owner_signers: Vec<Pubkey>,
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
        "interface transfer count exceeds the protocol maximum"
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
            _ => {
                panic!("interface transfer type must match its settlement account group");
            }
        }
    }
}

/// One writable nullifier-PDA account per nullifier, preserving input order.
pub fn nullifier_pda_accounts<'a>(
    input_tree: &Pubkey,
    nullifiers: impl IntoIterator<Item = &'a [u8; 32]>,
) -> Vec<AccountMeta> {
    nullifiers
        .into_iter()
        .map(|nullifier| AccountMeta::new(pda::nullifier_pda(input_tree, nullifier).0, false))
        .collect()
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
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ];
        accounts.extend(nullifier_pda_accounts(
            &self.input_tree,
            self.data
                .tail
                .inputs
                .iter()
                .map(|input| &input.nullifier_hash),
        ));
        accounts.extend(
            self.owner_signers
                .iter()
                .copied()
                .map(|signer| AccountMeta::new_readonly(signer, true)),
        );
        append_interface_transfer_accounts(
            &mut accounts,
            &self.data.bound.interface_transfers,
            &self.interface_transfer_accounts,
        );
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
    use crate::instruction::instruction_data::transact::{CircuitId, InputUtxo, TransactProof};
    use crate::instruction::{TransactIxBound, TransactIxTail};

    fn empty_data(interface_transfers: Vec<InterfaceTransfer>) -> TransactIxData {
        TransactIxData {
            bound: TransactIxBound {
                expiry_unix_ts: u64::MAX,
                tx_viewing_pk: [0u8; 33],
                salt: [0u8; 16],
                interface_transfers,
                outputs: Vec::new(),
                messages: Vec::new(),
            },
            tail: TransactIxTail {
                proof: TransactProof::zeroed(),
                private_tx_hash: [0u8; 32],
                circuit: CircuitId::ConfidentialEddsa(0, 0, 3),
                inputs: Vec::new(),
                data_hash: None,
                ring_data_hash: None,
            },
        }
    }

    #[test]
    fn single_sol_withdrawal_preserves_account_indices() {
        let recipient = Pubkey::new_unique();
        let owner_signer = Pubkey::new_unique();
        let builder = Transact {
            payer: Pubkey::new_unique(),
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            owner_signers: vec![owner_signer],
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
                PROGRAM_ID_PUBKEY,
                Pubkey::default(),
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
        let spl = TransactSplWithdrawalAccounts {
            mint: Pubkey::new_unique(),
            spl_interface: Pubkey::new_unique(),
            user_token_account: Pubkey::new_unique(),
            token_program: Pubkey::new_unique(),
        };
        let builder = Transact {
            payer: Pubkey::new_unique(),
            input_tree: Pubkey::new_unique(),
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

        let ix = builder.instruction();
        let keys: Vec<_> = ix.accounts.iter().map(|account| account.pubkey).collect();
        assert_eq!(
            keys,
            vec![
                builder.payer,
                builder.input_tree,
                builder.output_tree,
                PROGRAM_ID_PUBKEY,
                Pubkey::default(),
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
            input_tree: Pubkey::new_unique(),
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

        let ix = builder.instruction();
        let keys: Vec<_> = ix.accounts.iter().map(|account| account.pubkey).collect();
        assert_eq!(
            keys,
            vec![
                builder.payer,
                builder.input_tree,
                builder.output_tree,
                PROGRAM_ID_PUBKEY,
                Pubkey::default(),
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
        let spl = TransactSplDepositAccounts {
            mint: Pubkey::new_unique(),
            spl_interface: Pubkey::new_unique(),
            token_authority: Pubkey::new_unique(),
            user_token_account: Pubkey::new_unique(),
            token_program: Pubkey::new_unique(),
        };
        let builder = Transact {
            payer: Pubkey::new_unique(),
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            owner_signers: Vec::new(),
            interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::SplDeposit(spl)],
            data: empty_data(vec![InterfaceTransfer::SplDeposit {
                amount: 7,
                spl_interface_bump: 42,
            }]),
        };

        let ix = builder.instruction();
        assert_eq!(ix.accounts[5].pubkey, spl.mint);
        assert_eq!(ix.accounts[6].pubkey, spl.spl_interface);
        assert_eq!(ix.accounts[7].pubkey, spl.token_authority);
        assert!(ix.accounts[7].is_signer);
    }

    #[test]
    fn nullifier_pdas_follow_system_program_and_precede_owner_signers() {
        let recipient = Pubkey::new_unique();
        let owner_signer = Pubkey::new_unique();
        let input_tree = Pubkey::new_unique();
        let nullifiers = [[11u8; 32], [22u8; 32]];
        let mut data = empty_data(vec![InterfaceTransfer::SolWithdrawal { amount: 7 }]);
        data.tail.inputs = nullifiers
            .iter()
            .map(|nullifier_hash| InputUtxo {
                nullifier_hash: *nullifier_hash,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: 0,
            })
            .collect();
        let builder = Transact {
            payer: Pubkey::new_unique(),
            input_tree,
            output_tree: Pubkey::new_unique(),
            owner_signers: vec![owner_signer],
            interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient },
            )],
            data,
        };

        let ix = builder.instruction();
        let nullifier_pda = |nullifier: &[u8; 32]| pda::nullifier_pda(&input_tree, nullifier).0;
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new(builder.payer, true),
                AccountMeta::new(input_tree, false),
                AccountMeta::new(builder.output_tree, false),
                AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
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
    #[should_panic(expected = "equal lengths")]
    fn rejects_transfer_account_count_mismatch() {
        Transact {
            payer: Pubkey::new_unique(),
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            owner_signers: Vec::new(),
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
        .instruction();
    }
}
