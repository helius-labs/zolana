use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, PublicLeg, TransactIxData},
    MAX_WIRE_PUBLIC_LEGS, PROGRAM_ID_PUBKEY, SHIELDED_POOL_CPI_AUTHORITY_PUBKEY,
    SOL_INTERFACE_PUBKEY,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactSolLeg {
    pub recipient: Pubkey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactSplLeg {
    pub vault: Pubkey,
    pub recipient: Pubkey,
    pub user_token_account: Pubkey,
    pub token_program: Pubkey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactLegAccounts {
    Sol(TransactSolLeg),
    Spl(TransactSplLeg),
}

/// Builder for the `transact` instruction. The account layout mirrors the
/// program loader (`TransactAccounts::validate_and_parse`): `payer`, `tree`, the
/// ordered public-leg account groups, and the program account last for the
/// `emit_event` self-CPI.
pub struct Transact {
    pub payer: Pubkey,
    pub tree: Pubkey,
    pub legs: Vec<TransactLegAccounts>,
    pub data: TransactIxData,
}

pub(super) fn append_public_leg_accounts(
    accounts: &mut Vec<AccountMeta>,
    public_legs: &[PublicLeg],
    leg_accounts: &[TransactLegAccounts],
) {
    assert!(
        public_legs.len() <= MAX_WIRE_PUBLIC_LEGS,
        "public settlement leg count exceeds the u8 wire encoding"
    );
    assert_eq!(
        public_legs.len(),
        leg_accounts.len(),
        "public legs and settlement account groups must have equal lengths"
    );

    let mut has_sol = false;
    for (leg, leg_accounts) in public_legs.iter().zip(leg_accounts) {
        match (leg, leg_accounts) {
            (PublicLeg::Sol { is_deposit, .. }, TransactLegAccounts::Sol(sol)) => {
                has_sol = true;
                accounts.push(AccountMeta::new(SOL_INTERFACE_PUBKEY, false));
                accounts.push(AccountMeta::new(sol.recipient, *is_deposit));
            }
            (PublicLeg::Spl { is_deposit, .. }, TransactLegAccounts::Spl(spl)) => {
                if !*is_deposit {
                    accounts.push(AccountMeta::new_readonly(
                        SHIELDED_POOL_CPI_AUTHORITY_PUBKEY,
                        false,
                    ));
                }
                accounts.push(AccountMeta::new(spl.vault, false));
                accounts.push(AccountMeta::new(spl.recipient, *is_deposit));
                accounts.push(AccountMeta::new(spl.user_token_account, false));
                accounts.push(AccountMeta::new_readonly(spl.token_program, false));
            }
            (PublicLeg::Sol { .. }, TransactLegAccounts::Spl(_))
            | (PublicLeg::Spl { .. }, TransactLegAccounts::Sol(_)) => {
                panic!("public leg type must match its settlement account group");
            }
        }
    }

    if has_sol {
        accounts.push(AccountMeta::new_readonly(Pubkey::default(), false));
    }
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
            AccountMeta::new(self.tree, false),
        ];
        append_public_leg_accounts(&mut accounts, &self.data.public_legs, &self.legs);
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

    fn empty_data(public_legs: Vec<PublicLeg>) -> TransactIxData {
        TransactIxData {
            proof: TransactProof::zeroed_eddsa(),
            expiry_unix_ts: u64::MAX,
            private_tx_hash: [0u8; 32],
            circuit: CircuitId::ConfidentialEddsa,
            p256_signing_pk_x: None,
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            inputs: Vec::new(),
            public_legs,
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
            tree: Pubkey::new_unique(),
            legs: vec![TransactLegAccounts::Sol(TransactSolLeg { recipient })],
            data: empty_data(vec![PublicLeg::Sol {
                is_deposit: false,
                amount: 7,
            }]),
        };

        let ix = builder.instruction();
        let keys: Vec<_> = ix.accounts.iter().map(|account| account.pubkey).collect();
        assert_eq!(
            keys,
            vec![
                builder.payer,
                builder.tree,
                SOL_INTERFACE_PUBKEY,
                recipient,
                Pubkey::default(),
                PROGRAM_ID_PUBKEY,
            ]
        );
        assert!(!ix.accounts[3].is_signer);
    }

    #[test]
    fn single_spl_withdrawal_preserves_account_indices() {
        let spl = TransactSplLeg {
            vault: Pubkey::new_unique(),
            recipient: Pubkey::new_unique(),
            user_token_account: Pubkey::new_unique(),
            token_program: Pubkey::new_unique(),
        };
        let builder = Transact {
            payer: Pubkey::new_unique(),
            tree: Pubkey::new_unique(),
            legs: vec![TransactLegAccounts::Spl(spl)],
            data: empty_data(vec![PublicLeg::Spl {
                is_deposit: false,
                amount: 7,
            }]),
        };

        let ix = builder.instruction();
        let keys: Vec<_> = ix.accounts.iter().map(|account| account.pubkey).collect();
        assert_eq!(
            keys,
            vec![
                builder.payer,
                builder.tree,
                SHIELDED_POOL_CPI_AUTHORITY_PUBKEY,
                spl.vault,
                spl.recipient,
                spl.user_token_account,
                spl.token_program,
                PROGRAM_ID_PUBKEY,
            ]
        );
    }

    #[test]
    fn ordered_mixed_legs_share_one_system_program() {
        let sol_depositor = Pubkey::new_unique();
        let spl = TransactSplLeg {
            vault: Pubkey::new_unique(),
            recipient: Pubkey::new_unique(),
            user_token_account: Pubkey::new_unique(),
            token_program: Pubkey::new_unique(),
        };
        let sol_recipient = Pubkey::new_unique();
        let builder = Transact {
            payer: Pubkey::new_unique(),
            tree: Pubkey::new_unique(),
            legs: vec![
                TransactLegAccounts::Sol(TransactSolLeg {
                    recipient: sol_depositor,
                }),
                TransactLegAccounts::Spl(spl),
                TransactLegAccounts::Sol(TransactSolLeg {
                    recipient: sol_recipient,
                }),
            ],
            data: empty_data(vec![
                PublicLeg::Sol {
                    is_deposit: true,
                    amount: 3,
                },
                PublicLeg::Spl {
                    is_deposit: false,
                    amount: 5,
                },
                PublicLeg::Sol {
                    is_deposit: false,
                    amount: 2,
                },
            ]),
        };

        let ix = builder.instruction();
        let keys: Vec<_> = ix.accounts.iter().map(|account| account.pubkey).collect();
        assert_eq!(
            keys,
            vec![
                builder.payer,
                builder.tree,
                SOL_INTERFACE_PUBKEY,
                sol_depositor,
                SHIELDED_POOL_CPI_AUTHORITY_PUBKEY,
                spl.vault,
                spl.recipient,
                spl.user_token_account,
                spl.token_program,
                SOL_INTERFACE_PUBKEY,
                sol_recipient,
                Pubkey::default(),
                PROGRAM_ID_PUBKEY,
            ]
        );
        assert!(ix.accounts[3].is_signer);
        assert!(!ix.accounts[6].is_signer);
        assert!(!ix.accounts[10].is_signer);
    }

    #[test]
    fn spl_deposit_omits_cpi_authority_and_marks_recipient_signer() {
        let spl = TransactSplLeg {
            vault: Pubkey::new_unique(),
            recipient: Pubkey::new_unique(),
            user_token_account: Pubkey::new_unique(),
            token_program: Pubkey::new_unique(),
        };
        let builder = Transact {
            payer: Pubkey::new_unique(),
            tree: Pubkey::new_unique(),
            legs: vec![TransactLegAccounts::Spl(spl)],
            data: empty_data(vec![PublicLeg::Spl {
                is_deposit: true,
                amount: 7,
            }]),
        };

        let ix = builder.instruction();
        assert_eq!(ix.accounts[2].pubkey, spl.vault);
        assert_eq!(ix.accounts[3].pubkey, spl.recipient);
        assert!(ix.accounts[3].is_signer);
    }

    #[test]
    #[should_panic(expected = "equal lengths")]
    fn rejects_leg_account_count_mismatch() {
        Transact {
            payer: Pubkey::new_unique(),
            tree: Pubkey::new_unique(),
            legs: Vec::new(),
            data: empty_data(vec![PublicLeg::Sol {
                is_deposit: false,
                amount: 1,
            }]),
        }
        .instruction();
    }

    #[test]
    #[should_panic(expected = "public leg type")]
    fn rejects_leg_account_tag_mismatch() {
        Transact {
            payer: Pubkey::new_unique(),
            tree: Pubkey::new_unique(),
            legs: vec![TransactLegAccounts::Sol(TransactSolLeg {
                recipient: Pubkey::new_unique(),
            })],
            data: empty_data(vec![PublicLeg::Spl {
                is_deposit: false,
                amount: 1,
            }]),
        }
        .instruction();
    }
}
