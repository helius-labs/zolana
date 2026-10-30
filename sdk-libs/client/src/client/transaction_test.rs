use std::collections::HashMap;

use solana_account::Account;
use solana_program_pack::Pack;
use spl_token_2022_interface::state::AccountState;
use spr_interface::instruction::instruction_data::transact::{CircuitId, TransactProof};
use spr_transaction::{utxo::SppProofInputUtxo, ExternalData, SppProofOutputUtxo};

use super::*;

#[test]
fn a_proved_merge_builds_messages_for_different_fee_payers() {
    use spr_interface::instruction::instruction_data::merge_transact::{
        MergeOutputEncryption, MergeProof, MergeTransactIxData,
    };
    let proved = super::super::ProvedMerge {
        input_tree_id: 2,
        output_tree_id: 3,
        user_record: Address::new_unique(),
        data: MergeTransactIxData {
            expiry_unix_ts: 42,
            proof: MergeProof::zeroed(),
            output_utxo_hash: [1; 32],
            output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                salt: [0; 16],
                ciphertext: [[0; 32]; 3],
            },
            private_tx_hash: [2; 32],
            nullifiers: vec![[3; 32]],
            utxo_tree_root_index: 1,
            nullifier_tree_root_index: 2,
            cache_slot: None,
        },
        output_hash: [1; 32],
    };
    let expected_data = proved.data.clone();
    let budget = ComputeBudgetConfig::new(super::super::MERGE_CU_LIMIT).with_priority_fee(100);
    for (payer, blockhash, height) in [
        (Address::new_unique(), Hash::new_from_array([1; 32]), 100),
        (Address::new_unique(), Hash::new_from_array([2; 32]), 200),
    ] {
        let unsigned = proved
            .build_solana_message(payer, blockhash, height, budget)
            .unwrap();
        assert_eq!(
            unsigned,
            UnsignedMessage {
                message: compile_message(&payer, &[proved.instruction(payer)], blockhash, budget)
                    .unwrap(),
                last_valid_block_height: height,
            }
        );
    }
    assert_eq!(proved.data, expected_data);
}

fn proved_transaction() -> ProvedTransaction {
    ProvedTransaction {
        payer: Address::new_unique(),
        input_tree_ids: vec![],
        output_tree_id: 7,
        read_cache: None,
        write_cache: None,
        owner_signers: vec![Address::new_unique()],
        settlement_transfers: vec![],
        instruction_data: TransactIxData {
            expiry_unix_ts: 42,
            tx_viewing_pk: [0; 33],
            salt: [0; 16],
            interface_transfers: vec![],
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![],
            messages: vec![],
            private_tx_hash: [1; 32],
            circuit: CircuitId::ConfidentialSigner(1, 2, 2),
            proof: TransactProof::zeroed(),
            inputs: vec![],
            tree_contexts: vec![],
        },
    }
}

#[test]
fn a_proved_transaction_rebuilds_its_message_without_changing_its_instruction() {
    let proved = proved_transaction();
    let instruction = proved.instruction().unwrap();
    let budget = ComputeBudgetConfig::new(320_000).with_priority_fee(1234);
    let first_hash = Hash::new_from_array([1; 32]);
    let next_hash = Hash::new_from_array([2; 32]);
    let first = proved.build_solana_message(first_hash, 90, budget).unwrap();
    let next = proved.build_solana_message(next_hash, 140, budget).unwrap();
    assert_eq!(
        first,
        UnsignedMessage {
            message: compile_message(
                &proved.payer,
                core::slice::from_ref(&instruction),
                first_hash,
                budget
            )
            .unwrap(),
            last_valid_block_height: 90,
        }
    );
    assert_eq!(
        next,
        UnsignedMessage {
            message: compile_message(
                &proved.payer,
                core::slice::from_ref(&instruction),
                next_hash,
                budget
            )
            .unwrap(),
            last_valid_block_height: 140,
        }
    );
    assert_ne!(first, next);
    assert_eq!(proved.instruction().unwrap(), instruction);
}

#[test]
fn cache_write_proofs_remain_available_for_custom_instruction_composition() {
    let mut proved = proved_transaction();
    proved.write_cache = Some(Address::new_unique());
    assert!(matches!(
        proved.instruction(),
        Err(ClientError::CacheWriteNeedsWriter)
    ));
    assert_eq!(proved.instruction_data().proof, TransactProof::zeroed());
}

fn settlement_request(transfers: Vec<SettlementTransfer>) -> TransactionProofRequest<'static> {
    let mut external_data = ExternalData::new([0; 33], [0; 16], vec![], vec![], vec![]);
    external_data.interface_transfers = transfers;
    TransactionProofRequest::new(
        SppProofInputs {
            input_utxos: vec![SppProofInputUtxo::dummy(0).unwrap()],
            output_utxos: vec![SppProofOutputUtxo::default(); 2],
            blinding_seed: [0; 32],
            output_tree_id: 0,
            external_data,
            payer: Address::new_unique(),
            cache_accounts: Default::default(),
        },
        &[],
    )
    .unwrap()
}

struct Accounts(HashMap<Address, Account>);

#[async_trait::async_trait]
impl AsyncRpc for Accounts {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        Ok(self.0.get(&address).cloned())
    }
}

fn token_accounts(
    mint: Address,
    token_address: Address,
    authority: Address,
    token_program: Address,
) -> Accounts {
    let mut token_bytes = vec![0; TokenAccount::LEN];
    TokenAccount::pack(
        TokenAccount {
            mint,
            owner: authority,
            state: AccountState::Initialized,
            ..Default::default()
        },
        &mut token_bytes,
    )
    .unwrap();
    Accounts(HashMap::from([
        (
            mint,
            Account {
                owner: token_program,
                ..Default::default()
            },
        ),
        (
            token_address,
            Account {
                owner: token_program,
                data: token_bytes,
                ..Default::default()
            },
        ),
    ]))
}

#[tokio::test]
async fn settlement_resolution_preserves_order_and_resolves_token_program_and_authority() {
    let mint = Address::new_unique();
    let token_address = Address::new_unique();
    let authority = Address::new_unique();
    let recipient = Address::new_unique();
    for token_program in
        [SPL_TOKEN_PROGRAM_ID, SPL_TOKEN_2022_PROGRAM_ID].map(Address::new_from_array)
    {
        let accounts = token_accounts(mint, token_address, authority, token_program);
        let request = settlement_request(vec![
            SettlementTransfer::Sol {
                is_deposit: false,
                amount: 2,
                user_sol_account: recipient,
            },
            SettlementTransfer::Spl {
                mint,
                is_deposit: true,
                amount: 4,
                user_spl_token: token_address,
            },
            SettlementTransfer::Sol {
                is_deposit: true,
                amount: 1,
                user_sol_account: recipient,
            },
            SettlementTransfer::Spl {
                mint,
                is_deposit: false,
                amount: 2,
                user_spl_token: token_address,
            },
        ]);
        assert_eq!(
            request
                .resolve_settlement_accounts(&accounts)
                .await
                .unwrap(),
            vec![
                TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts { recipient }),
                TransactInterfaceTransferAccounts::SplDeposit(TransactSplDepositAccounts {
                    mint,
                    spl_interface: pda::spl_interface(&mint),
                    token_authority: authority,
                    user_token_account: token_address,
                    token_program,
                }),
                TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts { recipient }),
                TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
                    mint,
                    spl_interface: pda::spl_interface(&mint),
                    user_token_account: token_address,
                    token_program,
                }),
            ]
        );
    }
}

#[tokio::test]
async fn settlement_resolution_rejects_a_token_account_for_another_mint() {
    let mint = Address::new_unique();
    let token_address = Address::new_unique();
    let token_program = Address::new_from_array(SPL_TOKEN_PROGRAM_ID);
    let mut accounts = token_accounts(
        Address::new_unique(),
        token_address,
        Address::new_unique(),
        token_program,
    );
    accounts.0.insert(
        mint,
        Account {
            owner: token_program,
            ..Default::default()
        },
    );
    let request = settlement_request(vec![SettlementTransfer::Spl {
        mint,
        is_deposit: false,
        amount: 2,
        user_spl_token: token_address,
    }]);
    assert!(
        matches!(request.resolve_settlement_accounts(&accounts).await,
            Err(ClientError::InvalidSplTokenAccount { address, mint: rejected }) if address == token_address && rejected == mint
        )
    );
}

#[tokio::test]
async fn settlement_resolution_rejects_token_accounts_owned_by_another_program() {
    let mint = Address::new_unique();
    let token_address = Address::new_unique();
    let mut accounts = token_accounts(
        mint,
        token_address,
        Address::new_unique(),
        Address::new_from_array(SPL_TOKEN_PROGRAM_ID),
    );
    accounts.0.get_mut(&token_address).unwrap().owner = Address::new_unique();
    let request = settlement_request(vec![SettlementTransfer::Spl {
        mint,
        is_deposit: true,
        amount: 2,
        user_spl_token: token_address,
    }]);
    assert!(
        matches!(request.resolve_settlement_accounts(&accounts).await,
            Err(ClientError::InvalidSplTokenAccount { address, mint: rejected }) if address == token_address && rejected == mint
        )
    );
}

#[tokio::test]
async fn settlement_resolution_rejects_unsupported_mint_programs() {
    let mint = Address::new_unique();
    let token_address = Address::new_unique();
    let token_program = Address::new_unique();
    let accounts = token_accounts(mint, token_address, Address::new_unique(), token_program);
    let request = settlement_request(vec![SettlementTransfer::Spl {
        mint,
        is_deposit: true,
        amount: 2,
        user_spl_token: token_address,
    }]);
    assert!(
        matches!(request.resolve_settlement_accounts(&accounts).await,
            Err(ClientError::UnsupportedSplTokenProgram { mint: rejected, owner }) if rejected == mint && owner == token_program
        )
    );
}
