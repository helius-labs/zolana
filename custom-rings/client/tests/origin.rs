//! Ring attribution over the confirmed call stack.

use solana_address::Address;
use solana_signature::Signature;
use solana_transaction_status_client_types::EncodedConfirmedTransactionWithStatusMeta;
use zolana_event::{InstructionGroup, ParsedInstruction};
use zolana_interface::instruction::tag;
use zolana_interface::{
    instruction::{CircuitId, InterfaceTransfer, TransactIxData, TransactProof},
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID, SOL_INTERFACE,
};
use zolana_ring_client::{
    ring_invoked_in, ring_withdrawals_in, ConfirmedTransaction, OriginError, RingWithdrawal,
};
use zolana_transaction::SOL_MINT;

const RING: Address = Address::new_from_array([9u8; 32]);
const OTHER: Address = Address::new_from_array([8u8; 32]);
const POOL: Address = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
const SOL: Address = Address::new_from_array(SOL_INTERFACE);
const RECIPIENT: Address = Address::new_from_array([3u8; 32]);
const CPI_AUTHORITY: Address = Address::new_from_array(SHIELDED_POOL_CPI_AUTHORITY);
const MINT: Address = Address::new_from_array([4u8; 32]);
const TOKEN_ACCOUNT: Address = Address::new_from_array([5u8; 32]);

fn instruction(program_id: Address, stack_height: Option<u32>) -> ParsedInstruction {
    ParsedInstruction::new(program_id, Vec::new(), Vec::new(), stack_height)
}

fn group(outer: Address, inner: &[(Address, u32)]) -> InstructionGroup {
    InstructionGroup {
        outer: instruction(outer, Some(1)),
        inner: inner
            .iter()
            .map(|(program_id, height)| instruction(*program_id, Some(*height)))
            .collect(),
    }
}

#[test]
fn pool_directly_under_the_ring_is_attributed() {
    let groups = [group(RING, &[(POOL, 2), (OTHER, 3)])];
    assert!(ring_invoked_in(&groups, RING).expect("walk"));
}

#[test]
fn pool_at_top_level_is_not_attributed() {
    let groups = [group(POOL, &[(OTHER, 2)])];
    assert!(!ring_invoked_in(&groups, RING).expect("walk"));
}

#[test]
fn pool_under_an_intermediary_is_not_attributed() {
    let groups = [group(RING, &[(OTHER, 2), (POOL, 3)])];
    assert!(!ring_invoked_in(&groups, RING).expect("walk"));
}

#[test]
fn ring_nested_under_another_program_still_signs_for_the_pool() {
    let groups = [group(OTHER, &[(RING, 2), (POOL, 3), (OTHER, 2), (POOL, 3)])];
    assert!(ring_invoked_in(&groups, RING).expect("walk"));
    let groups = [group(OTHER, &[(RING, 2), (OTHER, 2), (POOL, 3)])];
    assert!(!ring_invoked_in(&groups, RING).expect("walk"));
}

#[test]
fn malformed_stack_heights_are_errors() {
    let groups = [InstructionGroup {
        outer: instruction(RING, Some(1)),
        inner: vec![instruction(POOL, None)],
    }];
    assert!(matches!(
        ring_invoked_in(&groups, RING),
        Err(OriginError::MissingStackHeight)
    ));
    let groups = [group(RING, &[(POOL, 4)])];
    assert!(matches!(
        ring_invoked_in(&groups, RING),
        Err(OriginError::InvalidStackHeight(4))
    ));
}

/// The pool program id arrives through a lookup table, so it is absent from
/// the static account keys and is resolved from `loadedAddresses`.
#[test]
fn v0_transactions_resolve_program_ids_from_loaded_addresses() {
    let payer = Address::new_from_array([1u8; 32]);
    let json = serde_json::json!({
        "slot": 7,
        "blockTime": null,
        "transaction": {
            "signatures": [Signature::from([6u8; 64]).to_string()],
            "message": {
                "header": {
                    "numRequiredSignatures": 1,
                    "numReadonlySignedAccounts": 0,
                    "numReadonlyUnsignedAccounts": 1
                },
                "accountKeys": [payer.to_string(), RING.to_string()],
                "recentBlockhash": Address::default().to_string(),
                "instructions": [
                    { "programIdIndex": 1, "accounts": [0], "data": "", "stackHeight": null }
                ],
                "addressTableLookups": []
            }
        },
        "meta": {
            "err": null,
            "status": { "Ok": null },
            "fee": 5000,
            "preBalances": [1, 0],
            "postBalances": [0, 0],
            "innerInstructions": [
                {
                    "index": 0,
                    "instructions": [
                        { "programIdIndex": 3, "accounts": [2], "data": "", "stackHeight": 2 }
                    ]
                }
            ],
            "loadedAddresses": {
                "writable": [OTHER.to_string()],
                "readonly": [POOL.to_string()]
            }
        },
        "version": 0
    });
    let transaction: EncodedConfirmedTransactionWithStatusMeta =
        serde_json::from_value(json).expect("rpc shape");
    let invoked = ConfirmedTransaction {
        signature: Signature::from([6u8; 64]),
        transaction,
    }
    .ring_invoked(RING)
    .expect("walk");
    assert!(invoked);
}

/// The settlement walk reads instruction groups, so it needs no confirmed
/// transaction and no RPC.
#[test]
fn withdrawals_read_from_instruction_groups_without_a_transaction() {
    let mut pool = instruction(POOL, Some(2));
    pool.data = ring_transact_bytes(vec![InterfaceTransfer::SolWithdrawal { amount: 77 }]);
    pool.accounts = vec![Address::default(), SOL, RECIPIENT];
    let groups = [InstructionGroup {
        outer: instruction(RING, Some(1)),
        inner: vec![pool],
    }];

    assert_eq!(
        ring_withdrawals_in(&groups, RING).expect("walk"),
        vec![RingWithdrawal {
            recipient: RECIPIENT,
            asset: SOL_MINT,
            amount: 77,
        }]
    );
}

#[test]
fn withdrawals_of_a_ring_that_did_not_sign_are_not_reported() {
    let mut pool = instruction(POOL, Some(2));
    pool.data = ring_transact_bytes(vec![InterfaceTransfer::SolWithdrawal { amount: 77 }]);
    pool.accounts = vec![Address::default(), SOL, RECIPIENT];
    let groups = [InstructionGroup {
        outer: instruction(OTHER, Some(1)),
        inner: vec![pool],
    }];

    assert!(ring_withdrawals_in(&groups, RING).expect("walk").is_empty());
}

fn ring_transact_bytes(interface_transfers: Vec<InterfaceTransfer>) -> Vec<u8> {
    let data = TransactIxData {
        expiry_unix_ts: u64::MAX,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        interface_transfers,
        outputs: Vec::new(),
        messages: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        circuit: CircuitId::RingEddsa(0, 0, 3),
        proof: TransactProof::zeroed(),
        private_tx_hash: [0u8; 32],
        inputs: Vec::new(),
    };
    let mut encoded = vec![tag::RING_TRANSACT];
    encoded.extend_from_slice(&data.serialize().expect("serialize"));
    encoded
}

fn ring_transact_data(interface_transfers: Vec<InterfaceTransfer>) -> String {
    bs58::encode(ring_transact_bytes(interface_transfers)).into_string()
}

/// A ring transact CPI with `accounts` as its pool-instruction account indices.
fn withdrawing_transaction(
    interface_transfers: Vec<InterfaceTransfer>,
    accounts: Vec<u8>,
) -> EncodedConfirmedTransactionWithStatusMeta {
    let payer = Address::new_from_array([1u8; 32]);
    let tree = Address::new_from_array([2u8; 32]);
    let json = serde_json::json!({
        "slot": 7,
        "blockTime": null,
        "transaction": {
            "signatures": [Signature::from([6u8; 64]).to_string()],
            "message": {
                "header": {
                    "numRequiredSignatures": 1,
                    "numReadonlySignedAccounts": 0,
                    "numReadonlyUnsignedAccounts": 6
                },
                "accountKeys": [
                    payer.to_string(),
                    RING.to_string(),
                    POOL.to_string(),
                    Address::default().to_string(),
                    OTHER.to_string(),
                    tree.to_string(),
                    SOL.to_string(),
                    RECIPIENT.to_string(),
                    CPI_AUTHORITY.to_string(),
                    MINT.to_string(),
                    TOKEN_ACCOUNT.to_string()
                ],
                "recentBlockhash": Address::default().to_string(),
                "instructions": [
                    { "programIdIndex": 1, "accounts": [0], "data": "", "stackHeight": null }
                ]
            }
        },
        "meta": {
            "err": null,
            "status": { "Ok": null },
            "fee": 5000,
            "preBalances": [1, 0],
            "postBalances": [0, 0],
            "innerInstructions": [
                {
                    "index": 0,
                    "instructions": [{
                        "programIdIndex": 2,
                        "accounts": accounts,
                        "data": ring_transact_data(interface_transfers),
                        "stackHeight": 2
                    }]
                }
            ]
        }
    });
    serde_json::from_value(json).expect("rpc shape")
}

/// The recipient is the account following `SOL_INTERFACE` in the settlement
/// accounts appended to the pool instruction.
#[test]
fn sol_withdrawal_reports_its_recipient_and_amount() {
    let origin = ConfirmedTransaction {
        signature: Signature::from([6u8; 64]),
        transaction: withdrawing_transaction(
            vec![InterfaceTransfer::SolWithdrawal { amount: 4_200 }],
            vec![0, 5, 5, 2, 3, 4, 6, 7],
        ),
    }
    .origin(RING)
    .expect("walk");

    assert!(origin.ring_invoked);
    assert_eq!(
        origin.withdrawals,
        vec![RingWithdrawal {
            recipient: RECIPIENT,
            asset: SOL_MINT,
            amount: 4_200,
        }]
    );
}

/// The credited token account and the mint sit at indices 3 and 1 of the SPL
/// settlement group.
#[test]
fn spl_withdrawal_reports_its_mint_and_token_account() {
    let origin = ConfirmedTransaction {
        signature: Signature::from([6u8; 64]),
        transaction: withdrawing_transaction(
            vec![InterfaceTransfer::SplWithdrawal {
                amount: 9,
                spl_interface_bump: 42,
            }],
            vec![0, 5, 5, 2, 3, 8, 9, 4, 10, 4],
        ),
    }
    .origin(RING)
    .expect("walk");

    assert_eq!(
        origin.withdrawals,
        vec![RingWithdrawal {
            recipient: TOKEN_ACCOUNT,
            asset: MINT,
            amount: 9,
        }]
    );
}

/// A preceding SPL withdrawal shifts the SOL settlement group by five accounts.
#[test]
fn mixed_spl_and_sol_legs_are_both_reported() {
    let origin = ConfirmedTransaction {
        signature: Signature::from([6u8; 64]),
        transaction: withdrawing_transaction(
            vec![
                InterfaceTransfer::SplWithdrawal {
                    amount: 9,
                    spl_interface_bump: 42,
                },
                InterfaceTransfer::SolWithdrawal { amount: 11 },
            ],
            vec![0, 5, 5, 2, 3, 8, 9, 4, 10, 4, 6, 7],
        ),
    }
    .origin(RING)
    .expect("walk");

    assert_eq!(
        origin.withdrawals,
        vec![
            RingWithdrawal {
                recipient: TOKEN_ACCOUNT,
                asset: MINT,
                amount: 9,
            },
            RingWithdrawal {
                recipient: RECIPIENT,
                asset: SOL_MINT,
                amount: 11,
            }
        ]
    );
}

#[test]
fn spl_settlement_group_without_the_cpi_authority_is_an_error() {
    let origin = ConfirmedTransaction {
        signature: Signature::from([6u8; 64]),
        transaction: withdrawing_transaction(
            vec![InterfaceTransfer::SplWithdrawal {
                amount: 9,
                spl_interface_bump: 42,
            }],
            vec![0, 5, 5, 2, 3, 4, 9, 4, 10, 4],
        ),
    }
    .origin(RING);

    assert!(matches!(origin, Err(OriginError::SettlementAccounts)));
}
