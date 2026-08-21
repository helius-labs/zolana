//! Ring attribution over the confirmed call stack.

use solana_address::Address;
use solana_signature::Signature;
use solana_transaction_status_client_types::EncodedConfirmedTransactionWithStatusMeta;
use zolana_event::{InstructionGroup, ParsedInstruction};
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;
use zolana_ring_client::{ring_invoked_in, ConfirmedTransaction, OriginError};

const RING: Address = Address::new_from_array([9u8; 32]);
const OTHER: Address = Address::new_from_array([8u8; 32]);
const POOL: Address = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);

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
