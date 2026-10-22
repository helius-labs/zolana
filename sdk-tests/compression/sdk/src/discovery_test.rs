use super::*;
use crate::shared::DEFAULT_TREE_ID;
use crate::{account_address, account_pda, state::AccountState};
use zolana_transaction::{OutputContext, OutputSlot};

const AUTHORITY: [u8; 32] = [7u8; 32];

fn test_pda() -> Address {
    account_pda(&Address::new_from_array(AUTHORITY))
}

fn account_state(_pda: &Address, value: u64, version: u64) -> AccountState {
    AccountState {
        authority: AUTHORITY,
        value,
        version,
    }
}

fn state_of(current: &DiscoveredAccount) -> AccountState {
    decode_state(current.utxo.utxo.data.utxo_data().unwrap())
        .unwrap()
        .1
}

fn tagged_plaintext(
    pda: Address,
    state: &AccountState,
    leaf_index: u64,
) -> (EncryptedUtxoMatch, [u8; 32], u32) {
    let first_nullifier = zolana_hasher::primitives::right_align(&leaf_index.to_be_bytes());
    let seed = derive_output_blinding_seed(&first_nullifier, &ACCOUNT_BLINDING_SEED).unwrap();
    let account = AccountUtxo {
        pda,
        address: account_address(&pda, DEFAULT_TREE_ID).unwrap(),
        state: state.clone(),
        blinding: derive_transact_output_blinding(&first_nullifier, &seed, 0).unwrap(),
    };
    let utxo = account.utxo().unwrap();
    let data_hash = account.data_hash().unwrap();
    let hash = utxo
        .hash(
            &zero_nullifier_key().pubkey().unwrap(),
            &data_hash,
            &[0u8; 32],
            DEFAULT_TREE_ID,
        )
        .unwrap();
    (
        EncryptedUtxoMatch {
            slot: 0,
            tx_signature: Default::default(),
            output_slot: OutputSlot {
                view_tag: pda.to_bytes(),
                output_context: OutputContext {
                    hash,
                    tree_id: DEFAULT_TREE_ID,
                    leaf_index,
                },
                payload: borsh::to_vec(&OutputDataEncoding::Plaintext(
                    account.utxo_data().unwrap(),
                ))
                .unwrap(),
            },
            tx_viewing_pk: None,
            salt: None,
        },
        first_nullifier,
        0,
    )
}

fn tagged_garbage(pda: Address, leaf_index: u64) -> (EncryptedUtxoMatch, [u8; 32], u32) {
    let first_nullifier = [0u8; 32];
    (
        EncryptedUtxoMatch {
            slot: 0,
            tx_signature: Default::default(),
            output_slot: OutputSlot {
                view_tag: pda.to_bytes(),
                output_context: OutputContext {
                    hash: [0u8; 32],
                    tree_id: DEFAULT_TREE_ID,
                    leaf_index,
                },
                payload: borsh::to_vec(&OutputDataEncoding::Plaintext(vec![0xff; 3])).unwrap(),
            },
            tx_viewing_pk: None,
            salt: None,
        },
        first_nullifier,
        0,
    )
}

fn unspent(_: &[u8; 32]) -> Result<bool> {
    Ok(false)
}

#[test]
fn malformed_plaintext_tagged_to_the_pda_is_skipped() {
    let pda = test_pda();
    let legit = account_state(&pda, 1, 0);
    let current = discover_from_matches(
        [tagged_plaintext(pda, &legit, 10), tagged_garbage(pda, 11)],
        &pda,
        unspent,
    )
    .unwrap();

    assert_eq!(current.version, 0);
    assert_eq!(state_of(&current).value, 1);
}

#[test]
fn forged_plaintext_with_a_higher_leaf_index_is_not_selected() {
    let pda = test_pda();
    let legit = account_state(&pda, 1, 0);
    let forged = account_state(&pda, 999, 7);
    match discover_from_matches(
        [
            tagged_plaintext(pda, &legit, 10),
            tagged_plaintext(pda, &forged, 11),
        ],
        &pda,
        unspent,
    ) {
        Ok(current) => {
            assert_eq!(current.version, 0);
            assert_eq!(state_of(&current).value, 1);
        }
        Err(err) => assert!(err.to_string().contains("multiple unspent"), "{err}"),
    }
}

#[test]
fn recovery_checks_the_creating_nullifier_and_output_position() {
    let pda = test_pda();
    let state = account_state(&pda, 3, 1);
    let (indexed, first, index) = tagged_plaintext(pda, &state, 10);
    let actual = decode_wallet_utxo(indexed.clone(), &pda, &first, index).unwrap();
    let wrong_first = zolana_hasher::primitives::right_align(&11u64.to_be_bytes());
    assert_eq!(
        (
            state_of(&actual),
            actual.utxo.slot_index,
            decode_wallet_utxo(indexed.clone(), &pda, &wrong_first, index).is_err(),
            decode_wallet_utxo(indexed, &pda, &first, index + 1).is_err()
        ),
        (state, index, true, true)
    );
}
