use custom_ring_interface::{tag, CustomRingProof, CustomRingTransactIxData, AUDITOR_MESSAGE_LEN};
use custom_ring_program::CustomRingError;
use solana_program_error::ProgramError;
use zolana_interface::N_PUBLIC_SLOTS;
use zolana_interface::{
    event::RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
    instruction::{
        instruction_data::transact::{
            CircuitId, OwnerTag, TransactIxData, TransactOutput, TransactProof,
        },
        MessageData,
    },
};

use crate::common::{
    auditor_pubkey, authority, initialized_config_account, initialized_policy_config_account,
    records_tree, records_tree_account, setup_mollusk, transact_fixture, Fixture,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

fn confidential_output() -> TransactOutput {
    let mut key = [0u8; 33];
    key[0] = 0x02;
    let mut body = vec![RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG];
    body.extend_from_slice(&key);
    body.extend_from_slice(&[9u8; 32]);
    let mut data = vec![1u8];
    data.extend_from_slice(&(body.len() as u32).to_le_bytes());
    data.extend_from_slice(&body);
    TransactOutput {
        utxo_hash: [1u8; 32],
        owner_tag: OwnerTag::Inline([2u8; 32]),
        data: Some(data),
    }
}

fn transact_data() -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [3u8; 32],
        circuit: CircuitId::RingEddsa(1, 1, N_PUBLIC_SLOTS as u8),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        proof: TransactProof::zeroed(),
        inputs: Vec::new(),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![confidential_output()],
        messages: vec![MessageData {
            view_tag: auditor_pubkey(2)[1..33].try_into().expect("view tag"),
            data: {
                let mut data = vec![0u8; AUDITOR_MESSAGE_LEN];
                data[0] = 0x02;
                data
            },
        }],
    }
}

fn policy_fixture(state_root_index: u16, nullifier_root_index: u16) -> Fixture {
    let mut data = vec![tag::TRANSACT];
    data.extend_from_slice(
        &wincode::serialize(&CustomRingTransactIxData {
            proof: CustomRingProof {
                proof_a: [0; 32],
                proof_b: [0; 64],
                proof_c: [0; 32],
                commitment: [0xFF; 32],
                commitment_pok: [0xFF; 32],
            },
            state_root_index,
            nullifier_root_index,
            transact: transact_data(),
        })
        .expect("serialize policy transact body"),
    );
    let mut fixture = transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        data,
    );
    fixture.set_account("input_tree", records_tree_account());
    fixture
}

/// The stored hash is what a rebuilt table must reproduce.
#[test]
fn a_drifted_policy_hash_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_fixture(0, 0);
    let mut config = initialized_policy_config_account();
    config.data[1] ^= 0xFF;
    fixture.set_account("policy_config", config);
    fixture.expect_err(&mollusk, custom(CustomRingError::PolicyHashMismatch));
}

/// The roots come from a real tree account, a stub never yields one.
#[test]
fn a_records_tree_that_is_not_a_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = policy_fixture(0, 0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidRecordsTree));
}

#[test]
fn the_records_tree_address_is_the_configured_one() {
    assert_eq!(
        initialized_policy_config_account().data[33..65],
        records_tree().to_bytes()
    );
}
