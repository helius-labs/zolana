use pinocchio::{error::ProgramError, Address};
use shielded_pool_program::{process_instruction, ID};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{tag, InputUtxo, OwnerTag, TransactIxData, TransactOutput, TransactProof},
};

#[test]
fn rejects_the_wrong_program_before_dispatch() {
    let wrong_program = Address::new_from_array([0u8; 32]);
    assert_eq!(
        process_instruction(&wrong_program, &mut [], &[tag::EMIT_EVENT]),
        Err(ProgramError::IncorrectProgramId)
    );
}

#[test]
fn rejects_empty_unknown_and_malformed_instruction_data_exactly() {
    assert_eq!(
        process_instruction(&ID, &mut [], &[]),
        Err(ProgramError::InvalidInstructionData)
    );
    assert_eq!(
        process_instruction(&ID, &mut [], &[255]),
        Err(ProgramError::InvalidInstructionData)
    );
    assert_eq!(
        process_instruction(&ID, &mut [], &[tag::DEPOSIT, 1, 2, 3]),
        Err(ProgramError::Custom(
            ShieldedPoolError::InvalidInstructionData as u32
        ))
    );
}

#[test]
fn valid_create_tree_payload_reaches_account_validation() {
    let mut data = vec![tag::CREATE_TREE];
    data.extend_from_slice(&[7u8; 32]);
    assert_eq!(
        process_instruction(&ID, &mut [], &data),
        Err(ProgramError::Custom(20_014))
    );
}

#[test]
fn emit_event_is_an_explicit_account_free_noop() {
    assert_eq!(
        process_instruction(&ID, &mut [], &[tag::EMIT_EVENT]),
        Ok(())
    );
}

/// Wire-parseable transact payload (one input, one inline output, zeroed eddsa
/// proof). The transact-family processors map a parse failure to the same bare
/// `InvalidInstructionData` as the dispatcher, so distinguishing dispatch from
/// rejection for those tags needs a payload that parses.
fn transfer_payload() -> Vec<u8> {
    TransactIxData {
        proof: TransactProof::zeroed_eddsa(),
        expiry_unix_ts: u64::MAX,
        relayer_fee: 0,
        private_tx_hash: [0u8; 32],
        p256_signing_pk_x: None,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        inputs: vec![InputUtxo {
            nullifier_hash: [1u8; 32],
            nullifier_tree_root_index: 0,
            utxo_tree_root_index: 0,
            tree_index: 0,
            eddsa_signer_index: 0,
        }],
        public_sol_amount: None,
        public_spl_amount: None,
        data_hash: None,
        zone_data_hash: None,
        outputs: vec![TransactOutput {
            utxo_hash: [2u8; 32],
            owner_tag: OwnerTag::Inline([3u8; 32]),
            data: None,
        }],
        messages: Vec::new(),
    }
    .serialize()
    .expect("transact payload serialization is infallible")
}

/// INV-XC-03: every first byte outside the implemented tag set {0..=16, 51} is
/// rejected at dispatch with exactly the bare `InvalidInstructionData`; every
/// byte inside the set dispatches to its processor.
#[test]
fn every_first_byte_dispatches_or_is_rejected_exactly() {
    const KNOWN_TAGS: [u8; 18] = [
        tag::TRANSACT,
        tag::DEPOSIT,
        tag::ZONE_TRANSACT,
        tag::ZONE_AUTHORITY_TRANSACT,
        tag::CREATE_SPL_INTERFACE,
        tag::CREATE_TREE,
        tag::CREATE_PROTOCOL_CONFIG,
        tag::UPDATE_PROTOCOL_CONFIG,
        tag::PAUSE_TREE,
        tag::CREATE_ZONE_CONFIG,
        tag::UPDATE_ZONE_CONFIG_OWNER,
        tag::UPDATE_ZONE_CONFIG,
        tag::MERGE_TRANSACT,
        tag::ZONE_MERGE_TRANSACT,
        tag::EMIT_EVENT,
        tag::ZONE_DEPOSIT,
        tag::CREATE_ASSET_COUNTER,
        tag::BATCH_UPDATE_NULLIFIER_TREE,
    ];
    let transact_payload = transfer_payload();

    for byte in 0..=u8::MAX {
        match byte {
            tag::EMIT_EVENT => {
                assert_eq!(process_instruction(&ID, &mut [], &[byte]), Ok(()));
            }
            // These processors return the bare InvalidInstructionData for a
            // malformed payload, so give them one that parses: the next step,
            // Clock::get, fails on the host with UnsupportedSysvar, which
            // proves the tag dispatched past parsing.
            tag::TRANSACT | tag::ZONE_TRANSACT | tag::ZONE_AUTHORITY_TRANSACT => {
                let mut data = vec![byte];
                data.extend_from_slice(&transact_payload);
                assert_eq!(
                    process_instruction(&ID, &mut [], &data),
                    Err(ProgramError::UnsupportedSysvar),
                    "tag {byte} must dispatch past payload parsing"
                );
            }
            _ if KNOWN_TAGS.contains(&byte) => {
                // A 1-byte payload: the processor rejects it, but never with
                // the dispatcher's bare InvalidInstructionData (processors
                // return Custom errors, e.g. 7000/7019/20014).
                let result = process_instruction(&ID, &mut [], &[byte]);
                assert_ne!(
                    result,
                    Err(ProgramError::InvalidInstructionData),
                    "known tag {byte} must reach its processor"
                );
                assert!(result.is_err(), "tag {byte} must reject an empty payload");
            }
            _ => {
                assert_eq!(
                    process_instruction(&ID, &mut [], &[byte]),
                    Err(ProgramError::InvalidInstructionData),
                    "unknown tag {byte} must be rejected at dispatch"
                );
            }
        }
    }
}
