use swap_program::instructions::{
    cancel::{CancelIxData, CancelProof},
    make::{MakeIxData, MakeProof, MARKER_PLACEHOLDER},
    shared::instruction_suffix,
    take::{TakeIxData, TakeProof},
    take_verifiable_encryption::{TakeVerifiableEncryptionIxData, TakeVerifiableEncryptionProof},
};
use zolana_interface::instruction::instruction_data::transact::{
    MessageData, TransactIxData, TransactProof,
};

fn transact(messages: Vec<MessageData>) -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: u64::MAX,
        relayer_fee: 0,
        private_tx_hash: [1; 32],
        p256_signing_pk_x: None,
        tx_viewing_pk: [2; 33],
        salt: [3; 16],
        proof: TransactProof::zeroed_eddsa(),
        inputs: Vec::new(),
        public_sol_amount: None,
        public_spl_amount: None,
        data_hash: None,
        zone_data_hash: None,
        outputs: Vec::new(),
        messages,
    }
}

#[test]
fn take_ends_with_the_exact_transact_encoding() {
    let plain_transact = transact(Vec::new());
    let plain_bytes = wincode::serialize(&plain_transact).unwrap();
    let take_proof = TakeProof {
        proof_a: [4; 32],
        proof_b: [5; 64],
        proof_c: [6; 32],
    };
    let take = wincode::serialize(&TakeIxData {
        proof: take_proof,
        transact: plain_transact.clone(),
    })
    .unwrap();
    assert_eq!(
        instruction_suffix(&take, wincode::serialized_size(&take_proof).unwrap()).unwrap(),
        plain_bytes
    );
}

#[test]
fn cancel_ends_with_the_exact_transact_encoding() {
    let plain_transact = transact(Vec::new());
    let plain_bytes = wincode::serialize(&plain_transact).unwrap();
    let cancel_proof = CancelProof {
        proof_a: [7; 32],
        proof_b: [8; 64],
        proof_c: [9; 32],
    };
    let order_expiry = 42;
    let cancel = wincode::serialize(&CancelIxData {
        proof: cancel_proof,
        order_expiry,
        transact: plain_transact.clone(),
    })
    .unwrap();
    let cancel_prefix = wincode::serialized_size(&cancel_proof).unwrap()
        + wincode::serialized_size(&order_expiry).unwrap();
    assert_eq!(
        instruction_suffix(&cancel, cancel_prefix).unwrap(),
        plain_bytes
    );
}

#[test]
fn take_verifiable_encryption_ends_with_the_exact_transact_encoding() {
    let plain_transact = transact(Vec::new());
    let plain_bytes = wincode::serialize(&plain_transact).unwrap();
    let verifiable_proof = TakeVerifiableEncryptionProof {
        proof_a: [10; 32],
        proof_b: [11; 64],
        proof_c: [12; 32],
        commitment: [13; 32],
        commitment_pok: [14; 32],
    };
    let verifiable = wincode::serialize(&TakeVerifiableEncryptionIxData {
        proof: verifiable_proof,
        transact: plain_transact,
    })
    .unwrap();
    assert_eq!(
        instruction_suffix(
            &verifiable,
            wincode::serialized_size(&verifiable_proof).unwrap()
        )
        .unwrap(),
        plain_bytes
    );
}

#[test]
fn make_ends_with_the_exact_transact_encoding() {
    let marker_transact = transact(vec![MessageData {
        view_tag: [15; 32],
        data: MARKER_PLACEHOLDER.to_vec(),
    }]);
    let marker_bytes = wincode::serialize(&marker_transact).unwrap();
    let make_proof = MakeProof {
        proof_a: [16; 32],
        proof_b: [17; 64],
        proof_c: [18; 32],
    };
    let make = wincode::serialize(&MakeIxData {
        proof: make_proof,
        transact: marker_transact,
    })
    .unwrap();
    assert_eq!(
        instruction_suffix(&make, wincode::serialized_size(&make_proof).unwrap()).unwrap(),
        marker_bytes
    );
}

#[test]
fn make_marker_tail_patch_updates_the_decoded_message() {
    let marker_transact = transact(vec![MessageData {
        view_tag: [15; 32],
        data: MARKER_PLACEHOLDER.to_vec(),
    }]);
    let make_proof = MakeProof {
        proof_a: [16; 32],
        proof_b: [17; 64],
        proof_c: [18; 32],
    };
    let make = wincode::serialize(&MakeIxData {
        proof: make_proof,
        transact: marker_transact,
    })
    .unwrap();
    let replacement = [0xA5; MARKER_PLACEHOLDER.len()];
    let mut patched = make;
    let replacement_offset = patched.len() - replacement.len();
    patched
        .get_mut(replacement_offset..)
        .unwrap()
        .copy_from_slice(&replacement);
    let decoded: MakeIxData = wincode::deserialize_exact(&patched).unwrap();
    assert_eq!(decoded.transact.messages.first().unwrap().data, replacement);
}
