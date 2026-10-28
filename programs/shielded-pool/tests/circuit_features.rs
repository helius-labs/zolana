use shielded_pool_program::circuit_features::{circuit_enabled, CONFIDENTIAL_EDDSA};
use spr_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{
            InputUtxo, TransactIxData, TransactIxDataRef, TransactProof, TreeContext,
        },
        tag::InstructionTag,
    },
    shape::CONFIDENTIAL_EDDSA_SHAPES,
    verifying_keys::{Bsb22Commitment, CacheAccess, CircuitId, EddsaProofData},
};

#[test]
fn instruction_validation_rejects_disabled_circuits_before_proof_verification() {
    let proof = EddsaProofData {
        bsb22_commitment: Bsb22Commitment {
            commitment: [0; 32],
            commitment_pok: [0; 32],
        },
        owner_pk: [0; 32],
    };
    let ix = TransactIxData {
        proof: TransactProof::zeroed(),
        expiry_unix_ts: 0,
        private_tx_hash: [0; 32],
        circuit: CircuitId::ConfidentialEddsa(2, 8, 3, proof),
        inputs: vec![InputUtxo {
            nullifier_hash: [1; 32],
            tree_index: 0,
        }],
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        }],
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        tx_viewing_pk: [0; 33],
        salt: [0; 16],
        outputs: Vec::new(),
        messages: Vec::new(),
    };
    let bytes = ix.serialize().expect("instruction bytes");
    let borrowed = TransactIxDataRef::from_bytes(&bytes).expect("borrow instruction");
    let expected = if cfg!(feature = "confidential-eddsa") {
        Ok(())
    } else {
        Err(ShieldedPoolError::InvalidTransactShape.into())
    };
    assert_eq!(
        shielded_pool_program::instructions::transact::validate_circuit_type(
            &borrowed,
            InstructionTag::Transact
        ),
        expected
    );
}

#[test]
fn every_confidential_eddsa_key_follows_the_compile_feature_including_cached_selectors() {
    let proof = EddsaProofData {
        bsb22_commitment: Bsb22Commitment {
            commitment: [0; 32],
            commitment_pok: [0; 32],
        },
        owner_pk: [0; 32],
    };
    let cache = CacheAccess {
        read_bitmap: 1,
        write_slots: CacheAccess::NO_WRITES,
    };
    for shape in CONFIDENTIAL_EDDSA_SHAPES {
        let circuit =
            CircuitId::ConfidentialEddsa(shape.n_inputs() as u8, shape.n_outputs() as u8, 3, proof);
        let cached = CircuitId::ConfidentialEddsaCached(
            shape.n_inputs() as u8,
            shape.n_outputs() as u8,
            3,
            proof,
            cache,
        );
        assert_eq!(
            (circuit_enabled(circuit), circuit_enabled(cached)),
            (
                cfg!(feature = "confidential-eddsa"),
                cfg!(feature = "confidential-eddsa")
            ),
            "{shape:?}"
        );
    }
    assert!(!CONFIDENTIAL_EDDSA.allows(&[0; 32]));
    assert!(!circuit_enabled(CircuitId::ConfidentialEddsa(
        1, 2, 3, proof
    )));
    assert!(circuit_enabled(CircuitId::ConfidentialSigner(2, 8, 3)));
}
