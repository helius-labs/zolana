use custom_ring_interface::{
    CustomRingProof, DepositContext, DepositPublicInput, PlainGroth16Proof,
};
use zolana_hasher::HasherError;

#[test]
fn context_binds_ring_tree_wire_and_wire_length() {
    let ring = [1; 32];
    let tree = [2; 32];
    let context = DepositContext {
        program_id: &ring,
        tree: &tree,
        spp_data: &[1],
    };
    let expected = context.hash().unwrap();
    for changed in [
        DepositContext {
            program_id: &[3; 32],
            ..context
        },
        DepositContext {
            tree: &[3; 32],
            ..context
        },
        DepositContext {
            spp_data: &[2],
            ..context
        },
        DepositContext {
            spp_data: &[0, 1],
            ..context
        },
    ] {
        assert_ne!(expected, changed.hash().unwrap());
    }
}

#[test]
fn public_statement_binds_each_opening_ciphertext_key_and_context() {
    let owners = [[1; 32], [2; 32]];
    let ciphertexts = [[3; 64], [4; 64]];
    let input = DepositPublicInput {
        context_hash: &[5; 32],
        owner_utxo_hashes: &owners,
        ciphertexts: &ciphertexts,
        auditor_pk: &[6; 33],
        eph_pk: &[7; 33],
    };
    let expected = input.hash().unwrap();
    for changed in [
        DepositPublicInput {
            context_hash: &[6; 32],
            ..input
        },
        DepositPublicInput {
            owner_utxo_hashes: &[[2; 32], [1; 32]],
            ..input
        },
        DepositPublicInput {
            ciphertexts: &[[4; 64], [3; 64]],
            ..input
        },
        DepositPublicInput {
            auditor_pk: &[7; 33],
            ..input
        },
        DepositPublicInput {
            eph_pk: &[8; 33],
            ..input
        },
        DepositPublicInput {
            owner_utxo_hashes: &owners[..1],
            ciphertexts: &ciphertexts[..1],
            ..input
        },
    ] {
        assert_ne!(expected, changed.hash().unwrap());
    }
}

#[test]
fn statement_rejects_empty_oversized_and_mismatched_batches() {
    let input = DepositPublicInput {
        context_hash: &[0; 32],
        owner_utxo_hashes: &[],
        ciphertexts: &[],
        auditor_pk: &[0; 33],
        eph_pk: &[0; 33],
    };
    assert_eq!(input.hash(), Err(HasherError::InvalidNumFields));
    assert_eq!(
        DepositPublicInput {
            owner_utxo_hashes: &[[0; 32]; 9],
            ciphertexts: &[[0; 64]; 9],
            ..input
        }
        .hash(),
        Err(HasherError::InvalidNumFields)
    );
    assert_eq!(
        DepositPublicInput {
            owner_utxo_hashes: &[[0; 32]],
            ..input
        }
        .hash(),
        Err(HasherError::InvalidNumFields)
    );
}

#[test]
fn proof_prefix_size_matches_the_instruction_serializer() {
    let proof = CustomRingProof {
        groth16: PlainGroth16Proof {
            proof_a: [1; 32],
            proof_b: [2; 64],
            proof_c: [3; 32],
        },
        commitment: [4; 32],
        commitment_pok: [5; 32],
    };
    let bytes = wincode::serialize(&proof).unwrap();
    assert_eq!(bytes.len(), CustomRingProof::SIZE);
    assert_eq!(&bytes[..32], &[1; 32]);
    assert_eq!(&bytes[160..], &[5; 32]);
}
