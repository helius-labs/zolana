use shielded_pool_program::testing::{MergeOwnerBinding, MergeProof, MergeProofInputs};
use zolana_hasher::hash_chain::{
    create_hash_chain_4_from_slice, create_right_hash_chain_4_from_slice,
};
use zolana_interface::{
    instruction::instruction_data::{
        merge_ring::{MergeRingIxData, MergeRingIxDataRef},
        merge_transact::{
            merge_circuit_width, MergeBody, MergeBodyRef, MergeEnvelope,
            MergeProof as MergeProofData, MergeProofCommitment, MergeTransactIxData,
            MergeTransactIxDataRef,
        },
    },
    merge_utils::merge_envelope_public_elements,
    tree_slot::{tree_slots_hash_chain, TreeSlot},
    INPUT_TREES,
};
use zolana_test_utils::transact::fe;

const SENT_NULLIFIERS: u64 = 3;

fn compressed_point(prefix: u8, start: u8) -> [u8; 33] {
    core::array::from_fn(|index| match index {
        0 => prefix,
        _ => start + (index - 1) as u8,
    })
}

fn proof_commitment() -> MergeProofCommitment {
    MergeProofCommitment {
        commitment: [0x41; 32],
        commitment_pok: [0x42; 32],
    }
}

fn envelope() -> MergeEnvelope {
    MergeEnvelope {
        ephemeral_pk: compressed_point(0x03, 0x50),
        ciphertext: core::array::from_fn(|index| 0x80 + index as u8),
    }
}

fn body() -> MergeBody {
    MergeBody {
        expiry_unix_ts: 7,
        proof: MergeProofData::zeroed(),
        output_utxo_hash: fe(11),
        eddsa_owner: false,
        private_tx_hash: fe(12),
        nullifiers: (1..=SENT_NULLIFIERS).map(fe).collect(),
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 0,
        cache_slot: None,
    }
}

fn ix_bytes() -> Vec<u8> {
    MergeTransactIxData {
        body: body(),
        proof_commitment: proof_commitment(),
        envelope: envelope(),
    }
    .serialize()
    .expect("serialize merge instruction")
}

fn ring_ix_bytes() -> Vec<u8> {
    MergeRingIxData {
        output_ring_data_hash: fe(51),
        merge: body(),
    }
    .serialize()
    .expect("serialize merge_ring instruction")
}

fn tree_slot() -> TreeSlot {
    TreeSlot {
        id: fe(21),
        utxo_root: fe(22),
        nullifier_root: fe(23),
    }
}

fn proof_inputs(owner_binding: MergeOwnerBinding<'_>) -> MergeProofInputs<'_> {
    MergeProofInputs {
        tree_slot: tree_slot(),
        output_tree_id: fe(31),
        external_data_hash: fe(32),
        allow_dummy_inputs: fe(1),
        owner_binding,
    }
}

fn default_binding<'a>(
    ix: &MergeTransactIxDataRef<'a>,
    viewing_pk: [u8; 33],
) -> MergeOwnerBinding<'a> {
    MergeOwnerBinding::Default {
        signing_pk_field: fe(41),
        nullifier_pk: fe(42),
        viewing_pk,
        proof_commitment: ix.proof_commitment,
        envelope: ix.envelope,
    }
}

fn common_prefix(ix: &MergeBodyRef<'_>) -> Vec<[u8; 32]> {
    let mut nullifiers = ix.nullifiers.clone();
    nullifiers.resize(
        merge_circuit_width(nullifiers.len()).expect("supported merge shape"),
        [0u8; 32],
    );
    let mut slots = [TreeSlot::ZERO; INPUT_TREES];
    if let Some(first) = slots.first_mut() {
        *first = tree_slot();
    }
    vec![
        create_right_hash_chain_4_from_slice(&nullifiers).expect("nullifier chain"),
        *ix.output_utxo_hash,
        tree_slots_hash_chain(&slots).expect("tree slot chain"),
        fe(31),
        *ix.private_tx_hash,
        fe(32),
        fe(1),
    ]
}

#[test]
fn default_rail_folds_owner_and_envelope_after_the_common_prefix() {
    let envelope = envelope();
    let bytes = ix_bytes();
    let ix = MergeTransactIxDataRef::from_bytes(&bytes).expect("parse merge instruction");
    let viewing_pk = compressed_point(0x02, 0x10);

    let mut preimage = common_prefix(&ix.body);
    preimage.extend([fe(41), fe(42)]);
    preimage.extend(merge_envelope_public_elements(
        &viewing_pk,
        &envelope.ephemeral_pk,
        &envelope.ciphertext,
    ));
    assert_eq!(preimage.len(), 13);

    assert_eq!(
        MergeProof::new(&ix.body, proof_inputs(default_binding(&ix, viewing_pk)))
            .public_input_hash(),
        Ok(create_hash_chain_4_from_slice(&preimage).expect("flat chain"))
    );
}

#[test]
fn ring_rail_folds_ring_binding_after_the_common_prefix() {
    let bytes = ring_ix_bytes();
    let ix = MergeRingIxDataRef::from_bytes(&bytes).expect("parse merge_ring instruction");

    let mut preimage = common_prefix(&ix.merge);
    preimage.extend([fe(51), fe(52)]);
    assert_eq!(preimage.len(), 9);

    let binding = MergeOwnerBinding::Ring {
        ring_program_id: fe(52),
        output_ring_data_hash: *ix.output_ring_data_hash,
    };
    assert_eq!(
        MergeProof::new(&ix.merge, proof_inputs(binding)).public_input_hash(),
        Ok(create_hash_chain_4_from_slice(&preimage).expect("flat chain"))
    );
}
