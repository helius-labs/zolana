//! The ring merge request around its compressed SPP proof point.

mod common;

use custom_ring_interface::{
    merge_disclosure_field_count, CustomRingError, CustomRingMergeIxData, CustomRingMergeIxDataRef,
    CustomRingProof, MergeDisclosure, PlainGroth16Proof,
};
use zolana_interface::instruction::instruction_data::merge_transact::{
    MergeOutputEncryption, MergeProof, MergeTransactIxData, MergeTransactIxDataRef,
};

fn request(disclosure: Option<MergeDisclosure>) -> CustomRingMergeIxData {
    CustomRingMergeIxData {
        registry_root_index: 3,
        output_ring_data_hash: [8; 32],
        disclosure,
        merge: MergeTransactIxData {
            expiry_unix_ts: 42,
            proof: MergeProof {
                a: [0x21; 32],
                b: common::spp_b(),
                c: [0x22; 32],
            },
            output_utxo_hash: [1; 32],
            output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                salt: [2; 16],
                ciphertext: [[3; 32]; 3],
            },
            private_tx_hash: [4; 32],
            nullifiers: vec![[5; 32]],
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
            cache_slot: None,
        },
    }
}

fn disclosure() -> MergeDisclosure {
    MergeDisclosure {
        proof: CustomRingProof {
            groth16: PlainGroth16Proof {
                proof_a: [9; 32],
                proof_b: [10; 64],
                proof_c: [11; 32],
            },
            commitment: [12; 32],
            commitment_pok: [13; 32],
        },
        eph_pk: [4; 33],
        ciphertext: [14; 32],
        fields: vec![[15; 32]; merge_disclosure_field_count(8)],
    }
}

#[test]
fn the_view_rebuilds_the_exact_spp_body_from_the_compressed_point() {
    for disclosure in [None, Some(disclosure())] {
        let request = request(disclosure);
        let bytes = request.serialize().unwrap();
        let spp_body = request.merge.serialize().unwrap();
        let view = CustomRingMergeIxDataRef::from_bytes(&bytes).unwrap();
        assert_eq!(view.registry_root_index, 3);
        assert_eq!(view.output_ring_data_hash, &[8; 32]);
        assert_eq!(view.spp_merge_body().unwrap(), spp_body);
        assert_eq!(
            bytes.len() + 64,
            1 + 32 + spp_body.len() + disclosure_len(&request)
        );
        match (&view.disclosure, &request.disclosure) {
            (Some(view), Some(owned)) => {
                assert_eq!(view.proof, &owned.proof);
                assert_eq!(view.eph_pk, &owned.eph_pk);
                assert_eq!(view.ciphertext, &owned.ciphertext);
                assert_eq!(view.fields, owned.fields);
            }
            (None, None) => {}
            _ => panic!("the view changed the disclosure presence"),
        }
    }
}

/// The wincode option tag and, when present, the disclosure.
fn disclosure_len(request: &CustomRingMergeIxData) -> usize {
    request.disclosure.as_ref().map_or(1, |disclosure| {
        1 + CustomRingProof::SIZE + 33 + 32 + 1 + 32 * disclosure.fields.len()
    })
}

#[test]
fn a_compressed_point_off_the_curve_is_refused() {
    let mut bytes = request(None).serialize().unwrap();
    // Root index, ring data hash, the absent disclosure, then expiry and `a` precede `b`.
    let b = 1 + 32 + 1 + 8 + 32;
    bytes[b..b + 64].fill(0xff);
    let view = CustomRingMergeIxDataRef::from_bytes(&bytes).unwrap();
    assert_eq!(
        view.spp_merge_body(),
        Err(CustomRingError::InvalidSppProofPoint)
    );
}

#[test]
fn framing_errors_are_refused_before_or_by_the_spp_parser() {
    let bytes = request(None).serialize().unwrap();
    let mut tag = bytes.clone();
    tag[33] = 2;
    assert!(CustomRingMergeIxDataRef::from_bytes(&tag).is_err());
    assert!(CustomRingMergeIxDataRef::from_bytes(&bytes[..1 + 32 + 1 + 8 + 32 + 63]).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    let view = CustomRingMergeIxDataRef::from_bytes(&trailing).unwrap();
    let body = view.spp_merge_body().unwrap();
    assert!(MergeTransactIxDataRef::from_bytes(&body).is_err());
}
