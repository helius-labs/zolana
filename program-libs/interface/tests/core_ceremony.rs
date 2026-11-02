//! Final ceremony proofs generated from the R1CS compiled at the integration base.
//! Source, checkpoint and export pins are recorded in docs/core-ceremony.md.
use groth16_solana::groth16::{negate_g1_be, Groth16Verifier, Groth16Verifyingkey};
use serde::Deserialize;
#[derive(Deserialize)]
struct Vector {
    id: String,
    a: Vec<u8>,
    b: Vec<u8>,
    c: Vec<u8>,
    public: [[u8; 32]; 1],
    commitment: Option<Vec<u8>>,
    pok: Option<Vec<u8>>,
}
fn verify(v: &Vector, public: &[[u8; 32]; 1], vk: &Groth16Verifyingkey) -> bool {
    let a = negate_g1_be(&v.a.as_slice().try_into().unwrap());
    let b = v.b.as_slice().try_into().unwrap();
    let c = v.c.as_slice().try_into().unwrap();
    if let (Some(commitment), Some(pok)) = (&v.commitment, &v.pok) {
        let commitment = commitment.as_slice().try_into().unwrap();
        let pok = pok.as_slice().try_into().unwrap();
        Groth16Verifier::new_with_commitment(&a, &b, &c, &commitment, &pok, public, vk)
            .unwrap()
            .verify()
            .is_ok()
    } else {
        Groth16Verifier::new(&a, &b, &c, public, vk)
            .unwrap()
            .verify()
            .is_ok()
    }
}
#[test]
fn final_core_keys_accept_real_proofs_and_reject_changed_public_inputs() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("fixtures/core-ceremony-2026-11-02.json")).unwrap();
    assert_eq!(vectors.len(), 41);
    let mut ids = std::collections::BTreeSet::new();
    for v in vectors {
        assert!(ids.insert(v.id.clone()), "duplicate fixture");
        let vk = match v.id.as_str() {
            "merge_24_1" => &spr_interface::verifying_keys::merge_24_1::VERIFYINGKEY,
            "merge_52_1" => &spr_interface::verifying_keys::merge_52_1::VERIFYINGKEY,
            "merge_8_1" => &spr_interface::verifying_keys::merge_8_1::VERIFYINGKEY,
            "transfer_confidential_12_2" => {
                &spr_interface::verifying_keys::transfer_confidential_12_2::VERIFYINGKEY
            }
            "transfer_confidential_12_4" => {
                &spr_interface::verifying_keys::transfer_confidential_12_4::VERIFYINGKEY
            }
            "transfer_confidential_12_8" => {
                &spr_interface::verifying_keys::transfer_confidential_12_8::VERIFYINGKEY
            }
            "transfer_confidential_16_2" => {
                &spr_interface::verifying_keys::transfer_confidential_16_2::VERIFYINGKEY
            }
            "transfer_confidential_16_4" => {
                &spr_interface::verifying_keys::transfer_confidential_16_4::VERIFYINGKEY
            }
            "transfer_confidential_16_8" => {
                &spr_interface::verifying_keys::transfer_confidential_16_8::VERIFYINGKEY
            }
            "transfer_confidential_1_16" => {
                &spr_interface::verifying_keys::transfer_confidential_1_16::VERIFYINGKEY
            }
            "transfer_confidential_1_2" => {
                &spr_interface::verifying_keys::transfer_confidential_1_2::VERIFYINGKEY
            }
            "transfer_confidential_1_4" => {
                &spr_interface::verifying_keys::transfer_confidential_1_4::VERIFYINGKEY
            }
            "transfer_confidential_1_8" => {
                &spr_interface::verifying_keys::transfer_confidential_1_8::VERIFYINGKEY
            }
            "transfer_confidential_24_2" => {
                &spr_interface::verifying_keys::transfer_confidential_24_2::VERIFYINGKEY
            }
            "transfer_confidential_24_4" => {
                &spr_interface::verifying_keys::transfer_confidential_24_4::VERIFYINGKEY
            }
            "transfer_confidential_2_16" => {
                &spr_interface::verifying_keys::transfer_confidential_2_16::VERIFYINGKEY
            }
            "transfer_confidential_2_2" => {
                &spr_interface::verifying_keys::transfer_confidential_2_2::VERIFYINGKEY
            }
            "transfer_confidential_2_4" => {
                &spr_interface::verifying_keys::transfer_confidential_2_4::VERIFYINGKEY
            }
            "transfer_confidential_2_8" => {
                &spr_interface::verifying_keys::transfer_confidential_2_8::VERIFYINGKEY
            }
            "transfer_confidential_32_2" => {
                &spr_interface::verifying_keys::transfer_confidential_32_2::VERIFYINGKEY
            }
            "transfer_confidential_3_2" => {
                &spr_interface::verifying_keys::transfer_confidential_3_2::VERIFYINGKEY
            }
            "transfer_confidential_3_4" => {
                &spr_interface::verifying_keys::transfer_confidential_3_4::VERIFYINGKEY
            }
            "transfer_confidential_3_8" => {
                &spr_interface::verifying_keys::transfer_confidential_3_8::VERIFYINGKEY
            }
            "transfer_confidential_40_2" => {
                &spr_interface::verifying_keys::transfer_confidential_40_2::VERIFYINGKEY
            }
            "transfer_confidential_48_2" => {
                &spr_interface::verifying_keys::transfer_confidential_48_2::VERIFYINGKEY
            }
            "transfer_confidential_49_2" => {
                &spr_interface::verifying_keys::transfer_confidential_49_2::VERIFYINGKEY
            }
            "transfer_confidential_4_16" => {
                &spr_interface::verifying_keys::transfer_confidential_4_16::VERIFYINGKEY
            }
            "transfer_confidential_4_2" => {
                &spr_interface::verifying_keys::transfer_confidential_4_2::VERIFYINGKEY
            }
            "transfer_confidential_4_4" => {
                &spr_interface::verifying_keys::transfer_confidential_4_4::VERIFYINGKEY
            }
            "transfer_confidential_4_8" => {
                &spr_interface::verifying_keys::transfer_confidential_4_8::VERIFYINGKEY
            }
            "transfer_confidential_5_16" => {
                &spr_interface::verifying_keys::transfer_confidential_5_16::VERIFYINGKEY
            }
            "transfer_confidential_5_2" => {
                &spr_interface::verifying_keys::transfer_confidential_5_2::VERIFYINGKEY
            }
            "transfer_confidential_5_4" => {
                &spr_interface::verifying_keys::transfer_confidential_5_4::VERIFYINGKEY
            }
            "transfer_confidential_5_8" => {
                &spr_interface::verifying_keys::transfer_confidential_5_8::VERIFYINGKEY
            }
            "transfer_confidential_6_2" => {
                &spr_interface::verifying_keys::transfer_confidential_6_2::VERIFYINGKEY
            }
            "transfer_confidential_6_4" => {
                &spr_interface::verifying_keys::transfer_confidential_6_4::VERIFYINGKEY
            }
            "transfer_confidential_6_8" => {
                &spr_interface::verifying_keys::transfer_confidential_6_8::VERIFYINGKEY
            }
            "transfer_confidential_8_16" => {
                &spr_interface::verifying_keys::transfer_confidential_8_16::VERIFYINGKEY
            }
            "transfer_confidential_8_2" => {
                &spr_interface::verifying_keys::transfer_confidential_8_2::VERIFYINGKEY
            }
            "transfer_confidential_8_4" => {
                &spr_interface::verifying_keys::transfer_confidential_8_4::VERIFYINGKEY
            }
            "transfer_confidential_8_8" => {
                &spr_interface::verifying_keys::transfer_confidential_8_8::VERIFYINGKEY
            }
            _ => panic!("unexpected core fixture"),
        };
        assert!(verify(&v, &v.public, vk), "valid proof rejected: {}", v.id);
        let mut changed = v.public;
        changed[0][31] ^= 1;
        assert!(
            !verify(&v, &changed, vk),
            "changed public input accepted: {}",
            v.id
        );
    }
}
