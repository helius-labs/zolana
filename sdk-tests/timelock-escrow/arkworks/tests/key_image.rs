use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};
use timelock_escrow_arkworks::Escrow;
use zk_program_sdk::{Groth16Keys, Groth16Prover, ProverErrorKind};

fn canonical_bytes(keys: &Groth16Keys) -> Vec<u8> {
    let mut bytes = Vec::new();
    keys.proving_key()
        .serialize_uncompressed(&mut bytes)
        .expect("serialize");
    bytes
}

#[test]
fn key_image_roundtrips_the_proving_key() {
    let prover = Groth16Prover::<Escrow>::new_with_test_setup().expect("setup");
    let keys = prover.keys();
    let image = keys.to_image_bytes();
    let loaded = Groth16Keys::from_image_bytes(&image).expect("image");
    assert_eq!(canonical_bytes(&loaded), canonical_bytes(keys));
}

#[test]
fn key_image_rejects_malformed_bytes() {
    let prover = Groth16Prover::<Escrow>::new_with_test_setup().expect("setup");
    let image = prover.keys().to_image_bytes();

    let cases: [(&str, Vec<u8>); 4] = [
        ("empty", Vec::new()),
        ("bad magic", b"PKIMG002".to_vec()),
        ("truncated", image[..image.len() / 2].to_vec()),
        ("trailing", [image.clone(), vec![0]].concat()),
    ];
    for (name, bytes) in cases {
        let error = Groth16Keys::from_image_bytes(&bytes).err().expect(name);
        assert!(
            matches!(error.kind(), ProverErrorKind::InvalidKeyImage(_)),
            "{name}: {error:?}"
        );
    }
}

#[test]
fn key_image_checked_verifies_the_sha256() {
    let prover = Groth16Prover::<Escrow>::new_with_test_setup().expect("setup");
    let keys = prover.keys();
    let image = keys.to_image_bytes();
    let checksum: [u8; 32] = Sha256::digest(&image).into();

    let loaded = Groth16Keys::from_image_checked(&image, &checksum).expect("checked image");
    assert_eq!(canonical_bytes(&loaded), canonical_bytes(keys));

    let mut wrong = checksum;
    wrong[0] ^= 1;
    let error = Groth16Keys::from_image_checked(&image, &wrong)
        .err()
        .expect("wrong checksum");
    assert!(matches!(
        error.kind(),
        ProverErrorKind::KeyImageChecksumMismatch
    ));
}
