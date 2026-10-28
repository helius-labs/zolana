#![no_std]

// Xark's generated native proving bindings require std; circuit code does not.
#[cfg(not(xark))]
extern crate std;

use xark::prelude::*;
use spr_circuit::{ArrayVec, poseidon};

#[input]
#[derive(
    Default,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
    spr_program::UtxoState,
    spr_program::PublicInputs,
)]
pub struct NoStdState {
    pub owner: spr_circuit::UtxoOwner,
    pub amount: u64,
}

#[circuit]
pub fn padded_commitment(values: Private<ArrayVec<u64, 3>>, expected: Public<Field>) {
    let padded = values.padded();
    let remaining = padded[0]
        .checked_sub(padded[1])
        .expect("transfer does not exceed balance")
        .checked_add(padded[2])
        .expect("balance fits in u64");
    let out = poseidon(&[Field::from(remaining), Field::from(padded[2])]).unwrap();
    require_eq(out, expected);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_std_state_codec_rejects_invalid_owner_preimages() {
        use spr_program::EncryptionCodec;
        for (tag, nullifier) in [(b'X', [0u8; 32]), (b'S', [0xffu8; 32])] {
            let bytes = borsh::to_vec(&(tag, [7u8; 32], nullifier, 1u64)).unwrap();
            let error = NoStdState::deserialize_after_decryption(&bytes).unwrap_err();
            assert_eq!(error.kind(), borsh::io::ErrorKind::InvalidData);
        }
    }

    fn inputs(a: u64, b: u64) -> ArrayVec<u64, 3> {
        ArrayVec::new([a, b]).unwrap()
    }
    #[test]
    fn compiled_constraints_accept_padding_and_reject_a_changed_commitment() {
        let expected = poseidon(&[Field::from(7u64), Field::zero()]).unwrap();
        padded_commitment(inputs(10, 3), expected).unwrap();
        assert!(padded_commitment(inputs(10, 3), expected + Field::one()).is_err());
    }
    #[test]
    fn compiled_constraints_reject_native_integer_underflow_and_overflow() {
        assert!(padded_commitment(inputs(3, 10), 0).is_err());
        assert!(padded_commitment(ArrayVec::new([u64::MAX, 0, 1]).unwrap(), 0).is_err());
    }
    #[test]
    fn groth16_proof_verifies() {
        let expected = poseidon(&[Field::from(7u64), Field::zero()]).unwrap();
        xark::prover::circuit(env!("CARGO_PKG_NAME"))
            .prove_dev(PaddedCommitmentInputs {
                values: inputs(10, 3),
                expected,
            })
            .unwrap();
    }
}
