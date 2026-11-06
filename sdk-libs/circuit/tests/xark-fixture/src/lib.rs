#![no_std]

// Xark's generated native proving bindings require std; circuit code does not.
#[cfg(not(xark))]
extern crate std;

use spr_circuit::{ArrayVec, poseidon};
use xark::prelude::*;

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
    let mut values = values.iter().copied();
    let (Some(balance), Some(debit), Some(credit)) = (values.next(), values.next(), values.next())
    else {
        panic!("three slots");
    };
    let remaining = balance
        .checked_sub(debit)
        .expect("transfer does not exceed balance")
        .checked_add(credit)
        .expect("balance fits in u64");
    let out = poseidon(&[Field::from(remaining), Field::from(credit)]).unwrap();
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
    /// The compiled circuit names the source expression whose constraint fails.
    fn failure<T: core::fmt::Debug, E: core::fmt::Display>(
        result: Result<T, E>,
    ) -> std::string::String {
        use std::string::ToString;
        result
            .expect_err("the compiled circuit must reject these inputs")
            .to_string()
    }
    #[test]
    fn compiled_constraints_accept_padding_and_reject_a_changed_commitment() {
        let expected = poseidon(&[Field::from(7u64), Field::zero()]).unwrap();
        padded_commitment(inputs(10, 3), expected).unwrap();
        let error = failure(padded_commitment(inputs(10, 3), expected + Field::one()));
        assert!(error.contains("require_eq(out, expected)"), "{error}");
    }
    /// Each expected commitment is what the circuit would compute without the
    /// overflow check, under both a field and a wrapping u64 reading of the
    /// result, so only the overflow check itself can reject the witness.
    #[test]
    fn compiled_constraints_reject_native_integer_underflow_and_overflow() {
        let unchecked =
            |remaining: Field, credit: u64| poseidon(&[remaining, Field::from(credit)]).unwrap();
        for expected in [
            unchecked(-Field::from(7u64), 0),
            unchecked(Field::from(3u64.wrapping_sub(10)), 0),
        ] {
            let error = failure(padded_commitment(inputs(3, 10), expected));
            assert!(error.contains(".checked_sub(debit)"), "{error}");
        }
        let overflowing = || ArrayVec::new([u64::MAX, 0, 1]).unwrap();
        for expected in [
            unchecked(Field::from(u64::MAX) + Field::one(), 1),
            unchecked(Field::from(u64::MAX.wrapping_add(1)), 1),
        ] {
            let error = failure(padded_commitment(overflowing(), expected));
            assert!(error.contains(".checked_add(credit)"), "{error}");
        }
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
