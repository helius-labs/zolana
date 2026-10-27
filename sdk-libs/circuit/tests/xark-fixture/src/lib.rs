use xark::prelude::*;
use zolana_circuit::{ArrayVec, poseidon};

#[circuit]
pub fn padded_commitment(values: Private<ArrayVec<u64, 3>>, expected: Public<Field>) {
    let padded = values.padded();
    let remaining = padded[0].checked_sub(padded[1]).expect("transfer does not exceed balance")
        .checked_add(padded[2]).expect("balance fits in u64");
    let out = poseidon(&[Field::from(remaining), Field::from(padded[2])]).unwrap();
    require_eq(out, expected);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inputs(a: u64, b: u64) -> ArrayVec<u64, 3> { ArrayVec::new([a, b]).unwrap() }
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
        xark::prover::circuit(env!("CARGO_PKG_NAME")).prove_dev(PaddedCommitmentInputs {
            values: inputs(10, 3), expected,
        }).unwrap();
    }
}
