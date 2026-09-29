use ark_bn254::Fr;
use zk_program_sdk::circuit::{constant, value, Bytes, CircuitVar, Field};

use super::{
    fixtures::{
        allocated, pack_forms, split_forms, Computed, Failure, FILE, PACK_BROKEN, PACK_FORMS,
        SPLIT_BROKEN, SPLIT_FORMS,
    },
    vectors::{Vector, TOO_LARGE, VALID, WIDE, WRONG},
};
use crate::{
    bytes::support::array,
    harness::fixture::{expected, native_circuit, per_vector, Fixture, Native, Visit, Visited},
};

type Constants = Vec<(String, Field)>;

fn constants(vars: &[CircuitVar]) -> Constants {
    vars.iter()
        .map(|var| (format!("{var:?}"), value(var).expect("a constant")))
        .collect()
}

fn byte_constants(bytes: &[u8]) -> Constants {
    bytes
        .iter()
        .map(|byte| (format!("CircuitVar::constant({byte})"), Field::from(*byte)))
        .collect()
}

fn byte_constants_of(vector: &Vector) -> Constants {
    byte_constants(&vector.bytes())
}

fn value_constant(vector: &Vector) -> Constants {
    vec![(
        format!("CircuitVar::constant({})", Fr::from(vector.value())),
        vector.value(),
    )]
}

struct NativeBytes;

impl Visit<Computed> for NativeBytes {
    type Output = Result<Constants, (&'static str, String)>;

    fn visit<F: Fixture<Computed>>(&self, fixture: &F) -> Self::Output {
        F::computed(&native_circuit(fixture).expect("native instantiation"))
            .map(|vars| constants(&vars))
            .map_err(|(name, message, _)| (name, message))
    }
}

struct NativeFailure;

impl Visit<Computed> for NativeFailure {
    type Output = Option<Failure>;

    fn visit<F: Fixture<Computed>>(&self, fixture: &F) -> Self::Output {
        F::computed(&native_circuit(fixture).expect("native instantiation")).err()
    }
}

fn too_wide() -> Result<Constants, (&'static str, String)> {
    Err((
        "CircuitError.BitWidthTooLarge",
        "a check over 256 bits is too wide; a circuit value holds at most 253 bits".to_string(),
    ))
}

#[test]
fn a_byte_proof_input_instantiates_to_one_constant_per_byte_natively() {
    let vectors = [&VALID[..], &WIDE].concat();
    assert_eq!(
        per_vector(&vectors, |vector| allocated(&NativeBytes, &vector.pair())),
        per_vector(&vectors, |vector| Ok(byte_constants_of(vector)))
    );
}

#[test]
fn constant_bytes_are_one_constant_per_byte_in_order() {
    let wide: [u8; 32] = array("00ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
    assert_eq!(
        (
            constants(Bytes::<0>::constant(&[]).bytes()),
            constants(Bytes::constant(&[7]).bytes()),
            constants(Bytes::constant(&[1, 2, 255]).bytes()),
            constants(Bytes::constant(&wide).bytes()),
        ),
        (
            vec![],
            byte_constants(&[7]),
            byte_constants(&[1, 2, 255]),
            byte_constants(&wide),
        )
    );
}

#[test]
fn default_bytes_are_constant_zeros() {
    assert_eq!(
        (
            constants(Bytes::<0>::default().bytes()),
            constants(Bytes::<3>::default().bytes()),
            constants(Bytes::<32>::default().bytes()),
        ),
        (vec![], byte_constants(&[0; 3]), byte_constants(&[0; 32]),)
    );
}

#[test]
fn a_split_constant_is_its_big_endian_bytes_in_every_form() {
    assert_eq!(
        per_vector(&VALID, |vector| split_forms(&NativeBytes, &vector.pair())),
        expected(&VALID, &SPLIT_FORMS, |vector, _| Ok(byte_constants_of(
            vector
        )))
    );
}

#[test]
fn a_constant_too_large_for_its_bytes_fails_to_split_with_value_too_large() {
    assert_eq!(
        per_vector(&TOO_LARGE, |vector| split_forms(
            &NativeBytes,
            &vector.pair()
        )),
        expected(&TOO_LARGE, &SPLIT_FORMS, |vector, _| Err((
            "CircuitError.ValueTooLarge",
            format!("a value does not fit in {} bits", 8 * vector.width())
        )))
    );
}

#[test]
fn splitting_into_32_bytes_fails_with_bit_width_too_large() {
    assert_eq!(
        per_vector(&WIDE, |vector| split_forms(&NativeBytes, &vector.pair())),
        expected(&WIDE, &SPLIT_FORMS, |_, _| too_wide())
    );
}

#[test]
fn a_split_refusal_is_located_at_the_caller() {
    let refused = [&TOO_LARGE[..], &WIDE].concat();
    assert_eq!(
        per_vector(&refused, |vector| split_forms(
            &NativeFailure,
            &vector.pair()
        )
        .into_iter()
        .map(|(form, failure)| (form, failure.map(|(_, _, file)| file)))
        .collect::<Visited<_>>()),
        expected(&refused, &SPLIT_FORMS, |_, _| Some(FILE))
    );

    let var = constant(256u64);
    let borrowed_line = line!() + 1;
    let borrowed = Bytes::<1>::try_from(&var).expect_err("one byte cannot hold 256");
    let owned_line = line!() + 1;
    let owned = Bytes::<1>::try_from(var).expect_err("one byte cannot hold 256");
    let var = constant(0u64);
    let wide_borrowed_line = line!() + 1;
    let wide_borrowed = Bytes::<32>::try_from(&var).expect_err("256 bits is unsupported");
    let wide_owned_line = line!() + 1;
    let wide_owned = Bytes::<32>::try_from(var).expect_err("256 bits is unsupported");
    for (error, expected_name, expected_line) in [
        (borrowed, "CircuitError.ValueTooLarge", borrowed_line),
        (owned, "CircuitError.ValueTooLarge", owned_line),
        (
            wide_borrowed,
            "CircuitError.BitWidthTooLarge",
            wide_borrowed_line,
        ),
        (wide_owned, "CircuitError.BitWidthTooLarge", wide_owned_line),
    ] {
        assert_eq!(
            (
                error.name(),
                error.location().file(),
                error.location().line()
            ),
            (expected_name, file!(), expected_line),
        );
    }
}

#[test]
fn a_split_holds_natively_exactly_when_the_bytes_are_the_values() {
    assert_eq!(
        (
            per_vector(&VALID, |vector| split_forms(&Native, &vector.pair())),
            per_vector(&WRONG, |vector| split_forms(&Native, &vector.pair())),
        ),
        (
            expected(&VALID, &SPLIT_FORMS, |_, _| Ok(())),
            expected(&WRONG, &SPLIT_FORMS, |_, _| Err(SPLIT_BROKEN)),
        )
    );
}

#[test]
fn packed_constant_bytes_are_their_big_endian_value_in_every_form() {
    assert_eq!(
        per_vector(&VALID, |vector| pack_forms(&NativeBytes, &vector.pair())),
        expected(&VALID, &PACK_FORMS, |vector, _| Ok(value_constant(vector)))
    );
}

#[test]
fn packing_32_bytes_fails_at_the_caller_with_bit_width_too_large() {
    assert_eq!(
        (
            per_vector(&WIDE, |vector| pack_forms(&NativeBytes, &vector.pair())),
            per_vector(&WIDE, |vector| pack_forms(&NativeFailure, &vector.pair())
                .into_iter()
                .map(|(form, failure)| (form, failure.map(|(_, _, file)| file)))
                .collect::<Visited<_>>()),
        ),
        (
            expected(&WIDE, &PACK_FORMS, |_, _| too_wide()),
            expected(&WIDE, &PACK_FORMS, |_, _| Some(FILE)),
        )
    );
}

#[test]
fn a_pack_holds_natively_exactly_when_the_value_is_the_bytes_read_big_endian() {
    let wrong = [&WRONG[..], &TOO_LARGE].concat();
    assert_eq!(
        (
            per_vector(&VALID, |vector| pack_forms(&Native, &vector.pair())),
            per_vector(&wrong, |vector| pack_forms(&Native, &vector.pair())),
        ),
        (
            expected(&VALID, &PACK_FORMS, |_, _| Ok(())),
            expected(&wrong, &PACK_FORMS, |_, _| Err(PACK_BROKEN)),
        )
    );
}

#[test]
fn splitting_then_packing_a_constant_returns_it() {
    let fitting = [&VALID[..], &WRONG].concat();
    let round_trip = |vector: &Vector| -> Field {
        let var = constant(vector.value());
        let packed = match vector.width() {
            0 => CircuitVar::try_from(Bytes::<0>::try_from(&var).expect("split")),
            1 => CircuitVar::try_from(Bytes::<1>::try_from(&var).expect("split")),
            2 => CircuitVar::try_from(Bytes::<2>::try_from(&var).expect("split")),
            _ => CircuitVar::try_from(Bytes::<31>::try_from(&var).expect("split")),
        };
        value(&packed.expect("pack")).expect("a constant")
    };
    assert_eq!(
        per_vector(&fitting, round_trip),
        per_vector(&fitting, Vector::value)
    );
}
