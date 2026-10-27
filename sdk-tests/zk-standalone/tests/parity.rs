//! A native Rust integer and an externally written field gadget have the same meaning.
use zolana_zk_standalone_fixture::WithdrawalInputs;
use xark::Field;
#[test]
fn typed_input_encoding_preserves_native_widths_and_public_order() {
    let input = WithdrawalInputs::example();
    let fields = xark::input::leaves(&input.public, "public");
    let expected = [input.public.commitment, Field::from(input.public.amount), input.public.destination_hi, Field::from(input.public.destination_lo)];
    assert_eq!(fields.iter().map(|(_, value)| value.to_string()).collect::<Vec<_>>(), expected.map(|value| value.to_decimal()));
}
