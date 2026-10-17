#[test]
fn width_errors_fail_the_build() {
    let cases = trybuild::TestCases::new();
    cases.pass("tests/ui/widths/pass/*.rs");
    cases.compile_fail("tests/ui/widths/fail/*.rs");
}

#[test]
fn a_zk_circuit_has_exactly_private_and_public() {
    trybuild::TestCases::new().compile_fail("tests/ui/shape/fail/*.rs");
}
