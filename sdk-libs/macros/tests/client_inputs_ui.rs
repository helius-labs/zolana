#[test]
fn invalid_client_declarations_are_rejected() {
    trybuild::TestCases::new().compile_fail("tests/client_inputs/fail/*.rs");
}
