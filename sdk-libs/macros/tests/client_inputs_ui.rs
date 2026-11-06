#[test]
fn client_declarations_compile_or_are_rejected() {
    let cases = trybuild::TestCases::new();
    cases.pass("tests/client_inputs/pass/*.rs");
    cases.compile_fail("tests/client_inputs/fail/*.rs");
}

#[test]
fn invalid_program_declarations_are_rejected() {
    trybuild::TestCases::new().compile_fail("tests/zk_program/fail/*.rs");
}
