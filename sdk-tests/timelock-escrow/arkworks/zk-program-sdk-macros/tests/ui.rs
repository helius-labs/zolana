#[test]
fn compile_errors() {
    trybuild::TestCases::new().compile_fail("tests/ui/fail/*.rs");
}
