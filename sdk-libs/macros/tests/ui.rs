mod support;

#[test]
fn compile_errors() {
    support::normalize_git_diagnostics();
    trybuild::TestCases::new().compile_fail("tests/ui/fail/*.rs");
}
