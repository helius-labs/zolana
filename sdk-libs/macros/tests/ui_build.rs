mod support;

#[test]
fn bounded_length_errors_fail_the_build() {
    support::normalize_git_diagnostics();
    let cases = trybuild::TestCases::new();
    cases.pass("tests/ui/lengths/pass/*.rs");
    cases.compile_fail("tests/ui/lengths/fail/*.rs");
}
