mod support;

#[test]
fn bounded_length_errors_fail_the_build() -> Result<(), Box<dyn std::error::Error>> {
    support::with_normalized_git_paths(|| {
        let cases = trybuild::TestCases::new();
        cases.pass("tests/ui/lengths/pass/*.rs");
        cases.compile_fail("tests/ui/lengths/fail/*.rs");
    })
}
